# agents/prefetch_agent/agent.py
"""
Prefetch Agent — analyses a single Windows .pf prefetch file for execution evidence.

Standalone CLI:  python -m agents.prefetch_agent.agent
Orchestrator:    await run_prefetch_analysis(prefetch=Path(...))

Tool: pyscca (libyal/libscca Python bindings, system-installed via libscca-python3).
Court-vetted, in-process — no subprocess, no temp files, no JSON roundtrip.

Detector set (low-FP by design):
- suspicious_execution_path  — executable_path under \\Users\\, \\Temp\\, \\AppData\\, \\ProgramData\\, …
- masquerade_execution        — basename in MASQUERADE_TARGETS but path != canonical (mirrors registry_agent)
- high_run_count_anomaly      — run_count > 50 AND suspicious path (frequent re-execution from user space)
"""

import asyncio
import hashlib
import os
import re
from datetime import UTC, datetime
from pathlib import Path

import yaml

from agents._chisel import Chisel
from cognee_schema.schema import derive_host_id

EVIDENCE_ROOT = Path(os.environ.get("EVIDENCE_ROOT", "/home/sansforensics/dfirskills2/evidence"))
EVIDENCE_NEW = EVIDENCE_ROOT / "new"
CLAIMS_TODO = EVIDENCE_ROOT / "claims/todo"

CHISEL_URL = os.environ.get("CHISEL_URL", "http://127.0.0.1:3000")
CHISEL_SECRET = os.environ["CHISEL_SECRET"]

# Win8+ retains 8 historical run times; Win7 retains 1. Probe up to 8 indices —
# pyscca returns None past the valid range, so over-asking is safe.
MAX_RUN_TIMES = 8

# Same suspicious-path heuristic the registry agent uses for ImagePath / Run-key data.
SUSPICIOUS_PATH_HINTS = (
    "\\users\\", "\\appdata\\", "\\temp\\",
    "\\programdata\\", "\\public\\", "\\$recycle.bin\\",
)

# Mirror registry_agent.MASQUERADE_TARGETS — system-critical exe basenames that
# must only appear at their canonical path. A prefetch entry for `svchost.exe`
# whose ExecutablePath is anything other than `c:\windows\system32\svchost.exe`
# is a near-certain masquerade.
MASQUERADE_TARGETS = {
    "svchost.exe":   "c:\\windows\\system32\\svchost.exe",
    "csrss.exe":     "c:\\windows\\system32\\csrss.exe",
    "lsass.exe":     "c:\\windows\\system32\\lsass.exe",
    "lsm.exe":       "c:\\windows\\system32\\lsm.exe",
    "smss.exe":      "c:\\windows\\system32\\smss.exe",
    "winlogon.exe":  "c:\\windows\\system32\\winlogon.exe",
    "wininit.exe":   "c:\\windows\\system32\\wininit.exe",
    "services.exe":  "c:\\windows\\system32\\services.exe",
    "explorer.exe":  "c:\\windows\\explorer.exe",
}

HIGH_RUN_COUNT_THRESHOLD = 50


def detect_prefetch(pf_path: Path) -> bool:
    """Cheap routing check — staged-suffix or bare .pf extension."""
    n = pf_path.name.lower()
    return n.endswith(".pf") or "__prefetch__" in n


def _detect_pf_anti_forensics_wipe(pf_path: Path) -> dict | None:
    """Return a finding dict iff the .pf file has been deliberately wiped to nulls.

    Tradecraft: anti-forensic actors zero-out specific prefetch files to erase
    execution evidence for a specific cmdline+image hash. The file size is
    preserved (so a quick `ls` still shows it as present), but the SCCA header is
    overwritten with NULs along with the rest of the content.

    A genuine prefetch file starts with: `<version> 53 43 43 41` (SCCA magic at
    offset 4). A wiped file is `00 00 ...` for the entire content.

    Returns None if the file looks normal (not wiped) or empty (different failure
    mode — agent already handles via provenance claim).
    """
    try:
        size = pf_path.stat().st_size
    except OSError:
        return None
    if size == 0:
        return None  # empty file — not a wipe, just zero-byte
    # Read up to 4 KB sample. A wiped file will be all-nulls; a corrupt or
    # different-format file will have non-null bytes somewhere in the first KB.
    sample_size = min(size, 4096)
    try:
        with open(pf_path, "rb") as f:
            sample = f.read(sample_size)
    except OSError:
        return None
    if any(b != 0 for b in sample):
        return None  # has content — not a wipe (could be corrupt or unsupported format)
    # Extract executable name from the prefetch filename pattern:
    #   RUNDLL32.EXE-E8194E9C.pf                                  → RUNDLL32.EXE
    #   chrome.exe-12345678.pf                                    → chrome.exe
    #   win7-32-nromanoff-c-drive__prefetch__RUNDLL32.EXE-E8194E9C.pf → RUNDLL32.EXE
    # The trailing `-<8-hex>.pf` is the path-hash + extension; the optional
    # `<host>-c-drive__prefetch__` prefix is added by the staged-extract layer.
    stem = pf_path.stem  # strips .pf
    if "__prefetch__" in stem:
        stem = stem.rsplit("__prefetch__", 1)[1]
    exe_hint = re.sub(r"-[0-9A-Fa-f]{8}$", "", stem) if "-" in stem else stem
    return {
        "type": "prefetch_anti_forensics_wipe",
        "prefetch_filename": pf_path.name,
        "prefetch_size_bytes": size,
        "wiped_executable_hint": exe_hint,
    }


def _parse_pf(pf_path: Path) -> dict | None:
    """Open a .pf via pyscca and pull every field we need.

    Returns a dict with: executable_name, executable_path, run_count, last_run_time,
    run_times (list, newest first, ISO8601), filenames (list of touched files,
    Windows paths uppercased by Prefetch), volumes ([{device_path, serial, creation_time}]).

    Returns None on parse failure (corrupt or non-prefetch file).
    """
    try:
        import pyscca
    except ImportError:
        print("   ❌ pyscca (libscca-python3) not installed — cannot parse prefetch")
        return None

    try:
        scca = pyscca.open(str(pf_path))
    except Exception as e:
        print(f"   ❌ pyscca failed to open {pf_path.name}: {e!r}")
        return None

    try:
        exe_name = scca.get_executable_filename() or ""
        run_count = scca.get_run_count() or 0

        # Up to 8 historical run times. pyscca returns None past the valid range
        # (Win7 → only index 0 is valid; Win8+ → 0..7).
        run_times: list = []
        for i in range(MAX_RUN_TIMES):
            try:
                rt = scca.get_last_run_time(i)
            except Exception:
                rt = None
            if rt is None:
                continue
            # pyscca returns datetime; normalize to ISO8601 Z.
            iso = rt.replace(tzinfo=UTC).isoformat().replace("+00:00", "Z") \
                if rt.tzinfo is None else rt.isoformat().replace("+00:00", "Z")
            run_times.append(iso)
        last_run = run_times[0] if run_times else None

        # Touched-files list. Prefetch records every file the binary opened in its
        # first 10s of execution — the binary itself appears in here as its full path.
        filenames: list = []
        try:
            for i in range(scca.get_number_of_filenames()):
                fn = scca.get_filename(i)
                if fn:
                    filenames.append(fn)
        except Exception:
            pass

        # Locate the executable's full path from Filenames. Convention: the entry whose
        # basename matches `exe_name` and lives under a Volume device path is the binary.
        exe_path = None
        for fn in filenames:
            # Filenames are like "\DEVICE\HARDDISKVOLUME1\WINDOWS\SYSTEM32\SVCHOST.EXE"
            tail = fn.rsplit("\\", 1)[-1].lower()
            if tail == exe_name.lower():
                exe_path = _normalize_volume_path(fn, scca)
                break

        # Volume info — serial number + creation time per volume the prefetch references.
        volumes: list = []
        try:
            for i in range(scca.get_number_of_volumes()):
                v = scca.get_volume_information(i)
                vct = v.get_creation_time()
                volumes.append({
                    "device_path": v.get_device_path(),
                    "serial": format(v.get_serial_number() or 0, "08x").upper(),
                    "creation_time": vct.replace(tzinfo=UTC).isoformat().replace("+00:00", "Z")
                        if vct and vct.tzinfo is None else (vct.isoformat().replace("+00:00", "Z") if vct else None),
                })
        except Exception:
            pass

        return {
            "executable_name": exe_name,
            "executable_path": exe_path,
            "run_count": run_count,
            "last_run_time": last_run,
            "run_times": run_times,
            "filenames": filenames,
            "volumes": volumes,
        }
    finally:
        try:
            scca.close()
        except Exception:
            pass


def _normalize_volume_path(prefetch_path: str, scca) -> str:
    """Convert a Prefetch \\DEVICE\\HARDDISKVOLUMEn\\... path to a `c:\\...` path.

    Heuristic: the first volume in the file is treated as `c:\\` (true on every
    single-disk Windows host we'll see in practice). For multi-volume hosts the
    raw \\DEVICE\\... form is returned unchanged so we don't lie about the drive.
    """
    p = prefetch_path
    try:
        n_vols = scca.get_number_of_volumes()
        if n_vols == 1:
            v = scca.get_volume_information(0)
            dev = v.get_device_path() or ""
            if p.upper().startswith(dev.upper()):
                p = "c:" + p[len(dev):]
    except Exception:
        pass
    return p.lower()  # lowercase for downstream comparison consistency


def detect_anomalies(parsed: dict) -> list[dict]:
    """Apply the detector set to a parsed prefetch dict."""
    findings: list = []
    exe_name = (parsed.get("executable_name") or "").lower()
    exe_path = (parsed.get("executable_path") or "").lower()
    run_count = parsed.get("run_count") or 0

    if exe_path and any(h in exe_path for h in SUSPICIOUS_PATH_HINTS):
        findings.append({
            "type": "suspicious_execution_path",
            "executable_name": exe_name,
            "executable_path": exe_path,
            "run_count": run_count,
            "last_run_time": parsed.get("last_run_time"),
        })

    expected = MASQUERADE_TARGETS.get(exe_name)
    if expected and exe_path and expected.lower() not in exe_path:
        findings.append({
            "type": "masquerade_execution",
            "executable_name": exe_name,
            "executable_path": exe_path,
            "expected_path": expected,
            "run_count": run_count,
            "last_run_time": parsed.get("last_run_time"),
        })

    # Compound: a binary in user-writable space being run repeatedly is much more
    # suspicious than a one-shot dropper. The threshold (50) is conservative —
    # legitimate user apps in AppData (Teams, Slack) easily clear this, but they
    # won't usually be flagged for masquerade or other co-occurring detectors.
    if run_count >= HIGH_RUN_COUNT_THRESHOLD and exe_path \
            and any(h in exe_path for h in SUSPICIOUS_PATH_HINTS):
        findings.append({
            "type": "high_run_count_anomaly",
            "executable_name": exe_name,
            "executable_path": exe_path,
            "run_count": run_count,
            "last_run_time": parsed.get("last_run_time"),
        })

    return findings


def _entities_from_parsed(parsed: dict, host_id: str) -> list[str]:
    """ProcessExecution entity (always) + File entity for the executable path (if known)."""
    out: set = set()
    exe = (parsed.get("executable_name") or "").lower()
    if exe:
        out.add(f"process_execution:{host_id}:{exe}")
    exe_path = parsed.get("executable_path")
    if exe_path:
        out.add(f"file:{host_id}:{exe_path}")
    return sorted(out)


def _execution_attrs_from_parsed(parsed: dict, host_id: str, findings: list[dict] | None = None) -> dict:
    """Per-entity attrs map for the extractor + validator spot-check.

    `masquerade_pattern` ("<basename>:<expected_path>") is added when this prefetch
    triggered the masquerade_execution detector, so the cross-host correlation rule
    can pivot on the same signature observed across hosts."""
    exe = (parsed.get("executable_name") or "").lower()
    if not exe:
        return {}
    inner = {
        "executable_name": exe,
        "executable_path": parsed.get("executable_path"),
        "last_run_time": parsed.get("last_run_time"),
        "run_count": parsed.get("run_count"),
        "run_times": parsed.get("run_times") or [],
        "source": "prefetch",  # discriminator for ProcessExecution.sources merge
    }
    if findings:
        for f in findings:
            if f.get("type") == "masquerade_execution" and f.get("expected_path"):
                inner["masquerade_pattern"] = f"{exe}:{f['expected_path'].lower()}"
                break
    return {f"process_execution:{host_id}:{exe}": inner}


def _format_finding(f: dict) -> str:
    t = f["type"]
    if t == "suspicious_execution_path":
        return f"- **suspicious_execution_path** `{f['executable_path']}` (run {f['run_count']}× last={f.get('last_run_time')})"
    if t == "masquerade_execution":
        return f"- **masquerade_execution** `{f['executable_name']}` ran from `{f['executable_path']}` (expected `{f['expected_path']}`; run {f['run_count']}× last={f.get('last_run_time')})"
    if t == "high_run_count_anomaly":
        return f"- **high_run_count_anomaly** `{f['executable_path']}` ran {f['run_count']}× from user-writable path"
    if t == "prefetch_anti_forensics_wipe":
        return (f"- **prefetch_anti_forensics_wipe** `{f['prefetch_filename']}` "
                f"({f['prefetch_size_bytes']:,} bytes of NULs) — "
                f"executable hint: `{f['wiped_executable_hint']}` ⚠️ ANTI-FORENSICS")
    return f"- **{t}** {f}"


def generate_claim(pf_path: Path, parsed: dict, findings: list[dict]) -> str:
    timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    exe = (parsed.get("executable_name") or "unknown").lower()
    cid_key = f"{pf_path.name}:{exe}:{parsed.get('last_run_time')}:" + "|".join(
        f"{f['type']}" for f in findings
    )
    cid = "prefetch-" + hashlib.md5(cid_key.encode()).hexdigest()[:14]
    host_id = derive_host_id(pf_path.name)

    entities = _entities_from_parsed(parsed, host_id) or [f"process_execution:{host_id}:{exe}"]
    execution_attrs = _execution_attrs_from_parsed(parsed, host_id, findings)

    rel = str(pf_path.relative_to(EVIDENCE_ROOT)) if pf_path.is_relative_to(EVIDENCE_ROOT) else pf_path.name

    fm = {
        "claim_id": cid,
        "status": "new",
        "generated_by": "prefetch-agent",
        "host": host_id,
        "prefetch_file": rel,
        "entities": entities,
        "evidence_refs": [rel],
        "confidence": 0.85 if findings else 0.5,
        "timestamp": timestamp,
        "anomaly_count": len(findings),
    }
    if execution_attrs:
        fm["execution_attrs"] = execution_attrs

    body_lines = [
        f"**Prefetch Execution Analysis: `{exe}`**",
        "",
        f"Source: `{pf_path.name}`",
        f"Executable: `{parsed.get('executable_path') or '(unknown path)'}` "
        f"(run {parsed.get('run_count', 0)}×, last at `{parsed.get('last_run_time') or 'n/a'}`)",
        "",
    ]

    if findings:
        body_lines.append(f"**Findings ({len(findings)}):**")
        body_lines.extend(_format_finding(f) for f in findings)
    else:
        body_lines.append("_No execution anomalies detected by this rule set._")

    run_times = parsed.get("run_times") or []
    if run_times:
        body_lines += ["", f"**Run history (most recent {len(run_times)}):**"]
        body_lines.extend(f"- `{rt}`" for rt in run_times)

    volumes = parsed.get("volumes") or []
    if volumes:
        body_lines += ["", "**Source volume(s):**"]
        for v in volumes:
            body_lines.append(
                f"- `{v.get('device_path')}` serial=`{v.get('serial')}` created=`{v.get('creation_time')}`"
            )

    body_lines += ["",
        "**Hypothesis:** Cross-reference run timestamps with evtx 4624 logons and "
        "registry persistence-wiring (`last_write_time` on Run-keys / Services). "
        "Pivot the executable basename to memory PIDs for live-process correlation.",
    ]

    return f"---\n{yaml.dump(fm, sort_keys=False)}---\n" + "\n".join(body_lines) + "\n"


async def run_prefetch_analysis(prefetch: Path | None = None):
    """Standalone entrypoint — also called in-process by the orchestrator dispatcher."""
    print("⚡ Prefetch Agent starting (Chisel-confined, pyscca in-process)...")
    chisel = Chisel(CHISEL_URL, CHISEL_SECRET)
    chisel.connect()
    print(f"🔒 Chisel session → {chisel.endpoint} (sid={chisel.session_id[:8]}…)")

    if prefetch is None:
        listing = chisel.shell("ls", ["-1", str(EVIDENCE_NEW)])
        for n in listing.splitlines():
            n = n.strip()
            if n and detect_prefetch(EVIDENCE_NEW / n):
                prefetch = EVIDENCE_NEW / n
                break
        if prefetch is None:
            print("❌ no prefetch file in evidence/new/")
            return

    print(f"📂 Parsing {prefetch.name}")
    parsed = await asyncio.to_thread(_parse_pf, prefetch)
    if parsed is None:
        # First check whether the parse failure is anti-forensic wipe (file is
        # non-zero size but all-nulls — attacker overwrote the SCCA header to
        # erase execution evidence for a specific cmdline+image hash). If yes,
        # emit a Tier-B finding instead of a provenance-only claim.
        wipe_finding = _detect_pf_anti_forensics_wipe(prefetch)
        if wipe_finding is not None:
            print(f"   🚨 ANTI-FORENSIC WIPE detected: "
                  f"{wipe_finding['prefetch_filename']} "
                  f"({wipe_finding['prefetch_size_bytes']:,} bytes of nulls, "
                  f"executable hint: {wipe_finding['wiped_executable_hint']})")
            empty = {"executable_name": wipe_finding["wiped_executable_hint"],
                     "executable_path": None, "run_count": 0, "last_run_time": None,
                     "run_times": [], "volumes": []}
            chisel.call("create_directory", {"path": str(CLAIMS_TODO)})
            claim = generate_claim(prefetch, empty, [wipe_finding])
            ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
            chisel.call("write_file",
                {"path": str(CLAIMS_TODO / f"prefetch_WIPED_{prefetch.stem}_{ts}.md"),
                 "content": claim})
            print("   ✅ Anti-forensic wipe claim written")
            return
        # Otherwise: empty file, non-prefetch format, or genuinely corrupt — emit
        # a provenance claim so the failure is visible in the case timeline.
        empty = {"executable_name": prefetch.stem, "executable_path": None,
                 "run_count": 0, "last_run_time": None, "run_times": [], "volumes": []}
        chisel.call("create_directory", {"path": str(CLAIMS_TODO)})
        claim = generate_claim(prefetch, empty, [])
        ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        chisel.call("write_file", {"path": str(CLAIMS_TODO / f"prefetch_{prefetch.stem}_{ts}.md"), "content": claim})
        print("   provenance claim written (parse failed)")
        return

    print(f"   exe=`{parsed['executable_name']}` path=`{parsed['executable_path']}` "
          f"runs={parsed['run_count']} history={len(parsed['run_times'])}")

    findings = detect_anomalies(parsed)
    print(f"🚨 Findings: {len(findings)}")
    for f in findings[:5]:
        print("   " + _format_finding(f).lstrip("- ").lstrip())

    chisel.call("create_directory", {"path": str(CLAIMS_TODO)})
    claim = generate_claim(prefetch, parsed, findings)
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    safe_exe = (parsed.get("executable_name") or "unknown").replace("\\", "_").replace("/", "_")
    claim_path = CLAIMS_TODO / f"prefetch_{safe_exe}_{ts}.md"
    chisel.call("write_file", {"path": str(claim_path), "content": claim})
    print(f"✅ Claim written → {claim_path.name}")


if __name__ == "__main__":
    asyncio.run(run_prefetch_analysis())
