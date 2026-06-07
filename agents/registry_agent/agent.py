# agents/registry_agent/agent.py
"""
Registry Agent — analyses a single Windows registry hive for persistence.

Standalone CLI:  python -m agents.registry_agent.agent
Orchestrator:    await run_registry_analysis(hive=Path(...))

Tool: RECmd (`dotnet /opt/zimmermantools/RECmd/RECmd.dll`) per the SIFT yara/EZ-tools
convention. Each persistence-relevant key is dumped via `--kn ... --json <tmp>`,
parsed in-process, and run through deterministic detectors. Findings emitted as
a markdown claim via Chisel; orchestrator picks it up through the standard
todo→doing→done pipeline and the correlation agent fires on it.
"""

import asyncio
import csv
import hashlib
import json
import os
import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import yaml

from agents._chisel import Chisel
from cognee_schema.schema import derive_host_id

EVIDENCE_ROOT = Path(os.environ.get("EVIDENCE_ROOT", "/home/sansforensics/dfirskills2/evidence"))
CLAIMS_TODO = EVIDENCE_ROOT / "claims/todo"
EVIDENCE_NEW = EVIDENCE_ROOT / "new"

CHISEL_URL = os.environ.get("CHISEL_URL", "http://127.0.0.1:3000")
CHISEL_SECRET = os.environ["CHISEL_SECRET"]

RECMD = ["dotnet", "/opt/zimmermantools/RECmd/RECmd.dll"]
APPCOMPAT_PARSER = ["dotnet", "/opt/zimmermantools/AppCompatCacheParser.dll"]
AMCACHE_PARSER = ["dotnet", "/opt/zimmermantools/AmcacheParser.dll"]

# Suspicious data-path substrings (case-insensitive) — user-writable locations a
# legitimate persistence value almost never points at.
SUSPICIOUS_PATH_HINTS = (
    "\\users\\",
    "\\appdata\\",
    "\\temp\\",
    "\\programdata\\",
    "\\public\\",
    "\\$recycle.bin\\",
)

# System-critical executables that must ONLY appear at their canonical path.
# Anything else with this basename is a masquerade attempt (e.g., the win7-nromanoff
# case has `c:\windows\system32\dllhost\svchost.exe` in a Run key).
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

# Per-hive-type key targets. Label → registry path (RECmd --kn).
SOFTWARE_KEYS = {
    "Run":        "Microsoft\\Windows\\CurrentVersion\\Run",
    "RunOnce":    "Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Wow6432_Run":"Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Winlogon":   "Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
    "IFEO":       "Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
    "Windows":    "Microsoft\\Windows NT\\CurrentVersion\\Windows",  # AppInit_DLLs lives here
}
SYSTEM_KEYS = {
    "Services_CS001": "ControlSet001\\Services",
    "Services_CS002": "ControlSet002\\Services",
}
NTUSER_KEYS = {
    "Run":     "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "RunOnce": "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
}

DEFAULT_USERINIT_RE = re.compile(r"^c:\\windows\\system32\\userinit\.exe,?\s*$", re.IGNORECASE)
DEFAULT_SHELL = "explorer.exe"


def detect_hive_kind(hive_path: Path) -> str | None:
    """SYSTEM | SOFTWARE | SAM | SECURITY | COMPONENTS | NTUSER.DAT | AMCACHE | None.

    Recognises both bare hive names and disk-image-agent's staged
    `<image_stem>__<HIVE>` / `<image_stem>__NTUSER.DAT_<user>` / `<image_stem>__Amcache.hve` form.
    """
    name = hive_path.name.upper()
    suffix = name.rsplit("__", 1)[-1] if "__" in name else name
    if suffix in {"SYSTEM", "SOFTWARE", "SAM", "SECURITY", "COMPONENTS"}:
        return suffix
    if suffix.startswith("NTUSER.DAT") or suffix == "NTUSER.DAT":
        return "NTUSER.DAT"
    # Amcache.hve lives at \Windows\AppCompat\Programs\, not in the standard config dir.
    if suffix == "AMCACHE.HVE" or suffix.startswith("AMCACHE"):
        return "AMCACHE"
    return None


def _ntuser_owner(hive_path: Path) -> str | None:
    """Pull the username out of `<image>__NTUSER.DAT_<user>` (or None for raw hives)."""
    m = re.search(r"NTUSER\.DAT_([^_/]+)$", hive_path.name)
    return m.group(1) if m else None


async def _recmd_dump_key(hive: Path, key: str) -> dict | None:
    """Run RECmd --kn for one key via local subprocess; return parsed JSON or None.

    Direct-subprocess exception per evtx_agent.run_evtxecmd rationale (RECmd.dll
    lives at /opt/zimmermantools/RECmd/, outside Chisel --root).
    """
    with tempfile.TemporaryDirectory(prefix="recmd_") as td:
        proc = await asyncio.create_subprocess_exec(
            *RECMD, "-f", str(hive), "--kn", key, "--json", td,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()
        # RECmd names the output after the leaf key (case can vary). Pick the .json file in the tempdir.
        files = list(Path(td).glob("*.json"))
        if not files:
            return None
        try:
            return json.loads(files[0].read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError:
            return None


async def _run_appcompat_parser(hive: Path) -> list[dict] | None:
    """Run AppCompatCacheParser via local subprocess on a SYSTEM hive; return parsed
    CSV rows.

    Single run-per-hive (the tool always processes the entire AppCompatCache REG_BINARY).
    Returns each row as a dict with columns:
      ControlSet, CacheEntryPosition, Path, LastModifiedTimeUTC, Executed, Duplicate, SourceFile

    Direct-subprocess exception per evtx_agent.run_evtxecmd rationale
    (AppCompatCacheParser.dll lives at /opt/zimmermantools/, outside Chisel --root).
    """
    with tempfile.TemporaryDirectory(prefix="appcompat_") as td:
        out_csv = Path(td) / "appcompat.csv"
        proc = await asyncio.create_subprocess_exec(
            *APPCOMPAT_PARSER, "-f", str(hive), "--csv", td, "--csvf", "appcompat.csv",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()
        if not out_csv.exists():
            return None
        try:
            with open(out_csv, encoding="utf-8") as f:
                return list(csv.DictReader(f))
        except (OSError, csv.Error):
            return None


def detect_shimcache_anomalies(rows: list[dict]) -> list[dict]:
    """Apply suspicious-path / masquerade / executed-from-user-path detectors to ShimCache rows.

    OS-aware: the `Executed` field is `Yes/No` on Win7 (direct execution evidence) and blank
    on Win8+ (cache only proves the compatibility manager *saw* the file). Skip Duplicate=True
    rows so cross-ControlSet duplicates aren't double-counted.
    """
    findings: list = []
    seen: set = set()  # (path_lower, controlset) for finding-level dedup
    for r in rows or []:
        if (r.get("Duplicate") or "").strip().lower() == "true":
            continue
        path = (r.get("Path") or "").strip()
        if not path:
            continue
        cs = (r.get("ControlSet") or "").strip()
        key = (path.lower(), cs)
        if key in seen:
            continue
        seen.add(key)

        executed = (r.get("Executed") or "").strip().lower()
        last_mod = (r.get("LastModifiedTimeUTC") or "").strip() or None
        position = (r.get("CacheEntryPosition") or "").strip()

        suspicious = _is_suspicious_path(path)
        masq = _is_masquerade(path)

        if suspicious and executed == "yes":
            findings.append({
                "type": "shimcache_executed_user_writable_path",
                "path": path, "controlset": cs, "position": position,
                "executed": "Yes",  # Win7 direct execution evidence
                "last_modified_time": last_mod,
            })
        elif suspicious:
            # Either Win8+ presence-only OR Win7 stat-only (Executed=No). Lower-confidence finding.
            findings.append({
                "type": "shimcache_suspicious_path",
                "path": path, "controlset": cs, "position": position,
                "executed": executed.capitalize() if executed else "(unknown)",
                "last_modified_time": last_mod,
            })
        if masq:
            findings.append({
                "type": "shimcache_masquerade",
                "path": path, "controlset": cs, "position": position,
                "binary": masq[0], "expected_path": masq[1],
                "executed": executed.capitalize() if executed else "(unknown)",
                "last_modified_time": last_mod,
            })
    return findings


async def _run_amcache_parser(hive: Path) -> list[dict] | None:
    """Run AmcacheParser on an Amcache.hve; return UNION of associated/unassociated/program rows.

    AmcacheParser produces multiple CSV files per run (unlike AppCompatCacheParser's single file):
      - <prefix>_AssociatedFileEntries.csv  — Win8+ per-binary records (SHA1, Publisher, etc.)
      - <prefix>_UnassociatedFileEntries.csv — Win8+ files seen but not linked to a program
      - <prefix>_ProgramEntries.csv         — installed-program records (Win7 SP1+)
    Each returned row gets a `_csv_source` discriminator so the detector knows which subset
    of fields are populated. Other CSVs (DriverBinaries, DeviceContainers, ShortcutEntries)
    are out of scope for this iteration.
    """
    # Direct-subprocess exception per evtx_agent.run_evtxecmd rationale
    # (AmcacheParser.dll lives at /opt/zimmermantools/, outside Chisel --root).
    with tempfile.TemporaryDirectory(prefix="amcache_") as td:
        proc = await asyncio.create_subprocess_exec(
            *AMCACHE_PARSER, "-f", str(hive), "--csv", td, "-i",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()
        all_rows: list = []
        for csv_path in sorted(Path(td).glob("*.csv")):
            n = csv_path.name
            if "_AssociatedFileEntries" in n:
                kind = "associated"
            elif "_UnassociatedFileEntries" in n:
                kind = "unassociated"
            elif "_ProgramEntries" in n:
                kind = "program"
            else:
                continue
            try:
                with open(csv_path, encoding="utf-8") as f:
                    for row in csv.DictReader(f):
                        row["_csv_source"] = kind
                        all_rows.append(row)
            except (OSError, csv.Error):
                continue
        return all_rows or None


def detect_amcache_anomalies(rows: list[dict]) -> list[dict]:
    """Apply suspicious-path / unsigned / publisher-mismatch / suspicious-program-install detectors.

    Filters to PE files (`IsPeFile=True`) with non-trivial size for the per-file detectors.
    Skips DriverBinaries-style records and any rows from CSV families we don't ingest.
    """
    findings: list = []
    seen: set = set()  # (path_lower, source) for dedup across CSV files
    for r in rows or []:
        src = r.get("_csv_source")

        # Per-file detectors (associated + unassociated): need IsPeFile + Size + FullPath.
        if src in ("associated", "unassociated"):
            if (r.get("IsPeFile") or "").strip().lower() != "true":
                continue
            full_path = (r.get("FullPath") or "").strip()
            if not full_path:
                continue
            try:
                size = int((r.get("Size") or "0").strip() or "0")
            except ValueError:
                size = 0
            if size < 1024:
                continue
            key = (full_path.lower(), src)
            if key in seen:
                continue
            seen.add(key)

            publisher = (r.get("Publisher") or "").strip()
            sha1 = (r.get("SHA1") or "").strip().lower() or None
            last_run = (r.get("FileKeyLastWriteTimestamp") or "").strip() or None
            basename = full_path.replace("/", "\\").rsplit("\\", 1)[-1].lower()

            common = {
                "path": full_path.lower(),
                "basename": basename,
                "size": size,
                "publisher": publisher or None,
                "sha1": sha1,
                "last_run_time": last_run,
                "csv_source": src,
            }

            in_user_writable = _is_suspicious_path(full_path)
            if in_user_writable:
                findings.append({"type": "amcache_executable_user_writable", **common})
                if not publisher:
                    findings.append({"type": "amcache_unsigned_user_writable_executable", **common})

            # Masquerade: claimed system-binary basename, but Publisher isn't Microsoft.
            expected = MASQUERADE_TARGETS.get(basename)
            if expected and publisher and "microsoft" not in publisher.lower():
                findings.append({
                    "type": "amcache_masquerade_publisher_mismatch",
                    **common,
                    "expected_path": expected,
                })

        # Program-install detector (program rows): RootDirPath in user-writable area.
        elif src == "program":
            root = (r.get("RootDirPath") or "").strip()
            if not root or not _is_suspicious_path(root):
                continue
            name = (r.get("Name") or r.get("ProgramName") or "").strip() or "(unnamed)"
            install_date = (r.get("InstallDate") or "").strip() or None
            findings.append({
                "type": "amcache_recently_installed_user_writable_program",
                "program_name": name,
                "root_dir_path": root.lower(),
                "install_date": install_date,
                "csv_source": "program",
            })
    return findings


def _normalize_path(value: str) -> str:
    """Lowercase + expand the env vars/aliases Windows uses in registry data so
    canonical-path comparisons aren't fooled by `%SystemRoot%`, `\\SystemRoot\\`, etc."""
    v = value.lower().strip().strip('"')
    v = v.replace("%systemroot%", "c:\\windows")
    v = v.replace("\\systemroot\\", "c:\\windows\\")
    v = v.replace("%windir%", "c:\\windows")
    v = v.replace("%programfiles(x86)%", "c:\\program files (x86)")
    v = v.replace("%programfiles%", "c:\\program files")
    v = v.replace("%programdata%", "c:\\programdata")
    # NT object-manager prefixes common in service ImagePath
    v = v.replace("\\??\\", "")
    v = v.replace("system32\\drivers\\", "c:\\windows\\system32\\drivers\\") if v.startswith("system32\\") else v
    return v


def _is_suspicious_path(value: str | None) -> bool:
    if not value:
        return False
    v = _normalize_path(value)
    return any(hint in v for hint in SUSPICIOUS_PATH_HINTS)


def _is_masquerade(value: str | None) -> tuple[str, str] | None:
    """Return (basename, expected_path) if `value` references a masquerade-target binary at a non-canonical path."""
    if not value:
        return None
    v = _normalize_path(value)
    # Strip arguments after the executable to find the basename
    exe_part = v.split()[0] if v else ""
    last_slash = max(exe_part.rfind("\\"), exe_part.rfind("/"))
    basename = exe_part[last_slash + 1:] if last_slash >= 0 else exe_part
    expected = MASQUERADE_TARGETS.get(basename)
    if expected and expected.lower() not in v:
        return basename, expected
    return None


def _check_run_values(data: dict, label: str) -> list[dict]:
    """Apply suspicious-path + masquerade detectors to the Values list of a Run-style key."""
    findings: list = []
    if not data:
        return findings
    key_name = data.get("KeyName") or label
    last_write = data.get("LastWriteTimestamp")  # ISO8601 string from RECmd
    for v in data.get("Values", []) or []:
        vd = v.get("ValueData") or ""
        vname = v.get("ValueName") or ""
        if _is_suspicious_path(vd):
            findings.append({
                "type": "suspicious_run_value",
                "key": key_name,
                "value_name": vname,
                "data": vd,
                "last_write_time": last_write,
            })
        m = _is_masquerade(vd)
        if m:
            findings.append({
                "type": "masquerade_run_value",
                "key": key_name,
                "value_name": vname,
                "data": vd,
                "binary": m[0],
                "expected_path": m[1],
                "last_write_time": last_write,
            })
    return findings


def detect_persistence(hive_kind: str, dumps: dict, hive_path: Path) -> list[dict]:
    """Per-hive-kind rule set. dumps maps label → parsed RECmd JSON (or None)."""
    findings: list = []

    if hive_kind == "SOFTWARE":
        for label in ("Run", "RunOnce", "Wow6432_Run"):
            findings += _check_run_values(dumps.get(label), label)

        wl = dumps.get("Winlogon")
        if wl:
            wl_lwt = wl.get("LastWriteTimestamp")
            for v in wl.get("Values", []) or []:
                vname = (v.get("ValueName") or "").lower()
                vd = v.get("ValueData") or ""
                if vname == "userinit" and not DEFAULT_USERINIT_RE.match(vd):
                    findings.append({"type": "userinit_modified", "key": wl.get("KeyName"), "data": vd, "last_write_time": wl_lwt})
                if vname == "shell" and vd.lower().strip() != DEFAULT_SHELL:
                    findings.append({"type": "shell_modified", "key": wl.get("KeyName"), "data": vd, "last_write_time": wl_lwt})

        ifeo = dumps.get("IFEO")
        if ifeo:
            for sub in ifeo.get("SubKeys", []) or []:
                sub_lwt = sub.get("LastWriteTimestamp")
                for v in sub.get("Values", []) or []:
                    if (v.get("ValueName") or "").lower() == "debugger":
                        findings.append({
                            "type": "ifeo_debugger",
                            "key": sub.get("KeyName"),
                            "value_name": v.get("ValueName"),
                            "data": v.get("ValueData"),
                            "last_write_time": sub_lwt,
                        })

        wnd = dumps.get("Windows")
        if wnd:
            wnd_lwt = wnd.get("LastWriteTimestamp")
            for v in wnd.get("Values", []) or []:
                if (v.get("ValueName") or "").lower() == "appinit_dlls" and (v.get("ValueData") or "").strip():
                    findings.append({
                        "type": "appinit_dlls",
                        "key": wnd.get("KeyName"),
                        "data": v.get("ValueData"),
                        "last_write_time": wnd_lwt,
                    })

    elif hive_kind == "SYSTEM":
        for label in ("Services_CS001", "Services_CS002"):
            services = dumps.get(label)
            if not services:
                continue
            for sub in services.get("SubKeys", []) or []:
                svc_name = sub.get("KeyName")
                sub_lwt = sub.get("LastWriteTimestamp")

                # VSS-suppression check: certain backup/snapshot services with Start=4
                # (Disabled) are an anti-recovery signal — typically pre-encryption ransomware
                # tradecraft. Default Start for VSS is 3 (Manual); explicit Disabled is
                # suspicious. Independent of ImagePath (a disabled service may not have one set).
                svc_name_lower = (svc_name or "").lower()
                if svc_name_lower in {"vss", "swprv", "sdrsvc", "wbengine"}:
                    start_value = next(
                        (v.get("ValueData") for v in sub.get("Values", []) or []
                         if (v.get("ValueName") or "").lower() == "start"),
                        None,
                    )
                    try:
                        start_int = int(start_value) if start_value is not None else None
                    except (TypeError, ValueError):
                        start_int = None
                    if start_int == 4:  # Disabled
                        findings.append({
                            "type": "vss_service_disabled",
                            "controlset": label,
                            "service": svc_name_lower,
                            "start_value": start_int,
                            "last_write_time": sub_lwt,
                        })

                ip = next(
                    (v.get("ValueData") for v in sub.get("Values", []) or []
                     if (v.get("ValueName") or "").lower() == "imagepath"),
                    None,
                )
                if not ip:
                    continue
                if _is_suspicious_path(ip):
                    findings.append({
                        "type": "suspicious_service_imagepath",
                        "controlset": label,
                        "service": svc_name,
                        "image_path": ip,
                        "last_write_time": sub_lwt,
                    })
                m = _is_masquerade(ip)
                if m:
                    findings.append({
                        "type": "masquerade_service_imagepath",
                        "controlset": label,
                        "service": svc_name,
                        "image_path": ip,
                        "binary": m[0],
                        "expected_path": m[1],
                        "last_write_time": sub_lwt,
                    })

    elif hive_kind == "NTUSER.DAT":
        for label in ("Run", "RunOnce"):
            findings += _check_run_values(dumps.get(label), label)

    return findings


def _key_attrs_from_findings(findings: list[dict], hive_kind: str, owner: str | None, host_id: str) -> dict:
    """Build {entity_id: {asserted attrs}} mirroring _entities_from_findings.
    Entity IDs are host-namespaced: registry_key:<host>:<path>, file:<host>:<path>.
    Each registry entity carries `last_write_time` (RECmd LastWriteTimestamp) so the
    correlation agent's temporal rule can anchor persistence-wiring events on the timeline."""
    attrs: dict = {}
    for f in findings:
        t = f["type"]
        lwt = f.get("last_write_time")
        if t in ("suspicious_run_value", "masquerade_run_value"):
            scope = f"HKCU\\{owner}" if owner else "HKLM"
            ent = f"registry_key:{host_id}:{scope}\\{f['key']}\\{f['value_name']}"
            ka = {"value": f.get("data"), "value_type": "RegSz", "last_write_time": lwt}
            if t == "masquerade_run_value" and f.get("binary") and f.get("expected_path"):
                ka["masquerade_pattern"] = f"{f['binary'].lower()}:{f['expected_path'].lower()}"
            attrs[ent] = ka
        elif t in ("suspicious_service_imagepath", "masquerade_service_imagepath"):
            fa = {"path": f["image_path"], "last_write_time": lwt}
            if t == "masquerade_service_imagepath" and f.get("binary") and f.get("expected_path"):
                fa["masquerade_pattern"] = f"{f['binary'].lower()}:{f['expected_path'].lower()}"
            attrs[f"file:{host_id}:{f['image_path']}"] = fa
        elif t == "userinit_modified":
            attrs[f"registry_key:{host_id}:HKLM\\" + f["key"] + "\\Userinit"] = {"value": f.get("data"), "value_type": "RegSz", "last_write_time": lwt}
        elif t == "shell_modified":
            attrs[f"registry_key:{host_id}:HKLM\\" + f["key"] + "\\Shell"] = {"value": f.get("data"), "value_type": "RegSz", "last_write_time": lwt}
        elif t == "ifeo_debugger":
            attrs[f"registry_key:{host_id}:HKLM\\" + f["key"] + "\\Debugger"] = {"value": f.get("data"), "value_type": "RegSz", "last_write_time": lwt}
        elif t == "appinit_dlls":
            attrs[f"registry_key:{host_id}:HKLM\\" + f["key"] + "\\AppInit_DLLs"] = {"value": f.get("data"), "value_type": "RegSz", "last_write_time": lwt}
    return attrs


def _entities_from_findings(findings: list[dict], hive_kind: str, owner: str | None, host_id: str) -> list[str]:
    """Build the `entities` list — all IDs host-namespaced as <type>:<host>:<rest>."""
    out: set[str] = set()
    for f in findings:
        t = f["type"]
        if t in ("suspicious_run_value", "masquerade_run_value"):
            scope = f"HKCU\\{owner}" if owner else "HKLM"
            out.add(f"registry_key:{host_id}:{scope}\\{f['key']}\\{f['value_name']}")
            if t == "masquerade_run_value":
                out.add(f"file:{host_id}:{f['data']}")
        elif t in ("suspicious_service_imagepath", "masquerade_service_imagepath"):
            out.add(f"service:{host_id}:{f['service']}")
            out.add(f"file:{host_id}:{f['image_path']}")
        elif t == "vss_service_disabled":
            out.add(f"service:{host_id}:{f['service']}")
        elif t == "userinit_modified":
            out.add(f"registry_key:{host_id}:HKLM\\" + f["key"] + "\\Userinit")
        elif t == "shell_modified":
            out.add(f"registry_key:{host_id}:HKLM\\" + f["key"] + "\\Shell")
        elif t == "ifeo_debugger":
            out.add(f"registry_key:{host_id}:HKLM\\" + f["key"] + "\\Debugger")
        elif t == "appinit_dlls":
            out.add(f"registry_key:{host_id}:HKLM\\" + f["key"] + "\\AppInit_DLLs")
        elif t in ("shimcache_suspicious_path", "shimcache_executed_user_writable_path", "shimcache_masquerade"):
            # Reuse the prefetch-agent entity shape so ProcessExecution nodes auto-merge in the graph
            exe_basename = f["path"].lower().rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
            if exe_basename:
                out.add(f"process_execution:{host_id}:{exe_basename}")
            out.add(f"file:{host_id}:{f['path'].lower()}")
        elif t in ("amcache_executable_user_writable",
                   "amcache_unsigned_user_writable_executable",
                   "amcache_masquerade_publisher_mismatch"):
            basename = f.get("basename") or f["path"].lower().rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
            if basename:
                out.add(f"process_execution:{host_id}:{basename}")
            out.add(f"file:{host_id}:{f['path']}")
        elif t == "amcache_recently_installed_user_writable_program":
            out.add(f"file:{host_id}:{f['root_dir_path']}")
    return sorted(out)


def _execution_attrs_from_findings(findings: list[dict], host_id: str) -> dict:
    """Build per-entity ProcessExecution attrs from shimcache + amcache findings.

    Same schema prefetch_agent emits — the extractor's `process_execution` dispatch and
    the validator's `SPOT_CHECK_FIELDS["process_execution"]` already handle this. Single-run
    sources (ShimCache/Amcache) emit `run_count: 1` and a 1-element `run_times`. The
    `source` discriminator lets downstream consumers tell the sources apart. Amcache adds
    SHA1 + Publisher, which the report agent surfaces and the graph merges into a single
    ProcessExecution node when prefetch/shimcache also flag the same exe basename.
    """
    attrs: dict = {}
    for f in findings:
        t = f["type"]
        if t in ("shimcache_suspicious_path", "shimcache_executed_user_writable_path", "shimcache_masquerade"):
            path = f.get("path") or ""
            exe_basename = path.lower().rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
            if not exe_basename:
                continue
            ent = f"process_execution:{host_id}:{exe_basename}"
            # First finding for this exe wins; subsequent ones (e.g. same exe across CS001 + CS002
            # with Duplicate=False on both) just confirm the existing record.
            if ent in attrs:
                continue
            sc_attrs = {
                "executable_name": exe_basename,
                "executable_path": path.lower(),
                "last_run_time": f.get("last_modified_time"),
                "run_count": 1,
                "run_times": [f["last_modified_time"]] if f.get("last_modified_time") else [],
                "source": "shimcache",
            }
            if t == "shimcache_masquerade" and f.get("binary") and f.get("expected_path"):
                sc_attrs["masquerade_pattern"] = f"{f['binary'].lower()}:{f['expected_path'].lower()}"
            attrs[ent] = sc_attrs
        elif t in ("amcache_executable_user_writable",
                   "amcache_unsigned_user_writable_executable",
                   "amcache_masquerade_publisher_mismatch"):
            basename = f.get("basename") or (f.get("path") or "").lower().rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
            if not basename:
                continue
            ent = f"process_execution:{host_id}:{basename}"
            # Prefer the richest finding for this exe — promote SHA1/Publisher if a later
            # detector for the same basename has them and the existing entry doesn't.
            existing = attrs.get(ent)
            if existing:
                if not existing.get("sha1") and f.get("sha1"):
                    existing["sha1"] = f["sha1"]
                if not existing.get("publisher") and f.get("publisher"):
                    existing["publisher"] = f["publisher"]
                continue
            last_run = f.get("last_run_time")
            attrs[ent] = {
                "executable_name": basename,
                "executable_path": f.get("path"),
                "last_run_time": last_run,
                "run_count": 1,
                "run_times": [last_run] if last_run else [],
                "sha1": f.get("sha1"),
                "publisher": f.get("publisher"),
                "file_size": f.get("size"),
                "source": "amcache",
            }
    return attrs


def _format_finding(f: dict) -> str:
    t = f["type"]
    lwt = f.get("last_write_time")
    suffix = f"  _(key last-written {lwt})_" if lwt else ""
    if t == "suspicious_run_value":
        return f"- **suspicious_run_value** `{f['key']}\\{f['value_name']}` → `{f['data']}`{suffix}"
    if t == "masquerade_run_value":
        return f"- **masquerade_run_value** `{f['key']}\\{f['value_name']}` → `{f['data']}` (binary `{f['binary']}` should be at `{f['expected_path']}`){suffix}"
    if t == "suspicious_service_imagepath":
        return f"- **suspicious_service_imagepath** [{f['controlset']}] service `{f['service']}` → `{f['image_path']}`{suffix}"
    if t == "masquerade_service_imagepath":
        return f"- **masquerade_service_imagepath** [{f['controlset']}] service `{f['service']}` → `{f['image_path']}` (binary `{f['binary']}` should be at `{f['expected_path']}`){suffix}"
    if t == "userinit_modified":
        return f"- **userinit_modified** `{f['key']}\\Userinit` = `{f['data']}` (default: `c:\\windows\\system32\\userinit.exe,`){suffix}"
    if t == "shell_modified":
        return f"- **shell_modified** `{f['key']}\\Shell` = `{f['data']}` (default: `explorer.exe`){suffix}"
    if t == "ifeo_debugger":
        return f"- **ifeo_debugger** `{f['key']}\\Debugger` = `{f['data']}`{suffix}"
    if t == "appinit_dlls":
        return f"- **appinit_dlls** `{f['key']}\\AppInit_DLLs` = `{f['data']}`{suffix}"
    if t == "vss_service_disabled":
        return (f"- **vss_service_disabled** [{f.get('controlset')}] service `{f.get('service')}` "
                f"Start={f.get('start_value')} (Disabled){suffix} "
                f"⚠️ ANTI-RECOVERY (pairs with ransomware)")
    # ShimCache findings carry their own LastModifiedTimeUTC, not RECmd's lwt
    sc_suffix = f"  _(ShimCache LastModified {f['last_modified_time']}, Executed={f.get('executed','?')}, CS{f.get('controlset','?')})_" \
        if t.startswith("shimcache_") and f.get("last_modified_time") else ""
    if t == "shimcache_executed_user_writable_path":
        return f"- **shimcache_executed_user_writable_path** `{f['path']}`{sc_suffix}"
    if t == "shimcache_suspicious_path":
        return f"- **shimcache_suspicious_path** `{f['path']}`{sc_suffix}"
    if t == "shimcache_masquerade":
        return f"- **shimcache_masquerade** `{f['path']}` (binary `{f['binary']}` should be at `{f['expected_path']}`){sc_suffix}"
    # Amcache findings include SHA1 + publisher when present.
    if t.startswith("amcache_"):
        sha = f.get("sha1") or "?"
        pub = f.get("publisher") if f.get("publisher") else "(empty/unsigned)"
        amc_meta = f"  _(SHA1=`{sha}`, Publisher=`{pub}`, last-run={f.get('last_run_time') or 'n/a'})_"
        if t == "amcache_executable_user_writable":
            return f"- **amcache_executable_user_writable** `{f['path']}` ({f.get('size', 0):,} bytes){amc_meta}"
        if t == "amcache_unsigned_user_writable_executable":
            return f"- **amcache_unsigned_user_writable_executable** `{f['path']}` ({f.get('size', 0):,} bytes){amc_meta}"
        if t == "amcache_masquerade_publisher_mismatch":
            return (f"- **amcache_masquerade_publisher_mismatch** `{f['path']}` "
                    f"(binary `{f.get('basename')}` claims `Publisher={f.get('publisher')}`, "
                    f"expected at `{f.get('expected_path')}`){amc_meta}")
        if t == "amcache_recently_installed_user_writable_program":
            return (f"- **amcache_recently_installed_user_writable_program** "
                    f"`{f.get('program_name')}` installed at `{f.get('root_dir_path')}` "
                    f"(install date: {f.get('install_date') or 'unknown'})")
    return f"- **{t}** {f}"


def generate_claim(hive_path: Path, hive_kind: str, owner: str | None, findings: list[dict]) -> str:
    timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    cid_key = f"{hive_path.name}:{hive_kind}:{owner or ''}:" + "|".join(
        f"{f['type']}:{f.get('key','')}:{f.get('value_name','')}:{f.get('service','')}"
        for f in findings
    )
    cid = "registry-" + hashlib.md5(cid_key.encode()).hexdigest()[:14]
    host_id = derive_host_id(hive_path.name)

    entities = _entities_from_findings(findings, hive_kind, owner, host_id) or [f"hive:{host_id}:{hive_kind}"]
    key_attrs = _key_attrs_from_findings(findings, hive_kind, owner, host_id)
    execution_attrs = _execution_attrs_from_findings(findings, host_id)

    # Split findings for body rendering — persistence vs shimcache vs amcache get their own sections.
    persistence_findings = [f for f in findings
                            if not f["type"].startswith("shimcache_")
                            and not f["type"].startswith("amcache_")]
    shimcache_findings = [f for f in findings if f["type"].startswith("shimcache_")]
    amcache_findings = [f for f in findings if f["type"].startswith("amcache_")]

    # Confidence: 0.85 with persistence anomalies; 0.75 with only execution-evidence findings
    # (Win8+ ShimCache + Amcache are execution-suggestive, not execution-confirmed); 0.5 baseline.
    if persistence_findings:
        confidence = 0.85
    elif shimcache_findings or amcache_findings:
        confidence = 0.75
    else:
        confidence = 0.5

    fm = {
        "claim_id": cid,
        "status": "new",
        "generated_by": "registry-agent",
        "host": host_id,
        "hive_kind": hive_kind,
        "hive_path": str(hive_path.relative_to(EVIDENCE_ROOT)) if hive_path.is_relative_to(EVIDENCE_ROOT) else hive_path.name,
        "user": owner,
        "entities": entities,
        "evidence_refs": [
            (str(hive_path.relative_to(EVIDENCE_ROOT)) if hive_path.is_relative_to(EVIDENCE_ROOT) else hive_path.name),
        ],
        "confidence": confidence,
        "timestamp": timestamp,
        "anomaly_count": len(findings),
    }
    if key_attrs:
        fm["key_attrs"] = key_attrs
    if execution_attrs:
        fm["execution_attrs"] = execution_attrs

    body_lines = [
        f"**Registry Persistence Analysis: `{hive_kind}`" + (f" (user `{owner}`)" if owner else "") + "**",
        "",
        f"Hive: `{hive_path.name}`",
        "",
    ]
    if persistence_findings:
        body_lines.append(f"**Persistence findings ({len(persistence_findings)}):**")
        body_lines.extend(_format_finding(f) for f in persistence_findings)
    elif not (shimcache_findings or amcache_findings):
        body_lines.append("_No persistence anomalies detected by this rule set._")

    if shimcache_findings:
        body_lines += [
            "",
            f"**ShimCache (AppCompatCache) Execution Evidence ({len(shimcache_findings)}):**",
        ]
        body_lines.extend(_format_finding(f) for f in shimcache_findings)
        body_lines += [
            "",
            "> _ShimCache evidentiary note: on Win7 `Executed=Yes` rows are direct execution "
            "evidence; on Win8+ the cache only confirms the file was *seen* by the compatibility "
            "manager — execution-suggestive, not execution-confirmed._",
        ]

    if amcache_findings:
        body_lines += [
            "",
            f"**Amcache (Application Compatibility) Execution Evidence ({len(amcache_findings)}):**",
        ]
        body_lines.extend(_format_finding(f) for f in amcache_findings)
        body_lines += [
            "",
            "> _Amcache evidentiary note: introduced in Win7 SP1+KB2952664 (program-only records), "
            "expanded in Win8+ to include per-file SHA1, Publisher, file size, and FileKeyLastWriteTimestamp. "
            "Presence in Amcache means the compatibility manager profiled the binary; combined with a "
            "user-writable path it's a strong execution-evidence signal. SHA1 enables direct VT/threat-intel pivoting._",
        ]

    body_lines.append("")
    body_lines.append("**Hypothesis:** Pivot flagged keys/services to disk timeline + memory PIDs with matching ImageFileName. ShimCache and Amcache exe basenames merge with prefetch/memory ProcessExecution nodes — check the cross-domain correlations. Where Amcache supplies SHA1, the ProcessExecution graph node now carries cryptographic identity for VT/threat-intel pivots.")
    return f"---\n{yaml.dump(fm, sort_keys=False)}---\n" + "\n".join(body_lines) + "\n"


async def run_registry_analysis(hive: Path | None = None):
    print("🗝️  Registry Agent starting (Chisel-confined)...")
    chisel = Chisel(CHISEL_URL, CHISEL_SECRET)
    chisel.connect()
    print(f"🔒 Chisel session → {chisel.endpoint} (sid={chisel.session_id[:8]}…)")

    if hive is None:
        # Discovery via Chisel — pick the first hive-shaped file in evidence/new/
        listing = chisel.shell("ls", ["-1", str(EVIDENCE_NEW)])
        for n in listing.splitlines():
            n = n.strip()
            if not n:
                continue
            candidate = EVIDENCE_NEW / n
            if detect_hive_kind(candidate):
                hive = candidate
                break
        if hive is None:
            print("❌ no hive in evidence/new/")
            return

    kind = detect_hive_kind(hive)
    if kind is None:
        print(f"❌ {hive.name}: cannot identify hive type")
        return
    owner = _ntuser_owner(hive) if kind == "NTUSER.DAT" else None
    print(f"📂 Analysing {kind}" + (f" (user `{owner}`)" if owner else "") + f" — {hive.name}")

    # AMCACHE has no per-key persistence dumps (it's not the standard hive shape) — jump
    # straight to AmcacheParser. Win7 pre-KB2952664 won't have an Amcache.hve at all; the
    # disk_image extractor reports that and we never reach this branch in that case.
    if kind == "AMCACHE":
        rows = await _run_amcache_parser(hive)
        if rows is None:
            print("   ⚠️  AmcacheParser produced no output — emitting provenance-only claim")
            findings: list[dict] = []
        else:
            findings = detect_amcache_anomalies(rows)
            n_assoc = sum(1 for r in rows if r.get("_csv_source") == "associated")
            n_unassoc = sum(1 for r in rows if r.get("_csv_source") == "unassociated")
            n_prog = sum(1 for r in rows if r.get("_csv_source") == "program")
            print(f"📦 Amcache: {len(rows):,} rows scanned "
                  f"(associated={n_assoc}, unassociated={n_unassoc}, programs={n_prog}); "
                  f"{len(findings)} flagged")
            for f in findings[:10]:
                print("   " + _format_finding(f).lstrip("- ").lstrip())
        chisel.call("create_directory", {"path": str(CLAIMS_TODO)})
        claim = generate_claim(hive, kind, owner, findings)
        ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        claim_path = CLAIMS_TODO / f"registry_AMCACHE_{hive.stem}_{ts}.md"
        chisel.call("write_file", {"path": str(claim_path), "content": claim})
        print(f"✅ Claim written → {claim_path.name}")
        return

    targets = {
        "SYSTEM":     SYSTEM_KEYS,
        "SOFTWARE":   SOFTWARE_KEYS,
        "NTUSER.DAT": NTUSER_KEYS,
    }.get(kind)
    if not targets:
        print(f"   ℹ️  {kind} hive — no rule set yet (SAM/SECURITY/COMPONENTS analysis is a future iteration)")
        # Still emit a "no findings" claim so provenance is recorded
        claim = generate_claim(hive, kind, owner, [])
        chisel.call("create_directory", {"path": str(CLAIMS_TODO)})
        ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        chisel.call("write_file", {"path": str(CLAIMS_TODO / f"registry_{kind}_{hive.stem}_{ts}.md"), "content": claim})
        print("   ✅ provenance claim written")
        return

    dumps: dict = {}
    for label, key in targets.items():
        data = await _recmd_dump_key(hive, key)
        dumps[label] = data
        present = "✓" if data else "✗"
        n_subs = len(data.get("SubKeys", [])) if data else 0
        n_vals = len(data.get("Values", [])) if data else 0
        print(f"   {present} {label}: {n_subs} subkeys, {n_vals} values")

    findings = detect_persistence(kind, dumps, hive)
    print(f"🚨 Persistence findings: {len(findings)}")
    for f in findings[:10]:
        print("   " + _format_finding(f).lstrip("- ").lstrip())

    # ShimCache (AppCompatCache) — only on SYSTEM hives. Single AppCompatCacheParser run
    # produces all entries across both ControlSets; detector dedups within-hive.
    if kind == "SYSTEM":
        rows = await _run_appcompat_parser(hive)
        if rows is None:
            print("   ⚠️  AppCompatCacheParser produced no output — skipping shimcache analysis")
        else:
            sc_findings = detect_shimcache_anomalies(rows)
            print(f"🕒 ShimCache: {len(rows)} cache entries scanned, {len(sc_findings)} flagged")
            for f in sc_findings[:10]:
                print("   " + _format_finding(f).lstrip("- ").lstrip())
            findings += sc_findings

    chisel.call("create_directory", {"path": str(CLAIMS_TODO)})
    claim = generate_claim(hive, kind, owner, findings)
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    user_tag = f"_{owner}" if owner else ""
    claim_path = CLAIMS_TODO / f"registry_{kind}{user_tag}_{hive.stem}_{ts}.md"
    chisel.call("write_file", {"path": str(claim_path), "content": claim})
    print(f"✅ Claim written → {claim_path.name}")


if __name__ == "__main__":
    asyncio.run(run_registry_analysis())
