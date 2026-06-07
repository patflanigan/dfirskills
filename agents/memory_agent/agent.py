# agents/memory_agent/agent.py
"""
Memory Agent — standalone, deterministic, Chisel-confined.

- Discovery (ls evidence/new/) and claim writes go through Chisel MCP,
  so the agent's filesystem reach is kernel-confined to the Chisel root.
- Volatility still runs as a local subprocess: it mmaps multi-GB dumps,
  and the path it receives was vetted by Chisel's confined enumeration.
"""

import asyncio
import fnmatch
import json
import os
import re
from pathlib import Path
from datetime import datetime, UTC
import yaml

from agents._chisel import Chisel
from cognee_schema.schema import derive_host_id

EVIDENCE_ROOT = Path(os.environ.get("EVIDENCE_ROOT", "/home/sansforensics/dfirskills2/evidence"))
CLAIMS_TODO = EVIDENCE_ROOT / "claims/todo"
EVIDENCE_BASELINES = EVIDENCE_ROOT / "baselines"
EVIDENCE_DUMPS = EVIDENCE_ROOT / "dumps"

CHISEL_URL = os.environ.get("CHISEL_URL", "http://127.0.0.1:3000")
CHISEL_SECRET = os.environ["CHISEL_SECRET"]

# YARA — uses SIFT yara CLI (yarac compile → yara -C scan), per ~/.claude/skills/yara-hunting/SKILL.md.
# Externals required by signature-base rules; dummy values at compile satisfy the references.
YARA_RULES_DIR = Path(os.environ.get(
    "YARA_RULES_DIR",
    str(Path(__file__).resolve().parents[2] / "rules" / "signature-base" / "yara"),
))
YARA_COMPILED = YARA_RULES_DIR.parent.parent / "signature-base.compiled"
YARA_EXTERNALS = ("filename", "filepath", "extension", "owner", "filetype")

# Anomaly weights (one application per PID per type), capped at 100.
# Tuned so that injection + yara_hit alone clears AUTO_DUMP_THRESHOLD.
ANOMALY_WEIGHTS = {
    "yara_hit": 50,
    "hidden": 35,
    "injection": 30,
    "baseline_new_pid": 25,
    "bad_parent": 25,
    "duplicate_singleton": 15,
}
AUTO_DUMP_THRESHOLD = 70  # triage marker; VAD dumping itself runs unconditionally for malfind PIDs


async def run_volatility_plugin(chisel: Chisel, memory_dump: Path, plugin: str,
                                extra_args: list[str] | None = None,
                                output_dir: Path | None = None) -> list:
    """Run a Vol3 plugin through Chisel. Routing through Chisel gets us:
      - allowlist enforcement (Chisel WHITELIST already includes 'vol')
      - audit-log entry per invocation in evidence/audit/<date>.jsonl
      - centralized retry/rate-limit (existing 429 handler in _chisel.py)

    extra_args go AFTER the plugin name (plugin-specific flags).
    output_dir is a global Vol3 flag; goes BEFORE the plugin name.

    Function remains `async def` for caller compatibility, but the underlying
    chisel.exec_tool() call is synchronous — blocks this coroutine for the
    duration. Memory_agent runs as its own subprocess with serial plugin loop,
    so blocking is fine here (no other coroutines waiting on the event loop).
    """
    extra_args = list(extra_args or [])
    extra_str = (" " + " ".join(extra_args)) if extra_args else ""
    out_str = f" --output-dir {output_dir}" if output_dir else ""
    print(f"   Running: vol -f {memory_dump.name} -r json{out_str} {plugin}{extra_str}")
    args = ["-f", str(memory_dump), "-r", "json"]
    if output_dir is not None:
        args += ["--output-dir", str(output_dir)]
    args += [plugin, *extra_args]
    try:
        result = chisel.exec_tool("vol", args, agent_name="memory-agent")
    except RuntimeError as e:
        print(f"   ❌ Plugin failed (Chisel error): {e}")
        return []
    if result["exit_code"] != 0:
        print(f"   ❌ Plugin failed (exit {result['exit_code']})")
        if result["stderr"]:
            print(f"   stderr: {result['stderr'][:300]}")
        return []
    try:
        return json.loads(result["stdout"])
    except json.JSONDecodeError:
        print("   ⚠️  Non-JSON output received")
        return []


PLUGINS = [
    "windows.pslist", "windows.psscan", "windows.pstree", "windows.malfind", "windows.netscan",
    # v2 corroborator plugins — feed Process.command_line, Service entities, and
    # userassist execution bullets into the graph so cross_domain_service_persistence
    # (rule 5), cross_domain_persistence_execution (rule 6), and temporal_compromise_window
    # (rule 12) auto-fire on richer evidence without any new correlation rules.
    "windows.cmdline",
    "windows.svcscan",
    "windows.registry.userassist",
]
TARGETED_PLUGINS = ["windows.dlllist", "windows.handles"]
MAX_TARGETED_PIDS = 20  # cap second-pass invocation size

# windows.info reports several time-shaped fields; we prefer SystemTime (wall-clock at
# capture). Variable names vary slightly across Vol3 versions, so probe in priority order.
DUMP_CAPTURE_TIME_KEYS = ("SystemTime", "Image date and time", "ImageDateTime")

# DLL paths under these substrings are considered system-resident; anything else
# loaded into a flagged process is worth a second look.
SYSTEM_PATH_HINTS = ("\\windows\\", "\\program files")
# Handle Name fragments worth surfacing on a flagged process (user-writable locations).
NOTABLE_HANDLE_HINTS = ("\\users\\", "\\temp\\", "\\appdata\\", "$recycle.bin")

# Canonical Win7+ parent expectations. Lowercased; multiple acceptable parents allowed.
# Entries are skipped at check-time when the parent process has already exited
# (e.g. userinit→explorer, smss-master→wininit/csrss/winlogon), since their
# absence from pslist makes parent-name lookup return None.
EXPECTED_PARENTS = {
    "lsass.exe": {"wininit.exe"},
    "lsm.exe": {"wininit.exe"},
    "services.exe": {"wininit.exe"},
    "wininit.exe": {"smss.exe"},
    "csrss.exe": {"smss.exe"},
    "winlogon.exe": {"smss.exe"},
    "svchost.exe": {"services.exe"},
    "spoolsv.exe": {"services.exe"},
    "taskhost.exe": {"services.exe"},
    "explorer.exe": {"userinit.exe"},
}

SINGLETON_PROCESSES = {"wininit.exe", "lsass.exe", "services.exe", "lsm.exe"}


def detect_anomalies(pslist: list, psscan: list, malfind: list) -> list[dict]:
    """Deterministic heuristics: injection, hidden, bad-parent, duplicate-singletons."""
    findings: list[dict] = []
    pslist_by_pid = {p["PID"]: p for p in pslist if p.get("PID") is not None}
    psscan_by_pid = {p["PID"]: p for p in psscan if p.get("PID") is not None}
    pid_to_name = {pid: (p.get("ImageFileName") or "").lower() for pid, p in pslist_by_pid.items()}

    # 1. Injected memory regions (malfind), deduped by (PID, start)
    seen = set()
    for m in malfind:
        key = (m.get("PID"), m.get("Start VPN"))
        if key in seen:
            continue
        seen.add(key)
        start = m.get("Start VPN")
        findings.append({
            "type": "injection",
            "pid": m.get("PID"),
            "process": m.get("Process"),
            "start_vpn": hex(start) if isinstance(start, int) else start,
            "protection": m.get("Protection"),
            "tag": m.get("Tag"),
        })

    # 2. Hidden — present in psscan but not in pslist, and not exited
    for pid, p in psscan_by_pid.items():
        if pid in pslist_by_pid or p.get("ExitTime"):
            continue
        findings.append({
            "type": "hidden",
            "pid": pid,
            "process": p.get("ImageFileName"),
            "offset": p.get("Offset(V)"),
        })

    # 3. Parent/child anomaly — parent name doesn't match the canonical set
    for pid, p in pslist_by_pid.items():
        name = (p.get("ImageFileName") or "").lower()
        expected = EXPECTED_PARENTS.get(name)
        if not expected:
            continue
        ppid = p.get("PPID")
        parent_name = pid_to_name.get(ppid)
        if parent_name and parent_name not in expected:
            findings.append({
                "type": "bad_parent",
                "pid": pid,
                "process": name,
                "ppid": ppid,
                "actual_parent": parent_name,
                "expected_parent": "|".join(sorted(expected)),
            })

    # 4. Duplicate singletons (system processes that should appear once)
    counts: dict[str, int] = {}
    for p in pslist:
        n = (p.get("ImageFileName") or "").lower()
        if n in SINGLETON_PROCESSES:
            counts[n] = counts.get(n, 0) + 1
    for n, c in counts.items():
        if c > 1:
            findings.append({"type": "duplicate_singleton", "process": n, "count": c})

    return findings


def enrich_flagged_pids(pslist: list, dlllist: list, handles: list, flagged_pids: list) -> dict:
    """Per-PID summary of dlllist + handles output. Pure function, deterministic."""
    pid_to_name = {p["PID"]: p.get("ImageFileName") for p in pslist if p.get("PID") is not None}
    out: dict = {}
    for pid in flagged_pids:
        dlls = [d for d in dlllist if d.get("PID") == pid]
        hnds = [h for h in handles if h.get("PID") == pid]
        nonsystem = []
        for d in dlls:
            path = (d.get("Path") or "").lower()
            if path and not any(h in path for h in SYSTEM_PATH_HINTS):
                nonsystem.append(d.get("Path"))
        notable = []
        for h in hnds:
            name = (h.get("Name") or "").lower()
            if name and any(s in name for s in NOTABLE_HANDLE_HINTS):
                notable.append((h.get("Type"), h.get("Name")))
        type_counts: dict = {}
        for h in hnds:
            t = h.get("Type") or "?"
            type_counts[t] = type_counts.get(t, 0) + 1
        top_types = dict(sorted(type_counts.items(), key=lambda kv: -kv[1])[:5])
        out[pid] = {
            "process": pid_to_name.get(pid),
            "dll_count": len(dlls),
            "handle_count": len(hnds),
            "top_handle_types": top_types,
            "nonsystem_dlls": nonsystem[:5],
            "notable_handles": notable[:5],
        }
    return out


async def extract_dump_metadata(chisel: Chisel, dump: Path) -> tuple[str | None, dict | None]:
    """Run `windows.info` once and pull both:
      - capture time (SystemTime / Image date and time)
      - OS info dict {"major", "minor", "sp", "arch"} for baseline selection

    The OS info is best-effort: missing fields → None for that field; entire dict
    → None if no OS-relevant rows are present. Single windows.info call (one of
    the more expensive vol3 plugins) shared between capture-time + baseline pipeline.
    """
    rows = await run_volatility_plugin(chisel, dump, "windows.info")
    if not isinstance(rows, list):
        return None, None
    capture_time: str | None = None
    os_info: dict = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        var = row.get("Variable")
        val = row.get("Value")
        if var in DUMP_CAPTURE_TIME_KEYS and val:
            capture_time = str(val)
        elif var == "NtMajorVersion" and val is not None:
            try:
                os_info["major"] = int(val)
            except (TypeError, ValueError):
                pass
        elif var == "NtMinorVersion" and val is not None:
            try:
                os_info["minor"] = int(val)
            except (TypeError, ValueError):
                pass
        elif var in ("CSDVersion", "Service Pack") and val is not None:
            # CSDVersion is "Service Pack 1" string OR an int
            m = re.search(r"\d+", str(val))
            if m:
                os_info["sp"] = int(m.group(0))
        elif var == "Is64Bit":
            os_info["arch"] = 64 if str(val).strip().lower() in ("true", "1", "yes") else 32
        elif var == "PE Machine" and "arch" not in os_info:
            # Fallback when Is64Bit isn't reported. PE Machine = "AMD64" / "I386" / "X86".
            sval = str(val or "").lower()
            if "amd64" in sval or "x64" in sval:
                os_info["arch"] = 64
            elif "i386" in sval or "x86" in sval:
                os_info["arch"] = 32
    return capture_time, (os_info or None)


# Back-compat shim: callers that only need capture time still work.
async def extract_dump_capture_time(chisel: Chisel, dump: Path) -> str | None:
    capture_time, _ = await extract_dump_metadata(chisel, dump)
    return capture_time


# ──────────────────────────────────────────────────────────────
# Baseline selection (OS-aware, per-host)
# ──────────────────────────────────────────────────────────────
# Filename convention: Win{Major}[SP{SP}]x{Arch}-baseline.img
# Examples: Win7SP1x86-baseline.img, Win7SP1x64-baseline.img, Win10x64-baseline.img
_BASELINE_NAME_RE = re.compile(r"^Win(\d+)(?:SP(\d+))?x(86|64)-baseline\.img$", re.I)

# Map (NtMajorVersion, NtMinorVersion) → marketing-major used in baseline filenames.
# Windows kernel versions documented at MS Learn; only the OSes we plausibly see here
# are listed. Server SKUs share kernel versions with the client SKUs of the same era.
_NT_TO_MARKETING_MAJOR = {
    (5, 1): 5,    # XP (we don't have an XP baseline today; included for honesty)
    (5, 2): 5,    # Server 2003 / XP x64
    (6, 0): 6,    # Vista / Server 2008
    (6, 1): 7,    # Win7 / Server 2008 R2
    (6, 2): 8,    # Win8 / Server 2012
    (6, 3): 8,    # Win8.1 / Server 2012 R2  (collapsed onto "8" — both pre-10)
    (10, 0): 10,  # Win10 / Win11 / Server 2016+
}


def _matches_family(live_major: int, live_minor: int, baseline_major: int) -> bool:
    """True iff `(live_major, live_minor)` belongs to the OS family represented by
    `baseline_major` in the baseline filename convention."""
    return _NT_TO_MARKETING_MAJOR.get((live_major, live_minor)) == baseline_major


def _select_baseline_for_dump(chisel: Chisel, baseline_dir: Path, os_info: dict | None) -> Path | None:
    """Pick the best baseline file for this dump's OS+arch from `baseline_dir`.

    Returns None if no acceptable match (caller proceeds without baseline — the
    only honest answer when no compatible baseline exists). Match policy:
      1. NtMajorVersion + NtMinorVersion + arch must agree.
      2. Among matching files, highest SP wins (SP1 baseline > SP0 baseline for SP1 dump).
      3. If OS info couldn't be parsed, no baseline is selected.
    """
    if not os_info or "major" not in os_info or "minor" not in os_info or "arch" not in os_info:
        return None
    try:
        listing = chisel.shell("ls", ["-1", str(baseline_dir)])
    except RuntimeError:
        return None
    candidates: list[tuple[int, Path]] = []
    for raw in listing.splitlines():
        name = raw.strip()
        if not name:
            continue
        m = _BASELINE_NAME_RE.match(name)
        if not m:
            continue
        b_major = int(m.group(1))
        b_sp = int(m.group(2)) if m.group(2) else 0
        # Filename uses "x86"/"x64" — x86 means 32-bit, x64 means 64-bit.
        b_arch = 32 if m.group(3) == "86" else 64
        if b_arch != os_info["arch"]:
            continue
        if not _matches_family(os_info["major"], os_info["minor"], b_major):
            continue
        candidates.append((b_sp, baseline_dir / name))
    if not candidates:
        return None
    return max(candidates, key=lambda t: t[0])[1]


async def parse_baseline(chisel: Chisel, baseline: Path) -> set[tuple[str, str]]:
    """Build (process_name, parent_name) pairs from a baseline dump's pslist.

    Cached as a JSON sidecar (`<baseline>.pslist.json`) so the ~30s pslist run
    happens at most once per baseline file.
    """
    cache_path = baseline.with_suffix(baseline.suffix + ".pslist.json")
    if cache_path.exists():
        try:
            data = json.loads(cache_path.read_text())
            print(f"📊 Baseline cache loaded: {len(data['pairs'])} (name, parent) pairs from {cache_path.name}")
            return {tuple(p) for p in data["pairs"]}
        except Exception as e:
            print(f"   ⚠️  baseline cache unreadable ({e}); rebuilding")

    print(f"📊 Building baseline pslist from {baseline.name} (one-time)...")
    rows = await run_volatility_plugin(chisel, baseline, "windows.pslist")
    if not isinstance(rows, list) or not rows:
        print("   ⚠️  baseline pslist empty — diff will be skipped")
        return set()
    pid_to_name = {r["PID"]: (r.get("ImageFileName") or "").lower() for r in rows if r.get("PID") is not None}
    pairs: set = set()
    for r in rows:
        name = (r.get("ImageFileName") or "").lower()
        parent = pid_to_name.get(r.get("PPID"), "")
        if name:
            pairs.add((name, parent))
    chisel.call("write_file", {
        "path": str(cache_path),
        "content": json.dumps({"baseline": baseline.name, "pairs": sorted([list(p) for p in pairs])}, indent=2),
    })
    print(f"   cached {len(pairs)} (name, parent) pairs → {cache_path.name}")
    return pairs


# ──────────────────────────────────────────────────────────────
# Network analysis (vol3 windows.netscan)
# ──────────────────────────────────────────────────────────────
import ipaddress as _ipaddress  # local-aliased to avoid clobbering future module-level imports


def _is_external_remote(addr: str) -> bool:
    """Routable, non-RFC1918, non-loopback, non-link-local. Mirrors evtx_agent's helper."""
    if not addr or addr in ("*", "0.0.0.0", "::", "::1"):
        return False
    try:
        a = _ipaddress.ip_address(addr)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local
                or a.is_multicast or a.is_unspecified or a.is_reserved)


def detect_network_anomalies(netscan: list, host_id: str) -> list[dict]:
    """Process-→external-IP edges from `windows.netscan`.

    Two tiers of TCP findings, both pointing at non-RFC1918 / non-loopback /
    non-link-local remote endpoints:
      * `process_external_connection` — state=ESTABLISHED, an active connection
        at dump time. High signal — the process is actively talking to the C2.
      * `process_external_connection_recent` — state in {CLOSED, TIME_WAIT,
        CLOSE_WAIT}, a connection that was torn down before the dump. C2 beacons
        that already checked in and entered sleep cycle leave these entries
        behind; the remote endpoint metadata is the IOC we care about (e.g.
        Cobalt Strike beaconing on its sleep interval). Lower signal but
        forensically important — preserves the C2 endpoint that ESTABLISHED-only
        filtering would discard.

    UDP rows are excluded (no state semantics; high false-positive rate from
    DNS / mDNS chatter). Listening sockets are deferred to a follow-up iteration
    where we can build a tight allowlist of legitimate Windows listeners.

    Each finding carries the (host, pid, process, local_addr, local_port, remote_addr,
    remote_port, proto, state, created) tuple — enough for cross-host C2-endpoint
    correlation in the next pipeline stage.
    """
    findings: list[dict] = []
    for row in netscan or []:
        if not isinstance(row, dict):
            continue
        proto = (row.get("Proto") or "").upper()
        state = (row.get("State") or "").upper()
        if not proto.startswith("TCP"):
            continue
        if state == "ESTABLISHED":
            ftype = "process_external_connection"
        elif state in ("CLOSED", "TIME_WAIT", "CLOSE_WAIT"):
            ftype = "process_external_connection_recent"
        else:
            continue
        foreign = (row.get("ForeignAddr") or "").strip()
        if not _is_external_remote(foreign):
            continue
        try:
            fport = int(row.get("ForeignPort") or 0)
        except (TypeError, ValueError):
            fport = 0
        if fport <= 0:
            continue
        try:
            lport = int(row.get("LocalPort") or 0) or None
        except (TypeError, ValueError):
            lport = None
        try:
            pid = int(row.get("PID")) if row.get("PID") is not None else None
        except (TypeError, ValueError):
            pid = None
        findings.append({
            "type": ftype,
            "pid": pid,
            "process": (row.get("Owner") or "").strip() or "?",
            "proto": proto,
            "local_addr": (row.get("LocalAddr") or "").strip() or None,
            "local_port": lport,
            "remote_addr": foreign,
            "remote_port": fport,
            "state": state,
            "created": row.get("Created"),
        })
    return findings


def _network_attrs_from_findings(findings: list, host_id: str) -> dict:
    """Per-connection attrs map for the cross-host correlation rule.
    Entity ID is `connection:<host>:<remote_ip>:<remote_port>` so the same C2 endpoint
    observed across hosts merges cleanly. Includes `is_external` (always True here —
    detector pre-filtered) so the existing `shared_external_ip_across_hosts` rule's
    is_external gate keeps working unchanged."""
    attrs: dict = {}
    for f in findings:
        if f.get("type") not in ("process_external_connection",
                                 "process_external_connection_recent"):
            continue
        ip = f.get("remote_addr")
        port = f.get("remote_port")
        if not ip or not port:
            continue
        ent = f"connection:{host_id}:{ip}:{port}"
        a = {
            "ip_address": ip,
            "is_external": True,
            "remote_port": port,
            "proto": f.get("proto"),
            "state": f.get("state"),
        }
        if f.get("pid") is not None:
            a["pid"] = f["pid"]
        if f.get("process"):
            a["process"] = f["process"]
        if f.get("local_port") is not None:
            a["local_port"] = f["local_port"]
        if f.get("created"):
            a["created"] = str(f["created"])
        # First write wins; the same (ip, port) seen with multiple PIDs would be unusual
        # — we'd rather flag the first observed PID and let the analyst pivot manually.
        attrs.setdefault(ent, a)
    return attrs


# ─── v2 corroborator constants (cmdline / svcscan / userassist) ─────────
# Service NAMES known to be attacker tradecraft. Conservative substring match —
# false positives here promote unrelated services to anomalies, so we keep the
# list short and well-curated. Mirrors agents/report_agent/ciso_summary.py.
_SUSPICIOUS_SERVICE_NAMES = (
    "psexec", "psexesvc",       # Sysinternals — common lateral movement
    "anydesk", "teamviewer",    # remote-control abuse
    "ngrok", "metsvc",          # tunneling / Metasploit
    "winexesvc",                # winexe — pentest/lateral
)
# Service NAMES / image paths that almost certainly come from legit vendor
# installs. Used to silently exclude from suspicious_service findings even when
# their image path passes other heuristics.
_BENIGN_SERVICE_HINTS = (
    "fres", "kernelpro",        # F-Response IR-tool drivers
    "windowsazure", "microsoft", "mcafee",
    "windows defender", "intel(", "sophos",
)
# UserAssist entries pointing into these path roots are almost certainly
# legitimate user app launches — surface only entries OUTSIDE these to keep
# the FP rate near shimcache_executed_user_writable_path's level.
_USER_WRITABLE_PATH_HINTS = (
    "\\users\\", "\\temp\\", "\\appdata\\", "\\programdata\\",
    "\\public\\", "\\$recycle.bin",
)
_SYSTEM_PATH_HINTS_USERASSIST = (
    "\\windows\\", "\\program files",
)


def parse_cmdline(cmdline_rows: list) -> dict[int, str]:
    """{pid: command_line_string} from windows.cmdline. Skips empty Args
    (kernel processes, exited PIDs, plugin-failed entries)."""
    out: dict[int, str] = {}
    for row in cmdline_rows:
        pid = row.get("PID")
        args = row.get("Args")
        if pid is None or not isinstance(args, str) or not args.strip():
            continue
        # Vol3 sometimes embeds error markers like "Required memory at ..." in Args
        # for swapped-out processes. These are not real command lines — skip.
        if args.startswith("Required memory at"):
            continue
        out[pid] = args.strip()
    return out


def parse_svcscan(svcscan_rows: list, host_id: str) -> tuple[dict, list[dict]]:
    """Returns (service_attrs, suspicious_findings).

    service_attrs is keyed by `service:<host>:<lowercased_svc_name>` and feeds
    the orchestrator extractor → Service node creation.

    suspicious_findings are anomaly dicts (one per attacker-tradecraft service
    name) that flow through the existing scoring/triage/body-render pipeline."""
    attrs: dict = {}
    suspicious: list[dict] = []
    for row in svcscan_rows:
        name = row.get("Name") or ""
        if not isinstance(name, str) or not name.strip():
            continue
        name = name.strip()
        display = row.get("Display") or row.get("DisplayName") or ""
        binary = row.get("Binary") or row.get("Binary (Services.exe)") or ""
        state = row.get("State") or ""
        start_mode = row.get("Start") or ""
        ent_id = f"service:{host_id}:{name.lower()}"
        attrs[ent_id] = {
            "name": name,
            "display_name": str(display),
            "image_path": str(binary),
            "state": str(state),
            "start_mode": str(start_mode),
        }
        # Suspicious-service detection: name OR image-path substring match against
        # the curated tradecraft list. Vendor allowlist suppresses noise.
        blob = f"{name}\t{display}\t{binary}".lower()
        if any(b in blob for b in _BENIGN_SERVICE_HINTS):
            continue
        if any(s in blob for s in _SUSPICIOUS_SERVICE_NAMES):
            suspicious.append({
                "type": "suspicious_service",
                "svc_name": name,
                "image_path": str(binary),
                "state": str(state),
                "start_mode": str(start_mode),
            })
    return attrs, suspicious


def parse_userassist(ua_rows: list) -> list[dict]:
    """Emit anomaly findings ONLY for UserAssist entries whose decoded path
    points at a user-writable location and is not under \\Windows\\ or
    \\Program Files. Mirrors registry_agent's shimcache_executed_user_writable_path
    pattern so the executive section can correlate the two."""
    out: list[dict] = []
    seen: set = set()  # de-dup per (path, hive_offset) — UserAssist sometimes lists duplicates per ROT13 variant
    for row in ua_rows:
        # Vol3 userassist row shape varies by version; we read defensively.
        path = row.get("Name") or row.get("Value Name") or ""
        if not isinstance(path, str):
            continue
        path = path.strip()
        if not path or "\\" not in path:
            continue
        pl = path.lower()
        if any(h in pl for h in _SYSTEM_PATH_HINTS_USERASSIST):
            continue
        if not any(h in pl for h in _USER_WRITABLE_PATH_HINTS):
            continue
        # Pull execution count + last-run from the structured Data dict if present.
        data = row.get("Data") or {}
        if not isinstance(data, dict):
            data = {}
        count = data.get("Count")
        last_run = data.get("Last Updated") or data.get("Last Updated Time") or row.get("Last Write Time")
        hive_offset = row.get("Hive Offset")
        key = (pl, hive_offset)
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "type": "userassist_execution_user_writable",
            "path": path,
            "count": count,
            "last_run": str(last_run) if last_run else None,
        })
    return out


def detect_baseline_anomalies(pslist: list, baseline_pairs: set) -> list[dict]:
    """Flag PIDs whose (name, parent_name) pair is absent from the baseline."""
    if not baseline_pairs:
        return []
    findings: list[dict] = []
    pid_to_name = {p["PID"]: (p.get("ImageFileName") or "").lower() for p in pslist if p.get("PID") is not None}
    for p in pslist:
        name = (p.get("ImageFileName") or "").lower()
        if not name:
            continue
        parent = pid_to_name.get(p.get("PPID"), "")
        if (name, parent) not in baseline_pairs:
            findings.append({
                "type": "baseline_new_pid",
                "pid": p.get("PID"),
                "process": name,
                "parent": parent or "?",
            })
    return findings


async def dump_vad_regions(chisel: Chisel, dump: Path, pids: list, dump_root: Path) -> dict:
    """Run `windows.vadinfo --pid <p> --dump --output-dir <pid_dir>` per PID.

    Returns {pid: [list of .dmp Path]}. Per-PID subdir keeps YARA scanning tidy.

    Note: dump dirs are created via direct `Path.mkdir` (not Chisel) — same
    documented exception as vol3 mmap'ing the source dump. Vol3 (running as
    the agent's UID) needs to own these scratch dirs to write into them; if
    Chisel runs as root, its mkdirs would be unwritable.
    """
    out: dict = {}
    for pid in pids:
        pid_dir = dump_root / f"pid_{pid}"
        pid_dir.mkdir(parents=True, exist_ok=True)
        # Clear stale .dmp files from any prior run on this dump+PID — vol3 will
        # re-dump the same VAD regions from the immutable source dump, so leftovers
        # only inflate file counts and double YARA scan time.
        for stale in pid_dir.glob(f"pid.{pid}.vad.*.dmp"):
            stale.unlink()
        await run_volatility_plugin(
            chisel, dump, "windows.vadinfo",
            extra_args=["--pid", str(pid), "--dump"],
            output_dir=pid_dir,
        )
        # Vol3 names dumped files like: pid.<pid>.vad.<start>-<end>.dmp
        dmps = sorted(pid_dir.glob(f"pid.{pid}.vad.*.dmp"))
        out[pid] = dmps
        print(f"   dumped {len(dmps)} VAD region(s) for PID {pid} → {pid_dir.relative_to(EVIDENCE_ROOT)}/")
    return out


async def compile_yara_rules() -> Path | None:
    """Compile signature-base into a single .rules binary (cached at YARA_COMPILED).
    Per the SIFT yara-hunting skill: yarac once, then yara -C for fast re-use.
    Returns None if the rules dir is missing or compile fails.

    INTENTIONAL EXCEPTION to the route-through-Chisel rule. The signature-base
    .yar source files live at /home/.../dfirskills2/rules/signature-base/yara/
    and the compiled output at /home/.../dfirskills2/rules/signature-base.compiled
    — both OUTSIDE Chisel's --root (/home/.../evidence). Chisel's path-confinement
    rejects the rule paths. Same root cause as the EZ Tools .dll exception
    (evtx_agent.run_evtxecmd has the long-form rationale). Audit-log gap accepted
    in exchange for keeping the YARA path simple and avoiding filesystem
    reorganization or Chisel-server changes.
    """
    if not YARA_RULES_DIR.exists():
        print(f"⚠️  YARA rules dir not found: {YARA_RULES_DIR} — YARA disabled")
        return None
    if YARA_COMPILED.exists():
        return YARA_COMPILED
    rule_files = sorted(YARA_RULES_DIR.glob("*.yar"))
    if not rule_files:
        print(f"⚠️  No .yar files in {YARA_RULES_DIR}")
        return None
    print(f"🦠 Compiling {len(rule_files)} YARA rule files → {YARA_COMPILED.name}...")
    cmd = ["yarac", "-w"]
    for ext in YARA_EXTERNALS:
        cmd += ["-d", f'{ext}=""']
    cmd += [str(p) for p in rule_files] + [str(YARA_COMPILED)]
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await proc.communicate()
    if proc.returncode != 0 or not YARA_COMPILED.exists():
        print(f"   ❌ yarac failed: {stderr.decode(errors='replace')[:300]}")
        return None
    print(f"   compiled OK ({YARA_COMPILED.stat().st_size // 1024} KB)")
    return YARA_COMPILED


async def scan_yara(compiled_rules: Path | None, dump_dir: Path) -> dict:
    """Recursive `yara -C` scan over dump_dir. Returns {pid: {file: [rules]}}.

    PID is recovered from the filename pattern `pid.<pid>.vad.*.dmp`.

    Direct-subprocess exception per compile_yara_rules rationale (the compiled
    rules path lives outside Chisel --root). 300s timeout preserved.
    """
    if compiled_rules is None or not dump_dir.exists():
        return {}
    cmd = ["yara", "-C", str(compiled_rules), "-r", str(dump_dir)]
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
    except asyncio.TimeoutError:
        proc.kill(); await proc.wait()
        print("   ❌ YARA scan timeout")
        return {}
    out: dict = {}
    for line in stdout.decode(errors="replace").splitlines():
        line = line.strip()
        if not line or " " not in line:
            continue
        rule_name, file_path = line.split(" ", 1)
        # Extract PID from filename: pid.<pid>.vad.<addr>-<addr>.dmp
        try:
            pid = int(Path(file_path).name.split(".")[1])
        except (IndexError, ValueError):
            continue
        out.setdefault(pid, {}).setdefault(file_path, []).append(rule_name)
    return out


def compute_scores(anomalies: list, yara_hits_by_pid: dict) -> dict:
    """Per-PID score 0-100 from anomaly types (one weight per type per PID) + YARA presence."""
    types_by_pid: dict[int, set] = {}
    for a in anomalies:
        pid = a.get("pid")
        if pid is None:
            continue
        types_by_pid.setdefault(pid, set()).add(a["type"])
    for pid in yara_hits_by_pid:
        types_by_pid.setdefault(pid, set()).add("yara_hit")
    scores: dict = {}
    for pid, types in types_by_pid.items():
        scores[pid] = min(100, sum(ANOMALY_WEIGHTS.get(t, 0) for t in types))
    return scores


def build_triage(scores: dict, pid_to_name: dict, yara_hits_by_pid: dict, dump_paths: dict, top_n: int = 10) -> list:
    """Sorted-by-score-desc triage list with high_confidence flag, YARA rules, dump dir."""
    triage: list = []
    for pid in sorted(scores, key=lambda p: -scores[p])[:top_n]:
        rules = sorted({r for hits in yara_hits_by_pid.get(pid, {}).values() for r in hits})
        dumps = dump_paths.get(pid, [])
        triage.append({
            "pid": pid,
            "process": pid_to_name.get(pid),
            "score": scores[pid],
            "high_confidence": scores[pid] >= AUTO_DUMP_THRESHOLD,
            "yara_rules": rules,
            "dump_dir": str(dumps[0].parent.relative_to(EVIDENCE_ROOT)) if dumps else None,
        })
    return triage


def _format_anomaly(a: dict) -> str:
    t = a["type"]
    if t == "injection":
        return f"- **injection** PID={a['pid']} ({a.get('process')}) start={a.get('start_vpn')} protection={a.get('protection')} tag={a.get('tag')}"
    if t == "hidden":
        return f"- **hidden** PID={a['pid']} ({a.get('process')}) offset={a.get('offset')}"
    if t == "bad_parent":
        return f"- **bad_parent** PID={a['pid']} ({a['process']}) parented by PID={a['ppid']} ({a['actual_parent']}); expected {a['expected_parent']}"
    if t == "duplicate_singleton":
        return f"- **duplicate_singleton** {a['process']} appears {a['count']} times"
    if t == "baseline_new_pid":
        return f"- **baseline_new_pid** PID={a['pid']} ({a['process']}) parent={a.get('parent')} — pair absent from baseline"
    if t == "yara_hit":
        return f"- **yara_hit** PID={a['pid']} rules={','.join(a.get('rule_names', []))} dump={a.get('dump_file')}"
    if t == "process_external_connection":
        return (f"- **process_external_connection** PID={a.get('pid')} ({a.get('process')}) "
                f"{a.get('proto')} {a.get('local_addr')}:{a.get('local_port')} → "
                f"`{a.get('remote_addr')}:{a.get('remote_port')}` state={a.get('state')}")
    if t == "process_external_connection_recent":
        return (f"- **process_external_connection_recent** PID={a.get('pid')} ({a.get('process')}) "
                f"{a.get('proto')} {a.get('local_addr')}:{a.get('local_port')} → "
                f"`{a.get('remote_addr')}:{a.get('remote_port')}` state={a.get('state')} "
                f"_(connection torn down — C2 endpoint preserved as IOC)_")
    if t == "suspicious_service":
        return (f"- **suspicious_service** svc=`{a.get('svc_name')}` "
                f"image=`{a.get('image_path')}` state={a.get('state')} start={a.get('start_mode')}")
    if t == "userassist_execution_user_writable":
        last = a.get("last_run") or "?"
        cnt = a.get("count")
        cnt_str = f" count={cnt}" if cnt is not None else ""
        return f"- **userassist_execution_user_writable** path=`{a.get('path')}`{cnt_str} last={last}"
    return f"- **{t}** {a}"


def _format_triage(t: dict) -> str:
    rules = ", ".join(t["yara_rules"]) if t["yara_rules"] else "(none)"
    dump = t["dump_dir"] or "(no dump)"
    flag = " 🔴" if t["high_confidence"] else ""
    return f"- **PID {t['pid']}** ({t['process']}) — score={t['score']}{flag} | yara: {rules} | dump: `{dump}`"


def _format_enrichment(pid: int, info: dict) -> str:
    types = ", ".join(f"{t}={c}" for t, c in info["top_handle_types"].items()) or "(none)"
    nonsys = "\n    - " + "\n    - ".join(info["nonsystem_dlls"]) if info["nonsystem_dlls"] else " (none)"
    notable = "\n    - " + "\n    - ".join(f"[{t}] {n}" for t, n in info["notable_handles"]) if info["notable_handles"] else " (none)"
    return (
        f"- **PID {pid}** ({info['process']}): {info['dll_count']} DLLs, {info['handle_count']} handles\n"
        f"  - top handle types: {types}\n"
        f"  - non-system DLLs:{nonsys}\n"
        f"  - notable handles:{notable}"
    )


def generate_claim(results: dict, anomalies: list, enrichment: dict, scores: dict, triage: list, dump_paths: dict, baseline_used: str | None, memory_dump: Path, dump_captured: str | None = None) -> str:
    timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    claim_id = f"mem-{timestamp.replace(':', '').replace('-', '')[:14]}"
    host_id = derive_host_id(memory_dump.name)

    pslist = results.get("windows.pslist", [])

    # Entities: triage-order PIDs (highest score first), then anomaly PIDs, then pslist top, capped at 30.
    seen: set = set()
    entity_pids: list = []
    for t in triage:
        pid = t["pid"]
        if pid not in seen:
            seen.add(pid); entity_pids.append(pid)
    for a in anomalies:
        pid = a.get("pid")
        if pid is not None and pid not in seen:
            seen.add(pid); entity_pids.append(pid)
    for p in pslist:
        pid = p.get("PID")
        if pid is not None and pid not in seen:
            seen.add(pid); entity_pids.append(pid)
        if len(entity_pids) >= 30:
            break

    cited_plugins = [p for p in (PLUGINS + TARGETED_PLUGINS) if p in results]
    cited_refs = [f"evidence/new/{memory_dump.name}#vol-{p.split('.', 1)[1]}" for p in cited_plugins]
    if dump_paths:
        cited_refs += [f"evidence/dumps/{memory_dump.stem}/pid_{pid}/" for pid in sorted(dump_paths)]

    frontmatter = {
        "claim_id": claim_id,
        "status": "new",
        "host": host_id,
        "entities": [f"process:{host_id}:{pid}" for pid in entity_pids[:30]],
        "evidence_refs": cited_refs,
        "confidence": 0.85,
        "generated_by": "memory-agent",
        "timestamp": timestamp,
        "anomaly_count": len(anomalies),
    }
    if enrichment:
        frontmatter["targeted_pids"] = sorted(enrichment.keys())
    if scores:
        frontmatter["scores"] = {pid: scores[pid] for pid in sorted(scores)}
    if triage:
        frontmatter["triage"] = [t["pid"] for t in triage]
    if dump_paths:
        # Skip PIDs whose dump produced no files (defensive — usually means vol3 silently failed for that PID).
        non_empty = {pid: dump_paths[pid] for pid in dump_paths if dump_paths[pid]}
        if non_empty:
            frontmatter["dump_paths"] = {pid: str(non_empty[pid][0].parent.relative_to(EVIDENCE_ROOT)) for pid in sorted(non_empty)}

    # Parent-PID map for the entities we cite — extractor turns this into PARENT_OF edges.
    pslist_by_pid = {p["PID"]: p for p in pslist if p.get("PID") is not None}
    pid_parents = {
        pid: pslist_by_pid[pid].get("PPID")
        for pid in entity_pids[:30]
        if pid in pslist_by_pid and pslist_by_pid[pid].get("PPID") is not None
    }
    if pid_parents:
        frontmatter["pid_parents"] = pid_parents

    # Per-PID asserted attributes for the extractor (real Process node attrs) and the
    # validator (spot-check the claim's assertion against the graph).
    pid_to_cmdline = parse_cmdline(results.get("windows.cmdline", []))
    pid_attrs = {}
    for pid in entity_pids[:30]:
        row = pslist_by_pid.get(pid)
        if not row:
            continue
        attrs = {"name": row.get("ImageFileName")}
        ppid = row.get("PPID")
        if ppid is not None:
            attrs["ppid"] = ppid
        ct = row.get("CreateTime")
        if ct:
            attrs["create_time"] = str(ct)
        cmdline = pid_to_cmdline.get(pid)
        if cmdline:
            attrs["command_line"] = cmdline
        pid_attrs[pid] = attrs
    if pid_attrs:
        frontmatter["pid_attrs"] = pid_attrs

    # Service entities + per-service attrs from windows.svcscan. ALL services are
    # emitted as graph entities so cross_domain_service_persistence (rule 5) can
    # auto-fire when the same service:<host>:<name> appears in registry/evtx claims.
    # Suspicious-service body bullets (PsExec etc.) are added to anomalies separately.
    service_attrs = parse_svcscan(results.get("windows.svcscan", []), host_id)[0]
    if service_attrs:
        # Cap at 100 to avoid frontmatter bloat. PRIORITIZE attacker-tradecraft service
        # names so they always survive the cap on hosts with >100 services; fill the
        # remainder alphabetically. Without this prioritization, PSEXESVC etc. silently
        # drop off when alphabetically later than 100 legit vendor services.
        suspicious_keys = [k for k in service_attrs.keys()
                           if any(s in k.lower() for s in _SUSPICIOUS_SERVICE_NAMES)]
        other_keys = [k for k in service_attrs.keys() if k not in suspicious_keys]
        kept_keys = suspicious_keys + other_keys[: max(0, 100 - len(suspicious_keys))]
        capped = {k: service_attrs[k] for k in kept_keys}
        existing_entities = frontmatter["entities"]
        frontmatter["entities"] = existing_entities + sorted(capped.keys())
        frontmatter["service_attrs"] = capped

    # Per-connection network attrs (process_external_connection findings only) — keyed
    # by `connection:<host>:<remote_ip>:<remote_port>` so cross-host correlation can
    # pivot on shared C2 endpoints. Built from the unified `anomalies` list since
    # detect_network_anomalies emits into it earlier in the pipeline.
    network_attrs = _network_attrs_from_findings(anomalies, host_id)
    if network_attrs:
        frontmatter["network_attrs"] = network_attrs

    frontmatter["baseline_used"] = baseline_used  # explicit None when no baseline registered
    if dump_captured:
        frontmatter["dump_captured"] = dump_captured  # ISO8601 wall-clock of dump capture (vol windows.info)

    counts_block = "\n".join(f"- {p}: {len(results.get(p, []))} rows" for p in cited_plugins)
    anomalies_block = "\n".join(_format_anomaly(a) for a in anomalies[:50]) if anomalies else "_None detected._"
    if enrichment:
        enrich_block = "\n".join(_format_enrichment(pid, info) for pid, info in sorted(enrichment.items()))
    else:
        enrich_block = "_No flagged PIDs to enrich._"
    triage_block = "\n".join(_format_triage(t) for t in triage) if triage else "_No scored PIDs._"

    body = f"""**Memory Analysis Finding**

Volatility 3 scan completed on `{memory_dump.name}`.
{f"Baseline used: `{baseline_used}`" if baseline_used else "_No baseline registered._"}
{f"Dump captured (wall-clock): `{dump_captured}`" if dump_captured else ""}

**Plugin row counts:**
{counts_block}

**Triage (top {len(triage)}, score-desc; 🔴 = ≥{AUTO_DUMP_THRESHOLD}):**
{triage_block}

**Anomalies ({len(anomalies)} total{', showing first 50' if len(anomalies) > 50 else ''}):**
{anomalies_block}

**Per-PID enrichment ({len(enrichment)} flagged PIDs):**
{enrich_block}

**Next hypothesis:** Triage 🔴 PIDs first — pull strings from their VAD dumps (`{EVIDENCE_DUMPS.relative_to(EVIDENCE_ROOT.parent)}/<dump>/pid_<pid>/`), pivot YARA rule names against threat intel, correlate with disk + netscan.
"""

    return f"""---
{yaml.dump(frontmatter, sort_keys=False)}---
{body}
"""


async def run_memory_analysis(dump: Path | None = None, baseline: Path | None = None,
                              baseline_dir: Path | None = None):
    """Analyze a memory dump and emit an enriched claim via Chisel.

    Pipeline: baseline-load (cached) → broad vol pass → anomaly detect →
    targeted vol pass (dlllist/handles --pid) → VAD dump per malfind PID →
    YARA scan dumps → score + triage → claim.

    Baseline selection precedence:
      1. Explicit `baseline` arg (back-compat / tests).
      2. `baseline_dir` arg + OS-aware match against this dump's `windows.info`.
         Multi-host fix: a 32-bit dump no longer gets diffed against a 64-bit baseline.
      3. None — diff skipped, `baseline_used: null` recorded in the claim.
    """
    print("🧠 Memory Agent starting (Chisel-confined, multi-plugin + YARA + scoring)...")

    chisel = Chisel(CHISEL_URL, CHISEL_SECRET)
    chisel.connect()
    print(f"🔒 Chisel session → {chisel.endpoint} (sid={chisel.session_id[:8]}…)")

    if dump is None:
        # Discover dump via Chisel (kernel-confined ls). Mirror the watcher's globs.
        new_dir = EVIDENCE_ROOT / "new"
        listing = chisel.shell("ls", ["-1", str(new_dir)])
        patterns = ["*memory*", "*raw*", "*.[0-9][0-9][0-9]", "*.[rR][aA][wW]", "*.[iI][mM][gG]", "*.[mM][eE][mM]"]
        dumps = [
            new_dir / name
            for name in (ln.strip() for ln in listing.splitlines()) if name
            if "baseline" not in name.lower()  # skip baselines on standalone runs
            if any(fnmatch.fnmatch(name, p) for p in patterns)
        ]
        dump = dumps[0] if dumps else None
        if not dump:
            print("❌ No memory dump found in evidence/new/")
            return

    print(f"📂 Analyzing: {dump.name}")

    # ─── Dump metadata (one windows.info call → capture time + OS info) ─────
    dump_captured, os_info = await extract_dump_metadata(chisel, dump)
    if dump_captured:
        print(f"   🕒 dump captured (wall-clock): {dump_captured}")
    else:
        print("   🕒 dump capture time unavailable (windows.info empty/unrecognized)")
    if os_info:
        print(f"   🖥️  detected OS: NT {os_info.get('major')}.{os_info.get('minor')} "
              f"SP{os_info.get('sp', '?')} x{os_info.get('arch', '?')}")
    else:
        print("   🖥️  OS detection unavailable (proceeding without baseline match)")

    # ─── OS-aware baseline selection ─────────────────────────────────────
    baseline_pairs: set = set()
    baseline_name = None
    if baseline is None and baseline_dir is not None:
        baseline = _select_baseline_for_dump(chisel, baseline_dir, os_info)
        if baseline is None:
            arch_str = f"x{os_info['arch']}" if os_info and os_info.get("arch") else "?"
            print(f"   🧠 No baseline found in {baseline_dir} matching this OS ({arch_str}); "
                  "proceeding without baseline (baseline_new_pid detector will be silent)")
        else:
            print(f"   🧠 Selected baseline: {baseline.name}")
    if baseline is not None and baseline.exists():
        baseline_pairs = await parse_baseline(chisel, baseline)
        baseline_name = baseline.name

    # ─── Broad pass ────────────────────────────────────────────────
    results: dict = {}
    for plugin in PLUGINS:
        rows = await run_volatility_plugin(chisel, dump, plugin)
        results[plugin] = rows if isinstance(rows, list) else []
        print(f"   {plugin}: {len(results[plugin])} rows")

    anomalies = detect_anomalies(
        results.get("windows.pslist", []),
        results.get("windows.psscan", []),
        results.get("windows.malfind", []),
    )
    if baseline_pairs:
        baseline_findings = detect_baseline_anomalies(results.get("windows.pslist", []), baseline_pairs)
        anomalies += baseline_findings
        print(f"   baseline diff: +{len(baseline_findings)} new (name, parent) pairs")

    # Network: process-→external-IP edges from windows.netscan. Findings join `anomalies`
    # so they get the standard score/triage treatment AND so the existing claim body
    # rendering picks them up automatically. Per-connection attrs go into `network_attrs`
    # below for the cross-host correlation rule.
    host_id = derive_host_id(dump.name)
    network_findings = detect_network_anomalies(results.get("windows.netscan", []), host_id)
    if network_findings:
        anomalies += network_findings
        print(f"   network: +{len(network_findings)} external TCP connections")

    # v2 corroborator findings: attacker-tradecraft services + UserAssist execution
    # in user-writable paths. These flow through the existing scoring/triage/body
    # pipeline and feed cross_domain_service_persistence (rule 5) and
    # cross_domain_persistence_execution (rule 6) when matching artifacts appear
    # in registry/evtx claims for the same host.
    _, suspicious_services = parse_svcscan(results.get("windows.svcscan", []), host_id)
    if suspicious_services:
        anomalies += suspicious_services
        print(f"   svcscan: +{len(suspicious_services)} suspicious service(s) "
              f"({', '.join(s['svc_name'] for s in suspicious_services[:5])})")

    ua_findings = parse_userassist(results.get("windows.registry.userassist", []))
    if ua_findings:
        anomalies += ua_findings
        print(f"   userassist: +{len(ua_findings)} user-writable execution entries")

    # ─── Targeted pass on flagged PIDs ─────────────────────────────
    flagged_pids: list = []
    seen: set = set()
    for a in anomalies:
        pid = a.get("pid")
        if pid is not None and pid not in seen:
            seen.add(pid); flagged_pids.append(pid)
    flagged_pids = flagged_pids[:MAX_TARGETED_PIDS]
    print(f"🚨 Anomalies: {len(anomalies)} across {len(flagged_pids)} flagged PIDs")

    enrichment: dict = {}
    if flagged_pids:
        pid_args = ["--pid", *(str(p) for p in flagged_pids)]
        for plugin in TARGETED_PLUGINS:
            rows = await run_volatility_plugin(chisel, dump, plugin, extra_args=pid_args)
            results[plugin] = rows if isinstance(rows, list) else []
            print(f"   {plugin} (--pid x{len(flagged_pids)}): {len(results[plugin])} rows")
        enrichment = enrich_flagged_pids(
            results.get("windows.pslist", []),
            results.get("windows.dlllist", []),
            results.get("windows.handles", []),
            flagged_pids,
        )

    # ─── VAD dump for malfind PIDs (input for YARA) ────────────────
    malfind_pids = sorted({a["pid"] for a in anomalies if a.get("type") == "injection" and a.get("pid") is not None})
    dump_paths: dict = {}
    if malfind_pids:
        dump_root = EVIDENCE_DUMPS / dump.stem
        dump_root.mkdir(parents=True, exist_ok=True)
        print(f"💾 Dumping VAD regions for {len(malfind_pids)} malfind PIDs → {dump_root.relative_to(EVIDENCE_ROOT)}/")
        dump_paths = await dump_vad_regions(chisel, dump, malfind_pids, dump_root)

    # ─── YARA scan ─────────────────────────────────────────────────
    yara_hits: dict = {}
    if dump_paths:
        compiled = await compile_yara_rules()
        if compiled is not None:
            dump_root = EVIDENCE_DUMPS / dump.stem
            print(f"🦠 YARA scanning {sum(len(v) for v in dump_paths.values())} dumped region(s)...")
            yara_hits = await scan_yara(compiled, dump_root)
            for pid, by_file in yara_hits.items():
                for fpath, rules in by_file.items():
                    anomalies.append({
                        "type": "yara_hit",
                        "pid": pid,
                        "rule_names": rules,
                        "dump_file": str(Path(fpath).relative_to(EVIDENCE_ROOT)),
                    })
            total_hits = sum(len(rules) for by_file in yara_hits.values() for rules in by_file.values())
            print(f"   YARA: {total_hits} hits across {len(yara_hits)} PID(s)")

    # ─── Scoring + triage ──────────────────────────────────────────
    pid_to_name = {p["PID"]: p.get("ImageFileName") for p in results.get("windows.pslist", []) if p.get("PID") is not None}
    scores = compute_scores(anomalies, yara_hits)
    triage = build_triage(scores, pid_to_name, yara_hits, dump_paths)
    high_conf = sum(1 for t in triage if t["high_confidence"])
    print(f"📊 Scored {len(scores)} PIDs; {high_conf} at or above threshold ({AUTO_DUMP_THRESHOLD})")

    # ─── Emit claim via Chisel ─────────────────────────────────────
    chisel.call("create_directory", {"path": str(CLAIMS_TODO)})
    claim_content = generate_claim(results, anomalies, enrichment, scores, triage, dump_paths, baseline_name, dump, dump_captured=dump_captured)
    claim_path = CLAIMS_TODO / f"memory_{dump.stem}_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.md"
    chisel.call("write_file", {"path": str(claim_path), "content": claim_content})

    print(f"✅ Claim written → {claim_path.name}")
    total_rows = sum(len(v) for v in results.values())
    print(f"   → {total_rows} vol rows, {len(anomalies)} anomalies, {sum(len(v) for v in dump_paths.values())} dumped VADs, {len(scores)} scored PIDs")
    print("   Orchestrator will now process this claim!")


if __name__ == "__main__":
    asyncio.run(run_memory_analysis())
