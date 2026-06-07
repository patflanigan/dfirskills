# agents/plaso_agent/agent.py
"""
Plaso Agent — lateral-movement detection from a Plaso-built super-timeline.

Pipeline:
  1. Discover staged evtx files in evidence/extracted/<image_stem>/evtx/ via Chisel.
  2. Run log2timeline.py against the SECURITY-relevant logs only (Security, System,
     PowerShell-Operational, TerminalServices-LocalSessionManager, TaskScheduler).
     Cached: skip if the .plaso storage file already exists for the same input set.
  3. Run psort.py -o json_line to materialize an event timeline as JSONL.
  4. Parse the JSONL, extract LogonType / WorkstationName / IpAddress / TargetUserName
     / TicketEncryptionType / ServiceName from the per-event XML EventData blob.
  5. Apply 4 lateral-movement detection rules, each emitting a finding-type token
     evtx_agent does NOT emit today (lm_* prefix to avoid collision):
       - lm_network_logon_from_remote        (4624 LogonType=3 from non-self workstation)
       - lm_explicit_credential_to_admin     (4648 to a privileged TargetUserName)
       - lm_kerberoasting_tgs                (4769 RC4-HMAC ticket request burst)
       - lm_psexec_install_with_logon        (7045 PSEXESVC ±60s of a 4624 LT3)
  6. Emit a single claim per finding-type into claims/todo/ with full event_attrs
     frontmatter so the existing extractor + validator handle it unchanged.

Rationale: evtx_agent's event_attrs serialization omits LogonType / WorkstationName
/ IpAddress / TicketEncryptionType (verified). Plaso's winevtx parser exposes the
full XML EventData blob, which is the cheapest path to those fields without writing
a parallel evtx parser. We use Plaso strictly as a richer field-extractor + unified-
timeline corroborator — NOT as a generic event dump (that would destroy graph
signal-to-noise; see SKILLS.md §1, §3).
"""

import asyncio
import fnmatch
import json
import os
import re
from collections import defaultdict
from datetime import datetime, UTC
from pathlib import Path
from xml.etree import ElementTree as ET

import yaml

from agents._chisel import Chisel
from cognee_schema.schema import derive_host_id

EVIDENCE_ROOT = Path(os.environ.get("EVIDENCE_ROOT", "/home/sansforensics/dfirskills2/evidence"))
EVIDENCE_EXTRACTED = EVIDENCE_ROOT / "extracted"
CLAIMS_TODO = EVIDENCE_ROOT / "claims/todo"

CHISEL_URL = os.environ.get("CHISEL_URL", "http://127.0.0.1:3000")
CHISEL_SECRET = os.environ["CHISEL_SECRET"]

LOG2TIMELINE = "/usr/bin/log2timeline.py"
PSORT = "/usr/bin/psort.py"

# Plaso runs are slow; we cache the .plaso storage per image. This list scopes
# log2timeline to the SECURITY-relevant evtx files only — Application.evtx,
# DNS Server.evtx, etc. would otherwise inflate runtime ~5x with no LM signal.
LM_RELEVANT_EVTX_PATTERNS = (
    "Security.evtx",
    "System.evtx",
    "Microsoft-Windows-PowerShell%4Operational.evtx",
    "Microsoft-Windows-TaskScheduler%4Operational.evtx",
    "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx",
    # v3: WMI / WinRM operational logs for tool-specific corroboration
    "Microsoft-Windows-WMI-Activity%4Operational.evtx",
    "Microsoft-Windows-WinRM%4Operational.evtx",
)

# Event IDs we care about (others discarded during JSONL parse to keep memory bounded).
# 4624: successful logon, 4648: explicit-credential logon, 4672: special privileges
# assigned, 4769: TGS request (Kerberoasting indicator if RC4), 7045: service install.
# 4688: process creation (parent-child for v3 WMI/WinRM/DCOM detection).
# 106/141: TaskScheduler create/delete (atexec cleanup signature).
# 5857/5860/5861: WMI-Activity provider startup/temp consumer (WMI confirmation).
# 91/142: WinRM operational (WinRM confirmation).
LM_RELEVANT_EVENT_IDS = {
    4624, 4625, 4648, 4672, 4688, 4769, 7045,
    106, 141,                  # TaskScheduler/Operational
    5857, 5860, 5861,          # WMI-Activity/Operational
    91, 142,                   # WinRM/Operational
}

# Privileged TargetUserName patterns for 4648 explicit-credential detection.
# Conservative: match exact privileged accounts, not substring matches.
_PRIVILEGED_USER_PATTERNS = (
    re.compile(r"^administrator$", re.I),
    re.compile(r"^domain\s*admin", re.I),
    re.compile(r"^enterprise\s*admin", re.I),
    re.compile(r"^schema\s*admin", re.I),
    re.compile(r"^krbtgt$", re.I),
    re.compile(r"^backup\s*operator", re.I),
)

# Builtin / service / machine accounts to suppress for ALL LM rules.
_BUILTIN_USER_NAMES = {
    "system", "anonymous logon", "network service", "local service",
    "iusr", "iwam", "dwm", "umfd",
}

# RC4 etype on Kerberos TGS requests is the canonical Kerberoasting signal
# (etype 0x17 = RC4-HMAC). 0x12 = AES256, 0x11 = AES128 are the modern non-roastable types.
KERBEROAST_RC4_ETYPE = "0x17"

# Multi-signal join window for lm_psexec_install_with_logon. Service install + auth
# event farther apart than this is unlikely to be the same lateral-move action.
PSEXEC_JOIN_WINDOW_S = 60

# Service-name substrings that are known-legitimate enterprise IT / AV /
# server-role services. A 7045 + 4624 LT3 join WITHIN this allowlist is the
# day-to-day SCCM / monitoring / patching pattern, not lateral movement.
# Matches case-insensitively against ServiceName OR ImagePath.
#
# Tradeoff: an attacker who names their service "ccmsetup" or "windowsupdate"
# would slip past this list. The cost of that risk is accepted in exchange for
# usable FP rate; the explicit ServiceName + ImagePath in every fired claim
# lets an analyst spot-check name spoofing within seconds. Tighten via env
# var FINDEVIL_SERVICE_INSTALL_ALLOWLIST_EXTRA="name1,name2" if needed.
_BENIGN_SERVICE_INSTALL_HINTS = (
    # Microsoft built-in / Windows Update
    "trustedinstaller", "wuauserv", "windowsupdate", "msiserver",
    "windefend", "msmpeng", "windowsdefender",
    # SCCM client / Microsoft management
    "ccmexec", "ccmsetup", "smstsmgr",
    "healthservice", "monitoringhost",  # SCOM agent
    # AV / EDR (vendor)
    "mcshield", "mfemms", "mfevtps", "mfeavfk", "mfehidk",
    "savadminservice", "savonaccess", "sappservice", "swc_service",  # Sophos
    "sentinelagent",  # SentinelOne
    "csagent", "csfalcon",  # CrowdStrike
    "cbdefense", "cbservice", "carbonblack",  # Carbon Black
    "ekrn", "egui",  # ESET
    "bdservicehost",  # BitDefender
    "tanium",
    # Common server roles (legit installs of these are not lateral movement)
    "mssqlserver", "sqlserveragent", "sqlbrowser", "sqltelemetry",
    "w3svc", "iisadmin", "was",
    "msexchange",  # Exchange
    # Splunk / Elastic forwarders (IT observability)
    "splunkforwarder", "splunkd", "splunkssetup",
    "elastic-agent", "winlogbeat",
    # F-Response IR (already in memory_agent's _BENIGN_SERVICE_HINTS)
    "fresdisk", "fresdiskl", "kernelpro",
)
_USER_BENIGN_EXTRA = tuple(
    s.strip().lower() for s in os.environ.get("FINDEVIL_SERVICE_INSTALL_ALLOWLIST_EXTRA", "").split(",")
    if s.strip()
)


def _is_benign_service_install(service_name: str | None, image_path: str | None) -> bool:
    """True iff the install matches the legit-IT allowlist. Defensive empty-data
    check: missing ServiceName AND ImagePath returns True (suppress) — we don't
    fire a Tier-A finding on an evidence gap."""
    blob = f"{service_name or ''}\t{image_path or ''}".lower()
    if not blob.strip():
        return True
    if any(h in blob for h in _BENIGN_SERVICE_INSTALL_HINTS):
        return True
    if any(h in blob for h in _USER_BENIGN_EXTRA):
        return True
    return False


# ─── v3 LM detection: WMI / WinRM / DCOM / atexec ───────────────────────
# Process names that act as REMOTE-EXECUTION HOSTS — when one of these is the
# parent of a 4688 process creation, the child was almost certainly invoked from
# a remote session. Map: parent process basename (lowercased) → tool-family tag.
_REMOTE_EXEC_HOST_PROCESSES = {
    "wmiprvse.exe": "WMI",
    "wsmprovhost.exe": "WinRM",
    "mmc.exe": "DCOM",  # MMC20.Application is the canonical DCOM-lateral COM object.
                        # Office processes (excel/outlook) explicitly DEFERRED to v3.1 — too
                        # noisy without a no-interactive-parent gate that 4688 alone can't provide.
}
# Children that count as "shell-like execution tools" for the WMI/WinRM/DCOM
# detector. A 4688 with one of the parents above + child in this set is the
# canonical lateral-execution signature. Children NOT in this set (e.g.,
# legitimate WMI provider methods, DCOM activations of Office documents) are
# silently filtered to keep FP rate at acceptable Tier-A levels. Sourced from
# LOLBAS shell-execution catalog.
_REMOTE_EXEC_SHELL_CHILDREN = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe",
    "regsvr32.exe", "rundll32.exe", "mshta.exe",
    "wscript.exe", "cscript.exe",
    "bitsadmin.exe", "certutil.exe", "msiexec.exe",
    "forfiles.exe", "pcalua.exe",
    # Schedule-service host (atexec runs as svchost.exe -k netsvcs running Schedule)
    # we do NOT include svchost.exe here — too generic; atexec gets its own detector.
}
# Source-host allowlist (env-tunable). When the source workstation/IP of a
# 4624 LT3 corroborator matches one of these, the LM rules suppress entirely —
# this is the operator's known IT management infrastructure (jump boxes, Ansible
# controllers, SCCM servers, monitoring hosts, etc.). Comma-separated, matched
# case-insensitively against EITHER WorkstationName OR IpAddress.
_LM_SOURCE_HOST_ALLOWLIST = tuple(
    s.strip().lower() for s in os.environ.get("FINDEVIL_LM_SOURCE_HOST_ALLOWLIST", "").split(",")
    if s.strip()
)


def _is_allowlisted_source(workstation: str | None, ip: str | None) -> bool:
    """True iff the source workstation OR IP matches the operator-tuned allowlist
    of known IT management infrastructure. Used to suppress legit-IT lateral
    movement (Ansible push, SCCM software-distribution, monitoring poll, etc.)."""
    if not _LM_SOURCE_HOST_ALLOWLIST:
        return False
    w = (workstation or "").strip().lower().rstrip("$")
    i = (ip or "").strip().lower()
    return any((w == h or i == h) for h in _LM_SOURCE_HOST_ALLOWLIST)


# Cmdline patterns that DEFINITELY indicate attacker tradecraft. When the spawned
# shell child has one of these in its CommandLine field, the rule fires even
# when other corroboration is weak. Conservative — false positives here would
# escalate benign admin work, so each pattern is highly specific.
_SUSPICIOUS_CMDLINE_PATTERNS = (
    # Use (?:^|\s) instead of \b before "-enc" — \b fails between space and dash
    # because both are non-word chars (no word boundary at that position).
    re.compile(r"(?:^|\s)-(?:enc|encodedcommand|encodedarguments)\s+[A-Za-z0-9+/=]{40,}", re.I),
    re.compile(r"\bDownloadString\s*\(", re.I),                  # Net.WebClient.DownloadString
    re.compile(r"\bDownloadFile\s*\(", re.I),
    re.compile(r"\bIEX\s*\(", re.I),                              # Invoke-Expression
    re.compile(r"\bInvoke-Expression\b", re.I),
    re.compile(r"\bFromBase64String\b", re.I),
    re.compile(r"(?:^|\s)-w\s+hidden\b", re.I),                   # window-style hidden
    re.compile(r"\bbypass\b.*\bnop\b|\bnop\b.*\bbypass\b", re.I),
    re.compile(r"\bcertutil\b.*\b-?urlcache\b.*\b-?f\b", re.I),   # certutil downloader
    re.compile(r"\bbitsadmin\b.*[/\-]transfer\b", re.I),
    re.compile(r"\bregsvr32\b.*[/\-]i:http", re.I),               # squiblydoo
    re.compile(r"\bmshta\b\s+http", re.I),                         # mshta remote
)


def _has_suspicious_cmdline(cmdline: str | None) -> bool:
    if not cmdline:
        return False
    return any(p.search(cmdline) for p in _SUSPICIOUS_CMDLINE_PATTERNS)


# ─── XML extraction helpers (Plaso emits the raw evtx XML in the `xml_string`
# field of windows:evtx:record events; we parse the EventData/Data subtree to get
# typed fields the high-level Plaso event message doesn't expose) ────────────

def _parse_event_data(xml_string: str) -> dict[str, str]:
    """Extract the <EventData><Data Name='X'>Y</Data></EventData> subtree as a dict.
    Robust to namespaced tags (Windows event XML wraps everything in the
    http://schemas.microsoft.com/win/2004/08/events/event namespace)."""
    if not xml_string:
        return {}
    out: dict[str, str] = {}
    try:
        root = ET.fromstring(xml_string)
    except ET.ParseError:
        return out
    # Walk all descendants; namespace-agnostic by using local-name matching.
    for el in root.iter():
        tag = el.tag.rsplit("}", 1)[-1]  # strip {ns}
        if tag != "Data":
            continue
        name = el.attrib.get("Name") or ""
        if not name:
            continue
        out[name] = (el.text or "").strip()
    return out


def _is_builtin_user(name: str | None) -> bool:
    if not name:
        return True
    nl = name.strip().lower()
    if not nl or nl in _BUILTIN_USER_NAMES:
        return True
    if nl.endswith("$"):  # machine account
        return True
    return False


def _is_privileged_user(name: str | None) -> bool:
    if not name:
        return False
    n = name.strip()
    return any(p.match(n) for p in _PRIVILEGED_USER_PATTERNS)


def _is_remote_workstation(workstation: str | None, self_host: str | None) -> bool:
    """True iff WorkstationName is non-empty AND not equal to the local host
    (case-insensitive). Self-referential 4624 LT3 traffic (e.g., AD replication
    to self) is silently filtered."""
    if not workstation:
        return False
    w = workstation.strip().lower().rstrip("$")
    if not w or w == "-":
        return False
    if not self_host:
        return True
    return w != self_host.strip().lower().rstrip("$")


# ─── Plaso subprocess invocation ────────────────────────────────────────────

async def run_log2timeline(chisel: Chisel, storage_file: Path, evtx_files: list[Path]) -> bool:
    """Invoke log2timeline.py through Chisel — once per evtx file.

    Modern Plaso (≥v20240308 — the SIFT default) changed CLI semantics:
      - `--storage_file <path>` is now a flag, not a positional argument
      - SOURCE positional has nargs='?' — accepts a SINGLE source per invocation
    The pre-2024 batched form (`log2timeline.py STORAGE SRC1 SRC2 ...`) was
    silently rejected with usage-text dump (exit 2). Verified against
    /usr/lib/python3/dist-packages/plaso/cli/log2timeline_tool.py:117 + 211.

    We loop log2timeline.py per evtx file; all invocations write into the SAME
    storage_file (Plaso appends events to existing storage). Per-file failure
    is isolated and logged — we continue with the rest of the file set so one
    corrupt evtx doesn't tank the whole timeline.

    Cached: if storage_file already exists and is non-empty, skip the whole
    loop (Plaso runs are slow and the same evtx set produces identical output).
    """
    if storage_file.exists() and storage_file.stat().st_size > 0:
        print(f"   ✓ Plaso storage cached: {storage_file.name} ({storage_file.stat().st_size:,} bytes) — skipping log2timeline")
        return True
    storage_file.parent.mkdir(parents=True, exist_ok=True)
    # Pin plaso's --logfile to a per-image logs/ subdir; otherwise it writes
    # timestamped log2timeline-*.log.gz files into the CWD (evidence/ root).
    logs_dir = storage_file.parent / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    print(f"   Running: log2timeline.py --parsers winevtx --storage_file {storage_file.name} (× {len(evtx_files)} evtx files)")
    failures = 0
    for i, evtx_file in enumerate(evtx_files, 1):
        print(f"   [{i}/{len(evtx_files)}] {evtx_file.name}")
        args = [
            "--parsers", "winevtx",
            "-q",  # quiet (per-event progress suppressed; we have audit log for elapsed_ms)
            "--logfile", str(logs_dir / f"log2timeline-{evtx_file.stem}.log"),
            "--storage_file", str(storage_file),
            str(evtx_file),
        ]
        try:
            result = chisel.exec_tool("log2timeline.py", args, agent_name="plaso-agent")
        except RuntimeError as e:
            print(f"      ❌ Chisel error on {evtx_file.name}: {e}")
            failures += 1
            continue
        if result["exit_code"] != 0:
            # Continue on per-file failure: corrupt/empty evtx files exist in the wild
            # and shouldn't tank the whole timeline. Aggregate failure check below.
            print(f"      ⚠️  log2timeline exit={result['exit_code']} on {evtx_file.name}")
            if result["stderr"]:
                print(f"         stderr: {result['stderr'][:200]}")
            failures += 1
    if failures == len(evtx_files):
        print(f"   ❌ log2timeline failed on ALL {len(evtx_files)} input files — aborting")
        return False
    if failures:
        print(f"   ⚠️  log2timeline succeeded on {len(evtx_files) - failures}/{len(evtx_files)} files — proceeding with partial storage")
    return storage_file.exists() and storage_file.stat().st_size > 0


async def run_psort(chisel: Chisel, storage_file: Path, jsonl_out: Path) -> bool:
    """Invoke psort.py through Chisel to materialize the storage as JSONL.
    Cached identically to log2timeline."""
    if jsonl_out.exists() and jsonl_out.stat().st_size > 0:
        print(f"   ✓ Plaso JSONL cached: {jsonl_out.name} ({jsonl_out.stat().st_size:,} bytes) — skipping psort")
        return True
    jsonl_out.parent.mkdir(parents=True, exist_ok=True)
    # Mirror log2timeline: keep psort's --logfile beside the .plaso storage,
    # not in the evidence/ root.
    logs_dir = storage_file.parent / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    print(f"   Running: psort.py -o json_line -w {jsonl_out.name} {storage_file.name}")
    args = [
        "--logfile", str(logs_dir / "psort.log"),
        "-o", "json_line", "-w", str(jsonl_out), str(storage_file),
    ]
    try:
        result = chisel.exec_tool("psort.py", args, agent_name="plaso-agent")
    except RuntimeError as e:
        print(f"   ❌ psort failed (Chisel error): {e}")
        return False
    if result["exit_code"] != 0:
        print(f"   ❌ psort failed (exit {result['exit_code']})")
        if result["stderr"]:
            print(f"   stderr: {result['stderr'][:500]}")
        return False
    return jsonl_out.exists() and jsonl_out.stat().st_size > 0


def parse_jsonl_events(jsonl_path: Path) -> list[dict]:
    """Stream-parse the timeline JSONL, keeping only events whose `event_identifier`
    is in LM_RELEVANT_EVENT_IDS. Each retained event gets its EventData parsed
    out of the xml_string blob and merged into the dict under `event_data`."""
    out: list[dict] = []
    with jsonl_path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            # Plaso emits these key names for windows:evtx:record events.
            data_type = ev.get("data_type") or ev.get("source_long") or ""
            if "evtx" not in data_type.lower() and "evt" not in str(ev.get("source", "")).lower():
                continue
            eid = ev.get("event_identifier") or ev.get("event_id")
            try:
                eid = int(eid)
            except (TypeError, ValueError):
                continue
            if eid not in LM_RELEVANT_EVENT_IDS:
                continue
            ev["event_id_int"] = eid
            ev["event_data"] = _parse_event_data(ev.get("xml_string") or ev.get("xml") or "")
            out.append(ev)
    return out


# ─── LM detection rules ────────────────────────────────────────────────────

def detect_lm_network_logon_from_remote(events: list[dict], self_host: str) -> list[dict]:
    """Rule 1: 4624 LogonType=3 from a non-self WorkstationName — network-share /
    SMB / WMI lateral movement traffic. Suppress builtins + machine accounts +
    self-referential traffic (AD replication to self)."""
    out: list[dict] = []
    for ev in events:
        if ev.get("event_id_int") != 4624:
            continue
        ed = ev["event_data"]
        if (ed.get("LogonType") or "").strip() != "3":
            continue
        target = ed.get("TargetUserName")
        if _is_builtin_user(target):
            continue
        workstation = ed.get("WorkstationName")
        if not _is_remote_workstation(workstation, self_host):
            continue
        ip = ed.get("IpAddress") or ""
        # Suppress empty/local IP — same noise pattern as builtin user
        if not ip or ip in ("-", "::1", "127.0.0.1", "0.0.0.0"):
            continue
        out.append({
            "type": "lm_network_logon_from_remote",
            "event_id": 4624,
            "record_number": ev.get("record_number"),
            "channel": "Security",
            "time_created": ev.get("date_time"),
            "target_user": target,
            "subject_user": ed.get("SubjectUserName"),
            "workstation": workstation,
            "ip_address": ip,
            "logon_type": 3,
        })
    return out


def detect_lm_explicit_credential_to_admin(events: list[dict]) -> list[dict]:
    """Rule 2: 4648 explicit-credential logon where TargetUserName is privileged
    AND distinct from SubjectUserName — runas / scheduled-task-as-admin tradecraft."""
    out: list[dict] = []
    for ev in events:
        if ev.get("event_id_int") != 4648:
            continue
        ed = ev["event_data"]
        target = ed.get("TargetUserName")
        subject = ed.get("SubjectUserName")
        if _is_builtin_user(target) or _is_builtin_user(subject):
            continue
        if (target or "").strip().lower() == (subject or "").strip().lower():
            continue
        if not _is_privileged_user(target):
            continue
        out.append({
            "type": "lm_explicit_credential_to_admin",
            "event_id": 4648,
            "record_number": ev.get("record_number"),
            "channel": "Security",
            "time_created": ev.get("date_time"),
            "target_user": target,
            "subject_user": subject,
            "target_server_name": ed.get("TargetServerName"),
            "process_name": ed.get("ProcessName"),
        })
    return out


def detect_lm_kerberoasting_tgs(events: list[dict]) -> list[dict]:
    """Rule 3: 4769 TGS-REQ with RC4-HMAC etype (0x17). evtx_agent emits
    `kerberoasting_burst` based on count, but loses the per-request etype +
    target service. We surface the per-request signal so correlation_agent can
    join individual TGS requests to specific service principals."""
    out: list[dict] = []
    for ev in events:
        if ev.get("event_id_int") != 4769:
            continue
        ed = ev["event_data"]
        etype = (ed.get("TicketEncryptionType") or "").strip().lower()
        if etype != KERBEROAST_RC4_ETYPE:
            continue
        target = ed.get("TargetUserName") or ed.get("ServiceName")
        if _is_builtin_user(target):
            continue
        out.append({
            "type": "lm_kerberoasting_tgs",
            "event_id": 4769,
            "record_number": ev.get("record_number"),
            "channel": "Security",
            "time_created": ev.get("date_time"),
            "target_service": target,
            "service_sid": ed.get("ServiceSid"),
            "client_user": ed.get("TargetUserName"),
            "client_address": ed.get("IpAddress"),
            "ticket_etype": etype,
        })
    return out


def detect_lm_psexec_install_with_logon(events: list[dict], self_host: str) -> list[dict]:
    """Rule 4: 7045 PSEXESVC service install within ±PSEXEC_JOIN_WINDOW_S of a
    4624 LogonType=3 from a non-self WorkstationName — the canonical PsExec
    lateral-movement chain (attacker authenticates over SMB → installs PSEXESVC
    on target → uses it to spawn arbitrary commands)."""
    psexec_installs = [
        ev for ev in events
        if ev.get("event_id_int") == 7045
        and "psexesvc" in ((ev["event_data"].get("ServiceName") or "")
                           + (ev["event_data"].get("ImagePath") or "")).lower()
    ]
    if not psexec_installs:
        return []
    network_logons = [
        ev for ev in events
        if ev.get("event_id_int") == 4624
        and (ev["event_data"].get("LogonType") or "").strip() == "3"
        and _is_remote_workstation(ev["event_data"].get("WorkstationName"), self_host)
        and not _is_builtin_user(ev["event_data"].get("TargetUserName"))
    ]
    out: list[dict] = []
    for inst in psexec_installs:
        inst_t = _parse_iso(inst.get("date_time"))
        if inst_t is None:
            continue
        for logon in network_logons:
            logon_t = _parse_iso(logon.get("date_time"))
            if logon_t is None:
                continue
            delta = abs((inst_t - logon_t).total_seconds())
            if delta > PSEXEC_JOIN_WINDOW_S:
                continue
            out.append({
                "type": "lm_psexec_install_with_logon",
                "event_id": 7045,
                "record_number": inst.get("record_number"),
                "channel": "System",
                "time_created": inst.get("date_time"),
                "service_name": inst["event_data"].get("ServiceName"),
                "image_path": inst["event_data"].get("ImagePath"),
                "joined_logon_record": logon.get("record_number"),
                "joined_logon_time": logon.get("date_time"),
                "joined_logon_user": logon["event_data"].get("TargetUserName"),
                "joined_logon_workstation": logon["event_data"].get("WorkstationName"),
                "joined_logon_ip": logon["event_data"].get("IpAddress"),
                "delta_seconds": delta,
            })
            break  # one join per install is enough for the finding
    return out


def detect_lm_service_install_with_logon(events: list[dict], self_host: str) -> list[dict]:
    """Generic version of detect_lm_psexec_install_with_logon — fires on ANY
    7045 service install within ±PSEXEC_JOIN_WINDOW_S of a 4624 LogonType=3
    from a non-self workstation, EXCEPT installs whose service name or image
    path matches the legit-IT allowlist (_is_benign_service_install). Catches
    PAExec, WinExe, RemCom, CSExec, Cobalt Strike service-based lateral,
    Metasploit psexec, SCShell, and any future PsExec clone with a different
    service name.

    Both this detector AND detect_lm_psexec_install_with_logon run on the same
    data: PsExec installs produce two findings (one generic, one PsExec-
    specific), so both Rule 15 and Rule 16 in correlation_agent see signal-d
    evidence. The correlation_agent dedups against Rule 15 to avoid double-
    counting in the executive summary."""
    installs = [
        ev for ev in events
        if ev.get("event_id_int") == 7045
        and not _is_benign_service_install(
            ev["event_data"].get("ServiceName"),
            ev["event_data"].get("ImagePath"),
        )
    ]
    if not installs:
        return []
    network_logons = [
        ev for ev in events
        if ev.get("event_id_int") == 4624
        and (ev["event_data"].get("LogonType") or "").strip() == "3"
        and _is_remote_workstation(ev["event_data"].get("WorkstationName"), self_host)
        and not _is_builtin_user(ev["event_data"].get("TargetUserName"))
    ]
    out: list[dict] = []
    for inst in installs:
        inst_t = _parse_iso(inst.get("date_time"))
        if inst_t is None:
            continue
        for logon in network_logons:
            logon_t = _parse_iso(logon.get("date_time"))
            if logon_t is None:
                continue
            delta = abs((inst_t - logon_t).total_seconds())
            if delta > PSEXEC_JOIN_WINDOW_S:
                continue
            out.append({
                "type": "lm_service_install_with_logon",
                "event_id": 7045,
                "record_number": inst.get("record_number"),
                "channel": "System",
                "time_created": inst.get("date_time"),
                "service_name": inst["event_data"].get("ServiceName"),
                "image_path": inst["event_data"].get("ImagePath"),
                "joined_logon_record": logon.get("record_number"),
                "joined_logon_time": logon.get("date_time"),
                "joined_logon_user": logon["event_data"].get("TargetUserName"),
                "joined_logon_workstation": logon["event_data"].get("WorkstationName"),
                "joined_logon_ip": logon["event_data"].get("IpAddress"),
                "delta_seconds": delta,
            })
            break
    return out


# ─── v3 detectors: WMI / WinRM / DCOM / atexec ──────────────────────────

def _network_logons_for_join(events: list[dict], self_host: str) -> list[dict]:
    """Filtered 4624 LogonType=3 events from non-self, non-allowlisted sources,
    with non-builtin TargetUserName. Shared by all v3 detectors."""
    return [
        ev for ev in events
        if ev.get("event_id_int") == 4624
        and (ev["event_data"].get("LogonType") or "").strip() == "3"
        and _is_remote_workstation(ev["event_data"].get("WorkstationName"), self_host)
        and not _is_builtin_user(ev["event_data"].get("TargetUserName"))
        and not _is_allowlisted_source(
            ev["event_data"].get("WorkstationName"),
            ev["event_data"].get("IpAddress"),
        )
    ]


def _detect_lm_remote_execution(events: list[dict], self_host: str,
                                host_process: str, finding_type: str) -> list[dict]:
    """Shared core for WMI / WinRM / DCOM detection. Finds 4688 events whose
    parent matches `host_process` AND whose child basename is in the shell-tool
    set, then joins to a 4624 LogonType=3 within ±PSEXEC_JOIN_WINDOW_S from a
    non-self, non-allowlisted source. Each match emits one finding tagged
    `finding_type`. The shared shape lets correlation_agent treat all three
    tool families uniformly while still letting report_agent surface them as
    distinct headlines (tool-specific finding-type tokens)."""
    matches: list[dict] = []
    for ev in events:
        if ev.get("event_id_int") != 4688:
            continue
        ed = ev["event_data"]
        parent = (ed.get("ParentProcessName") or "").rsplit("\\", 1)[-1].lower()
        child = (ed.get("NewProcessName") or "").rsplit("\\", 1)[-1].lower()
        if parent != host_process:
            continue
        if child not in _REMOTE_EXEC_SHELL_CHILDREN:
            # CRITICAL FP guard: WMI/WinRM/DCOM legitimately spawn many non-shell
            # processes (provider methods, document activations, etc.). Only shell
            # tool children indicate lateral execution.
            continue
        matches.append(ev)
    if not matches:
        return []
    network_logons = _network_logons_for_join(events, self_host)
    out: list[dict] = []
    for m in matches:
        m_t = _parse_iso(m.get("date_time"))
        if m_t is None:
            continue
        for logon in network_logons:
            l_t = _parse_iso(logon.get("date_time"))
            if l_t is None:
                continue
            delta = abs((m_t - l_t).total_seconds())
            if delta > PSEXEC_JOIN_WINDOW_S:
                continue
            ed = m["event_data"]
            ld = logon["event_data"]
            child_cmdline = ed.get("CommandLine") or ""
            out.append({
                "type": finding_type,
                "event_id": 4688,
                "record_number": m.get("record_number"),
                "channel": "Security",
                "time_created": m.get("date_time"),
                "parent_process": (ed.get("ParentProcessName") or "").rsplit("\\", 1)[-1],
                "child_process": (ed.get("NewProcessName") or "").rsplit("\\", 1)[-1],
                "child_cmdline": child_cmdline,
                "child_cmdline_suspicious": _has_suspicious_cmdline(child_cmdline),
                "subject_user": ed.get("SubjectUserName"),
                "joined_logon_record": logon.get("record_number"),
                "joined_logon_time": logon.get("date_time"),
                "joined_logon_user": ld.get("TargetUserName"),
                "joined_logon_workstation": ld.get("WorkstationName"),
                "joined_logon_ip": ld.get("IpAddress"),
                "delta_seconds": delta,
            })
            break  # one logon-join per 4688 is enough
    return out


def detect_lm_wmi_remote_execution(events: list[dict], self_host: str) -> list[dict]:
    """WMI lateral execution via Win32_Process.Create / wmic /node: / Invoke-WmiMethod.
    Signature: 4688 with parent=wmiprvse.exe AND child=shell tool, paired with
    a 4624 LT3 from non-self workstation within ±60s."""
    return _detect_lm_remote_execution(events, self_host, "wmiprvse.exe", "lm_wmi_remote_execution")


def detect_lm_winrm_remote_execution(events: list[dict], self_host: str) -> list[dict]:
    """WinRM / PowerShell Remoting lateral execution via Enter-PSSession,
    Invoke-Command, New-PSSession. Signature: 4688 with parent=wsmprovhost.exe
    AND child=shell tool, paired with 4624 LT3 (HTTP/5985 logon)."""
    return _detect_lm_remote_execution(events, self_host, "wsmprovhost.exe", "lm_winrm_remote_execution")


def detect_lm_dcom_remote_execution(events: list[dict], self_host: str) -> list[dict]:
    """DCOM lateral execution via MMC20.Application (the canonical case).
    Signature: 4688 with parent=mmc.exe AND child=shell tool, paired with
    4624 LT3. Office DCOM (Excel/Outlook) deferred to v3.1 — they need a
    no-interactive-parent gate that 4688 alone can't reliably provide."""
    return _detect_lm_remote_execution(events, self_host, "mmc.exe", "lm_dcom_remote_execution")


# atexec runs a transient scheduled task: create → execute → delete, all within
# seconds. The cleanup signature (eid 106 + 141 pair on the same task name
# within ATEXEC_CLEANUP_WINDOW_S) is the most reliable single signal.
ATEXEC_CLEANUP_WINDOW_S = 30


def detect_lm_atexec_scheduled_task(events: list[dict], self_host: str) -> list[dict]:
    """atexec.py (Impacket) lateral execution via SMB+ATSVC. Schedules a task,
    runs it, deletes it within seconds. Signature: TaskScheduler/Operational
    eid 106 (registered) + eid 141 (deleted) on the same TaskName within ±30s,
    paired with a 4624 LT3 from non-self workstation within ±60s of the create.
    Catches Impacket atexec, schtasks /create with /delete on similar timing."""
    creates: dict[str, dict] = {}
    deletes: dict[str, dict] = {}
    for ev in events:
        eid = ev.get("event_id_int")
        if eid not in (106, 141):
            continue
        task_name = ev["event_data"].get("TaskName") or ""
        if not task_name:
            continue
        if eid == 106 and task_name not in creates:
            creates[task_name] = ev
        elif eid == 141 and task_name not in deletes:
            deletes[task_name] = ev
    cleanup_pairs: list[tuple[str, dict, dict, datetime, float]] = []
    for name, c_ev in creates.items():
        d_ev = deletes.get(name)
        if d_ev is None:
            continue
        c_t = _parse_iso(c_ev.get("date_time"))
        d_t = _parse_iso(d_ev.get("date_time"))
        if c_t is None or d_t is None:
            continue
        cleanup_delta = (d_t - c_t).total_seconds()
        if abs(cleanup_delta) > ATEXEC_CLEANUP_WINDOW_S:
            continue
        cleanup_pairs.append((name, c_ev, d_ev, c_t, cleanup_delta))
    if not cleanup_pairs:
        return []
    network_logons = _network_logons_for_join(events, self_host)
    out: list[dict] = []
    for name, c_ev, d_ev, c_t, cleanup_delta in cleanup_pairs:
        for logon in network_logons:
            l_t = _parse_iso(logon.get("date_time"))
            if l_t is None:
                continue
            delta = abs((c_t - l_t).total_seconds())
            if delta > PSEXEC_JOIN_WINDOW_S:
                continue
            ld = logon["event_data"]
            out.append({
                "type": "lm_atexec_scheduled_task",
                "event_id": 106,
                "record_number": c_ev.get("record_number"),
                "channel": "TaskScheduler",
                "time_created": c_ev.get("date_time"),
                "task_name": name,
                "delete_record_number": d_ev.get("record_number"),
                "delete_time": d_ev.get("date_time"),
                "cleanup_delta_seconds": cleanup_delta,
                "joined_logon_record": logon.get("record_number"),
                "joined_logon_time": logon.get("date_time"),
                "joined_logon_user": ld.get("TargetUserName"),
                "joined_logon_workstation": ld.get("WorkstationName"),
                "joined_logon_ip": ld.get("IpAddress"),
                "delta_seconds": delta,
            })
            break
    return out


def _parse_iso(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        # Plaso JSONL typically emits "2012-04-05 10:51:17.149179" (naive) or
        # ISO8601 with Z; handle both.
        s2 = s.replace(" ", "T")
        if s2.endswith("Z"):
            s2 = s2[:-1] + "+00:00"
        dt = datetime.fromisoformat(s2)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt
    except ValueError:
        return None


# ─── Claim emission ────────────────────────────────────────────────────────

def _format_finding_bullet(f: dict) -> str:
    t = f["type"]
    if t == "lm_network_logon_from_remote":
        return (f"- **lm_network_logon_from_remote** record={f['record_number']} eid=4624 "
                f"user=`{f.get('target_user')}` from=`{f.get('workstation')}`@`{f.get('ip_address')}` "
                f"at {f.get('time_created')}")
    if t == "lm_explicit_credential_to_admin":
        return (f"- **lm_explicit_credential_to_admin** record={f['record_number']} eid=4648 "
                f"subject=`{f.get('subject_user')}` → target=`{f.get('target_user')}` "
                f"on `{f.get('target_server_name') or 'self'}` via `{f.get('process_name') or '?'}` "
                f"at {f.get('time_created')}")
    if t == "lm_kerberoasting_tgs":
        return (f"- **lm_kerberoasting_tgs** record={f['record_number']} eid=4769 "
                f"client=`{f.get('client_user')}` target_svc=`{f.get('target_service')}` "
                f"etype={f.get('ticket_etype')} at {f.get('time_created')}")
    if t == "lm_psexec_install_with_logon":
        return (f"- **lm_psexec_install_with_logon** record={f['record_number']} eid=7045 "
                f"svc=`{f.get('service_name')}` image=`{f.get('image_path')}` "
                f"joined logon record={f.get('joined_logon_record')} "
                f"user=`{f.get('joined_logon_user')}` from=`{f.get('joined_logon_workstation')}`@"
                f"`{f.get('joined_logon_ip')}` Δ={f.get('delta_seconds'):.1f}s")
    if t == "lm_service_install_with_logon":
        return (f"- **lm_service_install_with_logon** record={f['record_number']} eid=7045 "
                f"svc=`{f.get('service_name')}` image=`{f.get('image_path')}` "
                f"joined logon record={f.get('joined_logon_record')} "
                f"user=`{f.get('joined_logon_user')}` from=`{f.get('joined_logon_workstation')}`@"
                f"`{f.get('joined_logon_ip')}` Δ={f.get('delta_seconds'):.1f}s")
    if t in ("lm_wmi_remote_execution", "lm_winrm_remote_execution", "lm_dcom_remote_execution"):
        susp_marker = " 🚨SUSPICIOUS_CMDLINE" if f.get("child_cmdline_suspicious") else ""
        cmd = (f.get("child_cmdline") or "")[:200]
        return (f"- **{t}** record={f['record_number']} eid=4688 "
                f"parent=`{f.get('parent_process')}` child=`{f.get('child_process')}`{susp_marker} "
                f"cmdline=`{cmd}` "
                f"joined logon record={f.get('joined_logon_record')} "
                f"user=`{f.get('joined_logon_user')}` from=`{f.get('joined_logon_workstation')}`@"
                f"`{f.get('joined_logon_ip')}` Δ={f.get('delta_seconds'):.1f}s")
    if t == "lm_atexec_scheduled_task":
        return (f"- **lm_atexec_scheduled_task** create_record={f['record_number']} "
                f"delete_record={f.get('delete_record_number')} "
                f"task=`{f.get('task_name')}` cleanup_Δ={f.get('cleanup_delta_seconds'):.1f}s "
                f"joined logon record={f.get('joined_logon_record')} "
                f"user=`{f.get('joined_logon_user')}` from=`{f.get('joined_logon_workstation')}`@"
                f"`{f.get('joined_logon_ip')}` Δ={f.get('delta_seconds'):.1f}s")
    return f"- **{t}** {f}"


def generate_claim(host_id: str, image_stem: str, findings: list[dict],
                   storage_path: Path, jsonl_path: Path) -> str:
    """Emit a single per-host Plaso claim. event_attrs frontmatter mirrors
    evtx_agent's shape exactly so the existing extractor + validator handle this
    claim without any changes."""
    timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    claim_id = f"plaso-{timestamp.replace(':', '').replace('-', '')[:14]}"

    # entities + event_attrs in the same shape evtx_agent emits.
    entities: list[str] = []
    event_attrs: dict = {}
    for f in findings:
        rec = f.get("record_number")
        ch = f.get("channel") or "Security"
        if rec is None:
            continue
        ent = f"event:{host_id}:{ch}:{rec}"
        if ent not in event_attrs:
            entities.append(ent)
            event_attrs[ent] = {
                "channel": ch,
                "record_number": rec,
                "event_id": f.get("event_id"),
                "time_created": f.get("time_created"),
            }

    cited_refs = [
        f"evidence/extracted/{image_stem}/{storage_path.name}",
        f"evidence/extracted/{image_stem}/{jsonl_path.name}",
    ]

    frontmatter = {
        "claim_id": claim_id,
        "status": "new",
        "host": host_id,
        "entities": entities,
        "evidence_refs": cited_refs,
        "confidence": 0.85,  # Tier B (single-source); correlation_agent promotes to Tier A
        "generated_by": "plaso-agent",
        "timestamp": timestamp,
        "anomaly_count": len(findings),
    }
    if event_attrs:
        frontmatter["event_attrs"] = event_attrs

    # Group findings by type for body readability
    by_type: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        by_type[f["type"]].append(f)

    body_lines = [
        "**Lateral Movement Detection (Plaso super-timeline)**",
        "",
        f"Source: extracted evtx for `{image_stem}` ({len(findings)} finding(s) across "
        f"{len(by_type)} detection rule(s)).",
        "",
    ]
    for ftype, group in sorted(by_type.items()):
        body_lines.append(f"_{ftype} ({len(group)}):_")
        for f in group[:25]:
            body_lines.append(_format_finding_bullet(f))
        if len(group) > 25:
            body_lines.append(f"_…({len(group) - 25} more of this type)_")
        body_lines.append("")
    body_lines.append(
        "**Next hypothesis:** Pivot each finding to memory/MFT/registry claims for the "
        "same host to assemble the full lateral-move chain. The dedicated "
        "`psexec_lateral_movement` correlation rule will fire automatically when 3-of-4 "
        "PsExec signals (this finding + memory svcscan + MFT image + evtx 7045) are present."
    )

    return f"---\n{yaml.dump(frontmatter, sort_keys=False)}---\n" + "\n".join(body_lines) + "\n"


# ─── Discovery + main entry ────────────────────────────────────────────────

def _discover_evtx_root(chisel: Chisel) -> tuple[Path | None, str | None]:
    """Find the most recent evidence/extracted/<image_stem>/evtx/ directory.
    Returns (evtx_dir_path, image_stem) or (None, None) if no extraction exists."""
    listing = chisel.shell("ls", ["-1", str(EVIDENCE_EXTRACTED)])
    candidates: list[tuple[float, Path, str]] = []
    for name in (ln.strip() for ln in listing.splitlines() if ln.strip()):
        evtx_dir = EVIDENCE_EXTRACTED / name / "evtx"
        if not evtx_dir.exists():
            continue
        candidates.append((evtx_dir.stat().st_mtime, evtx_dir, name))
    if not candidates:
        return None, None
    candidates.sort(reverse=True)
    return candidates[0][1], candidates[0][2]


def _select_evtx_inputs(evtx_dir: Path) -> list[Path]:
    """Filter to LM-relevant evtx files only."""
    out: list[Path] = []
    for p in sorted(evtx_dir.iterdir()):
        if not p.is_file() or not p.name.endswith(".evtx"):
            continue
        if any(fnmatch.fnmatch(p.name, pat) for pat in LM_RELEVANT_EVTX_PATTERNS):
            out.append(p)
    return out


async def run_plaso_analysis():
    print("🕒 Plaso Agent starting (Chisel-confined; lateral-movement detection)...")
    chisel = Chisel(CHISEL_URL, CHISEL_SECRET)
    chisel.connect()
    print(f"🔒 Chisel session → {chisel.endpoint} (sid={chisel.session_id[:8]}…)")

    evtx_dir, image_stem = _discover_evtx_root(chisel)
    if not evtx_dir or not image_stem:
        print("❌ No extracted evtx/ directory found under evidence/extracted/ — nothing to do")
        return
    print(f"📂 evtx source: {evtx_dir.relative_to(EVIDENCE_ROOT)}")

    evtx_inputs = _select_evtx_inputs(evtx_dir)
    if not evtx_inputs:
        print(f"❌ No LM-relevant evtx files in {evtx_dir} — nothing to do")
        return
    print(f"   Selected {len(evtx_inputs)} LM-relevant evtx file(s):")
    for p in evtx_inputs:
        print(f"     - {p.name} ({p.stat().st_size:,} bytes)")

    # Cached storage per image_stem; cache key is the evtx file set.
    out_dir = EVIDENCE_EXTRACTED / image_stem
    storage_path = out_dir / f"{image_stem}.plaso"
    jsonl_path = out_dir / f"{image_stem}_lm_timeline.jsonl"

    if not await run_log2timeline(chisel, storage_path, evtx_inputs):
        print("❌ log2timeline failed — aborting")
        return
    if not await run_psort(chisel, storage_path, jsonl_path):
        print("❌ psort failed — aborting")
        return

    print("🧮 Parsing Plaso JSONL...")
    events = parse_jsonl_events(jsonl_path)
    print(f"   Loaded {len(events)} LM-relevant events from {jsonl_path.name}")

    host_id = derive_host_id(image_stem)
    print(f"🏠 host_id: {host_id}")

    findings: list[dict] = []
    findings += detect_lm_network_logon_from_remote(events, host_id)
    findings += detect_lm_explicit_credential_to_admin(events)
    findings += detect_lm_kerberoasting_tgs(events)
    findings += detect_lm_psexec_install_with_logon(events, host_id)
    findings += detect_lm_service_install_with_logon(events, host_id)
    # v3 detectors: WMI / WinRM / DCOM (4688 with remote-exec-host parent + shell child)
    # and atexec (TaskScheduler 106+141 cleanup signature)
    findings += detect_lm_wmi_remote_execution(events, host_id)
    findings += detect_lm_winrm_remote_execution(events, host_id)
    findings += detect_lm_dcom_remote_execution(events, host_id)
    findings += detect_lm_atexec_scheduled_task(events, host_id)
    print(f"🚨 Findings: {len(findings)}")
    if not findings:
        print("   (no LM signals detected — no claim emitted)")
        return

    chisel.call("create_directory", {"path": str(CLAIMS_TODO)})
    claim_content = generate_claim(host_id, image_stem, findings, storage_path, jsonl_path)
    claim_path = CLAIMS_TODO / f"plaso_{image_stem}_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.md"
    chisel.call("write_file", {"path": str(claim_path), "content": claim_content})
    print(f"✅ Claim written → {claim_path.name} ({len(claim_content):,} chars, {len(findings)} findings)")
    print("   Orchestrator will now process this claim!")


if __name__ == "__main__":
    asyncio.run(run_plaso_analysis())
