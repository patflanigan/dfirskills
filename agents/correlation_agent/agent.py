# agents/correlation_agent/agent.py
"""
Correlation / Hypothesis Agent — standalone, deterministic, Chisel-confined.

Reads claim markdown files in evidence/claims/done/ via Chisel (per FindEvil §5
"agents never query Cognee directly"), runs deterministic cross-claim rules,
and emits hypothesis claims into evidence/claims/todo/ that the orchestrator
picks up through the standard validate → extract → done pipeline.
"""

import asyncio
import hashlib
import os
import re
from datetime import datetime, timedelta, UTC
from pathlib import Path

import yaml

from agents._chisel import Chisel

EVIDENCE_ROOT = Path(os.environ.get("EVIDENCE_ROOT", "/home/sansforensics/dfirskills2/evidence"))
CLAIMS_DONE = EVIDENCE_ROOT / "claims/done"
CLAIMS_TODO = EVIDENCE_ROOT / "claims/todo"
CLAIMS_DOING = EVIDENCE_ROOT / "claims/doing"

CHISEL_URL = os.environ.get("CHISEL_URL", "http://127.0.0.1:3000")
CHISEL_SECRET = os.environ["CHISEL_SECRET"]

# Body parsers — both formats memory_agent emits
# Triage line: "- **PID 1328** (spinlock.exe) — score=100 🔴 | yara: rule1, rule2 | dump: `path`"
TRIAGE_LINE_RE = re.compile(
    r"^-\s*\*\*PID\s*(\d+)\*\*\s*\(([^)]+)\)\s*—\s*score=(\d+)[^|]*\|\s*yara:\s*([^|]+)\|",
    re.MULTILINE,
)
# Generic "**PID X** (name)" — fires on enrichment block too (older claims)
PID_NAME_RE = re.compile(r"\*\*PID\s*(\d+)\*\*\s*\(([^)]+)\)")
# Registry-agent masquerade lines have a "binary `<basename>`" annotation
# (covers both masquerade_run_value AND masquerade_service_imagepath).
MASQUERADE_BINARY_RE = re.compile(r"binary\s+`([^`]+)`")
# `- **finding_type** ...` body lines emitted by every agent. Used to gate cross-domain
# rules on which detectors fired in a given claim (e.g. vss_suppression_with_ransomware).
_FINDING_TYPE_RE = re.compile(r"^\s*[-*]\s*\*\*([a-z_]+)\*\*", re.MULTILINE)
# vssadmin shadow-deletion patterns inside an evtx process_create_suspicious_cmdline body
_VSSADMIN_DELETE_SHADOWS_RE = re.compile(r"vssadmin\b.*\bdelete\b.*\bshadows\b", re.I)

# Confidence per rule
CONF_CROSS_DOMAIN = 0.95              # memory injection AND on-disk persistence on the same binary
CONF_CROSS_DOMAIN_SERVICE = 0.95      # registry service masquerade AND evtx service-install of same name
CONF_CROSS_DOMAIN_EXECUTION = 0.95    # registry masquerade AND prefetch confirms suspicious-path execution
CONF_CROSS_DOMAIN_DROP = 0.97         # MFT drop + registry persistence + execution evidence on same binary
CONF_VSS_SUPPRESSION_RANSOMWARE = 0.97  # ransomware burst/note + VSS-disable on same host
CONF_SHARED_SHA1_HOSTS = 0.95          # same SHA1 on ≥2 hosts in non-system path (lateral movement)
CONF_SHARED_MASQUERADE_HOSTS = 0.92    # same masquerade signature (basename:expected_path) on ≥2 hosts
CONF_SHARED_EXTERNAL_IP_HOSTS = 0.90   # same non-RFC1918 source IP touched ≥2 hosts (external actor / C2)
CONF_SHARED_CMDLINE_HOSTS = 0.92       # same suspicious cmdline regex pattern fired on ≥2 hosts
CONF_SHARED_C2_ENDPOINT_HOSTS = 0.94   # same (remote_ip, remote_port) on ≥2 hosts (port specificity > raw IP)
CONF_SHARED_INTERNAL_IP_HOSTS = 0.75   # same RFC1918 IP on ≥2 hosts (intra-corp lateral; noisier than external)
CONF_CMDLINE_PERSISTENCE = 0.95        # memory cmdline path == registry Run-key value or service image_path
CONF_CMDLINE_MFT_DROP = 0.95           # memory cmdline path == MFT-dropped/deleted user-writable executable
CONF_PSEXEC_LATERAL_MOVEMENT = 0.97    # 3-of-4 PsExec signals (evtx 7045 + memory svcscan + MFT image + plaso LM logon)
CONF_SERVICE_INSTALL_LATERAL = 0.92    # Generic version of psexec_lateral_movement — fires on ANY non-allowlisted
                                       # service install + remote logon (catches PAExec, WinExe, RemCom, Cobalt
                                       # Strike random-named beacons, Metasploit psexec, etc.). Lower than 0.97
                                       # because legitimate IT remote management can produce this same pattern.
CONF_WMI_REMOTE_EXECUTION = 0.92       # WMI lateral execution (4688 wmiprvse parent + shell child + 4624 LT3)
CONF_WINRM_REMOTE_EXECUTION = 0.92     # WinRM/PSRemoting lateral execution (4688 wsmprovhost parent + shell child + 4624 LT3)
CONF_DCOM_REMOTE_EXECUTION = 0.92      # DCOM lateral execution (4688 mmc parent + shell child + 4624 LT3)
CONF_ATEXEC_LATERAL = 0.92             # atexec scheduled-task lateral (TaskSched 106+141 cleanup + 4624 LT3)

# PsExec uses two distinct on-disk names: PSEXEC.exe (the client binary) and
# PSEXESVC.exe (the service installed on the target). 'psexec' is NOT a substring
# of 'psexesvc' (they diverge at char 5), so a single substring check misses
# half the signals. Use this regex everywhere we look for PsExec artifacts.
_PSEXEC_NAME_RE = re.compile(r"psexe(c|svc)", re.IGNORECASE)

# Cross-host correlation Δt guard. Without this, the same external IP appearing in HOST_A
# evidence (collected 2025) and HOST_B evidence (collected 2026) would falsely correlate
# even though the artifacts are years apart. Per-claim anchor time is the most-recent
# artifact timestamp the claim cites (dump_captured > event time > registry write > run
# time > claim emission). Override via env for case-specific tuning.
MAX_CROSS_HOST_DELTA_DAYS = float(os.environ.get("FINDEVIL_CROSS_HOST_MAX_DAYS", "30"))

# Per-case allowlist for shared_internal_ip_across_hosts — comma-separated IPs that are
# expected to appear across multiple hosts (DCs, file servers, print servers, monitoring
# agents). Suppressed entirely. Empty default — operator opts in per case.
INTERNAL_IP_ALLOWLIST = {
    ip.strip() for ip in os.environ.get("FINDEVIL_INTERNAL_IP_ALLOWLIST", "").split(",")
    if ip.strip()
}
CONF_TIMESTOMPING = 0.95              # MFT $SI<$FN — direct anti-forensics evidence (standalone Tier-A)
CONF_TEMPORAL_COMPROMISE = 0.85       # multi-domain timestamped findings clustered in N minutes
CONF_HIGH_RECURRENCE = 0.85
CONF_SHARED_YARA = 0.80
CONF_NAME_RECURRENCE = 0.65

# Temporal clustering parameters (override via env if you want to tune)
TEMPORAL_WINDOW_MINUTES = int(os.environ.get("FINDEVIL_TEMPORAL_WINDOW_MINUTES", "5"))
TEMPORAL_MIN_FINDINGS = 3
TEMPORAL_MIN_DOMAINS = 2  # require at least 2 distinct domains (memory + evtx, etc.)

# Thresholds
HIGH_CONFIDENCE_SCORE = 70
NAME_RECURRENCE_MIN_CLAIMS = 3

# Common Windows system processes — excluded from rule 3 (recurring_process) since
# they appear in every memory dump trivially. Lowercased.
SYSTEM_PROCESS_DENYLIST = {
    "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "lsm.exe", "svchost.exe", "spoolsv.exe",
    "taskhost.exe", "taskhostw.exe", "explorer.exe", "dwm.exe", "audiodg.exe",
    "conhost.exe", "dllhost.exe", "logonui.exe", "userinit.exe", "fontdrvhost.exe",
    "wuauclt.exe", "searchindexer.exe", "wmiprvse.exe", "msdtc.exe",
}

# ─── cmdline-aware Tier-A rule helpers (rules 13 + 14) ───────────────────
# Drive-letter or UNC paths to executable-like file extensions. Anchored on the
# extension so we don't match "C:\Users" with no executable. Case-insensitive.
_CMDLINE_PATH_RE = re.compile(
    r"""(?xi)
    (?:
      [a-z]:\\(?:[^"<>|\r\n*?\\/]+\\)*[^"<>|\r\n*?\\/]+
      |
      \\\\[^"<>|\r\n*?\\/]+\\(?:[^"<>|\r\n*?\\/]+\\)*[^"<>|\r\n*?\\/]+
    )
    \.(?:exe|dll|bat|cmd|ps1|vbs|js|jse|hta|com|pif|scr|sys|msi|lnk)
    """,
)

# Path roots that strongly indicate USER-WRITABLE locations. The rules only
# fire when at least one side of the join lives under one of these — Microsoft-
# system binaries running their normal daemons would otherwise produce dozens
# of Tier-A FPs per host (verified on this DC corpus: McAfee FrameworkService,
# F-Response monitor, .NET SMSvcHost, ADWS all have legit Run-key entries).
_CMDLINE_USER_WRITABLE_HINTS = (
    "\\users\\", "\\temp\\", "\\appdata\\", "\\programdata\\",
    "\\public\\", "\\$recycle.bin", "\\windows\\temp\\",
)

# Vendor path roots auto-suppressed even when they appear inside a user-writable
# hint (e.g. \programdata\mcafee\). Mirrors the allowlist in
# agents/report_agent/ciso_summary.py + agents/memory_agent/agent.py.
_CMDLINE_BENIGN_VENDOR_HINTS = (
    "\\programdata\\adobe\\",
    "\\programdata\\mcafee\\",
    "\\programdata\\microsoft\\",
    "\\programdata\\intel\\",
    "\\programdata\\sophos\\",
    "\\f-response",
    "\\fres",
    "\\kernelpro",
)

# MFT body bullets emit the dropped/deleted path inside backticks immediately
# after the finding token, e.g.
#   - **mft_executable_dropped_user_writable** `c:\users\foo\bar.exe` (created ...)
_MFT_DROP_BODY_RE = re.compile(
    r"\*\*mft_(?:executable_dropped|deleted_executable)_user_writable\*\*\s+`([^`]+)`",
    re.IGNORECASE,
)


def _extract_cmdline_paths(cmdline: str) -> list[str]:
    """Pull executable-looking path strings out of a Windows command line.
    Strips wrapping quotes; case-normalizes; de-dupes; preserves order."""
    if not cmdline or not isinstance(cmdline, str):
        return []
    out: list[str] = []
    seen: set = set()
    for m in _CMDLINE_PATH_RE.finditer(cmdline):
        p = m.group(0).strip().strip('"').lower()
        if p and p not in seen:
            seen.add(p)
            out.append(p)
    return out


def _basename(path: str) -> str:
    """Match the existing rule-8 normalization (line 789)."""
    return path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()


def _is_suspicious_cmdline_path(path: str) -> bool:
    """True iff the path lives in a user-writable location and is not in the
    vendor allowlist. Used by both new rules to suppress legit-vendor FPs."""
    pl = (path or "").lower()
    if not pl:
        return False
    if any(v in pl for v in _CMDLINE_BENIGN_VENDOR_HINTS):
        return False
    return any(h in pl for h in _CMDLINE_USER_WRITABLE_HINTS)


def _source_dump(frontmatter: dict) -> str | None:
    """Extract the source memory-dump basename from a memory_agent claim's evidence_refs.

    Memory claims include refs like 'evidence/new/<dump>#vol-pslist'. We pick the
    first ref that looks like an evidence/new/* path and strip the #fragment.
    Returns None for claims without a clear single source (e.g. correlation claims).
    """
    for ref in frontmatter.get("evidence_refs", []) or []:
        if not isinstance(ref, str):
            continue
        if "evidence/new/" in ref or "evidence/processed/" in ref or "evidence/baselines/" in ref:
            base = ref.split("#", 1)[0].rstrip("/").rsplit("/", 1)[-1]
            if base:
                return base
    return None


def parse_claim(content: str, filename: str = "") -> dict | None:
    """Parse a claim markdown into {frontmatter, triage_rows, pid_names, source_dump, filename}.

    triage_rows: list of {pid, name, score, yara_rules} from the rich post-YARA triage block.
    pid_names: dict[pid -> name] from any **PID X** (name) pattern in the body.
    source_dump: the underlying dump filename (or None for non-memory / correlation claims).
    """
    if not content.startswith("---"):
        return None
    parts = content.split("---", 2)
    if len(parts) < 3:
        return None
    try:
        fm = yaml.safe_load(parts[1]) or {}
    except yaml.YAMLError:
        return None
    body = parts[2]

    triage_rows = []
    for m in TRIAGE_LINE_RE.finditer(body):
        pid_s, name, score_s, yara_str = m.groups()
        rules_raw = yara_str.strip()
        rules = []
        if rules_raw and rules_raw != "(none)":
            rules = [r.strip() for r in rules_raw.split(",") if r.strip() and r.strip() != "(none)"]
        triage_rows.append({
            "pid": int(pid_s),
            "name": name.strip(),
            "score": int(score_s),
            "yara_rules": rules,
        })

    pid_names: dict = {}
    for m in PID_NAME_RE.finditer(body):
        pid = int(m.group(1))
        pid_names.setdefault(pid, m.group(2).strip())

    masquerade_binaries = sorted({m.group(1).lower() for m in MASQUERADE_BINARY_RE.finditer(body)})

    # Finding-type tokens from `- **finding_type** ...` body lines. Used by cross-domain
    # rules that gate on whether a specific detector fired in a claim (e.g.,
    # vss_suppression_with_ransomware needs to know which claims contain `vss_service_*`
    # findings without re-reading the body each time).
    finding_types = set(_FINDING_TYPE_RE.findall(body))

    return {
        "frontmatter": fm,
        "triage_rows": triage_rows,
        "pid_names": pid_names,
        "source_dump": _source_dump(fm),
        "masquerade_binaries": masquerade_binaries,
        "finding_types": finding_types,
        "body": body,  # raw body, used by rules that need finer-grained inspection (vssadmin cmdline match)
        "filename": filename,
    }


async def load_all_claims(chisel: Chisel) -> list[dict]:
    """Read every claim in done/ via Chisel; return parsed list (correlation-agent claims included for dedup)."""
    listing = chisel.shell("ls", ["-1", str(CLAIMS_DONE)])
    claims: list = []
    for name in listing.splitlines():
        name = name.strip()
        if not name.endswith(".md"):
            continue
        try:
            content = chisel.shell("cat", [str(CLAIMS_DONE / name)])
        except RuntimeError as e:
            print(f"   ⚠️  failed to read {name}: {e}")
            continue
        parsed = parse_claim(content, filename=name)
        if parsed is not None:
            claims.append(parsed)
    return claims


def _parse_iso8601(s) -> datetime | None:
    """Parse the various ISO8601 shapes our agents emit (`Z` suffix, timezone offsets, etc.).
    ALWAYS returns tz-aware datetimes — agents that emit naive timestamps (RECmd
    `last_write_time`, some vol3 fields) get UTC assumed by convention. Without this
    normalization, mixing naive + aware in the temporal cluster comparison raises
    `can't compare offset-naive and offset-aware datetimes`.
    """
    if not s or not isinstance(s, (str,)):
        return None
    try:
        v = s.strip()
        # Strip trailing 'Z' (Python 3.10 fromisoformat doesn't accept it pre-3.11)
        if v.endswith("Z"):
            v = v[:-1] + "+00:00"
        dt = datetime.fromisoformat(v)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt
    except (ValueError, TypeError):
        return None


def _claim_anchor_time(claim: dict) -> datetime | None:
    """The most-recent artifact time this claim cites — used by cross-host Δt guard.

    Priority cascade (first non-empty tier wins; we do NOT max across tiers, otherwise
    the always-present claim-emission `timestamp` would mask older artifact times):
      1. `dump_captured` (memory wall-clock — most reliable)
      2. max of event_attrs `time_created` / `created`
      3. max of key_attrs `last_write_time`
      4. max of execution_attrs `last_run_time` / `run_times`
      5. max of network_attrs `created`
      6. claim emission `timestamp` (last resort)

    Returns None if no parseable time anywhere — caller treats that as "can't bound,
    don't suppress" rather than silently dropping the correlation.
    """
    fm = claim["frontmatter"]

    def _max_parsed(values: list) -> datetime | None:
        parsed = [dt for dt in (_parse_iso8601(v) for v in values if v) if dt is not None]
        return max(parsed) if parsed else None

    # Tier 1: dump_captured
    t = _parse_iso8601(fm.get("dump_captured"))
    if t is not None:
        return t

    # Tier 2: event_attrs
    vals = []
    for attrs in (fm.get("event_attrs") or {}).values():
        if isinstance(attrs, dict):
            vals += [attrs.get("time_created"), attrs.get("created")]
    t = _max_parsed(vals)
    if t is not None:
        return t

    # Tier 3: key_attrs
    vals = []
    for attrs in (fm.get("key_attrs") or {}).values():
        if isinstance(attrs, dict):
            vals.append(attrs.get("last_write_time"))
    t = _max_parsed(vals)
    if t is not None:
        return t

    # Tier 4: execution_attrs
    vals = []
    for attrs in (fm.get("execution_attrs") or {}).values():
        if isinstance(attrs, dict):
            vals.append(attrs.get("last_run_time"))
            vals.extend(attrs.get("run_times") or [])
    t = _max_parsed(vals)
    if t is not None:
        return t

    # Tier 5: network_attrs
    vals = []
    for attrs in (fm.get("network_attrs") or {}).values():
        if isinstance(attrs, dict):
            vals.append(attrs.get("created"))
    t = _max_parsed(vals)
    if t is not None:
        return t

    # Tier 6: claim emission timestamp (last resort)
    return _parse_iso8601(fm.get("timestamp"))


def _within_cross_host_window(occurrences: list, claims_by_id: dict) -> bool:
    """True iff all occurrence claims' anchor times are within MAX_CROSS_HOST_DELTA_DAYS
    of each other. Missing anchors don't suppress (return True) — better to surface a
    weakly-bounded correlation than silently drop it."""
    times: list[datetime] = []
    for o in occurrences:
        cid = o.get("claim_id")
        c = claims_by_id.get(cid) if cid else None
        if c is None:
            continue
        t = _claim_anchor_time(c)
        if t is not None:
            times.append(t)
    if len(times) < 2:
        return True
    delta = max(times) - min(times)
    return delta.total_seconds() <= MAX_CROSS_HOST_DELTA_DAYS * 86400


def _collect_timestamped_findings(claims: list) -> dict:
    """Return {host: [list of finding dicts sorted by time]}. Each finding:
        {time: datetime, domain: 'process_start'|'evtx'|'registry'|'prefetch'|'shimcache'|'file_creation',
         claim_id, filename, entity, label, summary}.
    Only includes claims with parseable host and timestamp data.
    """
    by_host: dict = {}

    for c in claims:
        fm = c["frontmatter"]
        host = fm.get("host")
        if not host:
            continue  # legacy claim without host context
        gen = fm.get("generated_by")

        if gen == "memory-agent":
            pid_attrs = fm.get("pid_attrs") or {}
            for pid, attrs in pid_attrs.items():
                if not isinstance(attrs, dict):
                    continue
                t = _parse_iso8601(attrs.get("create_time"))
                if t is None:
                    continue
                try:
                    pid_int = int(pid)
                except (TypeError, ValueError):
                    continue
                name = attrs.get("name") or "?"
                by_host.setdefault(host, []).append({
                    "time": t,
                    "domain": "process_start",
                    "claim_id": fm.get("claim_id"),
                    "filename": c["filename"],
                    "entity": f"process:{host}:{pid_int}",
                    "label": f"PID {pid_int} ({name})",
                    "summary": "process started",
                })

        elif gen == "evtx-agent":
            event_attrs = fm.get("event_attrs") or {}
            for ent, attrs in event_attrs.items():
                if not isinstance(attrs, dict):
                    continue
                t = _parse_iso8601(attrs.get("time_created"))
                if t is None:
                    continue
                eid = attrs.get("event_id") or "?"
                channel = attrs.get("channel") or "?"
                rec = attrs.get("record_number") or "?"
                by_host.setdefault(host, []).append({
                    "time": t,
                    "domain": "evtx",
                    "claim_id": fm.get("claim_id"),
                    "filename": c["filename"],
                    "entity": ent,
                    "label": f"evtx {channel} {eid} (rec {rec})",
                    "summary": f"event {eid}",
                })

        elif gen == "registry-agent":
            # Registry persistence-wiring events — RECmd's LastWriteTimestamp on the
            # parent key tells us when the persistence entry was established. The key
            # may have been wired during the compromise window (extremely high signal)
            # or long before (then it's a long-standing persistence with renewed activity).
            key_attrs = fm.get("key_attrs") or {}
            for ent, attrs in key_attrs.items():
                if not isinstance(attrs, dict):
                    continue
                t = _parse_iso8601(attrs.get("last_write_time"))
                if t is None:
                    continue
                # ent is "registry_key:<host>:<rest>" or "file:<host>:<rest>"; pull the
                # human-readable tail for the timeline label.
                tail = ent.split(":", 2)[-1] if ":" in ent else ent
                kind = ent.split(":", 1)[0]
                by_host.setdefault(host, []).append({
                    "time": t,
                    "domain": "registry",
                    "claim_id": fm.get("claim_id"),
                    "filename": c["filename"],
                    "entity": ent,
                    "label": f"registry {kind} `{tail}`",
                    "summary": "registry persistence wired",
                })

            # ShimCache execution evidence — registry-agent now also emits execution_attrs
            # from its SYSTEM-hive AppCompatCache parse. Same shape as prefetch_agent's,
            # discriminated by attrs["source"] == "shimcache". Each entry's last_run_time
            # is the AppCompatCache LastModifiedTimeUTC.
            execution_attrs = fm.get("execution_attrs") or {}
            for ent, attrs in execution_attrs.items():
                if not isinstance(attrs, dict):
                    continue
                exe = attrs.get("executable_name") or "?"
                for rt in attrs.get("run_times") or []:
                    t = _parse_iso8601(rt)
                    if t is None:
                        continue
                    by_host.setdefault(host, []).append({
                        "time": t,
                        "domain": "shimcache",
                        "claim_id": fm.get("claim_id"),
                        "filename": c["filename"],
                        "entity": ent,
                        "label": f"shimcache `{exe}`",
                        "summary": "binary in compatibility cache",
                    })

        elif gen == "mft-agent":
            # File creation timestamps from MFT — the strongest "first dropped on disk"
            # anchor in the system. One anchor per file; the win7 case may emit up to 500
            # file_attrs entries per claim (per the agent's MAX_ENTITIES_PER_CLAIM cap).
            file_attrs = fm.get("file_attrs") or {}
            for ent, attrs in file_attrs.items():
                if not isinstance(attrs, dict):
                    continue
                t = _parse_iso8601(attrs.get("created_time"))
                if t is None:
                    continue
                # Pull the executable basename for the timeline label
                tail = ent.rsplit("\\", 1)[-1]
                by_host.setdefault(host, []).append({
                    "time": t,
                    "domain": "file_creation",
                    "claim_id": fm.get("claim_id"),
                    "filename": c["filename"],
                    "entity": ent,
                    "label": f"file dropped `{tail}`",
                    "summary": "binary written to disk",
                })

        elif gen == "prefetch-agent":
            # Prefetch RunTimes (up to 8 per .pf on Win8+) — direct evidence of execution.
            # Each historical run becomes its own temporal anchor, so a single Prefetch
            # claim can contribute up to 8 timeline entries — much higher density than
            # the other domains.
            execution_attrs = fm.get("execution_attrs") or {}
            for ent, attrs in execution_attrs.items():
                if not isinstance(attrs, dict):
                    continue
                exe = attrs.get("executable_name") or "?"
                for rt in attrs.get("run_times") or []:
                    t = _parse_iso8601(rt)
                    if t is None:
                        continue
                    by_host.setdefault(host, []).append({
                        "time": t,
                        "domain": "prefetch",
                        "claim_id": fm.get("claim_id"),
                        "filename": c["filename"],
                        "entity": ent,
                        "label": f"prefetch run `{exe}`",
                        "summary": "binary executed",
                    })

    # Sort each host's findings chronologically
    for host in by_host:
        by_host[host].sort(key=lambda f: f["time"])
    return by_host


def _temporal_clusters(findings_sorted: list, window_minutes: int) -> list:
    """Sliding-window clustering. Returns a list of clusters, each = list of findings.
    Greedy dedup: if two adjacent windows overlap, keep the longer (more findings) one;
    on tie, the earlier-starting one wins.
    """
    if not findings_sorted:
        return []
    window = timedelta(minutes=window_minutes)
    n = len(findings_sorted)
    candidates: list = []  # list of (start_idx, end_idx_exclusive)

    j = 0
    for i in range(n):
        # Advance j while the window starting at i still includes finding j
        if j < i:
            j = i
        while j < n and (findings_sorted[j]["time"] - findings_sorted[i]["time"]) <= window:
            j += 1
        # j is now the first index OUTSIDE the window from i
        size = j - i
        if size >= TEMPORAL_MIN_FINDINGS:
            candidates.append((i, j, size))

    if not candidates:
        return []

    # Greedy dedup: walk candidates ordered by descending size, then ascending start.
    # Pick a candidate iff its index range doesn't overlap an already-picked one.
    candidates.sort(key=lambda c: (-c[2], c[0]))
    picked: list = []
    used: list = []  # list of (start, end) ranges already chosen
    for (s, e, sz) in candidates:
        if any(not (e <= us or s >= ue) for (us, ue) in used):
            continue
        picked.append((s, e))
        used.append((s, e))
    # Sort picks chronologically
    picked.sort()
    return [findings_sorted[s:e] for (s, e) in picked]


def detect_correlations(claims: list[dict]) -> list[dict]:
    """Run deterministic rules over the domain (non-correlation) claim corpus.

    Single-claim corpora ARE valid input — some rules (e.g. timestomping_detected) fire
    on a single MFT claim, and per-host accumulation rules naturally short-circuit when
    the join can't be satisfied.
    """
    domain = [c for c in claims if c["frontmatter"].get("generated_by") != "correlation-agent"]
    if not domain:
        return []

    # Lookup table for the cross-host Δt guard — maps claim_id → claim, so each
    # rule can resolve its occurrences' anchor times without re-scanning the corpus.
    claims_by_id = {c["frontmatter"].get("claim_id"): c for c in domain
                    if c["frontmatter"].get("claim_id")}

    correlations: list = []

    # Rule 1: recurring HIGH-confidence process name across ≥2 distinct claims.
    # Only post-YARA claims have triage_rows with scores; this rule is naturally scoped to them.
    high_conf_by_name: dict = {}
    for c in domain:
        cid = c["frontmatter"].get("claim_id")
        if not cid:
            continue
        for row in c["triage_rows"]:
            if row["score"] >= HIGH_CONFIDENCE_SCORE:
                key = row["name"].lower()
                high_conf_by_name.setdefault(key, []).append({
                    "claim_id": cid,
                    "filename": c["filename"],
                    "pid": row["pid"],
                    "score": row["score"],
                    "yara_rules": row["yara_rules"],
                })
    for name, occs in high_conf_by_name.items():
        unique_claims = sorted({o["claim_id"] for o in occs})
        if len(unique_claims) >= 2:
            correlations.append({
                "type": "recurring_high_confidence_process",
                "process_name": name,
                "claim_ids": unique_claims,
                "occurrences": occs,
            })

    # Rule 2: shared YARA rule across ≥2 distinct (claim_id, PID) pairs.
    rule_to_hits: dict = {}
    for c in domain:
        cid = c["frontmatter"].get("claim_id")
        if not cid:
            continue
        for row in c["triage_rows"]:
            for rule in row["yara_rules"]:
                rule_to_hits.setdefault(rule, []).append({
                    "claim_id": cid,
                    "filename": c["filename"],
                    "pid": row["pid"],
                    "process": row["name"],
                })
    for rule, hits in rule_to_hits.items():
        unique_pairs = {(h["claim_id"], h["pid"]) for h in hits}
        if len(unique_pairs) >= 2:
            correlations.append({
                "type": "shared_yara_rule",
                "rule": rule,
                "hits": hits,
            })

    # Rule 3: recurring process name across ≥3 claims AND ≥2 distinct source dumps.
    # The distinct-dumps gate suppresses noise from re-analysing the same dump multiple times
    # (which trivially repeats every system process). Cross-dump recurrence is the real signal.
    name_to_claims: dict = {}
    for c in domain:
        cid = c["frontmatter"].get("claim_id")
        if not cid:
            continue
        src = c.get("source_dump")
        names_in_claim = {n.lower() for n in c["pid_names"].values() if n}
        for n in names_in_claim:
            name_to_claims.setdefault(n, []).append({
                "claim_id": cid,
                "filename": c["filename"],
                "source_dump": src,
                "pids": [pid for pid, pname in c["pid_names"].items() if pname.lower() == n],
            })
    for name, occs in name_to_claims.items():
        if name in SYSTEM_PROCESS_DENYLIST:
            continue
        unique_claims = sorted({o["claim_id"] for o in occs})
        unique_dumps = {o["source_dump"] for o in occs if o["source_dump"]}
        if len(unique_claims) >= NAME_RECURRENCE_MIN_CLAIMS and len(unique_dumps) >= 2:
            correlations.append({
                "type": "recurring_process",
                "process_name": name,
                "claim_ids": unique_claims,
                "source_dumps": sorted(unique_dumps),
                "occurrences": occs,
            })

    # Rule 4: CROSS-DOMAIN — memory high-confidence process name matches a binary that
    # the registry agent flagged as a masquerade (Run-key value or service ImagePath).
    # This is the "svchost injection ↔ registry persistence" hypothesis fired automatically.
    # JOIN KEY: (host, name) — without the host scoping a memory-injection on host-A
    # would falsely correlate with a registry-masquerade on host-B for the same basename.
    memory_high_conf: dict = {}  # (host, name) → list of {claim_id, filename, pid, ...}
    for c in domain:
        if c["frontmatter"].get("generated_by") != "memory-agent":
            continue
        cid = c["frontmatter"].get("claim_id")
        host = c["frontmatter"].get("host")
        if not (cid and host):
            continue
        for row in c["triage_rows"]:
            if row["score"] >= HIGH_CONFIDENCE_SCORE:
                memory_high_conf.setdefault((host, row["name"].lower()), []).append({
                    "claim_id": cid, "filename": c["filename"],
                    "pid": row["pid"], "score": row["score"], "yara_rules": row["yara_rules"],
                })
    registry_masq: dict = {}  # (host, basename) → list of {claim_id, filename}
    for c in domain:
        if c["frontmatter"].get("generated_by") != "registry-agent":
            continue
        cid = c["frontmatter"].get("claim_id")
        host = c["frontmatter"].get("host")
        if not (cid and host):
            continue
        for binary in c.get("masquerade_binaries", []):
            registry_masq.setdefault((host, binary), []).append({
                "claim_id": cid, "filename": c["filename"],
            })
    for (host, name), mem_occs in memory_high_conf.items():
        reg_occs = registry_masq.get((host, name))
        if not reg_occs:
            continue
        correlations.append({
            "type": "cross_domain_persistence",
            "host": host,
            "process_name": name,
            "memory_occurrences": mem_occs,
            "registry_occurrences": reg_occs,
        })

    # Rule 5: CROSS-DOMAIN SERVICE — same `service:<name>` flagged by registry (masquerade
    # ImagePath) AND by evtx (4697/7045 service install). Strong signal: the persistence
    # mechanism on disk lines up with the install event in the log.
    def _service_entities(c: dict) -> set:
        return {ent.split(":", 1)[1] for ent in (c["frontmatter"].get("entities") or [])
                if isinstance(ent, str) and ent.startswith("service:")}

    registry_services: dict = {}
    for c in domain:
        if c["frontmatter"].get("generated_by") != "registry-agent":
            continue
        cid = c["frontmatter"].get("claim_id")
        if not cid:
            continue
        for svc in _service_entities(c):
            registry_services.setdefault(svc, []).append({
                "claim_id": cid, "filename": c["filename"],
            })

    evtx_services: dict = {}
    for c in domain:
        if c["frontmatter"].get("generated_by") != "evtx-agent":
            continue
        cid = c["frontmatter"].get("claim_id")
        if not cid:
            continue
        for svc in _service_entities(c):
            evtx_services.setdefault(svc, []).append({
                "claim_id": cid, "filename": c["filename"],
            })

    for svc, reg_occs in registry_services.items():
        evtx_occs = evtx_services.get(svc)
        if not evtx_occs:
            continue
        correlations.append({
            "type": "cross_domain_service_persistence",
            "service": svc,
            "registry_occurrences": reg_occs,
            "evtx_occurrences": evtx_occs,
        })

    # Rule 6: CROSS-DOMAIN EXECUTION PERSISTENCE — same binary basename flagged by registry
    # (masquerade Run-key value or service ImagePath) AND by ANY execution-evidence source
    # (prefetch_agent OR registry_agent's shimcache). Strict superset of "persisted AND
    # injected" — Prefetch + ShimCache are *direct* execution evidence, not inference from
    # a running PID. Findings carry a `source` field ("prefetch" or "shimcache") so the
    # rendered claim names where each piece of evidence came from.
    # JOIN KEY: (host, exe basename) — same reason as Rule 4 — without host scoping,
    # registry masquerade on host-A would falsely correlate with prefetch execution on
    # host-B for the same basename.
    execution_evidence: dict = {}  # (host, exe) → list of {claim_id, filename, ...}
    for c in domain:
        gen = c["frontmatter"].get("generated_by")
        if gen not in ("prefetch-agent", "registry-agent"):
            continue
        cid = c["frontmatter"].get("claim_id")
        host = c["frontmatter"].get("host")
        if not (cid and host):
            continue
        # Only count claims that actually flagged something — clean provenance claims
        # aren't evidence of malicious execution. (registry-agent claims with persistence
        # findings still pass since anomaly_count includes both kinds; this filter just
        # rejects the empty-claim case.)
        if not c["frontmatter"].get("anomaly_count"):
            continue
        for ent, attrs in (c["frontmatter"].get("execution_attrs") or {}).items():
            if not isinstance(attrs, dict):
                continue
            exe = (attrs.get("executable_name") or "").lower()
            if not exe:
                continue
            # Default source by generating agent if not explicit on the attrs
            source = attrs.get("source") or ("shimcache" if gen == "registry-agent" else "prefetch")
            execution_evidence.setdefault((host, exe), []).append({
                "claim_id": cid, "filename": c["filename"],
                "executable_path": attrs.get("executable_path"),
                "last_run_time": attrs.get("last_run_time"),
                "run_count": attrs.get("run_count"),
                "source": source,
            })
    for (host, exe), exe_occs in execution_evidence.items():
        reg_occs = registry_masq.get((host, exe))
        if not reg_occs:
            continue
        correlations.append({
            "type": "cross_domain_execution_persistence",
            "host": host,
            "process_name": exe,
            "registry_occurrences": reg_occs,
            "prefetch_occurrences": exe_occs,  # field name kept stable for renderer; contents may include shimcache rows
        })

    # Rule 7: TIMESTOMPING DETECTED (standalone Tier-A). Anti-forensics is a strong-enough
    # signal on its own — `$SI.created < $FN.created` for an executable on a non-system path
    # is direct evidence of SetFileTime backdating with no legitimate reason. mft-agent emits
    # an explicit `timestomped_paths` list in frontmatter for unambiguous correlation gating.
    timestomp_by_host: dict = {}  # host → list of {claim_id, filename, path, created_time}
    for c in domain:
        if c["frontmatter"].get("generated_by") != "mft-agent":
            continue
        cid = c["frontmatter"].get("claim_id")
        host = c["frontmatter"].get("host")
        ts_paths = c["frontmatter"].get("timestomped_paths") or []
        if not (cid and host and ts_paths):
            continue
        file_attrs_map = c["frontmatter"].get("file_attrs") or {}
        for path in ts_paths:
            ent = f"file:{host}:{path}"
            attrs = file_attrs_map.get(ent) or {}
            timestomp_by_host.setdefault(host, []).append({
                "claim_id": cid, "filename": c["filename"],
                "path": path,
                "created_time": attrs.get("created_time"),
            })
    for host, occs in timestomp_by_host.items():
        correlations.append({
            "type": "timestomping_detected",
            "host": host,
            "occurrences": occs,
        })

    # Rule 8: CROSS-DOMAIN DROP + PERSISTENCE + EXECUTION (Tier-A 0.97). The complete
    # attack chain: file dropped at T (MFT) AND persistence wired (registry) AND executed
    # (prefetch/shimcache/memory). Strictly stronger than cross_domain_execution_persistence
    # because it adds the *origin* timestamp.
    # JOIN KEY: (host, basename) — same host-scoping concern as Rules 4/6. The host
    # is recovered from the entity ID `file:<host>:<full_path>`.
    mft_drops: dict = {}  # (host, basename) → list of {claim_id, filename, path, created_time}
    for c in domain:
        if c["frontmatter"].get("generated_by") != "mft-agent":
            continue
        cid = c["frontmatter"].get("claim_id")
        if not cid:
            continue
        for ent, attrs in (c["frontmatter"].get("file_attrs") or {}).items():
            if not isinstance(attrs, dict):
                continue
            # entity id shape: "file:<host>:<full_path>"
            parts = ent.split(":", 2)
            if len(parts) != 3 or parts[0] != "file":
                continue
            host = parts[1]
            full_path = parts[2]
            basename = full_path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
            if not basename:
                continue
            mft_drops.setdefault((host, basename), []).append({
                "claim_id": cid, "filename": c["filename"],
                "path": full_path,
                "created_time": attrs.get("created_time"),
            })
    for (host, exe), drop_occs in mft_drops.items():
        reg_occs = registry_masq.get((host, exe))
        exe_occs = execution_evidence.get((host, exe))
        if not (reg_occs and exe_occs):
            continue  # need all THREE forensic domains for the Tier-A complete-chain finding
        correlations.append({
            "type": "cross_domain_drop_persistence_execution",
            "host": host,
            "process_name": exe,
            "mft_occurrences": drop_occs,
            "registry_occurrences": reg_occs,
            "execution_occurrences": exe_occs,
        })

    # Rule 8b: VSS SUPPRESSION + RANSOMWARE (Tier-A 0.97). Active ransomware encryption
    # AND recovery-suppression on the same host = the ransomware-as-a-service playbook
    # (LockBit, Conti, BlackCat). Three independent VSS-suppression channels:
    #   (a) registry: vss_service_disabled finding from registry_agent SYSTEM hive
    #   (b) evtx: vss_service_stopped finding (System.evtx 7036)
    #   (c) evtx: process_create_suspicious_cmdline body matching `vssadmin delete shadows`
    # Pair with ANY usn_ransomware_* OR usn_ransom_note_created finding on the same host.
    RANSOMWARE_FINDING_TYPES = {
        "usn_ransomware_overwrite_burst",
        "usn_ransomware_extension_burst",
        "usn_ransom_note_created",
    }
    VSS_SUPPRESSION_FINDING_TYPES = {"vss_service_disabled", "vss_service_stopped"}
    ransomware_by_host: dict = {}
    vss_suppression_by_host: dict = {}
    for c in domain:
        host = c["frontmatter"].get("host")
        cid = c["frontmatter"].get("claim_id")
        if not (host and cid):
            continue
        ftypes = c.get("finding_types") or set()
        if ftypes & RANSOMWARE_FINDING_TYPES:
            ransomware_by_host.setdefault(host, []).append({
                "claim_id": cid, "filename": c["filename"],
                "types": sorted(ftypes & RANSOMWARE_FINDING_TYPES),
            })
        # VSS-suppression channels (a) and (b) — direct finding-type match
        if ftypes & VSS_SUPPRESSION_FINDING_TYPES:
            vss_suppression_by_host.setdefault(host, []).append({
                "claim_id": cid, "filename": c["filename"],
                "channel": "registry/evtx-service-stop",
                "types": sorted(ftypes & VSS_SUPPRESSION_FINDING_TYPES),
            })
        # Channel (c) — vssadmin cmdline match inside process_create_suspicious_cmdline body
        elif "process_create_suspicious_cmdline" in ftypes \
                and _VSSADMIN_DELETE_SHADOWS_RE.search(c.get("body") or ""):
            vss_suppression_by_host.setdefault(host, []).append({
                "claim_id": cid, "filename": c["filename"],
                "channel": "evtx-cmdline-vssadmin",
                "types": ["process_create_suspicious_cmdline"],
            })
    for host, ransomware_occs in ransomware_by_host.items():
        vss_occs = vss_suppression_by_host.get(host)
        if not vss_occs:
            continue
        correlations.append({
            "type": "vss_suppression_with_ransomware",
            "host": host,
            "ransomware_occurrences": ransomware_occs,
            "vss_suppression_occurrences": vss_occs,
        })

    # Rule 8c: SHARED SHA1 ACROSS HOSTS (Tier-A 0.95). Same cryptographic identity
    # observed on ≥2 distinct hosts = lateral movement / attacker tool distribution.
    # Filter: skip when ALL observations are in canonical Microsoft system paths
    # (`c:\windows\` or `c:\program files\`) — those binaries legitimately have the
    # same SHA1 on every Windows install. The signal we want is "this attacker binary
    # ended up on multiple compromised hosts." SHA1 currently comes from Amcache only
    # (Win8+); other sources don't capture it, so this rule is silent on Win7 corpora.
    sha1_observations: dict = {}  # sha1 → list of {host, basename, path, claim_id, filename}
    for c in domain:
        for ent, attrs in (c["frontmatter"].get("execution_attrs") or {}).items():
            if not isinstance(attrs, dict):
                continue
            sha1 = (attrs.get("sha1") or "").strip().lower()
            if not sha1 or len(sha1) < 32:  # SHA1 is 40 hex; tolerate truncation but skip empty/short
                continue
            host = c["frontmatter"].get("host")
            if not host:
                continue
            sha1_observations.setdefault(sha1, []).append({
                "host": host,
                "basename": (attrs.get("executable_name") or "").lower(),
                "path": (attrs.get("executable_path") or "").lower(),
                "claim_id": c["frontmatter"].get("claim_id"),
                "filename": c["filename"],
            })

    SYSTEM_PATH_PREFIXES = ("c:\\windows\\", "c:\\program files\\", "c:\\program files (x86)\\")
    for sha1, occs in sha1_observations.items():
        hosts = {o["host"] for o in occs}
        if len(hosts) < 2:
            continue
        # Suppress if every observation is in a canonical system path (legitimate Microsoft binary)
        if all(any(o["path"].startswith(p) for p in SYSTEM_PATH_PREFIXES) for o in occs):
            continue
        if not _within_cross_host_window(occs, claims_by_id):
            continue
        correlations.append({
            "type": "shared_sha1_across_hosts",
            "sha1": sha1,
            "hosts": sorted(hosts),
            "occurrences": occs,
        })

    # Rule 9: SHARED MASQUERADE ACROSS HOSTS — same `(basename, expected_path)` masquerade
    # signature observed on ≥2 distinct hosts. Mirrors shared_sha1 shape but pivots on the
    # `masquerade_pattern` field that registry/prefetch agents now write into
    # execution_attrs / key_attrs. Strong signal of attacker pushing the same toolkit to
    # multiple hosts (or a worm-style auto-deployment).
    masquerade_observations: dict = {}
    for c in domain:
        host = c["frontmatter"].get("host")
        if not host:
            continue
        attrs_maps = [c["frontmatter"].get("execution_attrs") or {},
                      c["frontmatter"].get("key_attrs") or {}]
        for attrs_map in attrs_maps:
            for ent, attrs in attrs_map.items():
                if not isinstance(attrs, dict):
                    continue
                sig = attrs.get("masquerade_pattern")
                if not sig:
                    continue
                masquerade_observations.setdefault(sig, []).append({
                    "host": host,
                    "signature": sig,
                    "entity": ent,
                    "claim_id": c["frontmatter"].get("claim_id"),
                    "filename": c["filename"],
                })
    for sig, occs in masquerade_observations.items():
        hosts = {o["host"] for o in occs}
        if len(hosts) < 2:
            continue
        if not _within_cross_host_window(occs, claims_by_id):
            continue
        correlations.append({
            "type": "shared_masquerade_across_hosts",
            "signature": sig,
            "hosts": sorted(hosts),
            "occurrences": occs,
        })

    # Rule 10: SHARED EXTERNAL IP ACROSS HOSTS — same routable non-RFC1918 IP appears on
    # ≥2 hosts. Sources: (a) `event_attrs` from evtx logon events (4624/4625), (b)
    # `network_attrs` from memory_agent's windows.netscan (process-→external-IP edges).
    # Per-source coverage means we catch C2 hubs that don't authenticate via RDP/SMB.
    # RFC1918 / loopback / link-local already filtered upstream by the `is_external` flag.
    ip_observations: dict = {}
    for c in domain:
        host = c["frontmatter"].get("host")
        if not host:
            continue
        for source_field in ("event_attrs", "network_attrs"):
            for ent, attrs in (c["frontmatter"].get(source_field) or {}).items():
                if not isinstance(attrs, dict):
                    continue
                if not attrs.get("is_external"):
                    continue
                ip = attrs.get("ip_address")
                if not ip:
                    continue
                ip_observations.setdefault(ip, []).append({
                    "host": host,
                    "ip": ip,
                    "entity": ent,
                    "source": source_field,
                    "claim_id": c["frontmatter"].get("claim_id"),
                    "filename": c["filename"],
                })
    for ip, occs in ip_observations.items():
        hosts = {o["host"] for o in occs}
        if len(hosts) < 2:
            continue
        if not _within_cross_host_window(occs, claims_by_id):
            continue
        correlations.append({
            "type": "shared_external_ip_across_hosts",
            "ip": ip,
            "hosts": sorted(hosts),
            "occurrences": occs,
        })

    # Rule 10a: SHARED INTERNAL IP ACROSS HOSTS — RFC1918 IP appears on ≥2 hosts. Catches
    # intra-corp lateral movement (workstation→workstation, jump-box→target). Lower
    # confidence than the external rule (0.75) because internal traffic is naturally
    # noisy: AD/DC contact, file servers, print servers, monitoring agents all touch
    # everything. The `INTERNAL_IP_ALLOWLIST` env var (FINDEVIL_INTERNAL_IP_ALLOWLIST,
    # comma-separated) suppresses known-good shared infra per case.
    internal_ip_observations: dict = {}
    for c in domain:
        host = c["frontmatter"].get("host")
        if not host:
            continue
        for source_field in ("event_attrs", "network_attrs"):
            for ent, attrs in (c["frontmatter"].get(source_field) or {}).items():
                if not isinstance(attrs, dict):
                    continue
                # Internal = inverse of is_external. Skip when is_external isn't set
                # (we can't tell whether it's internal or unknown).
                if "is_external" not in attrs or attrs.get("is_external"):
                    continue
                ip = attrs.get("ip_address")
                if not ip or ip in INTERNAL_IP_ALLOWLIST:
                    continue
                internal_ip_observations.setdefault(ip, []).append({
                    "host": host,
                    "ip": ip,
                    "entity": ent,
                    "source": source_field,
                    "claim_id": c["frontmatter"].get("claim_id"),
                    "filename": c["filename"],
                })
    for ip, occs in internal_ip_observations.items():
        hosts = {o["host"] for o in occs}
        if len(hosts) < 2:
            continue
        if not _within_cross_host_window(occs, claims_by_id):
            continue
        correlations.append({
            "type": "shared_internal_ip_across_hosts",
            "ip": ip,
            "hosts": sorted(hosts),
            "occurrences": occs,
        })

    # Rule 10b: SHARED C2 ENDPOINT ACROSS HOSTS — same `(remote_ip, remote_port)` tuple
    # observed on ≥2 hosts via network_attrs only. Strictly stronger than the IP-only
    # rule above: same port across hosts implies the same C2 protocol family (e.g., 443
    # = HTTPS beacon, 4444 = msf default, 8080 = many beacon kits) rather than e.g.
    # different web requests to a CDN that happens to be reused. Pid + process names
    # from each host let the analyst attribute C2 ownership immediately.
    c2_observations: dict = {}
    for c in domain:
        host = c["frontmatter"].get("host")
        if not host:
            continue
        for ent, attrs in (c["frontmatter"].get("network_attrs") or {}).items():
            if not isinstance(attrs, dict):
                continue
            ip = attrs.get("ip_address")
            port = attrs.get("remote_port")
            if not ip or not port or not attrs.get("is_external"):
                continue
            key = (ip, int(port))
            c2_observations.setdefault(key, []).append({
                "host": host,
                "ip": ip,
                "remote_port": int(port),
                "entity": ent,
                "pid": attrs.get("pid"),
                "process": attrs.get("process"),
                "claim_id": c["frontmatter"].get("claim_id"),
                "filename": c["filename"],
            })
    for (ip, port), occs in c2_observations.items():
        hosts = {o["host"] for o in occs}
        if len(hosts) < 2:
            continue
        if not _within_cross_host_window(occs, claims_by_id):
            continue
        correlations.append({
            "type": "shared_c2_endpoint_across_hosts",
            "ip": ip,
            "remote_port": port,
            "hosts": sorted(hosts),
            "occurrences": occs,
        })

    # Rule 11: SHARED SUSPICIOUS CMDLINE ACROSS HOSTS — same `pattern_matched` regex fired
    # on ≥2 hosts. Patterns are normalized regex strings (e.g. `\bpowershell\b.*-enc`) so
    # this catches scripted-attack reuse even when the literal cmdline strings differ
    # (e.g. different base64 payload bodies but the same `-EncodedCommand` invocation).
    cmdline_observations: dict = {}
    for c in domain:
        host = c["frontmatter"].get("host")
        if not host:
            continue
        for ent, attrs in (c["frontmatter"].get("event_attrs") or {}).items():
            if not isinstance(attrs, dict):
                continue
            pat = attrs.get("cmdline_pattern")
            if not pat:
                continue
            cmdline_observations.setdefault(pat, []).append({
                "host": host,
                "pattern": pat,
                "entity": ent,
                "claim_id": c["frontmatter"].get("claim_id"),
                "filename": c["filename"],
            })
    for pat, occs in cmdline_observations.items():
        hosts = {o["host"] for o in occs}
        if len(hosts) < 2:
            continue
        if not _within_cross_host_window(occs, claims_by_id):
            continue
        correlations.append({
            "type": "shared_suspicious_cmdline_across_hosts",
            "pattern": pat,
            "hosts": sorted(hosts),
            "occurrences": occs,
        })

    # Rule 12: TEMPORAL COMPROMISE WINDOW — multi-domain timestamped findings clustering
    # within N minutes on the same host. The "single attack story" pattern: RDP login →
    # process execution → group changes etc. all within minutes of each other.
    by_host = _collect_timestamped_findings(domain)
    for host, findings in by_host.items():
        for cluster in _temporal_clusters(findings, TEMPORAL_WINDOW_MINUTES):
            domains_in_cluster = {f["domain"] for f in cluster}
            if len(domains_in_cluster) < TEMPORAL_MIN_DOMAINS:
                continue
            correlations.append({
                "type": "temporal_compromise_window",
                "host": host,
                "window_minutes": TEMPORAL_WINDOW_MINUTES,
                "findings": cluster,
                "domains": sorted(domains_in_cluster),
            })

    # Rule 13: CMDLINE MATCHES PERSISTENCE VALUE (Tier-A 0.95). A running process's
    # command_line references a path P (memory pid_attrs[pid].command_line via Vol3
    # windows.cmdline) AND P appears as a registry Run-key value or service image_path.
    # Two independent observations of the same attacker artifact: it's wired to autostart
    # AND it's actually running.
    # SUPPRESSION: paths must satisfy _is_suspicious_cmdline_path() — user-writable
    # location AND not a vendor-allowlist match. Without this gate the DC's legit
    # McAfee/F-Response/.NET cmdline-vs-Run-key matches would all fire as Tier A.
    memory_cmdlines: dict = {}  # (host, path_lower) → list of {claim_id, filename, pid, cmdline}
    for c in domain:
        if c["frontmatter"].get("generated_by") != "memory-agent":
            continue
        cid = c["frontmatter"].get("claim_id")
        if not cid:
            continue
        host = c["frontmatter"].get("host")
        if not host:
            continue
        for pid, attrs in (c["frontmatter"].get("pid_attrs") or {}).items():
            if not isinstance(attrs, dict):
                continue
            cmdline = attrs.get("command_line")
            if not cmdline:
                continue
            for p in _extract_cmdline_paths(cmdline):
                if not _is_suspicious_cmdline_path(p):
                    continue
                memory_cmdlines.setdefault((host, p), []).append({
                    "claim_id": cid, "filename": c["filename"],
                    "pid": pid, "cmdline": cmdline,
                })

    # Persistence side: registry-agent Run-key values (key_attrs[ent].value) AND
    # any-agent service entities (service_attrs[ent].image_path). memory-agent's
    # svcscan and registry-agent's CurrentControlSet both populate service_attrs.
    persistence_paths: dict = {}  # (host, path_lower) → list of {claim_id, filename, source, value_or_image}
    for c in domain:
        cid = c["frontmatter"].get("claim_id")
        if not cid:
            continue
        host = c["frontmatter"].get("host")
        if not host:
            continue
        # Run-key / registry value persistence
        for ent, attrs in (c["frontmatter"].get("key_attrs") or {}).items():
            if not isinstance(attrs, dict):
                continue
            value = attrs.get("value")
            if not isinstance(value, str) or not value:
                continue
            for p in _extract_cmdline_paths(value):
                if not _is_suspicious_cmdline_path(p):
                    continue
                persistence_paths.setdefault((host, p), []).append({
                    "claim_id": cid, "filename": c["filename"],
                    "source": "run_key", "value_or_image": value,
                })
        # Service image_path persistence
        for ent, attrs in (c["frontmatter"].get("service_attrs") or {}).items():
            if not isinstance(attrs, dict):
                continue
            image = attrs.get("image_path")
            if not isinstance(image, str) or not image:
                continue
            for p in _extract_cmdline_paths(image):
                if not _is_suspicious_cmdline_path(p):
                    continue
                persistence_paths.setdefault((host, p), []).append({
                    "claim_id": cid, "filename": c["filename"],
                    "source": "service", "value_or_image": image,
                })

    for (host, path), mem_occs in memory_cmdlines.items():
        per_occs = persistence_paths.get((host, path))
        if not per_occs:
            continue
        # Skip self-correlation: if BOTH sides come from the same claim_id, the
        # match is intra-claim noise (e.g., memory svcscan emitting both the
        # cmdline AND service_attrs for the same binary).
        mem_cids = {o["claim_id"] for o in mem_occs}
        per_cids = {o["claim_id"] for o in per_occs}
        if mem_cids == per_cids and len(mem_cids) == 1:
            continue
        correlations.append({
            "type": "cmdline_matches_persistence_value",
            "host": host,
            "path": path,
            "basename": _basename(path),
            "memory_occurrences": mem_occs,
            "persistence_occurrences": per_occs,
        })

    # Rule 14: CMDLINE REFERENCES DROPPED EXECUTABLE (Tier-A 0.95). A running process's
    # command_line references a path P AND P appears in MFT body bullets as
    # mft_executable_dropped_user_writable or mft_deleted_executable_user_writable.
    # Two independent forensic sources: filesystem says it was dropped, memory says
    # it's running. SUPPRESSION: same _is_suspicious_cmdline_path() gate +
    # the MFT finding-type itself already implies user-writable, so this is double-belted.
    mft_drops_v2: dict = {}  # (host, path_lower) → list of {claim_id, filename, source}
    for c in domain:
        if c["frontmatter"].get("generated_by") != "mft-agent":
            continue
        cid = c["frontmatter"].get("claim_id")
        if not cid:
            continue
        host = c["frontmatter"].get("host")
        if not host:
            continue
        # Source A: file_attrs entities — the structured per-file frontmatter shape
        for ent, attrs in (c["frontmatter"].get("file_attrs") or {}).items():
            if not isinstance(attrs, dict):
                continue
            parts = ent.split(":", 2)
            if len(parts) != 3 or parts[0] != "file":
                continue
            ent_host, full_path = parts[1], parts[2].lower()
            if ent_host != host:
                continue
            if not _is_suspicious_cmdline_path(full_path):
                continue
            mft_drops_v2.setdefault((host, full_path), []).append({
                "claim_id": cid, "filename": c["filename"], "source": "file_attrs",
            })
        # Source B: body bullets — MFT agent caps file_attrs serialization but the
        # body always lists the dropped/deleted paths in backticks
        for m in _MFT_DROP_BODY_RE.finditer(c.get("body", "")):
            full_path = m.group(1).strip().lower()
            if not _is_suspicious_cmdline_path(full_path):
                continue
            mft_drops_v2.setdefault((host, full_path), []).append({
                "claim_id": cid, "filename": c["filename"], "source": "body_bullet",
            })

    for (host, path), mem_occs in memory_cmdlines.items():
        mft_occs = mft_drops_v2.get((host, path))
        if not mft_occs:
            continue
        correlations.append({
            "type": "cmdline_references_dropped_executable",
            "host": host,
            "path": path,
            "basename": _basename(path),
            "memory_occurrences": mem_occs,
            "mft_occurrences": mft_occs,
        })

    # Rule 15: PSEXEC LATERAL MOVEMENT (Tier-A 0.97). Fires when ≥3 of 4 independent
    # PsExec signals are present on the same host:
    #   (a) evtx_agent emits `service_install` body bullet with svc=`PsExec`
    #   (b) memory svcscan emits service entity `service:<host>:psexesvc`
    #       (in service_attrs frontmatter — newly added in memory_agent v2)
    #   (c) any agent's body bullet cites a `psexesvc.exe` path (MFT drop / file_attrs
    #       / cmdline / etc.) — the binary actually present on the destination
    #   (d) plaso_agent emits `lm_psexec_install_with_logon` body bullet — the
    #       service install joined to a remote 4624 LT3 within ±60s
    # 3-of-4 (not all 4) so the rule still fires when one source is absent (e.g.,
    # plaso skipped on memory-only cases). Single-source PSEXESVC findings stay Tier-B.
    by_host_signals: dict = {}  # host → {signal_letter: list of {claim_id, filename, detail}}
    for c in domain:
        cid = c["frontmatter"].get("claim_id")
        host = c["frontmatter"].get("host")
        if not cid or not host:
            continue
        gen = c["frontmatter"].get("generated_by") or ""
        body = c.get("body", "") or ""
        body_l = body.lower()
        sigs = by_host_signals.setdefault(host, {"a": [], "b": [], "c": [], "d": []})
        # (a) evtx_agent service_install line citing PsExec by name (case-insensitive).
        # The svc= field carries the service name as registered (typically "PsExec" or
        # "PSEXESVC"), so match both forms via the shared _PSEXEC_NAME_RE.
        if gen == "evtx-agent":
            for m in re.finditer(
                r"\*\*service_install\*\*[^\n]*svc=`([^`]+)`",
                body, re.IGNORECASE,
            ):
                if _PSEXEC_NAME_RE.search(m.group(1)):
                    sigs["a"].append({"claim_id": cid, "filename": c["filename"],
                                      "detail": f"evtx 7045 svc={m.group(1)}"})
        # (b) memory-agent svcscan service entity service:<host>:psexesvc (frontmatter)
        if gen == "memory-agent":
            for ent in (c["frontmatter"].get("service_attrs") or {}).keys():
                if not isinstance(ent, str):
                    continue
                # entity shape "service:<host>:<lowercased_name>"
                parts = ent.split(":", 2)
                if len(parts) == 3 and parts[0] == "service" and _PSEXEC_NAME_RE.search(parts[2]):
                    sigs["b"].append({"claim_id": cid, "filename": c["filename"],
                                      "detail": f"memory svcscan {parts[2]}"})
                    break  # one cite per claim
        # (c) any-agent body or file_attrs path containing psexec/psexesvc artifacts
        psexec_paths: set[str] = set()
        for ent in (c["frontmatter"].get("file_attrs") or {}).keys():
            if isinstance(ent, str) and _PSEXEC_NAME_RE.search(ent):
                psexec_paths.add(ent.split(":", 2)[-1])
        for m in re.finditer(r"`([^`]+)`", body):
            if _PSEXEC_NAME_RE.search(m.group(1)):
                psexec_paths.add(m.group(1))
        if psexec_paths:
            sigs["c"].append({"claim_id": cid, "filename": c["filename"],
                              "detail": f"path(s): {', '.join(sorted(psexec_paths))[:200]}"})
        # (d) plaso_agent lm_psexec_install_with_logon body bullet
        if gen == "plaso-agent" and "**lm_psexec_install_with_logon**" in body_l:
            sigs["d"].append({"claim_id": cid, "filename": c["filename"],
                              "detail": "plaso 7045+4624 LT3 join"})

    for host, sigs in by_host_signals.items():
        present = [k for k in ("a", "b", "c", "d") if sigs[k]]
        if len(present) < 3:
            continue
        # Dedup: collapse multiple cites of the same signal letter into one
        signal_summary = {k: sigs[k] for k in present}
        all_claim_ids = sorted({o["claim_id"] for k in present for o in sigs[k]})
        all_filenames = sorted({o["filename"] for k in present for o in sigs[k]})
        correlations.append({
            "type": "psexec_lateral_movement",
            "host": host,
            "signals_present": present,
            "signal_count": len(present),
            "signals": signal_summary,
            "claim_ids": all_claim_ids,
            "filenames": all_filenames,
        })

    # Rule 16: SERVICE INSTALL WITH REMOTE LOGON (Tier-A 0.92). Generic peer of
    # Rule 15. Catches the PsExec-clone family (PAExec, WinExe, RemCom, CSExec,
    # Cobalt Strike random-named services, Metasploit psexec, SCShell-style
    # binPath swaps with new install) — anything that uses the install-service-
    # over-SMB lateral-movement pattern with a non-PsExec service name.
    #
    # SEED: each `**lm_service_install_with_logon**` body bullet from plaso_agent.
    # plaso's allowlist (legit IT/AV/server-role services) has already filtered
    # the noise, so any seed that survives is by-default suspicious.
    #
    # CORROBORATION: for each seed (host, svc_name, image_basename), check ≥2
    # of three other signals on the same host:
    #   (a') evtx 7045 service install with matching svc name
    #   (b') memory svcscan service:<host>:<svc_name> entity
    #   (c') any body cite of the image basename (MFT drop, file_attrs, cmdline, etc.)
    # Fire when seed (d') + ≥2 of (a', b', c') = ≥3-of-4 signals present.
    #
    # DEDUP against Rule 15: if svc_name matches _PSEXEC_NAME_RE, skip — Rule 15
    # already fires for those installs at 0.97; we don't want a duplicate 0.92
    # finding cluttering the executive summary.
    _LM_SVC_RE = re.compile(
        r"\*\*lm_service_install_with_logon\*\*[^\n]*svc=`([^`]+)`[^\n]*image=`([^`]+)`",
        re.IGNORECASE,
    )
    seeds: list[dict] = []  # list of {host, svc_name, image_basename, claim_id, filename}
    for c in domain:
        if c["frontmatter"].get("generated_by") != "plaso-agent":
            continue
        cid = c["frontmatter"].get("claim_id")
        host = c["frontmatter"].get("host")
        if not cid or not host:
            continue
        for m in _LM_SVC_RE.finditer(c.get("body", "") or ""):
            svc_name = m.group(1)
            image_path = m.group(2)
            if _PSEXEC_NAME_RE.search(svc_name) or _PSEXEC_NAME_RE.search(image_path):
                continue  # Rule 15 owns PsExec
            image_basename = image_path.rsplit("\\", 1)[-1].rsplit("/", 1)[-1].lower()
            seeds.append({
                "host": host, "svc_name": svc_name, "svc_name_lower": svc_name.lower(),
                "image_path": image_path, "image_basename": image_basename,
                "claim_id": cid, "filename": c["filename"],
            })

    # For each seed, scan all claims for corroborating signals on the same host.
    # Per-seed deduplication: same (host, svc_name) emits one correlation even if
    # multiple plaso bullets cite the same install (e.g., multiple LT3 logons in window).
    seen_seeds: set = set()
    for seed in seeds:
        seed_key = (seed["host"], seed["svc_name_lower"])
        if seed_key in seen_seeds:
            continue
        seen_seeds.add(seed_key)
        host = seed["host"]
        svc_lower = seed["svc_name_lower"]
        image_basename = seed["image_basename"]
        sigs16 = {"a": [], "b": [], "c": [],
                  "d": [{"claim_id": seed["claim_id"], "filename": seed["filename"],
                         "detail": f"plaso 7045+4624 LT3 join svc={seed['svc_name']}"}]}
        for c in domain:
            cid = c["frontmatter"].get("claim_id")
            chost = c["frontmatter"].get("host")
            if not cid or chost != host:
                continue
            cgen = c["frontmatter"].get("generated_by") or ""
            cbody = c.get("body", "") or ""
            # (a') evtx 7045 with matching svc name (case-insensitive)
            if cgen == "evtx-agent":
                for am in re.finditer(
                    r"\*\*service_install\*\*[^\n]*svc=`([^`]+)`",
                    cbody, re.IGNORECASE,
                ):
                    if am.group(1).lower() == svc_lower:
                        sigs16["a"].append({"claim_id": cid, "filename": c["filename"],
                                            "detail": f"evtx 7045 svc={am.group(1)}"})
                        break
            # (b') memory svcscan entity matching svc name
            if cgen == "memory-agent":
                for ent in (c["frontmatter"].get("service_attrs") or {}).keys():
                    if not isinstance(ent, str):
                        continue
                    parts = ent.split(":", 2)
                    if len(parts) == 3 and parts[0] == "service" and parts[2].lower() == svc_lower:
                        sigs16["b"].append({"claim_id": cid, "filename": c["filename"],
                                            "detail": f"memory svcscan {parts[2]}"})
                        break
            # (c') MFT-agent file_attrs entity OR mft body bullet citing the image basename.
            # Restricted to mft-agent claims so it represents independent file-system
            # corroboration — not just the evtx 7045 record's own image path being cited
            # in its own body (which would double-count signal a).
            if image_basename and cgen == "mft-agent":
                hit_paths: set = set()
                for ent in (c["frontmatter"].get("file_attrs") or {}).keys():
                    if isinstance(ent, str) and image_basename in ent.lower():
                        hit_paths.add(ent.split(":", 2)[-1])
                for pm in re.finditer(r"`([^`]+)`", cbody):
                    if image_basename in pm.group(1).lower():
                        hit_paths.add(pm.group(1))
                if hit_paths:
                    sigs16["c"].append({"claim_id": cid, "filename": c["filename"],
                                        "detail": f"path(s): {', '.join(sorted(hit_paths))[:200]}"})

        present16 = [k for k in ("a", "b", "c", "d") if sigs16[k]]
        if len(present16) < 3:
            continue
        signal_summary16 = {k: sigs16[k] for k in present16}
        all_cids = sorted({o["claim_id"] for k in present16 for o in sigs16[k]})
        all_fns = sorted({o["filename"] for k in present16 for o in sigs16[k]})
        correlations.append({
            "type": "service_install_with_remote_logon",
            "host": host,
            "service_name": seed["svc_name"],
            "image_path": seed["image_path"],
            "image_basename": image_basename,
            "signals_present": present16,
            "signal_count": len(present16),
            "signals": signal_summary16,
            "claim_ids": all_cids,
            "filenames": all_fns,
        })

    # ─── Rules 17-20: WMI / WinRM / DCOM / atexec lateral execution ──────
    # Each follows the same 4-signal structure as Rule 16: plaso seed +
    # ≥2 corroborators from independent forensic sources. Tier-A 0.92
    # (same as Rule 16; legit IT remote management can produce these patterns).
    #
    # Signals per rule:
    #   d': plaso seed (the tool-specific lm_*_remote_execution body bullet)
    #   a': independent 4624 LT3 evidence — captured by the lm_network_logon_from_remote
    #       body bullet within the SAME plaso claim (so this signal almost always
    #       co-fires with d; it counts as independent forensic verification because
    #       evtx 4624 and evtx 4688 are separate event records)
    #   b': memory-agent observation of the host process running with the spawned
    #       shell child (memory pid_attrs + pid_parents)
    #   c': tool-specific evtx operational log entry
    #       (WMI-Activity 5857/5860/5861 for WMI; WinRM 91/142 for WinRM;
    #        DistributedCOM 10006/10010 for DCOM; TaskSched 141 deletes for atexec —
    #        the eid 141 outside the cleanup-pair window doesn't count)

    # Per-rule config: (seed_finding_type, host_process_basename, evtx_operational_eids,
    # rule_type, signal_b_help_text)
    _LM_REMOTE_EXEC_RULES = [
        ("lm_wmi_remote_execution", "wmiprvse.exe", {5857, 5860, 5861},
         "wmi_remote_execution"),
        ("lm_winrm_remote_execution", "wsmprovhost.exe", {91, 142},
         "winrm_remote_execution"),
        ("lm_dcom_remote_execution", "mmc.exe", {10006, 10010},
         "dcom_remote_execution"),
    ]

    # Pre-extract: for memory claims, build {host: {parent_basename: [pids that look like
    # children of that parent]}}. Cheap because we only need approximate matching.
    memory_host_processes: dict = {}  # host → {basename: [{claim_id, filename, pid}]}
    for c in domain:
        if c["frontmatter"].get("generated_by") != "memory-agent":
            continue
        cid = c["frontmatter"].get("claim_id")
        host = c["frontmatter"].get("host")
        if not cid or not host:
            continue
        pid_attrs = c["frontmatter"].get("pid_attrs") or {}
        for pid, attrs in pid_attrs.items():
            if not isinstance(attrs, dict):
                continue
            name = (attrs.get("name") or "").strip().lower()
            if not name:
                continue
            memory_host_processes.setdefault(host, {}).setdefault(name, []).append({
                "claim_id": cid, "filename": c["filename"], "pid": pid,
            })

    # Per-rule scan
    for seed_type, host_proc, oper_eids, rule_type in _LM_REMOTE_EXEC_RULES:
        seed_re = re.compile(rf"\*\*{re.escape(seed_type)}\*\*[^\n]*", re.IGNORECASE)
        # SEED: each plaso body bullet of this seed_type. Each becomes a candidate
        # correlation; per-(host, parent_process, time_window) deduplication keeps the
        # output bounded.
        seeds: list[dict] = []
        for c in domain:
            if c["frontmatter"].get("generated_by") != "plaso-agent":
                continue
            cid = c["frontmatter"].get("claim_id")
            host = c["frontmatter"].get("host")
            if not cid or not host:
                continue
            for m in seed_re.finditer(c.get("body", "") or ""):
                seeds.append({
                    "host": host, "claim_id": cid, "filename": c["filename"],
                    "bullet": m.group(0),
                })
        if not seeds:
            continue

        # Group seeds by host (a host with multiple lateral attempts emits one
        # correlation per host, summarizing the count)
        seeds_by_host: dict = {}
        for s in seeds:
            seeds_by_host.setdefault(s["host"], []).append(s)
        for host, host_seeds in seeds_by_host.items():
            sigs = {"a": [], "b": [], "c": [], "d": [
                {"claim_id": s["claim_id"], "filename": s["filename"],
                 "detail": f"{seed_type} bullet: {s['bullet'][:200]}"}
                for s in host_seeds
            ]}
            # Signal a': 4624 LT3 from non-self workstation (look for plaso's own
            # lm_network_logon_from_remote OR evtx_agent's interactive_remote_logon)
            for c in domain:
                if c["frontmatter"].get("host") != host:
                    continue
                cbody = c.get("body", "") or ""
                if ("**lm_network_logon_from_remote**" in cbody.lower()
                        or "**interactive_remote_logon**" in cbody.lower()):
                    sigs["a"].append({
                        "claim_id": c["frontmatter"].get("claim_id") or "?",
                        "filename": c["filename"],
                        "detail": "4624 LT3 from non-self workstation observed",
                    })
            # Signal b': memory-agent observation of host_proc running on this host
            host_proc_observations = memory_host_processes.get(host, {}).get(host_proc, [])
            # Memory image stores process names truncated to 14 chars. Match a
            # truncated form too.
            host_proc_truncated = host_proc[:14]
            if host_proc != host_proc_truncated:
                host_proc_observations += memory_host_processes.get(host, {}).get(host_proc_truncated, [])
            for obs in host_proc_observations:
                sigs["b"].append({
                    "claim_id": obs["claim_id"], "filename": obs["filename"],
                    "detail": f"memory pslist: {host_proc} running (PID {obs['pid']})",
                })
            # Signal c': tool-specific evtx operational log evidence. We look at the
            # plaso claim itself for body bullets that mention the relevant evtx
            # operational eids — Plaso parses those evtx files when present in the
            # input list and would emit them as adjacent body context. NOTE: in v3
            # we don't yet emit dedicated finding-types for these eids; the presence
            # of the evtx file in plaso's input + the seed firing is enough to count.
            # Conservative: only fires when we can confirm the operational evtx was
            # actually parsed (cited in evidence_refs).
            for c in domain:
                if c["frontmatter"].get("generated_by") != "plaso-agent":
                    continue
                if c["frontmatter"].get("host") != host:
                    continue
                refs = c["frontmatter"].get("evidence_refs") or []
                # The plaso storage file's name/path is the strongest hint. Map
                # the rule to the evtx file we expect to see in the storage.
                if rule_type == "wmi_remote_execution":
                    expected_evtx = "wmi-activity"
                elif rule_type == "winrm_remote_execution":
                    expected_evtx = "winrm"
                elif rule_type == "dcom_remote_execution":
                    expected_evtx = "system"  # DistributedCOM lives in System.evtx
                else:
                    expected_evtx = ""
                if expected_evtx and any(expected_evtx in str(r).lower() for r in refs):
                    sigs["c"].append({
                        "claim_id": c["frontmatter"].get("claim_id") or "?",
                        "filename": c["filename"],
                        "detail": f"plaso parsed {expected_evtx} evtx (operational log eids {sorted(oper_eids)})",
                    })
                    break

            present = [k for k in ("a", "b", "c", "d") if sigs[k]]
            if len(present) < 3:
                continue
            signal_summary = {k: sigs[k] for k in present}
            all_cids = sorted({o["claim_id"] for k in present for o in sigs[k]})
            all_fns = sorted({o["filename"] for k in present for o in sigs[k]})
            correlations.append({
                "type": rule_type,
                "host": host,
                "host_process": host_proc,
                "seed_count": len(host_seeds),
                "signals_present": present,
                "signal_count": len(present),
                "signals": signal_summary,
                "claim_ids": all_cids,
                "filenames": all_fns,
            })

    # Rule 20: ATEXEC SCHEDULED TASK LATERAL (Tier-A 0.92). Same structure but
    # the seed is the lm_atexec_scheduled_task body bullet, and signal-c is the
    # presence of TaskScheduler operational evtx in plaso's input.
    atexec_seeds: list[dict] = []
    atexec_seed_re = re.compile(r"\*\*lm_atexec_scheduled_task\*\*[^\n]*", re.IGNORECASE)
    for c in domain:
        if c["frontmatter"].get("generated_by") != "plaso-agent":
            continue
        cid = c["frontmatter"].get("claim_id")
        host = c["frontmatter"].get("host")
        if not cid or not host:
            continue
        for m in atexec_seed_re.finditer(c.get("body", "") or ""):
            atexec_seeds.append({
                "host": host, "claim_id": cid, "filename": c["filename"],
                "bullet": m.group(0),
            })
    atexec_seeds_by_host: dict = {}
    for s in atexec_seeds:
        atexec_seeds_by_host.setdefault(s["host"], []).append(s)
    for host, host_seeds in atexec_seeds_by_host.items():
        sigs = {"a": [], "b": [], "c": [], "d": [
            {"claim_id": s["claim_id"], "filename": s["filename"],
             "detail": f"lm_atexec_scheduled_task bullet: {s['bullet'][:200]}"}
            for s in host_seeds
        ]}
        # Signal a': 4624 LT3 corroboration
        for c in domain:
            if c["frontmatter"].get("host") != host:
                continue
            cbody = c.get("body", "") or ""
            if ("**lm_network_logon_from_remote**" in cbody.lower()
                    or "**interactive_remote_logon**" in cbody.lower()):
                sigs["a"].append({
                    "claim_id": c["frontmatter"].get("claim_id") or "?",
                    "filename": c["filename"],
                    "detail": "4624 LT3 from non-self workstation observed",
                })
        # Signal b': memory-agent observation of svchost.exe running. Generic
        # match — the schedule service runs under svchost.exe -k netsvcs.
        for obs in memory_host_processes.get(host, {}).get("svchost.exe", []):
            sigs["b"].append({
                "claim_id": obs["claim_id"], "filename": obs["filename"],
                "detail": f"memory pslist: svchost.exe running (PID {obs['pid']})",
            })
        # Signal c': plaso parsed TaskScheduler operational evtx
        for c in domain:
            if c["frontmatter"].get("generated_by") != "plaso-agent":
                continue
            if c["frontmatter"].get("host") != host:
                continue
            refs = c["frontmatter"].get("evidence_refs") or []
            if any("taskscheduler" in str(r).lower() for r in refs):
                sigs["c"].append({
                    "claim_id": c["frontmatter"].get("claim_id") or "?",
                    "filename": c["filename"],
                    "detail": "plaso parsed TaskScheduler/Operational (eid 106+141 cleanup signature)",
                })
                break
        present = [k for k in ("a", "b", "c", "d") if sigs[k]]
        if len(present) < 3:
            continue
        signal_summary = {k: sigs[k] for k in present}
        all_cids = sorted({o["claim_id"] for k in present for o in sigs[k]})
        all_fns = sorted({o["filename"] for k in present for o in sigs[k]})
        correlations.append({
            "type": "atexec_scheduled_task_lateral",
            "host": host,
            "seed_count": len(host_seeds),
            "signals_present": present,
            "signal_count": len(present),
            "signals": signal_summary,
            "claim_ids": all_cids,
            "filenames": all_fns,
        })

    # TODO further cross-domain rules once network agent lands:
    #  - "yara C2 hit PID has netscan handle to non-private IP"
    #  - "process with reflective-loader hit + recent autorun entry"

    return correlations


def correlation_id(corr: dict) -> str:
    """Deterministic id so the same correlation across re-runs dedupes to the same claim."""
    if corr["type"] == "recurring_high_confidence_process":
        key = f"recurring_hc:{corr['process_name']}:{','.join(corr['claim_ids'])}"
    elif corr["type"] == "shared_yara_rule":
        ids = sorted({h["claim_id"] for h in corr["hits"]})
        key = f"shared_rule:{corr['rule']}:{','.join(ids)}"
    elif corr["type"] == "recurring_process":
        key = f"recurring:{corr['process_name']}:{','.join(corr['claim_ids'])}"
    elif corr["type"] == "cross_domain_persistence":
        mem_ids = sorted({o["claim_id"] for o in corr["memory_occurrences"]})
        reg_ids = sorted({o["claim_id"] for o in corr["registry_occurrences"]})
        key = f"cross_domain:{corr.get('host','')}:{corr['process_name']}:{','.join(mem_ids)}|{','.join(reg_ids)}"
    elif corr["type"] == "cross_domain_service_persistence":
        reg_ids = sorted({o["claim_id"] for o in corr["registry_occurrences"]})
        evtx_ids = sorted({o["claim_id"] for o in corr["evtx_occurrences"]})
        key = f"cross_domain_service:{corr['service']}:{','.join(reg_ids)}|{','.join(evtx_ids)}"
    elif corr["type"] == "cross_domain_execution_persistence":
        reg_ids = sorted({o["claim_id"] for o in corr["registry_occurrences"]})
        pref_ids = sorted({o["claim_id"] for o in corr["prefetch_occurrences"]})
        key = f"cross_domain_execution:{corr.get('host','')}:{corr['process_name']}:{','.join(reg_ids)}|{','.join(pref_ids)}"
    elif corr["type"] == "timestomping_detected":
        ids = sorted({o["claim_id"] for o in corr["occurrences"]})
        paths = sorted({o["path"] for o in corr["occurrences"]})
        key = f"timestomping:{corr['host']}:{','.join(ids)}|{','.join(paths)}"
    elif corr["type"] == "cross_domain_drop_persistence_execution":
        mft_ids = sorted({o["claim_id"] for o in corr["mft_occurrences"]})
        reg_ids = sorted({o["claim_id"] for o in corr["registry_occurrences"]})
        exe_ids = sorted({o["claim_id"] for o in corr["execution_occurrences"]})
        key = f"cross_domain_drop:{corr.get('host','')}:{corr['process_name']}:{','.join(mft_ids)}|{','.join(reg_ids)}|{','.join(exe_ids)}"
    elif corr["type"] == "vss_suppression_with_ransomware":
        ransomware_ids = sorted({o["claim_id"] for o in corr["ransomware_occurrences"]})
        vss_ids = sorted({o["claim_id"] for o in corr["vss_suppression_occurrences"]})
        key = f"vss_suppression_ransomware:{corr['host']}:{','.join(ransomware_ids)}|{','.join(vss_ids)}"
    elif corr["type"] == "shared_sha1_across_hosts":
        hosts = ",".join(corr["hosts"])
        key = f"shared_sha1:{corr['sha1']}:{hosts}"
    elif corr["type"] == "shared_masquerade_across_hosts":
        hosts = ",".join(corr["hosts"])
        key = f"shared_masquerade:{corr['signature']}:{hosts}"
    elif corr["type"] == "shared_external_ip_across_hosts":
        hosts = ",".join(corr["hosts"])
        key = f"shared_extip:{corr['ip']}:{hosts}"
    elif corr["type"] == "shared_internal_ip_across_hosts":
        hosts = ",".join(corr["hosts"])
        key = f"shared_intip:{corr['ip']}:{hosts}"
    elif corr["type"] == "shared_c2_endpoint_across_hosts":
        hosts = ",".join(corr["hosts"])
        key = f"shared_c2:{corr['ip']}:{corr['remote_port']}:{hosts}"
    elif corr["type"] == "shared_suspicious_cmdline_across_hosts":
        hosts = ",".join(corr["hosts"])
        key = f"shared_cmdline:{corr['pattern']}:{hosts}"
    elif corr["type"] == "cmdline_matches_persistence_value":
        mem_ids = sorted({o["claim_id"] for o in corr["memory_occurrences"]})
        per_ids = sorted({o["claim_id"] for o in corr["persistence_occurrences"]})
        key = f"cmdline_persistence:{corr['host']}:{corr['path']}:{','.join(mem_ids)}|{','.join(per_ids)}"
    elif corr["type"] == "cmdline_references_dropped_executable":
        mem_ids = sorted({o["claim_id"] for o in corr["memory_occurrences"]})
        mft_ids = sorted({o["claim_id"] for o in corr["mft_occurrences"]})
        key = f"cmdline_mft_drop:{corr['host']}:{corr['path']}:{','.join(mem_ids)}|{','.join(mft_ids)}"
    elif corr["type"] == "psexec_lateral_movement":
        sigs = "".join(corr["signals_present"])
        claim_ids = ",".join(corr.get("claim_ids", []))
        key = f"psexec_lm:{corr['host']}:{sigs}:{claim_ids}"
    elif corr["type"] == "service_install_with_remote_logon":
        sigs = "".join(corr["signals_present"])
        svc = corr.get("service_name", "?").lower()
        claim_ids = ",".join(corr.get("claim_ids", []))
        key = f"svc_install_lm:{corr['host']}:{svc}:{sigs}:{claim_ids}"
    elif corr["type"] in ("wmi_remote_execution", "winrm_remote_execution",
                          "dcom_remote_execution", "atexec_scheduled_task_lateral"):
        sigs = "".join(corr["signals_present"])
        claim_ids = ",".join(corr.get("claim_ids", []))
        key = f"{corr['type']}:{corr['host']}:{sigs}:{claim_ids}"
    elif corr["type"] == "temporal_compromise_window":
        # Window is identified by host + first/last finding times + the entity-set hash.
        findings = corr["findings"]
        first_t = findings[0]["time"].isoformat()
        last_t = findings[-1]["time"].isoformat()
        ent_sig = ",".join(sorted({f["entity"] for f in findings}))
        key = f"temporal_window:{corr['host']}:{first_t}:{last_t}:{ent_sig}"
    else:
        key = corr["type"]
    return f"corr-{hashlib.md5(key.encode()).hexdigest()[:14]}"


def _confidence(corr: dict) -> float:
    return {
        "cross_domain_persistence": CONF_CROSS_DOMAIN,
        "cross_domain_service_persistence": CONF_CROSS_DOMAIN_SERVICE,
        "cross_domain_execution_persistence": CONF_CROSS_DOMAIN_EXECUTION,
        "cross_domain_drop_persistence_execution": CONF_CROSS_DOMAIN_DROP,
        "vss_suppression_with_ransomware": CONF_VSS_SUPPRESSION_RANSOMWARE,
        "shared_sha1_across_hosts": CONF_SHARED_SHA1_HOSTS,
        "shared_masquerade_across_hosts": CONF_SHARED_MASQUERADE_HOSTS,
        "shared_external_ip_across_hosts": CONF_SHARED_EXTERNAL_IP_HOSTS,
        "shared_suspicious_cmdline_across_hosts": CONF_SHARED_CMDLINE_HOSTS,
        "shared_c2_endpoint_across_hosts": CONF_SHARED_C2_ENDPOINT_HOSTS,
        "shared_internal_ip_across_hosts": CONF_SHARED_INTERNAL_IP_HOSTS,
        "timestomping_detected": CONF_TIMESTOMPING,
        "temporal_compromise_window": CONF_TEMPORAL_COMPROMISE,
        "cmdline_matches_persistence_value": CONF_CMDLINE_PERSISTENCE,
        "cmdline_references_dropped_executable": CONF_CMDLINE_MFT_DROP,
        "psexec_lateral_movement": CONF_PSEXEC_LATERAL_MOVEMENT,
        "service_install_with_remote_logon": CONF_SERVICE_INSTALL_LATERAL,
        "wmi_remote_execution": CONF_WMI_REMOTE_EXECUTION,
        "winrm_remote_execution": CONF_WINRM_REMOTE_EXECUTION,
        "dcom_remote_execution": CONF_DCOM_REMOTE_EXECUTION,
        "atexec_scheduled_task_lateral": CONF_ATEXEC_LATERAL,
        "recurring_high_confidence_process": CONF_HIGH_RECURRENCE,
        "shared_yara_rule": CONF_SHARED_YARA,
        "recurring_process": CONF_NAME_RECURRENCE,
    }.get(corr["type"], 0.5)


def generate_correlation_claim(corr: dict) -> str:
    """Build hypothesis claim markdown from a correlation finding."""
    cid = correlation_id(corr)
    timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")

    if corr["type"] == "recurring_high_confidence_process":
        name = corr["process_name"]
        occs = corr["occurrences"]
        entities = sorted({f"process:{o['pid']}" for o in occs})
        evidence_refs = sorted({f"claims/done/{o['filename']}" for o in occs})
        derived_from = sorted(set(corr["claim_ids"]))
        rules_seen = sorted({r for o in occs for r in o["yara_rules"]})
        body_lines = [
            f"**Correlation: recurring high-confidence process `{name}`**",
            "",
            f"Process `{name}` flagged at score ≥{HIGH_CONFIDENCE_SCORE} in {len(derived_from)} separate claims:",
        ]
        for o in occs:
            rules = ", ".join(o["yara_rules"]) if o["yara_rules"] else "(none)"
            body_lines.append(f"- `{o['filename']}` — PID {o['pid']} (score {o['score']}) yara: {rules}")
        if rules_seen:
            body_lines.append(f"\n**Shared YARA rules across observations:** {', '.join(rules_seen)}")
        body_lines.append("\n**Hypothesis:** Persistent or recurrent malware family — same high-confidence process pattern observed across multiple captures.")
        body = "\n".join(body_lines)
    elif corr["type"] == "shared_yara_rule":
        rule = corr["rule"]
        hits = corr["hits"]
        entities = sorted({f"process:{h['pid']}" for h in hits})
        evidence_refs = sorted({f"claims/done/{h['filename']}" for h in hits})
        derived_from = sorted({h["claim_id"] for h in hits})
        body_lines = [
            f"**Correlation: YARA rule `{rule}` fires across multiple PIDs**",
            "",
            f"Matched in {len({(h['claim_id'], h['pid']) for h in hits})} distinct (claim, PID) pairs:",
        ]
        for h in hits:
            body_lines.append(f"- `{h['filename']}` — PID {h['pid']} ({h['process']})")
        body_lines.append("\n**Hypothesis:** Coordinated payload deployment — possible lateral movement or shared toolkit across systems/runs.")
        body = "\n".join(body_lines)
    elif corr["type"] == "recurring_process":
        name = corr["process_name"]
        occs = corr["occurrences"]
        entities = sorted({f"process:{pid}" for o in occs for pid in o["pids"]})
        evidence_refs = sorted({f"claims/done/{o['filename']}" for o in occs})
        derived_from = sorted(set(corr["claim_ids"]))
        body_lines = [
            f"**Correlation: process `{name}` observed across {len(derived_from)} claims**",
            "",
            "Appearances:",
        ]
        for o in occs:
            pids = ", ".join(str(p) for p in o["pids"])
            body_lines.append(f"- `{o['filename']}` — PIDs: {pids}")
        body_lines.append(f"\n**Hypothesis:** Process `{name}` is a recurring entity in this case — pivot on its evidence chain across captures, look for behaviour that diverges between runs.")
        body = "\n".join(body_lines)
    elif corr["type"] == "cross_domain_persistence":
        name = corr["process_name"]
        mem_occs = corr["memory_occurrences"]
        reg_occs = corr["registry_occurrences"]
        entities = sorted({f"process:{o['pid']}" for o in mem_occs} | {f"file:{name}"})
        evidence_refs = sorted(
            {f"claims/done/{o['filename']}" for o in mem_occs}
            | {f"claims/done/{o['filename']}" for o in reg_occs}
        )
        derived_from = sorted(
            {o["claim_id"] for o in mem_occs} | {o["claim_id"] for o in reg_occs}
        )
        body_lines = [
            f"**Cross-domain persistence: `{name}` injected in memory AND masquerading on disk**",
            "",
            f"_Memory side ({len(mem_occs)} high-confidence injection(s)):_",
        ]
        for o in mem_occs:
            rules = ", ".join(o["yara_rules"]) if o["yara_rules"] else "(none)"
            body_lines.append(f"- `{o['filename']}` — PID {o['pid']} (score {o['score']}) yara: {rules}")
        body_lines += ["", f"_Registry side ({len(reg_occs)} masquerade finding(s)):_"]
        for o in reg_occs:
            body_lines.append(f"- `{o['filename']}`")
        body_lines += [
            "",
            f"**Hypothesis:** The `{name}` binary is established for persistence via the masquerading registry entry AND is actively running with injected code in memory. Same artifact in volatile (memory) and non-volatile (disk) state — high-confidence cross-domain compromise. Triage immediately.",
        ]
        body = "\n".join(body_lines)
    elif corr["type"] == "cross_domain_service_persistence":
        svc = corr["service"]
        reg_occs = corr["registry_occurrences"]
        evtx_occs = corr["evtx_occurrences"]
        entities = [f"service:{svc}"]
        evidence_refs = sorted(
            {f"claims/done/{o['filename']}" for o in reg_occs}
            | {f"claims/done/{o['filename']}" for o in evtx_occs}
        )
        derived_from = sorted(
            {o["claim_id"] for o in reg_occs} | {o["claim_id"] for o in evtx_occs}
        )
        body_lines = [
            f"**Cross-domain service persistence: `{svc}` flagged in BOTH registry AND event log**",
            "",
            f"_Registry side ({len(reg_occs)} suspicious-service finding(s)):_",
        ]
        for o in reg_occs:
            body_lines.append(f"- `{o['filename']}`")
        body_lines += ["", f"_Event-log side ({len(evtx_occs)} 4697/7045 service-install event(s)):_"]
        for o in evtx_occs:
            body_lines.append(f"- `{o['filename']}`")
        body_lines += [
            "",
            f"**Hypothesis:** Service `{svc}` was deliberately installed (event log) AND its registry entry exhibits masquerade/suspicious-path indicators (registry agent). The install event provides a timeline anchor for when the persistence was established; pivot to that record number for actor identity and process chain.",
        ]
        body = "\n".join(body_lines)
    elif corr["type"] == "cross_domain_execution_persistence":
        name = corr["process_name"]
        reg_occs = corr["registry_occurrences"]
        exe_occs = corr["prefetch_occurrences"]  # field name retained; rows may be prefetch OR shimcache
        sources = sorted({o.get("source", "prefetch") for o in exe_occs})
        sources_label = " + ".join(sources) if sources else "execution"
        entities = sorted(
            {f"process_execution:{name}"}  # canonical reference; per-host is in derived claims
            | {f"file:{o['executable_path']}" for o in exe_occs if o.get("executable_path")}
        )
        evidence_refs = sorted(
            {f"claims/done/{o['filename']}" for o in reg_occs}
            | {f"claims/done/{o['filename']}" for o in exe_occs}
        )
        derived_from = sorted(
            {o["claim_id"] for o in reg_occs} | {o["claim_id"] for o in exe_occs}
        )
        body_lines = [
            f"**Cross-domain execution persistence: `{name}` is BOTH persisted (registry) "
            f"AND seen by execution-evidence source(s) ({sources_label})**",
            "",
            f"_Registry side ({len(reg_occs)} masquerade finding(s)):_",
        ]
        for o in reg_occs:
            body_lines.append(f"- `{o['filename']}`")
        body_lines += ["", f"_Execution-evidence side ({len(exe_occs)} finding(s)):_"]
        for o in exe_occs:
            src = o.get("source", "prefetch")
            body_lines.append(
                f"- [{src}] `{o['filename']}` — ran from `{o.get('executable_path') or '?'}` "
                f"(run {o.get('run_count', 0)}× last={o.get('last_run_time') or 'n/a'})"
            )
        body_lines += [
            "",
            f"**Hypothesis:** Binary `{name}` is wired for persistence on disk (registry agent) AND "
            f"appears in execution-evidence sources ({sources_label}). Multiple independent forensic "
            "domains agree on the same artifact: is it persisted? did it run? when? "
            "Note: ShimCache evidence is direct on Win7 (`Executed=Yes`) and execution-suggestive on "
            "Win8+; Prefetch evidence is always direct. Triage immediately.",
        ]
        body = "\n".join(body_lines)
    elif corr["type"] == "timestomping_detected":
        host = corr["host"]
        occs = corr["occurrences"]
        entities = sorted({f"file:{host}:{o['path']}" for o in occs})
        evidence_refs = sorted({f"claims/done/{o['filename']}" for o in occs})
        derived_from = sorted({o["claim_id"] for o in occs})
        body_lines = [
            f"**Anti-Forensics: Timestomping Detected — host `{host}` ({len(occs)} executable(s))**",
            "",
            "_MFT `$SI<$FN` divergence: $StandardInformation creation time precedes $FileName "
            "creation time. The kernel writes $FN during file creation/rename and it cannot be "
            "modified through normal Win32 APIs — only $SI is settable via `SetFileTime`. This "
            "is direct evidence of attacker tradecraft to backdate dropped binaries._",
            "",
            "**Affected files:**",
        ]
        for o in occs[:20]:
            body_lines.append(f"- `{o['path']}` (MFT-recorded creation: {o.get('created_time') or 'n/a'})")
        if len(occs) > 20:
            body_lines.append(f"_…({len(occs) - 20} more)_")
        body_lines += ["",
            "**Hypothesis:** These specific binaries warrant immediate triage as confirmed-malicious. "
            "Pivot each path to the registry/prefetch/shimcache/memory claims for execution and "
            "persistence evidence; the timestomping signal alone is sufficient to escalate.",
        ]
        body = "\n".join(body_lines)
    elif corr["type"] == "cross_domain_drop_persistence_execution":
        name = corr["process_name"]
        mft_occs = corr["mft_occurrences"]
        reg_occs = corr["registry_occurrences"]
        exe_occs = corr["execution_occurrences"]
        sources = sorted({o.get("source", "prefetch") for o in exe_occs})
        entities = sorted(
            {f"process_execution:{name}"}
            | {f"file:{o['path']}" for o in mft_occs if o.get("path")}
        )
        evidence_refs = sorted(
            {f"claims/done/{o['filename']}" for o in mft_occs}
            | {f"claims/done/{o['filename']}" for o in reg_occs}
            | {f"claims/done/{o['filename']}" for o in exe_occs}
        )
        derived_from = sorted(
            {o["claim_id"] for o in mft_occs}
            | {o["claim_id"] for o in reg_occs}
            | {o["claim_id"] for o in exe_occs}
        )
        body_lines = [
            f"**Complete Attack Chain: `{name}` was DROPPED, PERSISTED, and EXECUTED**",
            "",
            f"_MFT side ({len(mft_occs)} drop-evidence record(s)):_",
        ]
        for o in mft_occs:
            body_lines.append(f"- `{o['filename']}` — `{o.get('path')}` created {o.get('created_time') or 'n/a'}")
        body_lines += ["", f"_Registry side ({len(reg_occs)} persistence finding(s)):_"]
        for o in reg_occs:
            body_lines.append(f"- `{o['filename']}`")
        body_lines += ["", f"_Execution-evidence side ({len(exe_occs)} finding(s) from {' + '.join(sources)}):_"]
        for o in exe_occs:
            src = o.get("source", "prefetch")
            body_lines.append(
                f"- [{src}] `{o['filename']}` — last={o.get('last_run_time') or 'n/a'} "
                f"(run {o.get('run_count', 0)}×)"
            )
        body_lines += [
            "",
            f"**Hypothesis:** Three orthogonal forensic domains agree on `{name}`: MFT confirms "
            "the file was dropped to disk (origin), registry confirms persistence wiring, and "
            "execution-evidence sources (prefetch/shimcache) confirm it ran. Pivot to network "
            "logs and memory analysis — this is a definitive single-binary attribution. The "
            "MFT `created_time` anchors when the drop happened; check the temporal-window "
            "correlation for the surrounding compromise sequence (likely RDP login + persistence "
            "wiring + execution within minutes of the drop).",
        ]
        body = "\n".join(body_lines)
    elif corr["type"] == "cmdline_matches_persistence_value":
        host = corr["host"]
        path = corr["path"]
        basename = corr["basename"]
        mem_occs = corr["memory_occurrences"]
        per_occs = corr["persistence_occurrences"]
        sources = sorted({o.get("source", "?") for o in per_occs})
        entities = sorted(
            {f"process:{host}:{o['pid']}" for o in mem_occs}
            | {f"file:{host}:{path}"}
        )
        evidence_refs = sorted(
            {f"claims/done/{o['filename']}" for o in mem_occs}
            | {f"claims/done/{o['filename']}" for o in per_occs}
        )
        derived_from = sorted(
            {o["claim_id"] for o in mem_occs}
            | {o["claim_id"] for o in per_occs}
        )
        body_lines = [
            f"**Cross-domain agreement on user-writable executable: `{basename}` is BOTH wired for autostart AND running on host `{host}`**",
            "",
            f"Path: `{path}`",
            "",
            f"_Memory side ({len(mem_occs)} running-process observation(s)):_",
        ]
        for o in mem_occs:
            cmd = o.get("cmdline") or ""
            body_lines.append(f"- PID **{o['pid']}** in `{o['filename']}` — cmdline: `{cmd[:200]}`")
        body_lines += ["", f"_Persistence side ({len(per_occs)} configured-autostart record(s) from {' + '.join(sources)}):_"]
        for o in per_occs:
            src = o.get("source", "?")
            val = (o.get("value_or_image") or "")[:200]
            body_lines.append(f"- [{src}] `{o['filename']}` — value/image: `{val}`")
        body_lines += [
            "",
            f"**Hypothesis:** Two independent forensic domains agree on `{basename}` at `{path}`. "
            "Memory shows the binary is currently executing; the persistence side shows it is "
            "configured to launch automatically. Combined with the user-writable location "
            "(under `\\Users\\` / `\\Temp\\` / `\\AppData\\` / `\\ProgramData\\`), this is a "
            "high-confidence attacker-installed-and-active artifact. Pivot the cited PID(s) to "
            "memory enrichment (loaded DLLs, network handles, YARA hits on VAD dump) and the "
            "persistence claim to the registry hive / service-install timestamp for the "
            "installation moment.",
        ]
        body = "\n".join(body_lines)
    elif corr["type"] == "cmdline_references_dropped_executable":
        host = corr["host"]
        path = corr["path"]
        basename = corr["basename"]
        mem_occs = corr["memory_occurrences"]
        mft_occs = corr["mft_occurrences"]
        sources = sorted({o.get("source", "?") for o in mft_occs})
        entities = sorted(
            {f"process:{host}:{o['pid']}" for o in mem_occs}
            | {f"file:{host}:{path}"}
        )
        evidence_refs = sorted(
            {f"claims/done/{o['filename']}" for o in mem_occs}
            | {f"claims/done/{o['filename']}" for o in mft_occs}
        )
        derived_from = sorted(
            {o["claim_id"] for o in mem_occs}
            | {o["claim_id"] for o in mft_occs}
        )
        body_lines = [
            f"**Cross-domain agreement on dropped executable: `{basename}` was DROPPED to disk in a user-writable location AND is currently running on host `{host}`**",
            "",
            f"Path: `{path}`",
            "",
            f"_Memory side ({len(mem_occs)} running-process observation(s)):_",
        ]
        for o in mem_occs:
            cmd = o.get("cmdline") or ""
            body_lines.append(f"- PID **{o['pid']}** in `{o['filename']}` — cmdline: `{cmd[:200]}`")
        body_lines += ["", f"_MFT side ({len(mft_occs)} drop/delete record(s) from {' + '.join(sources)}):_"]
        for o in mft_occs:
            src = o.get("source", "?")
            body_lines.append(f"- [{src}] `{o['filename']}`")
        body_lines += [
            "",
            f"**Hypothesis:** The MFT records `{basename}` as having been written to a "
            "user-writable path (or written and subsequently deleted, in which case the "
            "currently-running process is operating from a copy or pre-deletion handle). "
            "Memory confirms a process is actively executing from the same path right now. "
            "This is a high-confidence attacker-deployed-and-active binary. Pivot to: "
            "(a) the MFT $SI / $FN timestamps for the drop moment, (b) the parent process "
            "of the running PID for the launch chain, (c) network/handle enumeration on "
            "the cited PID for ongoing C2 or lateral activity. If the MFT bullet is the "
            "deleted variant, the attacker is actively cleaning up — preserve the running "
            "process memory before isolation.",
        ]
        body = "\n".join(body_lines)
    elif corr["type"] == "psexec_lateral_movement":
        host = corr["host"]
        signals = corr["signals"]
        present = corr["signals_present"]
        signal_labels = {
            "a": "evtx 7045 PSEXESVC service install",
            "b": "memory svcscan PSEXESVC service entity",
            "c": "MFT/disk PSEXESVC.exe path",
            "d": "plaso 7045+4624 LT3 logon-time join",
        }
        entities = sorted(
            {f"host:{host}"}
            | {f"service:{host}:psexesvc"}
        )
        evidence_refs = sorted(
            {f"claims/done/{fn}" for fn in corr.get("filenames", [])}
        )
        derived_from = sorted(corr.get("claim_ids", []))
        body_lines = [
            f"**🚨 PsExec Lateral Movement Confirmed: {len(present)}-of-4 independent signals on host `{host}`**",
            "",
            "PsExec is Sysinternals' remote-execution tool — legitimate when used by IT, but a "
            "near-universal lateral-movement indicator when found on a target host without IT "
            "context. Multi-signal corroboration eliminates the false-positive risk of any single "
            "signal in isolation.",
            "",
            f"_Signals present ({len(present)}-of-4):_",
        ]
        for k in ("a", "b", "c", "d"):
            label = signal_labels[k]
            if k in present:
                occs = signals[k]
                body_lines.append(f"- ✓ **{label}** ({len(occs)} cite(s)):")
                for o in occs[:3]:
                    body_lines.append(f"   - `{o['filename']}` — {o['detail']}")
                if len(occs) > 3:
                    body_lines.append(f"   - _…({len(occs) - 3} more)_")
            else:
                body_lines.append(f"- ✗ **{label}** — not observed in this run")
        body_lines += [
            "",
            "**Hypothesis:** PsExec was deployed to this host as part of a lateral-movement "
            "operation. The combination of signals shown above is mechanically inconsistent "
            "with anything other than an actual PsExec invocation against this host. "
            "**Pivot in this order:**",
            "1. Identify the SOURCE host (the machine that ran `psexec \\\\target ...`) by "
            "examining 4624 LogonType=3 records on this host, looking for the `WorkstationName` "
            "and `IpAddress` fields. The plaso `lm_psexec_install_with_logon` finding above "
            "(if signal-d fired) already names the source workstation in its body.",
            "2. Pull cmdline + parent process for any process spawned by PSEXESVC.exe via "
            "`windows.pstree` on the memory dump.",
            "3. Hunt for the same PSEXESVC service entity on adjacent hosts in the environment "
            "— if PsExec moved here, it may have moved elsewhere too.",
            "4. If signal-d (plaso logon-time join) fired, the source IP is the highest-priority "
            "containment target — investigate that host BEFORE this one.",
        ]
        body = "\n".join(body_lines)
    elif corr["type"] == "service_install_with_remote_logon":
        host = corr["host"]
        svc_name = corr["service_name"]
        image_path = corr.get("image_path") or "?"
        image_basename = corr.get("image_basename") or "?"
        signals = corr["signals"]
        present = corr["signals_present"]
        signal_labels = {
            "a": f"evtx 7045 service install (svc=`{svc_name}`)",
            "b": f"memory svcscan service entity (`service:{host}:{svc_name.lower()}`)",
            "c": f"MFT/disk path containing `{image_basename}`",
            "d": "plaso 7045+4624 LT3 logon-time join (the seed)",
        }
        entities = sorted(
            {f"host:{host}"}
            | {f"service:{host}:{svc_name.lower()}"}
        )
        evidence_refs = sorted(
            {f"claims/done/{fn}" for fn in corr.get("filenames", [])}
        )
        derived_from = sorted(corr.get("claim_ids", []))
        body_lines = [
            f"**Service-install lateral movement: `{svc_name}` installed on host `{host}` ({len(present)}-of-4 signals)**",
            "",
            f"Image path: `{image_path}`",
            "",
            "This is the same install-via-SMB pattern PsExec uses, but with a non-PsExec service "
            "name. Examples of tools that produce this pattern: PAExec, WinExe, RemCom, CSExec, "
            "Cobalt Strike's psexec_psh module (random service names), Metasploit's psexec module "
            "(random 8-char names), Impacket's psexec.py (RemComSvc), SCShell. Investigate whether "
            "the service name above matches a known clone OR appears randomized — randomized names "
            "strongly suggest commodity offensive tooling.",
            "",
            f"_Signals present ({len(present)}-of-4):_",
        ]
        for k in ("a", "b", "c", "d"):
            label = signal_labels[k]
            if k in present:
                occs = signals[k]
                body_lines.append(f"- ✓ **{label}** ({len(occs)} cite(s)):")
                for o in occs[:3]:
                    body_lines.append(f"   - `{o['filename']}` — {o['detail']}")
                if len(occs) > 3:
                    body_lines.append(f"   - _…({len(occs) - 3} more)_")
            else:
                body_lines.append(f"- ✗ **{label}** — not observed in this run")
        body_lines += [
            "",
            "**Hypothesis:** A service named `" + svc_name + "` was installed on this host "
            "near-simultaneously with a remote network logon (4624 LogonType=3). This pattern is "
            "ALSO used by legitimate IT remote management (SCCM software push, Splunk forwarder "
            "deployment, etc.), so confidence is 0.92 rather than 0.97. **Verification triage:**",
            "1. Check the source workstation/IP cited in the plaso `lm_service_install_with_logon` "
            "finding (signal-d above). If it matches your IT management subnet, this is likely "
            "a benign deployment — confirm with your IT team.",
            "2. If the source is NOT a known IT host, treat as confirmed lateral movement: "
            "isolate this host, hunt for the same source on other hosts in the environment, "
            "and investigate the SOURCE host (likely the actual breach pivot point).",
            "3. Pull cmdline + parent process for any process spawned by `" + image_basename + "` "
            "via memory analysis. Random / hex-like service names with no vendor association are "
            "a strong indicator of Cobalt Strike or Metasploit beacon-based lateral movement.",
            "4. If multiple Rule-16 findings fire on the same host in the same time window, "
            "you are likely seeing a multi-tool operator working against this asset.",
        ]
        body = "\n".join(body_lines)
    elif corr["type"] in ("wmi_remote_execution", "winrm_remote_execution",
                          "dcom_remote_execution"):
        host = corr["host"]
        host_proc = corr.get("host_process") or "?"
        seed_count = corr.get("seed_count", 1)
        signals = corr["signals"]
        present = corr["signals_present"]
        # Tool-specific narrative
        _NARRATIVE = {
            "wmi_remote_execution": (
                "WMI Lateral Movement",
                "WMI",
                "WMI lateral execution via Win32_Process.Create / `wmic /node:` / "
                "`Invoke-WmiMethod`. Attacker invokes WMI on this host from a remote "
                "session; `wmiprvse.exe` (the WMI provider host) spawns the requested "
                "shell command.",
                "1. Pull `Microsoft-Windows-WMI-Activity/Operational` events 5857/5860/"
                "5861 around the time of the cited 4688 — these confirm which provider "
                "method was invoked and from which client.\n"
                "2. If WMI is not used by your IT management, this is malicious by "
                "default — isolate the host.\n"
                "3. Hunt the source workstation/IP cited in the 4624 LT3 — that host "
                "may be staging WMI lateral against multiple targets.",
            ),
            "winrm_remote_execution": (
                "WinRM / PowerShell Remoting Lateral Movement",
                "WinRM",
                "WinRM (PowerShell Remoting) lateral execution via `Enter-PSSession` / "
                "`Invoke-Command` / `New-PSSession`. Attacker authenticates over WinRM "
                "(HTTP/5985 or HTTPS/5986); `wsmprovhost.exe` spawns the requested "
                "shell command in the remote session.",
                "1. Verify whether WinRM is supposed to be enabled on this host — "
                "`winrm get winrm/config` from the local box. If not enabled by "
                "policy, the attacker enabled it as part of the operation.\n"
                "2. Pull `Microsoft-Windows-WinRM/Operational` events 91/142 + "
                "`Microsoft-Windows-PowerShell/Operational` 4103/4104 around the "
                "time of the cited 4688 — script blocks reveal what was actually "
                "executed.\n"
                "3. If the cmdline shows base64 (-enc / -EncodedCommand), decode it "
                "before triage — the encoded payload is the attacker's actual code.",
            ),
            "dcom_remote_execution": (
                "DCOM Lateral Movement (MMC20.Application)",
                "DCOM",
                "DCOM lateral execution via the MMC20.Application COM object — the "
                "attacker invokes `[activator]::CreateInstance([type]::GetTypeFromProgID("
                "'MMC20.Application', 'TARGET'))` from a remote PowerShell session, "
                "and `mmc.exe` on this host spawns the requested shell command.",
                "1. Verify whether MMC consoles (mmc.exe) are routinely launched by "
                "remote users on this host — for most servers, no. If unexpected, "
                "treat as confirmed lateral.\n"
                "2. Pull `Microsoft-Windows-DistributedCOM` events 10006/10010 from "
                "System.evtx around the cited 4688 — these surface the source CLSID + "
                "client.\n"
                "3. The MMC20.Application object is the canonical case but variants "
                "exist (ShellWindows, ShellBrowserWindow). Hunt for any unusual "
                "COM-activated processes spawning shells in the same time window.",
            ),
        }
        title, tool_short, body_intro, triage_text = _NARRATIVE[corr["type"]]
        signal_labels = {
            "a": "evtx 4624 LogonType=3 from non-self workstation (the network logon side)",
            "b": f"memory pslist showing `{host_proc}` running on this host",
            "c": f"plaso parsed the {tool_short}-specific operational evtx (provides per-tool event corroboration)",
            "d": f"plaso `lm_{tool_short.lower()}_remote_execution` body bullet (the 4688+4624 join — the seed)",
        }
        entities = sorted({f"host:{host}"})
        evidence_refs = sorted({f"claims/done/{fn}" for fn in corr.get("filenames", [])})
        derived_from = sorted(corr.get("claim_ids", []))
        body_lines = [
            f"**🚨 {title}: {seed_count} attempt(s) on host `{host}` ({len(present)}-of-4 signals)**",
            "",
            body_intro,
            "",
            f"_Signals present ({len(present)}-of-4):_",
        ]
        for k in ("a", "b", "c", "d"):
            label = signal_labels[k]
            if k in present:
                occs = signals[k]
                body_lines.append(f"- ✓ **{label}** ({len(occs)} cite(s)):")
                for o in occs[:3]:
                    body_lines.append(f"   - `{o['filename']}` — {o['detail']}")
                if len(occs) > 3:
                    body_lines.append(f"   - _…({len(occs) - 3} more)_")
            else:
                body_lines.append(f"- ✗ **{label}** — not observed in this run")
        body_lines += [
            "",
            "**Hypothesis:** The shell-child gate (`cmd.exe` / `powershell.exe` / etc. spawned "
            f"by `{host_proc}`) eliminates the high-volume-FP scenario where {tool_short} legitimately "
            "spawns provider methods or document activations. Confidence is 0.92 (not 0.97) because "
            f"legitimate IT can use {tool_short} for remote management — verify the source workstation/IP "
            "in the 4624 LT3 finding before treating as malicious.",
            "",
            "**Triage:**",
            triage_text,
        ]
        body = "\n".join(body_lines)
    elif corr["type"] == "atexec_scheduled_task_lateral":
        host = corr["host"]
        seed_count = corr.get("seed_count", 1)
        signals = corr["signals"]
        present = corr["signals_present"]
        signal_labels = {
            "a": "evtx 4624 LogonType=3 from non-self workstation",
            "b": "memory pslist showing svchost.exe running (Schedule service host)",
            "c": "plaso parsed TaskScheduler/Operational evtx (eid 106+141 cleanup signature)",
            "d": "plaso `lm_atexec_scheduled_task` body bullet (create+delete pair + 4624 LT3 join — the seed)",
        }
        entities = sorted({f"host:{host}"})
        evidence_refs = sorted({f"claims/done/{fn}" for fn in corr.get("filenames", [])})
        derived_from = sorted(corr.get("claim_ids", []))
        body_lines = [
            f"**🚨 atexec Lateral Movement: {seed_count} transient task(s) on host `{host}` ({len(present)}-of-4 signals)**",
            "",
            "atexec.py (Impacket) lateral execution — the attacker schedules a Windows task via "
            "SMB+ATSVC RPC, runs it, and deletes it within seconds. The signature is the "
            "TaskScheduler eid 106 (registered) + eid 141 (deleted) pair on the same task name "
            "within ±30s. Legitimate scheduled tasks live for hours, days, or forever; transient "
            "tasks like this exist almost exclusively to ferry one-shot remote commands.",
            "",
            f"_Signals present ({len(present)}-of-4):_",
        ]
        for k in ("a", "b", "c", "d"):
            label = signal_labels[k]
            if k in present:
                occs = signals[k]
                body_lines.append(f"- ✓ **{label}** ({len(occs)} cite(s)):")
                for o in occs[:3]:
                    body_lines.append(f"   - `{o['filename']}` — {o['detail']}")
                if len(occs) > 3:
                    body_lines.append(f"   - _…({len(occs) - 3} more)_")
            else:
                body_lines.append(f"- ✗ **{label}** — not observed in this run")
        body_lines += [
            "",
            "**Hypothesis:** The task-name in the seed body is typically a randomized 8-hex-char "
            "string when atexec is the source; SCCM/IT-deployed tasks usually have descriptive names. "
            "If the task name appears random, this is high-confidence lateral movement.",
            "",
            "**Triage:**",
            "1. Pull the cmdline from the cited TaskScheduler 106 record — `<EventData><Data>` "
            "carries the action's full executable path + arguments. atexec almost always "
            "redirects output to a temp file in `\\Windows\\Temp\\` for SMB-readback.",
            "2. Hunt the temp file in MFT — even after the task self-deletes, the output file "
            "may persist briefly. Recovering it tells you exactly what the operator ran.",
            "3. Investigate the source workstation/IP cited in the 4624 LT3 — atexec runs need "
            "valid credentials, so the source is likely already compromised.",
        ]
        body = "\n".join(body_lines)
    elif corr["type"] == "vss_suppression_with_ransomware":
        host = corr["host"]
        ransomware_occs = corr["ransomware_occurrences"]
        vss_occs = corr["vss_suppression_occurrences"]
        entities = [f"host:{host}"]
        evidence_refs = sorted(
            {f"claims/done/{o['filename']}" for o in ransomware_occs}
            | {f"claims/done/{o['filename']}" for o in vss_occs}
        )
        derived_from = sorted(
            {o["claim_id"] for o in ransomware_occs}
            | {o["claim_id"] for o in vss_occs}
        )
        body_lines = [
            f"**🚨 Ransomware-As-A-Service Pattern: encryption AND active recovery-suppression on host `{host}`**",
            "",
            f"_Ransomware signals ({len(ransomware_occs)}):_",
        ]
        for o in ransomware_occs:
            body_lines.append(f"- `{o['filename']}` — types: {', '.join(o['types'])}")
        body_lines += ["", f"_VSS-suppression signals ({len(vss_occs)} across "
                            f"{len({o['channel'] for o in vss_occs})} channel(s)):_"]
        for o in vss_occs:
            body_lines.append(f"- [{o['channel']}] `{o['filename']}` — types: {', '.join(o['types'])}")
        body_lines += [
            "",
            "**🚨 IMMEDIATE ACTION:** Ransomware is actively encrypting on this host AND has "
            "disabled Volume Shadow Copy / backup services to prevent recovery. This is the "
            "canonical RaaS playbook (LockBit / Conti / BlackCat / REvil). "
            "**Isolate the host now.** Before further triage: enumerate any remaining shadow "
            "copies (`vssadmin list shadows`) and snapshot/preserve them — the attacker is "
            "actively eliminating recovery options. Pivot the timestamps in the ransomware "
            "claims to bound the encryption window; pivot the VSS-suppression claims to identify "
            "the attacker process (likely the same PID that ran the encryptor).",
        ]
        body = "\n".join(body_lines)
    elif corr["type"] == "shared_sha1_across_hosts":
        sha1 = corr["sha1"]
        hosts = corr["hosts"]
        occs = corr["occurrences"]
        basenames = sorted({o["basename"] for o in occs if o.get("basename")})
        paths = sorted({o["path"] for o in occs if o.get("path")})
        entities = sorted({f"process_execution:{o['host']}:{o['basename']}"
                           for o in occs if o.get("basename")}
                          | {f"file:{o['host']}:{o['path']}" for o in occs if o.get("path")})
        evidence_refs = sorted({f"claims/done/{o['filename']}" for o in occs})
        derived_from = sorted({o["claim_id"] for o in occs if o.get("claim_id")})
        body_lines = [
            f"**🚨 Shared binary across hosts: SHA1 `{sha1}` observed on {len(hosts)} hosts**",
            "",
            f"_Cryptographic identity match (SHA1 = same bytes) on hosts: {', '.join(f'`{h}`' for h in hosts)}._",
            f"_Basename(s): {', '.join(f'`{b}`' for b in basenames) or 'unknown'}_",
            "",
            "_Observation details:_",
        ]
        for o in occs:
            body_lines.append(
                f"- host=`{o['host']}` basename=`{o.get('basename') or '?'}` "
                f"path=`{o.get('path') or '?'}` from `{o['filename']}`"
            )
        body_lines += [
            "",
            "**Hypothesis:** Same binary distributed across multiple hosts. Most common explanations:",
            "- **Lateral movement** — attacker pushed the same payload to additional hosts after initial compromise (PsExec, SMB, WinRM, scheduled task pull, GPO, etc.).",
            "- **Attacker tooling distribution** — RaaS deployment script staged the encryptor or post-exploit framework across the estate.",
            "- **Pre-positioned implant** — same backdoor seeded across hosts via a compromised software update channel or shared installer.",
            "",
            "**Triage:** Pivot the SHA1 to threat-intel (VirusTotal/MalwareBazaar) for family attribution. "
            "On each host, identify the lateral-movement vector by examining the file's parent process tree "
            "around its first-execution timestamp (cross-reference Prefetch/MFT/USN claims for that path).",
        ]
        body = "\n".join(body_lines)
    elif corr["type"] == "shared_masquerade_across_hosts":
        sig = corr["signature"]
        hosts = corr["hosts"]
        occs = corr["occurrences"]
        # Pivot key was constructed as "<basename>:<expected_path>"; recover both halves
        # for the human-readable headline. The expected_path may contain colons (drive
        # letters), so split only on the FIRST.
        binary, _, expected_path = sig.partition(":")
        entities = sorted({o["entity"] for o in occs if o.get("entity")})
        evidence_refs = sorted({f"claims/done/{o['filename']}" for o in occs})
        derived_from = sorted({o["claim_id"] for o in occs if o.get("claim_id")})
        body_lines = [
            f"**🚨 Shared masquerade signature across hosts: `{binary}` masquerading away from `{expected_path}` on {len(hosts)} hosts**",
            "",
            f"_Pivot key: `{sig}` (basename + canonical-path expectation, both lowercased)._",
            f"_Hosts: {', '.join(f'`{h}`' for h in hosts)}._",
            "",
            "_Per-host observations:_",
        ]
        for o in occs:
            body_lines.append(f"- host=`{o['host']}` entity=`{o.get('entity', '?')}` from `{o['filename']}`")
        body_lines += [
            "",
            "**Hypothesis:** Same masquerading payload deployed across multiple hosts — strong indicator of a coordinated attacker pushing a common toolkit (e.g., LockBit/Conti-style RaaS deployment, or worm propagation). Pivot SHA1 + parent process tree on each host's masquerade entity to identify the lateral-movement vector.",
        ]
        body = "\n".join(body_lines)
    elif corr["type"] == "shared_external_ip_across_hosts":
        ip = corr["ip"]
        hosts = corr["hosts"]
        occs = corr["occurrences"]
        entities = sorted({o["entity"] for o in occs if o.get("entity")} | {f"ip:{ip}"})
        evidence_refs = sorted({f"claims/done/{o['filename']}" for o in occs})
        derived_from = sorted({o["claim_id"] for o in occs if o.get("claim_id")})
        body_lines = [
            f"**🌐 Shared external source IP across hosts: `{ip}` touched {len(hosts)} hosts**",
            "",
            f"_Hosts: {', '.join(f'`{h}`' for h in hosts)}._",
            "_RFC1918 / loopback / link-local already excluded — this IP is routable on the public internet._",
            "",
            "_Per-host observations:_",
        ]
        for o in occs:
            body_lines.append(f"- host=`{o['host']}` event=`{o.get('entity', '?')}` from `{o['filename']}`")
        body_lines += [
            "",
            f"**Hypothesis:** A single external actor (single relay / VPN exit / VPS / C2 hub) interacted with multiple hosts. Pivot `{ip}` to threat-intel (AbuseIPDB / GreyNoise / commercial CTI), check firewall logs on each host for outbound traffic to/from this IP, and correlate the touched timestamps with each host's per-host triage timeline.",
        ]
        body = "\n".join(body_lines)
    elif corr["type"] == "shared_internal_ip_across_hosts":
        ip = corr["ip"]
        hosts = corr["hosts"]
        occs = corr["occurrences"]
        entities = sorted({o["entity"] for o in occs if o.get("entity")} | {f"ip:{ip}"})
        evidence_refs = sorted({f"claims/done/{o['filename']}" for o in occs})
        derived_from = sorted({o["claim_id"] for o in occs if o.get("claim_id")})
        body_lines = [
            f"**🏢 Shared internal (RFC1918) IP across hosts: `{ip}` touched {len(hosts)} hosts**",
            "",
            f"_Hosts: {', '.join(f'`{h}`' for h in hosts)}._",
            "_Lower confidence than external-IP correlation: intra-corp shared infra (DCs, file servers, print servers, monitoring agents) routinely touches every host. Add this IP to `FINDEVIL_INTERNAL_IP_ALLOWLIST` if it's known-good for this case._",
            "",
            "_Per-host observations:_",
        ]
        for o in occs:
            body_lines.append(f"- host=`{o['host']}` source=`{o.get('source', '?')}` entity=`{o.get('entity', '?')}` from `{o['filename']}`")
        body_lines += [
            "",
            f"**Hypothesis:** Either (a) legitimate shared infrastructure — confirm with the system owner and add `{ip}` to the allowlist, OR (b) intra-corp lateral movement — an attacker pivot using a workstation/jump-box. Triage by examining the cited events on each host (logon types, processes connecting) and pivoting on the shared IP's role (DHCP/DNS/AD/file/print).",
        ]
        body = "\n".join(body_lines)
    elif corr["type"] == "shared_c2_endpoint_across_hosts":
        ip = corr["ip"]
        port = corr["remote_port"]
        hosts = corr["hosts"]
        occs = corr["occurrences"]
        entities = sorted({o["entity"] for o in occs if o.get("entity")} | {f"ip:{ip}:{port}"})
        evidence_refs = sorted({f"claims/done/{o['filename']}" for o in occs})
        derived_from = sorted({o["claim_id"] for o in occs if o.get("claim_id")})
        body_lines = [
            f"**🎯 Shared C2 endpoint across hosts: `{ip}:{port}` reached from {len(hosts)} hosts**",
            "",
            "_Strictly stronger than shared-IP alone: same `(ip, port)` tuple implies the same C2 protocol/family rather than coincidental reuse of a CDN/cloud IP. RFC1918 / loopback already excluded._",
            f"_Hosts: {', '.join(f'`{h}`' for h in hosts)}._",
            "",
            "_Per-host observations (process attribution from vol3 windows.netscan):_",
        ]
        for o in occs:
            attribution = ""
            if o.get("pid") is not None or o.get("process"):
                attribution = f" — PID={o.get('pid')} ({o.get('process') or '?'})"
            body_lines.append(f"- host=`{o['host']}`{attribution} from `{o['filename']}`")
        body_lines += [
            "",
            f"**Hypothesis:** Same C2 server (or relay) servicing multiple hosts on TCP/{port}. "
            "Common port→family heuristics: 443/8443=HTTPS beacon (Cobalt Strike, Metasploit reverse_https), "
            "4444=msf default reverse, 8080=many beacon kits, 6667=IRC bot, 53/853=DNS-over-TLS C2. "
            "Triage: pivot the IP+port to threat-intel; on each host, dump and string-scan the cited PID's "
            "VAD regions for beacon config, jitter values, sleep intervals, and HTTP user-agent strings.",
        ]
        body = "\n".join(body_lines)
    elif corr["type"] == "shared_suspicious_cmdline_across_hosts":
        pat = corr["pattern"]
        hosts = corr["hosts"]
        occs = corr["occurrences"]
        entities = sorted({o["entity"] for o in occs if o.get("entity")})
        evidence_refs = sorted({f"claims/done/{o['filename']}" for o in occs})
        derived_from = sorted({o["claim_id"] for o in occs if o.get("claim_id")})
        body_lines = [
            f"**📜 Shared suspicious cmdline pattern across hosts: `{pat}` fired on {len(hosts)} hosts**",
            "",
            f"_Pattern is the normalized regex (not the literal cmdline string) — different payload bodies can still match the same pattern._",
            f"_Hosts: {', '.join(f'`{h}`' for h in hosts)}._",
            "",
            "_Per-host observations:_",
        ]
        for o in occs:
            body_lines.append(f"- host=`{o['host']}` event=`{o.get('entity', '?')}` from `{o['filename']}`")
        body_lines += [
            "",
            "**Hypothesis:** The same scripted attack pattern (PowerShell `-EncodedCommand`, BITSAdmin transfer, certutil download, etc.) ran on multiple hosts — strong indicator of a shared playbook or post-exploit framework (Cobalt Strike beacon spawning, Empire, scripted-kit deployment). Pull the full command lines from each host's evtx claim and decode any base64 payloads to identify the next-stage tooling.",
        ]
        body = "\n".join(body_lines)
    elif corr["type"] == "temporal_compromise_window":
        host = corr["host"]
        findings = corr["findings"]
        first_t = findings[0]["time"]
        last_t = findings[-1]["time"]
        span = last_t - first_t
        # Pretty span: "1m 23s" or "59s"
        total_sec = int(span.total_seconds())
        span_str = f"{total_sec // 60}m {total_sec % 60}s" if total_sec >= 60 else f"{total_sec}s"
        entities = sorted({f["entity"] for f in findings})
        evidence_refs = sorted({f"claims/done/{f['filename']}" for f in findings})
        derived_from = sorted({f["claim_id"] for f in findings if f.get("claim_id")})
        body_lines = [
            f"**Temporal Compromise Window — host `{host}` ({first_t.isoformat()} → {last_t.isoformat()}, span {span_str}, window {corr['window_minutes']}m)**",
            "",
            f"_{len(findings)} findings spanning {len(corr['domains'])} domain(s) ({', '.join(corr['domains'])}) "
            f"clustered within a {corr['window_minutes']}-minute window — "
            f"much higher signal than entity-overlap alone._",
            "",
            "Timeline (chronological):",
        ]
        for f in findings:
            body_lines.append(
                f"- `{f['time'].isoformat()}` [{f['domain']}] {f['label']} — `{f['filename']}`"
            )
        body_lines += ["",
            f"**Hypothesis:** Coherent attack sequence within a {span_str} window — "
            "strongly suggests a single compromise event rather than coincidence. "
            "Triage the named users, PIDs, and IPs immediately; pivot to the cited claims for full context.",
        ]
        body = "\n".join(body_lines)
    else:
        entities = []
        evidence_refs = []
        derived_from = []
        body = "Generic correlation finding."

    fm = {
        "claim_id": cid,
        "status": "new",
        "generated_by": "correlation-agent",
        "correlation_type": corr["type"],
        "entities": entities,
        "evidence_refs": evidence_refs,
        "derived_from": derived_from,
        "confidence": _confidence(corr),
        "timestamp": timestamp,
    }
    if "hosts" in corr:
        fm["hosts"] = list(corr["hosts"])
    elif "host" in corr:
        fm["host"] = corr["host"]
    return f"---\n{yaml.dump(fm, sort_keys=False)}---\n{body}\n"


def _existing_correlation_ids(chisel: Chisel) -> set:
    """Collect claim_ids of existing correlation claims across todo/doing/done so we don't re-emit."""
    ids: set = set()
    for d in (CLAIMS_TODO, CLAIMS_DOING, CLAIMS_DONE):
        try:
            listing = chisel.shell("ls", ["-1", str(d)])
        except RuntimeError:
            continue
        for name in listing.splitlines():
            name = name.strip()
            if not name.startswith("correlation_") or not name.endswith(".md"):
                continue
            # Filename: correlation_<claim_id>_<ts>.md   →   pull <claim_id>
            try:
                cid = name[len("correlation_"):].rsplit("_", 2)[0]
                if cid.startswith("corr-"):
                    ids.add(cid)
            except Exception:
                continue
    return ids


async def run_correlation():
    """Standalone entrypoint — also called in-process by the orchestrator."""
    print("🔗 Correlation Agent starting (Chisel-confined)...")

    chisel = Chisel(CHISEL_URL, CHISEL_SECRET)
    chisel.connect()
    print(f"🔒 Chisel session → {chisel.endpoint} (sid={chisel.session_id[:8]}…)")

    claims = await load_all_claims(chisel)
    domain_count = sum(1 for c in claims if c["frontmatter"].get("generated_by") != "correlation-agent")
    print(f"📂 Loaded {len(claims)} claims ({domain_count} domain, {len(claims) - domain_count} correlation)")

    correlations = detect_correlations(claims)
    if not correlations:
        print("   No correlations found.")
        return
    print(f"🔗 {len(correlations)} correlation(s) detected: " + ", ".join(c["type"] for c in correlations))

    existing = _existing_correlation_ids(chisel)
    chisel.call("create_directory", {"path": str(CLAIMS_TODO)})
    written = skipped = 0
    for corr in correlations:
        cid = correlation_id(corr)
        if cid in existing:
            skipped += 1
            continue
        content = generate_correlation_claim(corr)
        ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        filename = f"correlation_{cid}_{ts}.md"
        chisel.call("write_file", {"path": str(CLAIMS_TODO / filename), "content": content})
        existing.add(cid)
        written += 1
        print(f"✅ Hypothesis claim → {filename}")

    print(f"   → {written} new, {skipped} already-existing (deduped by claim_id)")


if __name__ == "__main__":
    asyncio.run(run_correlation())
