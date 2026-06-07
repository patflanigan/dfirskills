# agents/report_agent/agent.py
"""
Report Agent — curates claims in evidence/claims/done/ into an analyst-facing
case report (markdown) plus a Cognee graph visualization (HTML).

Standalone CLI:  python -m agents.report_agent.agent

Core principle: this agent makes NO new claims. Every assertion in the report
is "Claim X says Y" with a link to the source claim file. The report is a
curator, not a witness — it cannot amplify a fabricating claim into an
authoritative-sounding finding because it never speaks in its own voice.
"""

import asyncio
import os
import re
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path

import yaml

from agents._chisel import Chisel
from agents.report_agent.ciso_summary import render_ciso_summary

EVIDENCE_ROOT = Path(os.environ.get("EVIDENCE_ROOT", "/home/sansforensics/dfirskills2/evidence"))
CLAIMS_DONE = EVIDENCE_ROOT / "claims/done"
CLAIMS_TODO = EVIDENCE_ROOT / "claims/todo"
REPORTS_ROOT = EVIDENCE_ROOT.parent / "reports"

CHISEL_URL = os.environ.get("CHISEL_URL", "http://127.0.0.1:3000")
CHISEL_SECRET = os.environ["CHISEL_SECRET"]

TIER_A = 0.95   # cross-domain — executive summary
TIER_B = 0.80   # high-confidence single-domain — domain sections
TIER_C = 0.65   # recurring / low-confidence — appendix
# anything below TIER_C goes in informational appendix as well

# Triage line in memory claim body (matches memory_agent's _format_triage)
TRIAGE_LINE_RE = re.compile(
    r"^-\s*\*\*PID\s*(\d+)\*\*\s*\(([^)]+)\)\s*—\s*score=(\d+)[^|]*\|\s*yara:\s*([^|]+)\|",
    re.MULTILINE,
)

DISCLAIMER = (
    "> ⚠️ This report **curates and cites** claims emitted by FindEvil agents.\n"
    "> **Spot-checked against the persistent Cognee graph at validator pass:** "
    "frontmatter assertions on `name` / `ppid` / `create_time` (Process), "
    "`value` / `value_type` (RegistryKey), `event_id` / `channel` / `time_created` (Event), "
    "AND inline body `**PID X** (name)` patterns. Claims that disagree with the graph — "
    "or that assert sentinel values like `unknown` / empty — are rejected and re-queued "
    "before reaching `done/`.\n"
    "> **NOT verified:** free-form body text outside the structured PID/name pattern; "
    "fields beyond the spot-check list above (e.g., `command_line`, hexdumps); the "
    "underlying tool output that produced the claim; selective omission in this report. "
    "See **Confidence Architecture** at the bottom for the full gap analysis."
)


def parse_claim(content: str, filename: str) -> dict | None:
    """Parse a claim's frontmatter + body. Robust to incomplete/garbled claims."""
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
        pid, name, score, rules = m.groups()
        triage_rows.append({
            "pid": int(pid), "name": name.strip(), "score": int(score),
            "yara_rules": [r.strip() for r in rules.split(",") if r.strip() and r.strip() != "(none)"],
        })
    return {"frontmatter": fm, "body": body, "triage_rows": triage_rows, "filename": filename}


async def load_all_claims(chisel: Chisel) -> list[dict]:
    listing = chisel.shell("ls", ["-1", str(CLAIMS_DONE)])
    out = []
    for name in listing.splitlines():
        name = name.strip()
        if not name.endswith(".md"):
            continue
        try:
            content = chisel.shell("cat", [str(CLAIMS_DONE / name)])
        except RuntimeError:
            continue
        c = parse_claim(content, name)
        if c is not None:
            out.append(c)
    return out


# ──────────────────────────────────────────────────────────────
# ATT&CK technique mapping
# ──────────────────────────────────────────────────────────────
# Centralized in report_agent (presentation, not evidence) so the claim layer stays
# pure. Maps finding-type strings (extracted from agent body lines like
# `- **mft_timestomping_detected** ...`) AND correlation_type strings (from frontmatter)
# to a list of (technique_id, technique_name, tactic). Tactic uses MITRE's kill-chain
# vocabulary so the coverage section can be sorted in attack-progression order.

TACTIC_ORDER = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact",
]

ATTACK_TECHNIQUE_MAP: dict[str, list[tuple[str, str, str]]] = {
    # ─── memory_agent anomaly types ───
    "injection":                                         [("T1055", "Process Injection", "Defense Evasion")],
    "hidden":                                            [("T1014", "Rootkit", "Defense Evasion")],
    "bad_parent":                                        [("T1055", "Process Injection", "Defense Evasion")],
    "duplicate_singleton":                               [("T1036.005", "Masquerading: Match Legitimate Name", "Defense Evasion")],
    "yara_hit":                                          [("T1059", "Command and Scripting Interpreter", "Execution")],
    "baseline_new_pid":                                  [("T1055", "Process Injection", "Defense Evasion")],
    # ─── registry_agent persistence detectors ───
    "suspicious_run_value":                              [("T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys", "Persistence")],
    "masquerade_run_value":                              [("T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys", "Persistence"),
                                                          ("T1036.005", "Masquerading: Match Legitimate Name", "Defense Evasion")],
    "userinit_modified":                                 [("T1547", "Boot or Logon Autostart Execution", "Persistence")],
    "shell_modified":                                    [("T1547", "Boot or Logon Autostart Execution", "Persistence")],
    "ifeo_debugger":                                     [("T1546.012", "Event Triggered Execution: IFEO Injection", "Privilege Escalation")],
    "appinit_dlls":                                      [("T1546.010", "Event Triggered Execution: AppInit DLLs", "Privilege Escalation")],
    "suspicious_service_imagepath":                      [("T1543.003", "Create or Modify System Process: Windows Service", "Persistence")],
    "masquerade_service_imagepath":                      [("T1543.003", "Create or Modify System Process: Windows Service", "Persistence"),
                                                          ("T1036.005", "Masquerading: Match Legitimate Name", "Defense Evasion")],
    # ─── registry_agent ShimCache detectors (execution evidence) ───
    "shimcache_executed_user_writable_path":             [("T1059", "Command and Scripting Interpreter", "Execution")],
    "shimcache_suspicious_path":                         [("T1059", "Command and Scripting Interpreter", "Execution")],
    "shimcache_masquerade":                              [("T1036.005", "Masquerading: Match Legitimate Name", "Defense Evasion")],
    # ─── registry_agent Amcache detectors (Win8+ identity) ───
    "amcache_executable_user_writable":                  [("T1059", "Command and Scripting Interpreter", "Execution")],
    "amcache_unsigned_user_writable_executable":         [("T1036", "Masquerading", "Defense Evasion")],
    "amcache_masquerade_publisher_mismatch":             [("T1036.001", "Masquerading: Invalid Code Signature", "Defense Evasion")],
    "amcache_recently_installed_user_writable_program":  [("T1218", "System Binary Proxy Execution", "Defense Evasion")],
    # ─── evtx_agent ───
    "audit_log_cleared":                                 [("T1070.001", "Indicator Removal: Clear Windows Event Logs", "Defense Evasion")],
    "service_install":                                   [("T1543.003", "Create or Modify System Process: Windows Service", "Persistence")],
    "process_create_user_writable_path":                 [("T1059", "Command and Scripting Interpreter", "Execution")],
    "process_create_suspicious_cmdline":                 [("T1059.001", "PowerShell", "Execution")],
    "account_create":                                    [("T1136", "Create Account", "Persistence")],
    "privileged_group_change":                           [("T1098", "Account Manipulation", "Persistence")],
    "interactive_remote_logon":                          [("T1021.001", "Remote Services: RDP", "Lateral Movement")],
    "new_credentials_logon":                             [("T1550.002", "Use Alternate Authentication Material: Pass the Hash", "Lateral Movement")],
    # New evtx_agent detectors (PowerShell + brute-force + privilege elevation)
    "powershell_suspicious_scriptblock":                 [("T1059.001", "PowerShell", "Execution"),
                                                          ("T1027", "Obfuscated Files or Information", "Defense Evasion")],
    "failed_logon_burst":                                [("T1110.001", "Brute Force: Password Guessing", "Credential Access"),
                                                          ("T1110.003", "Brute Force: Password Spraying", "Credential Access")],
    "special_privilege_assigned":                        [("T1078", "Valid Accounts", "Defense Evasion"),
                                                          ("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation")],
    # Active Directory / DC attack detection (workstation EVTX rarely produces these)
    "kerberoasting_burst":                               [("T1558.003", "Steal or Forge Kerberos Tickets: Kerberoasting", "Credential Access")],
    "as_rep_roasting":                                   [("T1558.004", "Steal or Forge Kerberos Tickets: AS-REP Roasting", "Credential Access")],
    "dcsync_attempt":                                    [("T1003.006", "OS Credential Dumping: DCSync", "Credential Access")],
    "suspicious_ntds_access":                            [("T1003.003", "OS Credential Dumping: NTDS", "Credential Access")],
    # ─── prefetch_agent ───
    "suspicious_execution_path":                         [("T1059", "Command and Scripting Interpreter", "Execution")],
    "masquerade_execution":                              [("T1036.005", "Masquerading: Match Legitimate Name", "Defense Evasion")],
    "high_run_count_anomaly":                            [("T1059", "Command and Scripting Interpreter", "Execution")],
    # ─── mft_agent ───
    "mft_timestomping_detected":                         [("T1070.006", "Indicator Removal: Timestomp", "Defense Evasion")],
    "mft_executable_dropped_user_writable":              [("T1105", "Ingress Tool Transfer", "Command and Control")],
    "mft_deleted_executable_user_writable":              [("T1070.004", "Indicator Removal: File Deletion", "Defense Evasion")],
    "mft_executable_in_recycle_bin":                     [("T1564", "Hide Artifacts", "Defense Evasion")],
    "mft_alternate_data_stream_executable":              [("T1564.004", "Hide Artifacts: NTFS File Attributes", "Defense Evasion")],
    # ─── mft_agent USN code path ───
    "usn_drop_then_delete_executable":                   [("T1105", "Ingress Tool Transfer", "Command and Control"),
                                                          ("T1070.004", "Indicator Removal: File Deletion", "Defense Evasion")],
    "usn_burst_create_executables_user_writable":        [("T1105", "Ingress Tool Transfer", "Command and Control")],
    "usn_executable_renamed_user_writable":              [("T1036", "Masquerading", "Defense Evasion")],
    "usn_ransomware_overwrite_burst":                    [("T1486", "Data Encrypted for Impact", "Impact")],
    "usn_ransomware_extension_burst":                    [("T1486", "Data Encrypted for Impact", "Impact")],
    "usn_ransom_note_created":                           [("T1486", "Data Encrypted for Impact", "Impact"),
                                                          ("T1491.001", "Defacement: Internal Defacement", "Impact")],
    # ─── VSS suppression detectors (registry + evtx) ───
    "vss_service_disabled":                              [("T1490", "Inhibit System Recovery", "Impact")],
    "vss_service_stopped":                               [("T1490", "Inhibit System Recovery", "Impact")],
    # ─── mft_agent recycle-bin code path ───
    "recycle_executable_user_writable_origin":           [("T1564", "Hide Artifacts", "Defense Evasion")],
    "recycle_masquerade_origin":                         [("T1036.005", "Masquerading: Match Legitimate Name", "Defense Evasion")],
    # ─── correlation_agent rule types (frontmatter.correlation_type) ───
    "cross_domain_persistence":                          [("T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys", "Persistence"),
                                                          ("T1055", "Process Injection", "Defense Evasion")],
    "cross_domain_service_persistence":                  [("T1543.003", "Create or Modify System Process: Windows Service", "Persistence")],
    "cross_domain_execution_persistence":                [("T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys", "Persistence"),
                                                          ("T1059", "Command and Scripting Interpreter", "Execution")],
    "cross_domain_drop_persistence_execution":           [("T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys", "Persistence"),
                                                          ("T1059", "Command and Scripting Interpreter", "Execution"),
                                                          ("T1105", "Ingress Tool Transfer", "Command and Control")],
    "vss_suppression_with_ransomware":                   [("T1486", "Data Encrypted for Impact", "Impact"),
                                                          ("T1490", "Inhibit System Recovery", "Impact")],
    "shared_sha1_across_hosts":                          [("T1570", "Lateral Tool Transfer", "Lateral Movement"),
                                                          ("T1021", "Remote Services", "Lateral Movement")],
    "shared_masquerade_across_hosts":                    [("T1036", "Masquerading", "Defense Evasion"),
                                                          ("T1570", "Lateral Tool Transfer", "Lateral Movement")],
    "shared_external_ip_across_hosts":                   [("T1071", "Application Layer Protocol", "Command and Control"),
                                                          ("T1021", "Remote Services", "Lateral Movement")],
    "shared_suspicious_cmdline_across_hosts":            [("T1059", "Command and Scripting Interpreter", "Execution"),
                                                          ("T1570", "Lateral Tool Transfer", "Lateral Movement")],
    "shared_c2_endpoint_across_hosts":                   [("T1071", "Application Layer Protocol", "Command and Control"),
                                                          ("T1090", "Proxy", "Command and Control")],
    "shared_internal_ip_across_hosts":                   [("T1021", "Remote Services", "Lateral Movement"),
                                                          ("T1570", "Lateral Tool Transfer", "Lateral Movement")],
    "process_external_connection":                       [("T1071", "Application Layer Protocol", "Command and Control"),
                                                          ("T1571", "Non-Standard Port", "Command and Control")],
    "process_external_connection_recent":                [("T1071", "Application Layer Protocol", "Command and Control"),
                                                          ("T1571", "Non-Standard Port", "Command and Control")],
    "timestomping_detected":                             [("T1070.006", "Indicator Removal: Timestomp", "Defense Evasion")],
    "temporal_compromise_window":                        [("T1078", "Valid Accounts", "Initial Access")],
    "shared_yara_rule":                                  [("T1059", "Command and Scripting Interpreter", "Execution")],
    "recurring_high_confidence_process":                 [("T1055", "Process Injection", "Defense Evasion")],
    # `recurring_process` deliberately unmapped — too generic; would be noise.
}

# Match `- **finding_type** ...` and `_<finding_type> (...):_` patterns in claim bodies.
# The first form is the standard agent finding line; the second is mft_agent's grouping
# header (we want both so timestomping etc. get counted from the standalone MFT claim).
_FINDING_TYPE_RE = re.compile(
    r"(?:^\s*[-*]\s*\*\*([a-z_]+)\*\*"            # bullet form
    r"|^_([a-z_]+)\s*\(\d+\):_)",                  # mft section-header form
    re.MULTILINE,
)


def _techniques_for_claim(claim: dict) -> list[tuple[str, str, str]]:
    """Pull finding types from a claim's frontmatter + body, return deduped technique list."""
    fm = claim["frontmatter"]
    body = claim.get("body", "")
    types: set[str] = set()
    ctype = fm.get("correlation_type")
    if ctype:
        types.add(ctype)
    for m in _FINDING_TYPE_RE.finditer(body):
        token = m.group(1) or m.group(2)
        if token:
            types.add(token)
    techniques: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for t in types:
        for tup in ATTACK_TECHNIQUE_MAP.get(t, []):
            if tup[0] not in seen:
                seen.add(tup[0])
                techniques.append(tup)
    return techniques


def _format_attack_brackets(techniques: list[tuple[str, str, str]]) -> str:
    """Inline `[T1234, T5678.001]` annotation for finding bullets."""
    if not techniques:
        return ""
    return " `[" + ", ".join(t[0] for t in techniques) + "]`"


def _claim_hosts(claim: dict) -> set[str]:
    """Hosts a claim belongs to. Single-domain claims set `host`; the cross-host
    correlation rule sets `hosts: [...]`. Returns empty set if neither present."""
    fm = claim["frontmatter"]
    out: set[str] = set()
    h = fm.get("host")
    if isinstance(h, str) and h:
        out.add(h)
    for h in fm.get("hosts") or []:
        if isinstance(h, str) and h:
            out.add(h)
    return out


def _hosts_in_corpus(claims: list) -> list[str]:
    """Sorted list of every host observed across all claims."""
    seen: set[str] = set()
    for c in claims:
        seen.update(_claim_hosts(c))
    return sorted(seen)


def _claim_in_host(claim: dict, host: str) -> bool:
    """True iff this claim belongs to the named host (single- or multi-host)."""
    return host in _claim_hosts(claim)


def claim_tier(c: dict) -> str:
    conf = c["frontmatter"].get("confidence", 0.0)
    try:
        conf = float(conf)
    except (TypeError, ValueError):
        conf = 0.0
    if conf >= TIER_A:
        return "A"
    if conf >= TIER_B:
        return "B"
    if conf >= TIER_C:
        return "C"
    return "D"


def is_security_finding(c: dict) -> bool:
    """True iff the claim is a security finding (i.e., NOT a mechanical-extraction
    manifest). Disk-image-agent emits a confidence=1.0 manifest per extracted
    image — that's provenance, not a finding, and gets excluded from Tier-A
    counts and the executive summary. Single source of truth so the CLI tier
    counter and the executive-summary filter can't drift."""
    return c["frontmatter"].get("generated_by") != "disk-image-agent"


def build_pid_corroboration(claims: list) -> dict:
    """{pid: [list of claim filenames citing it]} — cross-claim trust signal."""
    out = defaultdict(list)
    for c in claims:
        for ent in c["frontmatter"].get("entities") or []:
            if isinstance(ent, str) and ent.startswith("process:"):
                try:
                    pid = int(ent.split(":", 1)[1])
                except ValueError:
                    continue
                out[pid].append(c["filename"])
    return dict(out)


def latest_memory_triage(claims: list, host: str | None = None) -> tuple[list, str | None, dict]:
    """Pull triage rows + pid_attrs from the most-recent memory-agent claim.
    If `host` is provided, restrict to memory claims for that host.
    Returns (triage_rows, filename, pid_attrs). pid_attrs is empty for pre-A claims."""
    mem_claims = [c for c in claims if c["frontmatter"].get("generated_by") == "memory-agent"]
    if host is not None:
        mem_claims = [c for c in mem_claims if _claim_in_host(c, host)]
    if not mem_claims:
        return [], None, {}
    mem_claims.sort(key=lambda c: c["frontmatter"].get("timestamp", ""), reverse=True)
    latest = mem_claims[0]
    return latest["triage_rows"], latest["filename"], latest["frontmatter"].get("pid_attrs") or {}


def _claim_spot_check_summary(c: dict) -> dict:
    """Tally per-claim spot-check coverage from frontmatter (no Cognee call — claims in
    done/ already passed the validator's checks; here we just summarize what got verified).

    Returns {'attrs_with_check': N, 'is_meta': bool, 'covered_fields': [...]}.
    """
    fm = c["frontmatter"]
    pid_attrs = fm.get("pid_attrs") or {}
    key_attrs = fm.get("key_attrs") or {}
    event_attrs = fm.get("event_attrs") or {}
    n_checked = 0
    fields_seen: set = set()
    for attrs in pid_attrs.values():
        if isinstance(attrs, dict):
            for f in ("name", "ppid", "create_time"):
                if attrs.get(f):
                    n_checked += 1
                    fields_seen.add(f)
    for attrs in key_attrs.values():
        if isinstance(attrs, dict):
            for f in ("value", "value_type"):
                if attrs.get(f):
                    n_checked += 1
                    fields_seen.add(f)
    for attrs in event_attrs.values():
        if isinstance(attrs, dict):
            for f in ("event_id", "channel", "time_created"):
                if attrs.get(f) is not None:
                    n_checked += 1
                    fields_seen.add(f)
    return {
        "attrs_with_check": n_checked,
        "is_meta": n_checked == 0,
        "covered_fields": sorted(fields_seen),
    }


def render_evidence_integrity(report_ts: str) -> str:
    """Render the chain-of-custody integrity table from evidence_manifest_post.json.
    Returns empty string for runs predating the manifest feature (file missing)."""
    import json
    manifest_path = EVIDENCE_ROOT / "audit" / report_ts / "evidence_manifest_post.json"
    if not manifest_path.is_file():
        return ""
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception:
        return ""
    summary = data.get("summary", {})
    files = data.get("files", [])
    if not files:
        return ""
    verdict = "✅ UNCHANGED" if summary.get("modified", 0) == 0 and summary.get("missing", 0) == 0 else "❌ FAILED"
    lines = [
        "## Evidence Integrity",
        "",
        f"- **Verdict**: {verdict} ({summary.get('unchanged', 0)}/{summary.get('checked', 0)} files unchanged)",
        f"- **Algorithm**: {data.get('algorithm', 'sha256')}",
        f"- **Verified at**: {data.get('verified_at_utc', '?')}",
        "",
        "| File | Size (bytes) | SHA256 (first 16) | Status |",
        "| --- | ---: | --- | --- |",
    ]
    for entry in files:
        v = entry.get("verification", {})
        sha = entry.get("sha256", "")[:16] + "…"
        name = Path(entry.get("original_path", "")).name
        lines.append(f"| `{name}` | {entry.get('size_bytes', 0):,} | `{sha}` | {v.get('status', '?')} |")
    lines.append("")
    return "\n".join(lines)


def render_validation_status(claims: list, in_flight_todo: int) -> str:
    """Real per-claim spot-check stats from the loaded done/ corpus.
    All claims in done/ have already passed the validator at ingest; here we summarize
    HOW MUCH was verified for each.
    """
    summaries = [_claim_spot_check_summary(c) for c in claims]
    spot_checkable = sum(1 for s in summaries if not s["is_meta"])
    meta_only = sum(1 for s in summaries if s["is_meta"])
    total_attrs_verified = sum(s["attrs_with_check"] for s in summaries)
    lines = [
        "## Validation Status",
        "",
        f"- **Total claims in done/**: {len(claims)}",
        f"- **Claims with spot-checkable attrs**: {spot_checkable} "
        f"(total attrs verified vs graph at ingest: {total_attrs_verified})",
        f"- **Meta-claims (correlation/manifest, no asserted attrs)**: {meta_only} "
        f"(passed validator vacuously — they observe but don't assert)",
        f"- **Claims still in todo/** (pending or re-queued by validator): {in_flight_todo}",
        "- **File-existence check (3a)**: passed for all claims in done/ "
        "(failures are kept in todo/ — see above count)",
        "- **Multi-field spot-check (5a)** covers: "
        f"{', '.join(f'{prefix}={fields}' for prefix, fields in __import__('orchestrator.validator', fromlist=['SPOT_CHECK_FIELDS']).SPOT_CHECK_FIELDS.items())}",
        "- **Body-text spot-check**: inline `**PID X** (name)` patterns are verified against the graph "
        "(catches the 'honest frontmatter, lying body' attack)",
        "- **Sentinel-assertion rejection**: claims asserting `unknown` / empty for identity fields are refused entry to `done/`",
    ]
    return "\n".join(lines)


def render_executive_summary(tier_a_claims: list) -> str:
    lines = ["## Executive Summary", "",
             f"_Tier A findings only — confidence ≥ {TIER_A:.2f} (cross-domain corroborated). "
             "Inline `[T...]` brackets are MITRE ATT&CK technique IDs derived from the claim's "
             "finding-type via `report_agent.ATTACK_TECHNIQUE_MAP`._", ""]
    if not tier_a_claims:
        lines.append("_No Tier A findings in current corpus._")
        return "\n".join(lines)
    for c in tier_a_claims:
        fm = c["frontmatter"]
        ctype = fm.get("correlation_type", fm.get("generated_by", "?"))
        cid = fm.get("claim_id", "?")
        # First non-blank line after the second `---` is the headline
        body_first = next((ln for ln in c["body"].splitlines() if ln.strip().startswith("**")), "")
        headline = body_first.strip().strip("*") or ctype
        attack_tags = _format_attack_brackets(_techniques_for_claim(c))
        lines.append(f"- **{headline}**{attack_tags}  ")
        lines.append(f"  Cited claim: `{c['filename']}` (id `{cid}`, confidence {fm.get('confidence')})")
    return "\n".join(lines)


def render_attack_coverage(claims: list, host: str | None = None, heading_level: int = 2) -> str:
    """Section listing every observed ATT&CK technique grouped by tactic in
    kill-chain order. Citation count + sample claim filenames per technique.
    The table is the case's at-a-glance technique view — useful for analyst
    handoff and for checking which kill-chain stages the evidence covers.

    If `host` is provided, restrict to claims for that host (cross-host correlation
    claims are included if they list the host). Used by `render_per_host_section`
    to give each host its own kill-chain coverage view.
    """
    if host is not None:
        claims = [c for c in claims if _claim_in_host(c, host)]
    # tactic → tid → {name, claims-citing-this-technique}
    coverage: dict[str, dict[str, dict]] = defaultdict(dict)
    for c in claims:
        for tid, tname, tactic in _techniques_for_claim(c):
            entry = coverage[tactic].setdefault(tid, {"name": tname, "claims": set()})
            entry["claims"].add(c["filename"])

    h = "#" * heading_level
    title = f"{h} ATT&CK Technique Coverage" + (f" — host `{host}`" if host else "")
    lines = [title, ""]
    if not coverage:
        lines.append("_No findings mapped to ATT&CK techniques" + (f" for host `{host}`._" if host else "._"))
        return "\n".join(lines)

    total_techniques = sum(len(d) for d in coverage.values())
    tactics_hit = len(coverage)
    scope = f"host `{host}`" if host else "this case"
    lines.append(
        f"_{total_techniques} distinct techniques observed across {tactics_hit} tactics in {scope}. "
        "Sorted by kill-chain order (top = earliest stage). The full finding-type → "
        "technique mapping lives in `report_agent.ATTACK_TECHNIQUE_MAP`; unmapped "
        "finding types (e.g. `recurring_process`) are silently excluded._"
    )
    lines.append("")
    lines.append("| Tactic | Technique | Citations | Sample claims |")
    lines.append("|---|---|---:|---|")
    for tactic in TACTIC_ORDER:
        if tactic not in coverage:
            continue
        # Within a tactic, sort by citation count desc so the most-evidenced techniques rise.
        items = sorted(coverage[tactic].items(), key=lambda kv: -len(kv[1]["claims"]))
        for tid, info in items:
            sample = sorted(info["claims"])[:3]
            extra = f" (+{len(info['claims']) - 3})" if len(info["claims"]) > 3 else ""
            sample_str = ", ".join(f"`{f}`" for f in sample) + extra
            lines.append(f"| {tactic} | **{tid}** {info['name']} | {len(info['claims'])} | {sample_str} |")
    return "\n".join(lines)


def render_triage(triage_rows: list, mem_filename: str | None, corrob: dict, mem_pid_attrs: dict, heading_level: int = 2) -> str:
    """Triage table with a Validation Depth column showing per-PID spot-check coverage."""
    h = "#" * heading_level
    lines = [f"{h} Triage (top 10 PIDs by score)", ""]
    if not triage_rows:
        lines.append("_No memory-agent triage available._")
        return "\n".join(lines)
    lines.append(f"_Source: `{mem_filename}` (latest memory claim)._")
    lines.append("")
    lines.append("| Score | PID | Process | YARA | Cross-corroboration | Validation depth | High-conf? |")
    lines.append("|---|---|---|---|---|---|---|")
    for r in triage_rows[:10]:
        rules = ", ".join(r["yara_rules"]) if r["yara_rules"] else "(none)"
        n_claims = len(corrob.get(r["pid"], []))
        corro_badge = "**🔗 multi-claim**" if n_claims >= 2 else "single-source"
        hc = "🔴" if r["score"] >= 70 else ""
        # Validation depth: which fields the source memory claim asserted (and validator verified).
        attrs = mem_pid_attrs.get(r["pid"]) or mem_pid_attrs.get(str(r["pid"])) or {}
        verified_fields = [f for f in ("name", "ppid", "create_time") if attrs.get(f) not in (None, "")]
        if verified_fields:
            depth = f"🟢 {'+'.join(verified_fields)} verified vs graph"
        else:
            depth = "🟡 attr-less (no spot-check coverage)"
        lines.append(f"| {r['score']} | {r['pid']} | {r['name']} | {rules} | {n_claims} ({corro_badge}) | {depth} | {hc} |")
    lines.append("")
    lines.append("_Process names + verified fields agree with the persistent Cognee graph (validator's spot-check passed at ingest). Body-text claims outside frontmatter `pid_attrs` are NOT in the depth column._")
    return "\n".join(lines)


def render_cross_domain(tier_a_claims: list, host: str | None = None, heading_level: int = 2) -> str:
    """Tier-A correlation details. If `host` is provided, restrict to single-host
    correlations belonging to that host (cross-host correlations are rendered separately
    by `render_cross_host_correlations`)."""
    if host is not None:
        tier_a_claims = [c for c in tier_a_claims
                         if _claim_in_host(c, host) and len(_claim_hosts(c)) == 1]
    h = "#" * heading_level
    sub_h = "#" * (heading_level + 1)
    lines = [f"{h} Cross-Domain Correlations (full details)", ""]
    if not tier_a_claims:
        lines.append("_None._")
        return "\n".join(lines)
    for c in tier_a_claims:
        fm = c["frontmatter"]
        lines.append(f"{sub_h} `{fm.get('claim_id', '?')}` — {fm.get('correlation_type', '?')}")
        lines.append("")
        lines.append(c["body"].strip())
        lines.append("")
        lines.append(f"_Source claim file: `{c['filename']}`_")
        lines.append("")
    return "\n".join(lines)


def render_cross_host_summary(claims: list) -> str:
    """Top-level table: host × claim-count × Tier-A-count × top finding-types.
    Always renders, but flags single-host cases as such so the section is informative
    even when only one host is in scope."""
    hosts = _hosts_in_corpus(claims)
    lines = ["## Cross-Host Summary", ""]
    if not hosts:
        lines.append("_No host-attributed claims in corpus._")
        return "\n".join(lines)
    if len(hosts) == 1:
        lines.append(f"_Single-host case: `{hosts[0]}`. Cross-host correlation rules require ≥2 hosts to fire._")
    else:
        lines.append(f"_{len(hosts)} hosts present in this case. Per-host findings are detailed below in the **Per-Host Reports** section._")
    lines.append("")
    lines.append("| Host | Claims | Tier-A | Top finding types |")
    lines.append("|---|---:|---:|---|")
    for host in hosts:
        host_claims = [c for c in claims if _claim_in_host(c, host)]
        n_tier_a = sum(1 for c in host_claims if claim_tier(c) == "A" and is_security_finding(c))
        type_counts: Counter = Counter()
        for c in host_claims:
            for m in _FINDING_TYPE_RE.finditer(c.get("body", "")):
                token = m.group(1) or m.group(2)
                if token:
                    type_counts[token] += 1
        top = ", ".join(f"`{t}`×{n}" for t, n in type_counts.most_common(3)) or "_(none)_"
        lines.append(f"| `{host}` | {len(host_claims)} | {n_tier_a} | {top} |")
    return "\n".join(lines)


def render_cross_host_correlations(claims: list) -> str:
    """Correlations that span ≥2 hosts — `shared_sha1`, `shared_masquerade`,
    `shared_external_ip`, `shared_internal_ip`, `shared_c2_endpoint`,
    `shared_suspicious_cmdline`. Rendered as its own section because the operational
    meaning (lateral movement / common toolkit / shared C2) is qualitatively different
    from same-host cross-domain correlation. Includes ALL confidence bands — even a
    Tier-B (0.92) shared_masquerade across 2 hosts warrants analyst review, since the
    cross-host predicate alone is high-signal regardless of the per-rule confidence."""
    multi_host = sorted(
        [c for c in claims
         if c["frontmatter"].get("generated_by") == "correlation-agent"
         and len(_claim_hosts(c)) >= 2],
        key=lambda c: -float(c["frontmatter"].get("confidence", 0.0)),
    )
    lines = ["## Cross-Host Correlations", ""]
    if not multi_host:
        lines.append("_No correlations span multiple hosts._")
        return "\n".join(lines)
    lines.append(
        f"_{len(multi_host)} correlation(s) span ≥2 hosts (confidence range "
        f"{min(float(c['frontmatter'].get('confidence', 0.0)) for c in multi_host):.2f}–"
        f"{max(float(c['frontmatter'].get('confidence', 0.0)) for c in multi_host):.2f}). "
        "These are the strongest single signal of lateral movement or shared attacker tooling — "
        "investigate before per-host triage._"
    )
    lines.append("")
    for c in multi_host:
        fm = c["frontmatter"]
        hosts = sorted(_claim_hosts(c))
        attack_tags = _format_attack_brackets(_techniques_for_claim(c))
        conf = fm.get("confidence", "?")
        lines.append(f"### `{fm.get('claim_id', '?')}` — {fm.get('correlation_type', '?')} (confidence {conf}){attack_tags}")
        lines.append("")
        lines.append(f"_Hosts: {', '.join(f'`{h}`' for h in hosts)}_")
        lines.append("")
        lines.append(c["body"].strip())
        lines.append("")
        lines.append(f"_Source claim file: `{c['filename']}`_")
        lines.append("")
    return "\n".join(lines)


def render_per_host_section(claims: list, host: str, tier_a_claims: list) -> str:
    """One host's full per-host slice: triage + per-host cross-domain correlations
    + findings-by-domain. Headings are demoted one level below the section header."""
    triage_rows, mem_filename, mem_pid_attrs = latest_memory_triage(claims, host=host)
    corrob = build_pid_corroboration([c for c in claims if _claim_in_host(c, host)])
    parts = [
        f"### Host: `{host}`",
        "",
        render_attack_coverage(claims, host=host, heading_level=4),
        "",
        render_triage(triage_rows, mem_filename, corrob, mem_pid_attrs, heading_level=4),
        "",
        render_cross_domain(tier_a_claims, host=host, heading_level=4),
        "",
        render_findings_by_domain(claims, host=host, heading_level=4),
    ]
    return "\n".join(parts)


def render_findings_by_domain(claims: list, host: str | None = None, heading_level: int = 2) -> str:
    if host is not None:
        claims = [c for c in claims if _claim_in_host(c, host)]
    by_gen = defaultdict(list)
    for c in claims:
        by_gen[c["frontmatter"].get("generated_by", "?")].append(c)
    domain_groups = [
        ("Memory", "memory-agent"),
        ("Disk / Registry", "registry-agent"),
        ("Event Log", "evtx-agent"),
        ("Disk Image Extraction", "disk-image-agent"),
    ]
    h = "#" * heading_level
    sub_h = "#" * (heading_level + 1)
    lines = [f"{h} Findings by Domain", ""]
    for label, gen in domain_groups:
        cs = by_gen.get(gen, [])
        if not cs:
            continue
        # Sort by anomaly_count desc, then claim_id
        cs.sort(key=lambda c: (
            -(c["frontmatter"].get("anomaly_count") or 0),
            c["filename"],
        ))
        total_anomalies = sum(c["frontmatter"].get("anomaly_count", 0) for c in cs)
        lines.append(f"{sub_h} {label} ({len(cs)} claim(s), {total_anomalies} anomaly(ies) total)")
        lines.append("")
        for c in cs[:8]:  # cap per-domain
            fm = c["frontmatter"]
            extra_bits = []
            if fm.get("anomaly_count") is not None:
                extra_bits.append(f"{fm['anomaly_count']} anomaly(ies)")
            if fm.get("hive_kind"):
                extra_bits.append(f"hive={fm['hive_kind']}")
            if fm.get("log_name"):
                extra_bits.append(f"log={fm['log_name']}")
            if fm.get("event_count_total"):
                extra_bits.append(f"events_scanned={fm['event_count_total']}")
            extras = " | ".join(extra_bits)
            lines.append(f"- `{c['filename']}` — confidence {fm.get('confidence')} | {extras}")
        if len(cs) > 8:
            lines.append(f"- _…({len(cs) - 8} more, see appendix)_")
        lines.append("")
    return "\n".join(lines).rstrip()


def _build_process_execution_index(claims: list) -> list[dict]:
    """Aggregate per-(host, basename) ProcessExecution view from claim frontmatter.

    Each claim's `execution_attrs` map contributes one observation per entity. We
    union paths/sources/run_times/etc. across all claims, mirroring what the
    orchestrator's extractor merges into the Cognee graph (so this report view
    matches what a graph-side query like `MATCH (n:ProcessExecution) ...` would see).
    """
    index: dict[tuple[str, str], dict] = {}
    for c in claims:
        attrs_map = c["frontmatter"].get("execution_attrs") or {}
        for entity_id, attrs in attrs_map.items():
            if not isinstance(attrs, dict) or not isinstance(entity_id, str):
                continue
            parts = entity_id.split(":", 2)
            if len(parts) != 3 or parts[0] != "process_execution":
                continue
            host, basename = parts[1], parts[2]
            entry = index.setdefault((host, basename), {
                "host": host, "basename": basename,
                "paths": set(), "sources": set(),
                "run_times": set(), "sha1s": set(), "publishers": set(),
                "claim_count": 0,
            })
            if attrs.get("executable_path"):
                entry["paths"].add(attrs["executable_path"])
            if attrs.get("source"):
                entry["sources"].add(attrs["source"])
            for rt in attrs.get("run_times") or []:
                entry["run_times"].add(rt)
            if attrs.get("sha1"):
                entry["sha1s"].add(attrs["sha1"])
            if attrs.get("publisher"):
                entry["publishers"].add(attrs["publisher"])
            entry["claim_count"] += 1
    return list(index.values())


def render_process_execution_index(claims: list) -> str:
    """Multi-source ProcessExecution view derived from claim aggregation. Surfaces
    multi-path basenames as masquerade candidates (same exe at canonical AND
    non-canonical paths is the canonical Windows-binary masquerade signature)."""
    rows = _build_process_execution_index(claims)
    lines = ["## Multi-Source ProcessExecution Index", ""]
    if not rows:
        lines.append("_No ProcessExecution entities observed in this corpus._")
        return "\n".join(lines)

    # Sort: most multi-source first, then most multi-path, then most claims.
    rows.sort(key=lambda r: (-len(r["sources"]), -len(r["paths"]), -r["claim_count"]))

    multi_source = sum(1 for r in rows if len(r["sources"]) >= 2)
    multi_path = sum(1 for r in rows if len(r["paths"]) >= 2)

    lines.append(
        f"_Per-(host, basename) cross-source aggregation. "
        f"**{len(rows)}** unique basenames; **{multi_source}** corroborated by 2+ sources; "
        f"**{multi_path}** with 2+ paths (masquerade candidates — same exe basename living "
        f"at multiple paths means at least one is non-canonical). Rows sorted by "
        f"sources × paths × citations descending; multi-path rows are bolded._"
    )
    lines.append("")
    lines.append("| Host | Basename | Sources | Paths | Runs | SHA1s | Publishers |")
    lines.append("|---|---|---|---:|---:|---|---|")
    cap = 50
    for r in rows[:cap]:
        sources = ", ".join(sorted(r["sources"])) or "(none)"
        paths_list = sorted(r["paths"])
        if len(paths_list) <= 2:
            paths_str = "; ".join(f"`{p}`" for p in paths_list) or "(none)"
        else:
            paths_str = "; ".join(f"`{p}`" for p in paths_list[:2]) + f" (+{len(paths_list) - 2} more)"
        sha1_str = ", ".join(sorted(r["sha1s"])[:1]) or "(none)"
        pub_str = ", ".join(sorted(r["publishers"])) or "(none)"
        bold = "**" if len(r["paths"]) >= 2 else ""
        lines.append(
            f"| `{r['host']}` | {bold}`{r['basename']}`{bold} | {sources} | "
            f"{paths_str} | {len(r['run_times'])} | {sha1_str} | {pub_str} |"
        )
    if len(rows) > cap:
        lines.append("")
        lines.append(f"_…({len(rows) - cap} more basenames truncated; see `evidence/claims/done/` for full data)_")
    return "\n".join(lines)


def render_recommendations(tier_a_claims: list, claims: list) -> str:
    """Deterministic suggestions based on which detector types fired anywhere in the corpus."""
    lines = ["## Recommended Next Actions", ""]
    fired_types = set()
    for c in claims:
        body = c["body"].lower()
        for marker in ("masquerade_run_value", "masquerade_service_imagepath",
                       "interactive_remote_logon", "audit_log_cleared",
                       "service_install", "process_create_suspicious_cmdline",
                       "appinit_dlls", "ifeo_debugger", "injection",
                       "cross_domain_persistence", "cross_domain_service_persistence"):
            if marker in body:
                fired_types.add(marker)

    suggestions: list = []
    if "cross_domain_persistence" in fired_types or "cross_domain_service_persistence" in fired_types:
        suggestions.append("**Isolate the host** — cross-domain corroboration indicates an established foothold (memory + on-disk persistence).")
    if "injection" in fired_types or "masquerade_run_value" in fired_types:
        suggestions.append("Preserve the memory dump and dumped VAD regions in `evidence/dumps/` for offline reverse-engineering.")
    if "interactive_remote_logon" in fired_types:
        suggestions.append("Pull additional 4624/4625 events from the Security log; cross-reference source IPs against firewall logs and threat intel.")
    if "audit_log_cleared" in fired_types:
        suggestions.append("**Audit log clearing detected** — assume anti-forensics. Pull volume shadow copies if present; check backup logs.")
    if "appinit_dlls" in fired_types or "ifeo_debugger" in fired_types:
        suggestions.append("Triage AppInit_DLLs / IFEO debugger entries — these load into multiple processes; inspect each referenced DLL.")
    if "service_install" in fired_types:
        suggestions.append("Cross-reference each 4697/7045 service install with the registry agent's findings on `\\Services\\` keys.")
    if not suggestions:
        suggestions.append("_No detector signatures fired strongly enough to recommend specific actions. Review individual claims._")

    for s in suggestions:
        lines.append(f"- {s}")
    return "\n".join(lines)


def render_appendix(claims: list) -> str:
    by_gen = defaultdict(list)
    for c in claims:
        by_gen[c["frontmatter"].get("generated_by", "?")].append(c)
    lines = ["## Appendix: All Claims (full inventory)", "",
             "_For evidence-chain completeness; lower-confidence claims are listed here._", ""]
    for gen in sorted(by_gen):
        cs = sorted(by_gen[gen], key=lambda c: c["filename"])
        lines.append(f"### {gen} ({len(cs)} claim(s))")
        lines.append("")
        for c in cs:
            fm = c["frontmatter"]
            tier = claim_tier(c)
            lines.append(f"- [Tier {tier}] `{c['filename']}` — id `{fm.get('claim_id', '?')}` | conf {fm.get('confidence')}")
        lines.append("")
    return "\n".join(lines).rstrip()


def render_confidence_architecture() -> str:
    """Explicit, honest list of what is and is not validated. Lets the analyst trust
    the report exactly as much as it deserves — no more, no less."""
    return "\n".join([
        "## Confidence Architecture",
        "",
        "_What this report's spot-check actively guarantees, and where the gaps remain. "
        "Read this before treating any single claim as ground truth._",
        "",
        "**Verified at validator pass (claim cannot reach `done/` without these passing):**",
        "",
        "- ✅ Frontmatter `pid_attrs` / `key_attrs` / `event_attrs` field-by-field match the persistent Cognee graph "
        "(multi-field: name + ppid + create_time for processes; value + value_type for registry; event_id + channel + time_created for events).",
        "- ✅ Inline body `**PID X** (name)` patterns match the graph's Process.name (catches the 'honest frontmatter, lying body' attack).",
        "- ✅ Claims asserting sentinel values (`unknown`, empty, `?`, `-`) for identity fields are rejected outright.",
        "- ✅ All `evidence_refs` paths exist on disk (catches dangling refs / fabricated evidence pointers).",
        "",
        "**NOT verified — analyst-side scrutiny still required:**",
        "",
        "- ❌ Free-form body text outside the structured `**PID X** (name)` pattern. A claim's prose narrative can lie freely.",
        "- ❌ Fields beyond the spot-check coverage list (e.g., `command_line`, `hexdump`, registry value contents > 256 chars).",
        "- ❌ Whether the underlying tool output (vol3 JSON, RECmd JSON, EvtxECmd JSON) faithfully reflects the original evidence — we trust the tools.",
        "- ❌ Selective omission in this report itself. A curated finding-not-shown is invisible to the validator.",
        "- ❌ Tamper-evidence on the claim files themselves. A drop-in markdown attack (writing a fake claim straight to `claims/todo/`) is technically possible. (Cryptographic agent signing would close this; deferred.)",
        "",
        "**Strongest non-spot-check trust signal: cross-claim corroboration.**",
        "A finding cited by a single source claim could plausibly be undetected fabrication. "
        "A finding cited by 5+ distinct claims would require coordinated fabrication across multiple agents — "
        "much harder. The Triage table's 'Cross-corroboration' column is your best heuristic for trustworthiness "
        "beyond the validator's spot-check.",
    ])


async def render_visualization(report_ts: str) -> Path | None:
    """Call cognee.visualize_graph; return the output Path or None on failure."""
    try:
        import cognee
    except ImportError:
        return None
    out_path = REPORTS_ROOT / f"case_graph_{report_ts}.html"
    try:
        await cognee.visualize_graph(destination_file_path=str(out_path))
    except Exception as e:
        print(f"   ⚠️  cognee.visualize_graph failed: {e!r}")
        return None
    if not out_path.exists():
        return None
    return out_path


def render_report(claims: list, in_flight_todo: int, viz_path: Path | None, report_ts: str) -> str:
    # Tier A in the executive summary = high-confidence SECURITY findings only.
    # Manifest claims (disk-image-agent) have confidence 1.0 because extraction is
    # mechanical, not a finding — exclude them from the summary, keep them in the
    # appendix for provenance.
    tier_a = sorted(
        [c for c in claims if claim_tier(c) == "A" and is_security_finding(c)],
        key=lambda c: c["frontmatter"].get("timestamp", ""), reverse=True,
    )
    hosts = _hosts_in_corpus(claims)

    parts = [
        f"# Case Report — {report_ts}",
        "",
        DISCLAIMER,
        "",
        render_evidence_integrity(report_ts),
        "",
        render_ciso_summary(claims, tier_a, hosts, in_flight_todo),
        "",
        render_validation_status(claims, in_flight_todo),
        "",
        render_executive_summary(tier_a),
        "",
        render_attack_coverage(claims),
        "",
        render_cross_host_summary(claims),
        "",
        render_cross_host_correlations(claims),
        "",
        "## Per-Host Reports",
        "",
    ]
    if hosts:
        for host in hosts:
            parts.append(render_per_host_section(claims, host, tier_a))
            parts.append("")
    else:
        # Fallback: no host attribution at all — flat triage + findings + correlations.
        triage_rows, mem_filename, mem_pid_attrs = latest_memory_triage(claims)
        corrob = build_pid_corroboration(claims)
        parts.extend([
            "_No host attribution in claim frontmatter — rendering as a single flat case._",
            "",
            render_triage(triage_rows, mem_filename, corrob, mem_pid_attrs, heading_level=3),
            "",
            render_cross_domain(tier_a, heading_level=3),
            "",
            render_findings_by_domain(claims, heading_level=3),
            "",
        ])
    parts.extend([
        render_process_execution_index(claims),
        "",
        render_recommendations(tier_a, claims),
        "",
        "## Graph",
        "",
        (f"Cognee typed-graph visualization: `{viz_path.relative_to(REPORTS_ROOT.parent) if viz_path else 'NOT GENERATED'}`"
         if viz_path else "Visualization not generated this run (see log)."),
        "",
        render_confidence_architecture(),
        "",
        render_appendix(claims),
        "",
    ])
    return "\n".join(parts)


async def run_report():
    print("📝 Report Agent starting (Chisel-confined)...")
    chisel = Chisel(CHISEL_URL, CHISEL_SECRET)
    chisel.connect()
    print(f"🔒 Chisel session → {chisel.endpoint} (sid={chisel.session_id[:8]}…)")

    claims = await load_all_claims(chisel)
    try:
        todo_listing = chisel.shell("ls", ["-1", str(CLAIMS_TODO)])
        in_flight = sum(1 for n in todo_listing.splitlines() if n.strip().endswith(".md"))
    except RuntimeError:
        in_flight = 0
    print(f"📂 Loaded {len(claims)} claims from done/; {in_flight} pending in todo/")

    REPORTS_ROOT.mkdir(parents=True, exist_ok=True)
    # Use orchestrator-supplied CASE_ID so reports/case_{ts}.md and the per-case
    # Cognee paths under evidence/audit/<ts>/ share the same timestamp. Falls
    # back to a fresh ts for standalone runs (e.g. ad-hoc debugging).
    ts = os.environ.get("FINDEVIL_CASE_ID") or datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    print("🎨 Rendering Cognee graph...")
    viz_path = await render_visualization(ts)
    if viz_path:
        print(f"   → {viz_path}")

    report_md = render_report(claims, in_flight, viz_path, ts)
    md_path = REPORTS_ROOT / f"case_{ts}.md"
    md_path.write_text(report_md, encoding="utf-8")
    print(f"✅ Report written → {md_path}")
    # Findings count mirrors the executive-summary filter (is_security_finding)
    # so the CLI line cannot drift from what the report actually displays.
    # Manifests are surfaced separately as a parenthetical for transparency.
    n_findings = {t: sum(1 for c in claims if claim_tier(c) == t and is_security_finding(c))
                  for t in ("A", "B", "C", "D")}
    n_manifests = sum(1 for c in claims if not is_security_finding(c))
    manifest_note = (f" (+{n_manifests} extraction manifest{'s' if n_manifests != 1 else ''})"
                     if n_manifests else "")
    print(f"   {len(report_md):,} chars; findings: " + ", ".join(
        f"{t}={n_findings[t]}" for t in ("A", "B", "C", "D")
    ) + manifest_note)


if __name__ == "__main__":
    asyncio.run(run_report())
