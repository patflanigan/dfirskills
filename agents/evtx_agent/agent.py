# agents/evtx_agent/agent.py
"""
Event-log Agent — analyses a single Windows .evtx file for incident-triage signals.

Standalone CLI:  python -m agents.evtx_agent.agent
Orchestrator:    await run_evtx_analysis(evtx=Path(...))

Tool: EvtxECmd (`dotnet /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll`) per the SIFT
windows-artifacts skill. Output is JSON Lines (UTF-8 BOM); each line is one event
with `EventId`, `Channel`, `RecordNumber`, `TimeCreated`, `Payload` (nested JSON
string), plus `PayloadData1..6` flat-string conveniences.

Detector set (initial — tight, low FP):
- audit_log_cleared (1102) — always fires
- service_install (4697 / 7045) — always fires
- process_create_user_writable_path (4688) — NewProcessName under \\Users\\, \\Temp\\, etc.
- process_create_suspicious_cmdline (4688) — anti-forensic patterns
- account_create (4720) — always fires
- privileged_group_change (4732/4733 with privileged GroupName) — always fires
- interactive_remote_logon (4624 LogonType=10) — RDP
- new_credentials_logon (4624 LogonType=9) — runas /netonly, pass-the-hash territory
"""

import asyncio
import hashlib
import ipaddress
import json
import os
import re
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import yaml

from agents._chisel import Chisel
from cognee_schema.schema import derive_host_id

EVIDENCE_ROOT = Path(os.environ.get("EVIDENCE_ROOT", "/home/sansforensics/dfirskills2/evidence"))
EVIDENCE_NEW = EVIDENCE_ROOT / "new"
CLAIMS_TODO = EVIDENCE_ROOT / "claims/todo"

CHISEL_URL = os.environ.get("CHISEL_URL", "http://127.0.0.1:3000")
CHISEL_SECRET = os.environ["CHISEL_SECRET"]

EVTXECMD = ["dotnet", "/opt/zimmermantools/EvtxeCmd/EvtxECmd.dll"]

# 4624 PayloadData2 contains "LogonType N"
LOGONTYPE_RE = re.compile(r"LogonType\s+(\d+)")

# 4688 cmdline patterns flagged as anti-forensic / off-the-shelf abuse.
SUSPICIOUS_CMDLINE_PATTERNS = [
    re.compile(r"\bpowershell\b.*\b(-enc|-encodedcommand|-w\s+hidden|frombase64string)\b", re.I),
    re.compile(r"\bmshta\b.*\bhttps?://", re.I),
    re.compile(r"\bwmic\b.*\b(process\s+call\s+create|shadowcopy\s+delete)\b", re.I),
    re.compile(r"\bvssadmin\b.*\bdelete\b.*\bshadows\b", re.I),
    re.compile(r"\bnet\s+user\b.*/add\b", re.I),
    re.compile(r"[A-Za-z0-9+/]{200,}={0,2}"),  # bare base64 blob > 200 chars
]
USER_WRITABLE_PATH_HINTS = (
    "\\users\\", "\\appdata\\", "\\temp\\", "\\programdata\\", "\\public\\", "\\$recycle.bin\\",
)
PRIVILEGED_GROUPS = {
    "administrators", "backup operators", "remote desktop users",
    "domain admins", "enterprise admins", "schema admins", "account operators",
}

# PowerShell 4104 — script-block logging. These patterns target the most common
# PS-based attacker tradecraft: encoded payloads, in-memory loaders, AMSI bypasses,
# Defender-disable cmdlets, web download cradles. Patterns are deliberately broad —
# some legitimate sysadmin scripts will trigger; that's the right tradeoff for
# catching Meterpreter / CobaltStrike / Empire-style payloads which use these patterns
# heavily.
SUSPICIOUS_PS_PATTERNS = [
    re.compile(r"\b(?:iex|invoke-expression)\b\s*\(", re.I),                            # IEX(... loader
    re.compile(r"\b(?:invoke-webrequest|invoke-restmethod|iwr|irm)\b.*\bhttps?://", re.I),
    re.compile(r"\.downloadstring\s*\(", re.I),                                         # WebClient.DownloadString
    re.compile(r"\.downloadfile\s*\(", re.I),
    re.compile(r"\.downloaddata\s*\(", re.I),
    re.compile(r"\bfrombase64string\s*\(", re.I),
    re.compile(r"\bnew-object\s+(?:net\.webclient|system\.net\.webclient)", re.I),
    re.compile(r"\b-encodedcommand\b|\b-enc\b\s|\s-e\s+[A-Za-z0-9+/=]{40,}", re.I),
    re.compile(r"amsiInitFailed", re.I),                                                # AMSI bypass marker
    re.compile(r"\[ref\]\.assembly\.gettype\s*\(", re.I),                               # AMSI/AmsiUtils bypass cradle
    re.compile(r"\[reflection\.assembly\]::load\b", re.I),                              # in-memory assembly load
    re.compile(r"set-mppreference\s+-disablerealtimemonitoring", re.I),                 # Defender disable
    re.compile(r"add-mppreference\s+-exclusionpath\b", re.I),                           # Defender exclusion add
    re.compile(r"[A-Za-z0-9+/]{200,}={0,2}", re.I),                                     # bare base64 blob ≥200 chars
]

# 4672 — Special privileges assigned. Filter out built-in service accounts so we don't
# flood the analyst with one finding per system service start (LocalSystem gets these
# every reboot, every service spawn, every admin tool launch).
BUILTIN_SERVICE_ACCOUNTS = {
    "system", "local system", "networkservice", "network service",
    "localservice", "local service", "anonymous logon",
}
HIGH_POWER_PRIVILEGES = {
    "sedebugprivilege",          # process injection / token theft
    "seimpersonateprivilege",    # token impersonation (potato attacks)
    "setcbprivilege",            # act as part of OS
    "setakeownershipprivilege",  # bypass file/key ACLs
    "sebackupprivilege",         # read any file (NTDS.dit dump)
    "serestoreprivilege",        # write any file
    "seloaddriverprivilege",     # kernel-mode access
    "secreatetokenprivilege",    # mint arbitrary tokens
}

# 4625 burst-detection thresholds. Sliding window per source IP so a single attacker
# spraying many usernames from one IP is caught even though no individual user has 10
# failures. Conservative threshold — legitimate users rarely hit 10 fails in 5 min.
FAILED_LOGON_BURST_WINDOW_MIN = 5
FAILED_LOGON_BURST_THRESHOLD = 10

# 7036 — Service Control Manager state changes. We surface ONLY VSS-related services
# entering the "stopped" state. Pre-encryption ransomware tradecraft typically stops
# Volume Shadow Copy + Microsoft Software Shadow Copy Provider so existing snapshots
# can't be used for recovery. False-positive risk: VSS legitimately stops on graceful
# shutdown — this detector pairs with ransomware findings via the cross-domain
# correlation rule rather than firing as a standalone Tier-A signal.
VSS_SERVICE_NAMES = {
    "volume shadow copy",   # display name
    "vss",                  # service name (short form)
    "swprv",                # Microsoft Software Shadow Copy Provider
    "windows backup",       # SDRSVC display name
    "wbengine",             # Block-level Backup Engine
}

# ─── Active Directory / DC attack detection ─────────────────────────
# Kerberos encryption type values reported in 4768/4769 TicketEncryptionType.
# RC4-HMAC (0x17) is the roasting target — the ticket fragment is brute-forceable
# offline because RC4 doesn't include a salt. AES-128/256 (0x11/0x12) cannot be
# practically roasted, so requests using those etypes don't qualify.
KERBEROS_RC4_ETYPE = "0x17"
KERBEROS_AES_ETYPES = {"0x11", "0x12"}

# Per-IP burst detection for Kerberoasting (4769 TGS requests). Same shape as
# FAILED_LOGON_BURST_*. Lower threshold/window because legitimate Kerberos chatter
# rarely produces many RC4 TGS requests for non-krbtgt SPNs in a short period.
KERBEROAST_BURST_THRESHOLD = 5
KERBEROAST_BURST_WINDOW_S = 60

# Active Directory replication-rights GUIDs — observed in 4662 Properties when an
# account requests credential replication (DCSync). Granted to DCs and to
# delegated-replication accounts; non-DC subjects requesting these is the attack
# fingerprint of mimikatz `lsadump::dcsync` / impacket `secretsdump.py -ntds`.
DSREPLICATION_GUIDS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes-All
    "89e95b76-444d-4c62-991a-0facbeda640c",  # DS-Replication-Get-Changes-In-Filtered-Set
}

# Process names allowed to read NTDS.dit. Anything else (4663 file access on
# `\NTDS\ntds.dit`) is a credential-dumping signal — `ntdsutil ifm`, `secretsdump`,
# `vssadmin`-mounted-shadow reads, etc.
NTDS_TRUSTED_PROCESSES = {"lsass.exe", "ntds.exe", "services.exe", "system"}
NTDS_PATH_MARKER = "\\ntds\\ntds.dit"


def detect_log_kind(evtx_path: Path) -> str:
    """Recover the channel/log name from the staged or bare filename.
    Examples:
      'win7-...__evtx_Security.evtx'                       → 'Security'
      'Microsoft-Windows-PowerShell%4Operational.evtx'     → 'Microsoft-Windows-PowerShell%4Operational'
    """
    name = evtx_path.name
    if "__evtx_" in name:
        name = name.rsplit("__evtx_", 1)[1]
    if name.lower().endswith(".evtx"):
        name = name[: -len(".evtx")]
    return name


async def run_evtxecmd(evtx_path: Path, out_dir: Path) -> Path | None:
    """Invoke EvtxECmd via local subprocess; return the path to its produced .json
    file or None. EvtxECmd may exit non-zero on logs with chunk errors but still
    produces a file — we do not gate on exit_code, only on file presence.

    INTENTIONAL EXCEPTION to the route-through-Chisel rule. The EvtxECmd .dll
    lives at /opt/zimmermantools/EvtxeCmd/EvtxECmd.dll — outside Chisel's --root
    (/home/.../evidence). Chisel's path-confinement (validate_path) rejects any
    arg outside --root, so chisel.exec_tool("dotnet", ["/opt/zimmermantools/...",
    ...]) is rejected with `security error: resolved path is outside configured
    root`. Same root cause as the icat exception in disk_image_agent.extract_file
    — tool binaries that ship outside the evidence tree can't be argued through
    Chisel without either reorganizing the filesystem (bind mount, copy-into-
    evidence) or extending Chisel itself (--tool-root flag). We accept the
    audit-log gap for these tool invocations in exchange for keeping the agents
    simple. Sister exceptions: mft_agent (MFTECmd, RBCmd), registry_agent
    (RECmd, AmcacheParser, AppCompatCacheParser), memory_agent (yara, yarac).
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    proc = await asyncio.create_subprocess_exec(
        *EVTXECMD, "-f", str(evtx_path), "--json", str(out_dir),
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    await proc.communicate()
    files = sorted(out_dir.glob("*.json"))
    return files[-1] if files else None


def _payload_field(ev: dict, field_name: str) -> str | None:
    """Pull a named field out of the nested Payload JSON string."""
    p = ev.get("Payload")
    if not isinstance(p, str):
        return None
    try:
        parsed = json.loads(p)
    except json.JSONDecodeError:
        return None
    data = parsed.get("EventData", {}) if isinstance(parsed.get("EventData"), dict) else {}
    items = data.get("Data", []) if isinstance(data, dict) else []
    if isinstance(items, list):
        for item in items:
            if isinstance(item, dict) and item.get("@Name") == field_name:
                return item.get("#text")
    return None


def _parse_evtx_ts(s) -> datetime | None:
    """EvtxECmd emits ISO8601 strings like '2012-04-03 22:21:31.4084488' or with 'T' /
    trailing 'Z'. Truncate sub-microsecond precision (Python only accepts up to 6 digits)
    and force UTC if naive (Windows event logs are UTC by convention)."""
    if not s or not isinstance(s, str):
        return None
    iso = s.strip().replace(" ", "T", 1)
    if iso.endswith("Z"):
        iso = iso[:-1] + "+00:00"
    if "." in iso:
        head, frac = iso.rsplit(".", 1)
        if "+" in frac:
            frac, off = frac.split("+", 1)
            iso = f"{head}.{frac[:6]}+{off}"
        else:
            iso = f"{head}.{frac[:6]}"
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        return None
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt


def detect_evtx_anomalies(events: list) -> list:
    findings: list = []
    failed_logons: list[dict] = []   # 4625 events for post-loop burst detection
    kerb_tgs_events: list[dict] = [] # 4769 RC4 candidates for post-loop kerberoasting burst
    for ev in events:
        eid = ev.get("EventId")
        rec = ev.get("RecordNumber") or ev.get("EventRecordId")
        ts = ev.get("TimeCreated")
        chan = ev.get("Channel")
        common = {"event_id": eid, "record_number": rec, "time": ts, "channel": chan}

        if eid == 1102:
            findings.append({"type": "audit_log_cleared", **common})

        elif eid in (4697, 7045):
            findings.append({
                "type": "service_install",
                **common,
                "service": _payload_field(ev, "ServiceName") or "?",
                "image_path": _payload_field(ev, "ImagePath") or _payload_field(ev, "ServiceFileName") or "?",
            })

        elif eid == 4688:
            new_proc = _payload_field(ev, "NewProcessName") or ""
            new_pid = _payload_field(ev, "NewProcessId") or "?"
            parent = _payload_field(ev, "ParentProcessName") or ""
            cmdline = _payload_field(ev, "CommandLine") or ""

            np_l = new_proc.lower()
            if any(h in np_l for h in USER_WRITABLE_PATH_HINTS):
                findings.append({
                    "type": "process_create_user_writable_path",
                    **common,
                    "new_process_name": new_proc, "new_process_id": new_pid,
                    "parent_process_name": parent, "command_line": cmdline,
                })
            for pat in SUSPICIOUS_CMDLINE_PATTERNS:
                if pat.search(cmdline):
                    findings.append({
                        "type": "process_create_suspicious_cmdline",
                        **common,
                        "new_process_name": new_proc, "new_process_id": new_pid,
                        "parent_process_name": parent, "command_line": cmdline,
                        "pattern_matched": pat.pattern[:60],
                    })
                    break  # one match per event

        elif eid == 4720:
            findings.append({
                "type": "account_create",
                **common,
                "target_user": _payload_field(ev, "TargetUserName") or "?",
            })

        elif eid in (4732, 4733):
            group = (_payload_field(ev, "TargetUserName") or "").lower()
            if group in PRIVILEGED_GROUPS:
                findings.append({
                    "type": "privileged_group_change",
                    **common,
                    "group": group,
                    "member": _payload_field(ev, "MemberName") or "?",
                })

        elif eid == 4624:
            pd2 = ev.get("PayloadData2") or ""
            m = LOGONTYPE_RE.search(pd2)
            if not m:
                continue
            lt = int(m.group(1))
            if lt == 10:
                findings.append({
                    "type": "interactive_remote_logon",
                    **common,
                    "logon_type": lt,
                    "target_user": _payload_field(ev, "TargetUserName") or "?",
                    "ip_address": _payload_field(ev, "IpAddress") or "?",
                })
            elif lt == 9:
                findings.append({
                    "type": "new_credentials_logon",
                    **common,
                    "logon_type": lt,
                    "target_user": _payload_field(ev, "TargetUserName") or "?",
                    "process_name": _payload_field(ev, "ProcessName") or "?",
                })

        elif eid == 4104:
            # PowerShell script-block log. ScriptBlockText is in the standard
            # EventData.Data array (same structure as Security events) — `_payload_field`
            # handles it. Match against every PS pattern; emit one finding per matched
            # pattern (a payload triggering both encoded-cmd AND base64 blob is two
            # separate signals, both worth surfacing).
            sbt = _payload_field(ev, "ScriptBlockText") or ""
            if not sbt:
                continue
            sbt_truncated = sbt[:300]  # claim body shows a preview, not the full payload
            matched_patterns: list[str] = []
            for pat in SUSPICIOUS_PS_PATTERNS:
                if pat.search(sbt):
                    matched_patterns.append(pat.pattern[:60])
            if matched_patterns:
                findings.append({
                    "type": "powershell_suspicious_scriptblock",
                    **common,
                    "patterns_matched": matched_patterns,
                    "scriptblock_preview": sbt_truncated,
                    "scriptblock_length": len(sbt),
                    # Path / ID of the script block (chained 4104 events form one logical script)
                    "script_block_id": _payload_field(ev, "ScriptBlockId") or "?",
                    "path": _payload_field(ev, "Path") or "(in-memory)",
                })

        elif eid == 4625:
            # Failed logon. Buffered here, processed for burst patterns post-loop so we
            # can sliding-window across the chronologically-sorted set.
            failed_logons.append({
                **common,
                "ts_parsed": _parse_evtx_ts(ts),
                "ip_address": (_payload_field(ev, "IpAddress") or "").strip() or "?",
                "target_user": _payload_field(ev, "TargetUserName") or "?",
                "logon_type": _payload_field(ev, "LogonType") or "?",
                "failure_reason": _payload_field(ev, "Status") or _payload_field(ev, "SubStatus") or "?",
            })

        elif eid == 4672:
            # Special privileges assigned. Filter built-in service accounts (LocalSystem
            # gets these every reboot — pure noise) and require the privilege list to
            # include at least one HIGH_POWER_PRIVILEGES entry. The `PrivilegeList`
            # field is a comma-separated string from EvtxECmd.
            subj = (_payload_field(ev, "SubjectUserName") or "").lower()
            if subj in BUILTIN_SERVICE_ACCOUNTS or subj.endswith("$"):
                # `*$` filters domain-joined computer accounts (WKS-WIN732BITA$ etc.) —
                # these get high privs every boot and aren't analyst-actionable.
                continue
            priv_list_raw = _payload_field(ev, "PrivilegeList") or ""
            priv_set = {p.strip().lower() for p in priv_list_raw.split(",") if p.strip()}
            high_privs = sorted(priv_set & HIGH_POWER_PRIVILEGES)
            if not high_privs:
                continue
            findings.append({
                "type": "special_privilege_assigned",
                **common,
                "subject_user": _payload_field(ev, "SubjectUserName") or "?",
                "subject_domain": _payload_field(ev, "SubjectDomainName") or "?",
                "subject_logon_id": _payload_field(ev, "SubjectLogonId") or "?",
                "high_privileges": high_privs,
                "all_privileges": sorted(priv_set),
            })

        elif eid == 4768:
            # Kerberos AS-REQ (TGT request). AS-REP roasting targets accounts with
            # `Don't require Kerberos pre-authentication` set: the 4768 has
            # PreAuthType=0 AND the encryption is RC4 (only roastable etype). Each
            # such event is high-fidelity — legitimate accounts always preauth.
            pre_auth = (_payload_field(ev, "PreAuthType") or "").strip()
            etype = (_payload_field(ev, "TicketEncryptionType") or "").lower().strip()
            if pre_auth == "0" and etype == KERBEROS_RC4_ETYPE:
                target_user = (_payload_field(ev, "TargetUserName") or "?").strip()
                ip = (_payload_field(ev, "IpAddress") or "").strip().lstrip(":") or "?"
                findings.append({
                    "type": "as_rep_roasting",
                    **common,
                    "client_account": target_user,
                    "kerberos_etype": etype,
                    "ip_address": ip,
                    "pre_auth_type": pre_auth,
                })

        elif eid == 4769:
            # Kerberos TGS-REQ (service ticket request). Kerberoasting requests
            # tickets for SPN-bound service accounts using RC4 so the encrypted
            # ticket fragment can be brute-forced offline. Single requests are
            # noisy (legitimate service traffic); we collect for post-loop burst
            # detection — ≥KERBEROAST_BURST_THRESHOLD requests in
            # KERBEROAST_BURST_WINDOW_S from the same source IP fires.
            etype = (_payload_field(ev, "TicketEncryptionType") or "").lower().strip()
            service = (_payload_field(ev, "ServiceName") or "").strip()
            # `krbtgt` (TGT) and `krbtgt/<DOMAIN>` (referral) are normal Kerberos
            # protocol traffic — always exclude. Roasting targets non-krbtgt SPNs.
            svc_lower = service.lower()
            is_krbtgt = svc_lower == "krbtgt" or svc_lower.startswith("krbtgt/")
            if etype == KERBEROS_RC4_ETYPE and not is_krbtgt:
                target_user = (_payload_field(ev, "TargetUserName") or "?").strip()
                ip = (_payload_field(ev, "IpAddress") or "").strip().lstrip(":") or "?"
                kerb_tgs_events.append({
                    **common,
                    "ts_parsed": _parse_evtx_ts(ts),
                    "ip_address": ip,
                    "service_name": service,
                    "client_account": target_user,
                    "kerberos_etype": etype,
                })

        elif eid == 4662:
            # AD Object Operation. DCSync uses the replication API to pull credentials
            # from a DC; the request shows up here as a 4662 with Properties listing
            # the DS-Replication-Get-Changes GUIDs. DC computer accounts (ending in
            # `$`) legitimately exercise these rights for AD replication — anyone
            # else asking for them is dumping creds.
            properties = (_payload_field(ev, "Properties") or "").lower()
            matched_guids = sorted(g for g in DSREPLICATION_GUIDS if g in properties)
            if not matched_guids:
                continue
            subject_account = (_payload_field(ev, "SubjectUserName") or "?").strip()
            if subject_account.endswith("$"):
                # Legitimate DC-to-DC replication. Suppress.
                continue
            findings.append({
                "type": "dcsync_attempt",
                **common,
                "subject_account": subject_account,
                "subject_domain": (_payload_field(ev, "SubjectDomainName") or "?").strip(),
                "replication_rights": matched_guids,
            })

        elif eid == 4663:
            # Object Access (file read/write/etc). Surface ONLY ntds.dit access from
            # processes outside the trusted AD service set — credential-dumping signal.
            # Requires Object Access auditing enabled on \Windows\NTDS\ (frequently
            # off by default; absence of findings is not absence of attack).
            obj_name = (_payload_field(ev, "ObjectName") or "").lower()
            if NTDS_PATH_MARKER not in obj_name:
                continue
            proc_full = (_payload_field(ev, "ProcessName") or "").lower()
            proc_name = proc_full.rsplit("\\", 1)[-1] if "\\" in proc_full else proc_full
            if proc_name in NTDS_TRUSTED_PROCESSES:
                continue
            findings.append({
                "type": "suspicious_ntds_access",
                **common,
                "accessed_path": obj_name,
                "process_name": proc_name or "?",
                "subject_account": (_payload_field(ev, "SubjectUserName") or "?").strip(),
            })

        elif eid == 7036:
            # Service Control Manager — service entered the X state. Surface only when
            # a VSS-related service stops (pre-encryption ransomware tradecraft). Lives
            # in System.evtx. EvtxECmd's payload uses `param1=ServiceName` + `param2=State`
            # for 7036 — different from EventData.Data array used by Security events.
            svc_name = (_payload_field(ev, "param1") or "").lower().strip()
            svc_state = (_payload_field(ev, "param2") or "").lower().strip()
            if svc_state == "stopped" and svc_name in VSS_SERVICE_NAMES:
                findings.append({
                    "type": "vss_service_stopped",
                    **common,
                    "service": svc_name,
                    "state": svc_state,
                })

    # Post-loop: 4625 burst detection. Sliding window per source IP.
    if failed_logons:
        findings.extend(_detect_failed_logon_bursts(failed_logons))
    # Post-loop: 4769 RC4-TGS burst detection (Kerberoasting).
    if kerb_tgs_events:
        findings.extend(_detect_kerberoasting_bursts(kerb_tgs_events))
    return findings


def _detect_failed_logon_bursts(events: list[dict]) -> list[dict]:
    """Group 4625 events by source IP, sort each group chronologically, then sliding-
    window for ≥FAILED_LOGON_BURST_THRESHOLD events within FAILED_LOGON_BURST_WINDOW_MIN
    minutes. Each qualifying window emits ONE burst finding (greedy — we don't try to
    enumerate every overlapping window; emit at the threshold-crossing point and skip
    forward by the window length).
    """
    out: list[dict] = []
    window = timedelta(minutes=FAILED_LOGON_BURST_WINDOW_MIN)
    by_ip: dict[str, list[dict]] = {}
    for ev in events:
        if not ev.get("ts_parsed"):
            continue
        by_ip.setdefault(ev["ip_address"], []).append(ev)
    for ip, evs in by_ip.items():
        if len(evs) < FAILED_LOGON_BURST_THRESHOLD:
            continue
        evs.sort(key=lambda e: e["ts_parsed"])
        i = 0
        while i < len(evs) - FAILED_LOGON_BURST_THRESHOLD + 1:
            start = evs[i]["ts_parsed"]
            # Find the earliest j where evs[j].ts > start + window
            j = i
            while j < len(evs) and (evs[j]["ts_parsed"] - start) <= window:
                j += 1
            n_in_window = j - i
            if n_in_window >= FAILED_LOGON_BURST_THRESHOLD:
                window_evs = evs[i:j]
                target_users = sorted({e["target_user"] for e in window_evs})
                logon_types = sorted({str(e["logon_type"]) for e in window_evs})
                out.append({
                    "type": "failed_logon_burst",
                    "event_id": 4625,
                    "channel": window_evs[0]["channel"],
                    "record_number": window_evs[0]["record_number"],  # first event in burst
                    "time": window_evs[0]["time"],                     # ditto
                    "ip_address": ip,
                    "fail_count": n_in_window,
                    "window_minutes": FAILED_LOGON_BURST_WINDOW_MIN,
                    "first_failure_time": window_evs[0]["time"],
                    "last_failure_time": window_evs[-1]["time"],
                    "target_users": target_users,           # password spray if many distinct users
                    "logon_types": logon_types,
                })
                i = j  # skip past this burst's window
            else:
                i += 1
    return out


def _detect_kerberoasting_bursts(events: list[dict]) -> list[dict]:
    """Per-source-IP sliding window over RC4-TGS requests (4769 candidates collected
    from `detect_evtx_anomalies`). Same shape as `_detect_failed_logon_bursts` but
    with shorter window (60s) and lower threshold (5) — Kerberoasting tooling
    (`Rubeus kerberoast`, `GetUserSPNs.py`) typically blasts SPNs in seconds. Each
    qualifying window emits one finding with the full SPN list in `services_targeted`.
    """
    out: list[dict] = []
    window = timedelta(seconds=KERBEROAST_BURST_WINDOW_S)
    by_ip: dict[str, list[dict]] = {}
    for ev in events:
        if not ev.get("ts_parsed"):
            continue
        by_ip.setdefault(ev["ip_address"], []).append(ev)
    for ip, evs in by_ip.items():
        if len(evs) < KERBEROAST_BURST_THRESHOLD:
            continue
        evs.sort(key=lambda e: e["ts_parsed"])
        i = 0
        while i < len(evs) - KERBEROAST_BURST_THRESHOLD + 1:
            start = evs[i]["ts_parsed"]
            j = i
            while j < len(evs) and (evs[j]["ts_parsed"] - start) <= window:
                j += 1
            n_in_window = j - i
            if n_in_window >= KERBEROAST_BURST_THRESHOLD:
                window_evs = evs[i:j]
                services_targeted = sorted({e["service_name"] for e in window_evs if e.get("service_name")})
                client_accounts = sorted({e["client_account"] for e in window_evs if e.get("client_account")})
                out.append({
                    "type": "kerberoasting_burst",
                    "event_id": 4769,
                    "channel": window_evs[0]["channel"],
                    "record_number": window_evs[0]["record_number"],
                    "time": window_evs[0]["time"],
                    "ip_address": ip,
                    "tgs_count": n_in_window,
                    "window_seconds": KERBEROAST_BURST_WINDOW_S,
                    "first_request_time": window_evs[0]["time"],
                    "last_request_time": window_evs[-1]["time"],
                    "services_targeted": services_targeted,  # one per SPN — fan-out = signal
                    "client_accounts": client_accounts,
                    "kerberos_etype": KERBEROS_RC4_ETYPE,
                })
                i = j
            else:
                i += 1
    return out


def _process_id_int(v) -> int | None:
    if v is None:
        return None
    s = str(v).strip()
    if not s or s in ("?", "-"):
        return None
    try:
        return int(s, 16) if s.lower().startswith("0x") else int(s)
    except ValueError:
        return None


def _entities_from_findings(findings: list, log_name: str, host_id: str) -> list:
    """All entity IDs host-namespaced as <type>:<host>:<rest>."""
    out: set = set()
    for f in findings:
        rec = f.get("record_number")
        if rec is not None:
            out.add(f"event:{host_id}:{log_name}:{rec}")
        pid_int = _process_id_int(f.get("new_process_id"))
        if pid_int is not None:
            out.add(f"process:{host_id}:{pid_int}")
        for k in ("service",):
            v = f.get(k)
            if v and v != "?":
                out.add(f"service:{host_id}:{v}")
        for k in ("target_user", "member", "subject_user", "client_account", "subject_account"):
            v = f.get(k)
            if v and v not in ("?", "-"):
                out.add(f"user:{host_id}:{v}")
        for k in ("image_path", "new_process_name", "process_name"):
            v = f.get(k)
            if v and v not in ("?", "-"):
                out.add(f"file:{host_id}:{v}")
        # Kerberoasting fans out into many SPN entities — each is an analyst pivot.
        for spn in f.get("services_targeted") or []:
            if spn:
                out.add(f"service:{host_id}:{spn}")
        # NTDS.dit access — emit the file entity for the accessed path.
        ap = f.get("accessed_path")
        if ap:
            out.add(f"file:{host_id}:{ap}")
        # 4625 burst — emit user entities for every distinct target user in the burst
        # (password-spray bursts have many distinct users; each is an analyst pivot).
        for u in f.get("target_users") or []:
            if u and u not in ("?", "-"):
                out.add(f"user:{host_id}:{u}")
        # 4104 PowerShell — emit file entity if the script came from a file on disk
        # ("(in-memory)" is the marker for inline / IEX'd payloads — no file entity).
        ps_path = f.get("path")
        if ps_path and ps_path not in ("?", "-", "(in-memory)"):
            out.add(f"file:{host_id}:{ps_path}")
    return sorted(out)


_IP_FINDING_TYPES = {
    "interactive_remote_logon", "new_credentials_logon", "failed_logon_burst",
    "as_rep_roasting", "kerberoasting_burst",
}


def _is_external_ip(ip: str) -> bool:
    """True iff `ip` is a routable, non-private, non-loopback, non-link-local address.
    Used by the cross-host correlation rule to suppress intra-corp/RFC1918 noise."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local
                or a.is_multicast or a.is_unspecified or a.is_reserved)


def _event_attrs_from_findings(findings: list, log_name: str, host_id: str) -> dict:
    """Per-event attrs (event_id, time_created, channel). Entity IDs are host-namespaced.

    Augments with cross-host correlation pivots:
    - `ip_address` + `is_external` for logon-related findings (cross_host shared-IP rule)
    - `cmdline_pattern` for suspicious cmdline findings (cross_host shared-cmdline rule)
    Both are read by `correlation_agent.detect_correlations` without parsing claim bodies.
    """
    attrs: dict = {}
    for f in findings:
        rec = f.get("record_number")
        if rec is None:
            continue
        ent = f"event:{host_id}:{log_name}:{rec}"
        a = {
            "channel": log_name,
            "record_number": int(rec) if isinstance(rec, (int, str)) and str(rec).isdigit() else rec,
            "event_id": f.get("event_id"),
            "time_created": f.get("time"),
        }
        if f["type"] in _IP_FINDING_TYPES:
            ip = (f.get("ip_address") or "").strip()
            if ip and ip != "?":
                a["ip_address"] = ip
                a["is_external"] = _is_external_ip(ip)
        elif f["type"] == "process_create_suspicious_cmdline":
            pat = (f.get("pattern_matched") or "").strip()
            if pat:
                a["cmdline_pattern"] = pat
        # Kerberos / AD pivots — cross-host correlation reads these to spot the same
        # Kerberos service / target account / DCSync principal across hosts.
        if f["type"] in ("as_rep_roasting", "kerberoasting_burst"):
            etype = (f.get("kerberos_etype") or "").strip()
            if etype:
                a["kerberos_etype"] = etype
            client = (f.get("client_account") or "").strip()
            if client and client != "?":
                a["client_account"] = client
        if f["type"] == "kerberoasting_burst" and f.get("services_targeted"):
            a["services_targeted"] = f["services_targeted"]
        if f["type"] == "dcsync_attempt":
            subj = (f.get("subject_account") or "").strip()
            if subj and subj != "?":
                a["subject_account"] = subj
            if f.get("replication_rights"):
                a["replication_rights"] = f["replication_rights"]
        if f["type"] == "suspicious_ntds_access":
            proc = (f.get("process_name") or "").strip()
            if proc and proc != "?":
                a["process_name"] = proc
            path = (f.get("accessed_path") or "").strip()
            if path:
                a["accessed_path"] = path
        attrs[ent] = a
    return attrs


def _format_finding(f: dict) -> str:
    t = f["type"]
    rec = f.get("record_number", "?")
    if t == "audit_log_cleared":
        return f"- **audit_log_cleared** record={rec} time={f.get('time')}"
    if t == "service_install":
        return f"- **service_install** record={rec} eid={f['event_id']} svc=`{f.get('service')}` image=`{f.get('image_path')}`"
    if t == "process_create_user_writable_path":
        cmd = (f.get("command_line") or "")[:80]
        return f"- **process_create_user_writable_path** record={rec} new=`{f.get('new_process_name')}` parent=`{f.get('parent_process_name')}` cmd=`{cmd}`"
    if t == "process_create_suspicious_cmdline":
        cmd = (f.get("command_line") or "")[:80]
        return f"- **process_create_suspicious_cmdline** record={rec} new=`{f.get('new_process_name')}` pattern=`{f.get('pattern_matched')}` cmd=`{cmd}`"
    if t == "account_create":
        return f"- **account_create** record={rec} new_user=`{f.get('target_user')}`"
    if t == "privileged_group_change":
        return f"- **privileged_group_change** record={rec} eid={f['event_id']} group=`{f.get('group')}` member=`{f.get('member')}`"
    if t == "interactive_remote_logon":
        return f"- **interactive_remote_logon** record={rec} type=10 user=`{f.get('target_user')}` ip=`{f.get('ip_address')}`"
    if t == "new_credentials_logon":
        return f"- **new_credentials_logon** record={rec} type=9 user=`{f.get('target_user')}` proc=`{f.get('process_name')}`"
    if t == "powershell_suspicious_scriptblock":
        preview = (f.get("scriptblock_preview") or "").replace("\n", " ⏎ ")[:160]
        patterns = ", ".join(f.get("patterns_matched") or [])
        return (f"- **powershell_suspicious_scriptblock** record={rec} "
                f"path=`{f.get('path')}` len={f.get('scriptblock_length')} "
                f"patterns=[{patterns}] preview=`{preview}` ⚠️ PS TRADECRAFT")
    if t == "failed_logon_burst":
        users = ", ".join((f.get("target_users") or [])[:5])
        more_users = f" (+{len(f.get('target_users') or []) - 5})" if len(f.get('target_users') or []) > 5 else ""
        return (f"- **failed_logon_burst** ip=`{f.get('ip_address')}` "
                f"{f.get('fail_count')} failures in {f.get('window_minutes')}min "
                f"({f.get('first_failure_time')} → {f.get('last_failure_time')}); "
                f"target_users=[{users}{more_users}] "
                f"logon_types={f.get('logon_types')} 🚨 BRUTE-FORCE / SPRAY")
    if t == "special_privilege_assigned":
        privs = ", ".join(f.get("high_privileges") or [])
        return (f"- **special_privilege_assigned** record={rec} "
                f"user=`{f.get('subject_domain')}\\{f.get('subject_user')}` "
                f"high_privs=[{privs}] logon_id=`{f.get('subject_logon_id')}` ⚠️ ADMIN ELEVATION")
    if t == "vss_service_stopped":
        return (f"- **vss_service_stopped** record={rec} svc=`{f.get('service')}` "
                f"state=`{f.get('state')}` time={f.get('time')} ⚠️ ANTI-RECOVERY (pairs with ransomware)")
    if t == "as_rep_roasting":
        return (f"- **as_rep_roasting** record={rec} client=`{f.get('client_account')}` "
                f"etype=`{f.get('kerberos_etype')}` (RC4) ip=`{f.get('ip_address')}` "
                f"pre_auth=`{f.get('pre_auth_type')}` 🔓 AS-REP ROASTING")
    if t == "kerberoasting_burst":
        spns = ", ".join((f.get("services_targeted") or [])[:5])
        more_spns = f" (+{len(f.get('services_targeted') or []) - 5})" if len(f.get('services_targeted') or []) > 5 else ""
        return (f"- **kerberoasting_burst** ip=`{f.get('ip_address')}` "
                f"{f.get('tgs_count')} RC4 TGS requests in {f.get('window_seconds')}s "
                f"({f.get('first_request_time')} → {f.get('last_request_time')}); "
                f"SPNs=[{spns}{more_spns}] 🚨 KERBEROASTING")
    if t == "dcsync_attempt":
        rights = ", ".join((f.get("replication_rights") or [])[:3])
        return (f"- **dcsync_attempt** record={rec} "
                f"subject=`{f.get('subject_domain')}\\{f.get('subject_account')}` "
                f"rights=[{rights}] 🚨 CREDENTIAL-DUMPING via AD REPLICATION")
    if t == "suspicious_ntds_access":
        return (f"- **suspicious_ntds_access** record={rec} path=`{f.get('accessed_path')}` "
                f"proc=`{f.get('process_name')}` subject=`{f.get('subject_account')}` "
                f"🚨 NTDS.DIT ACCESS (credential-dumping)")
    return f"- **{t}** record={rec}"


def generate_claim(evtx_path: Path, log_name: str, findings: list, total_events: int) -> str:
    timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    cid_key = f"{evtx_path.name}:" + "|".join(f"{f['type']}:{f.get('record_number')}" for f in findings)
    cid = "evtx-" + hashlib.md5(cid_key.encode()).hexdigest()[:14]
    host_id = derive_host_id(evtx_path.name)

    entities = _entities_from_findings(findings, log_name, host_id) or [f"event_log:{host_id}:{log_name}"]
    rel = str(evtx_path.relative_to(EVIDENCE_ROOT)) if evtx_path.is_relative_to(EVIDENCE_ROOT) else evtx_path.name

    event_attrs = _event_attrs_from_findings(findings, log_name, host_id)

    fm = {
        "claim_id": cid,
        "status": "new",
        "generated_by": "evtx-agent",
        "host": host_id,
        "log_name": log_name,
        "entities": entities[:50],
        "evidence_refs": [rel],
        "confidence": 0.85 if findings else 0.5,
        "timestamp": timestamp,
        "event_count_total": total_events,
        "anomaly_count": len(findings),
    }
    if event_attrs:
        fm["event_attrs"] = event_attrs

    body_lines = [
        f"**Event Log Analysis: `{log_name}`**",
        "",
        f"Source: `{evtx_path.name}` ({total_events:,} events scanned)",
        "",
    ]
    if findings:
        by_type: dict = {}
        for f in findings:
            by_type.setdefault(f["type"], []).append(f)
        body_lines.append(f"**Findings ({len(findings)} total across {len(by_type)} type(s)):**")
        for t in sorted(by_type):
            sub = by_type[t]
            body_lines.append(f"\n_{t} ({len(sub)}):_")
            for f in sub[:25]:
                body_lines.append(_format_finding(f))
            if len(sub) > 25:
                body_lines.append(f"_…({len(sub) - 25} more of this type)_")
    else:
        body_lines.append("_No anomalies detected by this rule set._")
    body_lines.append("")
    body_lines.append("**Hypothesis:** Pivot record numbers in the source .evtx for full event detail; cross-reference flagged users/services with memory PIDs and registry persistence findings.")
    return f"---\n{yaml.dump(fm, sort_keys=False)}---\n" + "\n".join(body_lines) + "\n"


async def run_evtx_analysis(evtx: Path | None = None):
    print("📜 Evtx Agent starting (Chisel-confined)...")
    chisel = Chisel(CHISEL_URL, CHISEL_SECRET)
    chisel.connect()
    print(f"🔒 Chisel session → {chisel.endpoint} (sid={chisel.session_id[:8]}…)")

    if evtx is None:
        listing = chisel.shell("ls", ["-1", str(EVIDENCE_NEW)])
        for n in listing.splitlines():
            n = n.strip()
            if not n:
                continue
            if n.lower().endswith(".evtx") or "__evtx_" in n.lower():
                evtx = EVIDENCE_NEW / n
                break
        if evtx is None:
            print("❌ no evtx file in evidence/new/")
            return

    log_name = detect_log_kind(evtx)
    print(f"📂 Analysing {log_name} — {evtx.name}")

    events: list = []
    with tempfile.TemporaryDirectory(prefix="evtx_") as td:
        json_path = await run_evtxecmd(evtx, Path(td))
        if json_path is None:
            print("   ⚠️  EvtxECmd produced no output; emitting empty claim")
        else:
            try:
                with open(json_path, encoding="utf-8-sig") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            events.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
            except Exception as e:
                print(f"   ⚠️  failed to read EvtxECmd output: {e}")

    print(f"   {len(events):,} events scanned")
    findings = detect_evtx_anomalies(events)
    print(f"🚨 Findings: {len(findings)}")
    for f in findings[:5]:
        print("   " + _format_finding(f).lstrip("- "))

    chisel.call("create_directory", {"path": str(CLAIMS_TODO)})
    claim = generate_claim(evtx, log_name, findings, len(events))
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    safe_log = log_name.replace("%", "_").replace("/", "_").replace(" ", "_")
    claim_path = CLAIMS_TODO / f"evtx_{safe_log}_{ts}.md"
    chisel.call("write_file", {"path": str(claim_path), "content": claim})
    print(f"✅ Claim written → {claim_path.name}")


if __name__ == "__main__":
    asyncio.run(run_evtx_analysis())
