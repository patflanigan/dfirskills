# agents/mft_agent/agent.py
"""
MFT Agent — analyses NTFS $MFT files (snapshot view) AND $UsnJrnl:$J streams (lifecycle view)
using MFTECmd. Dispatches by filename: `__mft__` → MFT snapshot detectors;
`__usnjrnl__` → USN journal lifecycle detectors (drop-then-delete, burst-create, rename).

Standalone CLI:  python -m agents.mft_agent.agent
Orchestrator:    await run_mft_analysis(mft=Path(...))

Tool: MFTECmd (`dotnet /opt/zimmermantools/MFTECmd.dll`) per the SIFT windows-artifacts skill.
For USN parsing the `-m <MFT>` flag resolves parent FRNs to human-readable paths.

MFT detector set (low-FP, layered against real Windows install noise):
- mft_timestomping_detected         — SI<FN True for an executable in user-writable path; significant skew
- mft_executable_dropped_user_writable — exe in \\Users\\, \\Temp\\, \\AppData\\, etc. (excluding browser cache)
- mft_deleted_executable_user_writable — same as above but InUse=False (deleted)
- mft_executable_in_recycle_bin     — executable under \\$Recycle.Bin\\
- mft_alternate_data_stream_executable — IsAds=True with executable extension

USN detector set (lifecycle signals MFT alone can't see):
- usn_drop_then_delete_executable   — exe with FileCreate AND FileDelete in same journal, lifetime <24h
- usn_burst_create_executables_user_writable — ≥3 exe FileCreates in same parent within 5min
- usn_executable_renamed_user_writable — RenameNewName on exe in user-writable path
"""

import asyncio
import csv
import hashlib
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

MFTECMD = ["dotnet", "/opt/zimmermantools/MFTECmd.dll"]
RBCMD = ["dotnet", "/opt/zimmermantools/RBCmd.dll"]

# Per-claim caps. The win7 case MFT has 133k records / ~9k SI<FN-flagged executables — without
# caps we'd flood the timeline rule with anchors. Cap entities so the validator's spot-check
# stays fast and the analyst gets a tractable claim.
MAX_ENTITIES_PER_CLAIM = 500

# Executable extensions worth tracking. Keep tight — every extra extension explodes finding count.
EXECUTABLE_EXTS = {".exe", ".dll", ".sys", ".scr", ".ps1", ".bat", ".vbs", ".js", ".com", ".cpl"}

# User-writable parent-path hints. Mirrors registry_agent's SUSPICIOUS_PATH_HINTS so the
# two agents agree on what "attacker-friendly" means.
USER_WRITABLE_HINTS = (
    "\\users\\", "\\appdata\\", "\\temp\\",
    "\\programdata\\", "\\public\\", "\\$recycle.bin\\",
)

# Browser caches and routine OS-update noise that polute "user-writable executable" counts.
# Anything matching these gets dropped from suspicious-drop findings (timestomping detector
# uses a separate exclusion list — these specific paths almost always have legitimate skew
# from cache turnover and aren't security-relevant on their own).
# Browser profile dirs (Firefox `\profiles\`, Chrome `\user data\`) are also excluded —
# the .js files in there are config (prefs.js, sessionstore.js), not scripts.
BROWSER_CACHE_HINTS = (
    "\\temporary internet files\\", "\\inetcache\\", "\\webcache\\",
    "\\webstore\\", "\\caches\\", "\\code cache\\", "\\service worker\\",
    "\\cookies\\", "\\indexeddb\\", "\\local storage\\",
    "\\firefox\\profiles\\", "\\mozilla\\firefox\\",
    "\\chrome\\user data\\", "\\google\\chrome\\",
    "\\edge\\user data\\", "\\microsoft\\edge\\",
)

# Paths that legitimately have SI predating FN by years — driver redist, side-by-side
# component store, .NET assemblies, signed system updates. Suppressing these slashes the
# timestomping false-positive rate from ~9k to ~30 on a typical Win7 image.
TIMESTOMP_EXCLUSION_PATHS = (
    "\\windows\\system32\\spool\\drivers\\",
    "\\windows\\system32\\driverstore\\",
    "\\windows\\winsxs\\",
    "\\windows\\servicing\\",
    "\\windows\\microsoft.net\\",
    "\\windows\\assembly\\",
    "\\program files\\common files\\microsoft shared\\",
    "\\program files (x86)\\common files\\microsoft shared\\",
    "\\windows\\softwaredistribution\\",
    "\\windows\\panther\\",
    # Adobe Reader auto-updater redist — extracts thousands of pre-packaged binaries with
    # SI predating FN (legit packaging timestamp vs. install timestamp). Same pattern as
    # WinSxS but in ProgramData. Generalize to all of Adobe ARM.
    "\\programdata\\adobe\\arm\\",
    "\\program files\\common files\\adobe\\arm\\",
    "\\program files (x86)\\common files\\adobe\\arm\\",
    # MSI installer caches — same pre-packaged-binary pattern.
    "\\windows\\installer\\",
    "\\config.msi\\",
    # Other vendor app-package directories with bundled scripts (.js/.vbs/.ps1) where
    # SI=build-time and FN=install-time legitimately differ by days/weeks. Same shape
    # as Adobe ARM. Confirmed FP source on the win7-64-nfury image: 25/25 timestomping
    # findings were under \programdata\skype\apps\login\static\js\ before this exclusion.
    "\\programdata\\skype\\",
    "\\programdata\\microsoft\\teams\\",
    "\\programdata\\zoom\\",
    "\\programdata\\google\\",
)

# Significant timestomping skew. Trivial sub-second differences happen in legit OS activity;
# only flag deltas over 1 day so we catch SetFileTime backdating but ignore noise.
TIMESTOMP_MIN_SKEW = timedelta(days=1)


# USN drop-then-delete: maximum lifetime to flag. Files that legitimately exist for >24h
# don't fit the dropper-tradecraft pattern (which is usually seconds-to-minutes).
USN_DROP_DELETE_MAX_LIFETIME = timedelta(hours=24)
# USN burst-create: window + min count for the burst-create detector.
USN_BURST_WINDOW = timedelta(minutes=5)
USN_BURST_MIN_COUNT = 3

# Common user data extensions ransomware targets — documents, images, archives, db.
# Kept tight; every extra extension expands the per-user-tree counter's state.
USER_DATA_EXTS = {
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",   # office
    ".pdf", ".rtf", ".txt", ".csv",                       # docs
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff",     # images
    ".mp4", ".avi", ".mov", ".wav",                       # media (.mp3 deliberately omitted —
                                                          # it's also a ransomware extension; let the
                                                          # extension detector own it)
    ".zip", ".rar", ".7z", ".tar", ".gz",                 # archives
    ".sql", ".mdb", ".accdb",                             # databases
    ".psd", ".ai",                                        # creative
}

# Known ransomware-family appended extensions. Sourced from MITRE ATT&CK + AnyRun.
# NOT exhaustive — expanding when a new family ships is the maintenance cost.
KNOWN_RANSOMWARE_EXTS = {
    ".locky", ".lockie", ".lokd", ".lukitus",            # Locky family
    ".crypted", ".encrypted", ".crypt", ".crypz",        # generic
    ".cryptolocker", ".ctbl", ".vault", ".vvv",          # CTB-Locker, etc.
    ".ezz", ".exx", ".ecc",                              # TeslaCrypt
    ".micro", ".thor", ".aesir", ".odin",                # Locky variants
    ".zepto", ".sage",                                    # Sage
    ".xtbl", ".crinf",                                   # Cerber
    ".ccc", ".ttt", ".zzzzz",                            # TeslaCrypt v3
    ".wcry", ".wncry", ".wnry",                          # WannaCry
    ".djvu", ".djvur", ".djvuq", ".djvuu",               # STOP/DJVU
    ".phobos", ".eight", ".elbie",                       # Phobos family
    ".lockbit", ".abcd",                                 # LockBit
    ".conti", ".ryuk",                                   # Conti, Ryuk
    ".sodinokibi", ".revil",                             # Sodinokibi/REvil
    ".babuk",                                            # Babuk
    ".hive", ".rorschach",                               # newer families
}

# Ransomware burst thresholds. Tuned conservatively — legitimate user activity rarely
# generates >50 DataOverwrites on user-data files in a single dir-tree within 5 min.
# Adjust if FP-rate drives noise.
RANSOMWARE_OVERWRITE_THRESHOLD = 50    # DataOverwrite events / 5min / user-dir-tree
RANSOMWARE_RENAME_THRESHOLD = 10       # RenameNewName-to-ransomware-ext / 5min (global)

# Ransom-note filename patterns. Single match = Tier-A finding (no legitimate file is
# named "HOW_TO_DECRYPT.txt"). Patterns target both generic conventions and several
# well-known family-specific note names. Anchored at line start (`^`) — partial matches
# in the middle of long names are usually unrelated.
RANSOM_NOTE_PATTERNS = [
    re.compile(r"^how[_\s-]?to[_\s-]?decrypt", re.I),
    re.compile(r"^_?readme(_for_decrypt)?\.(txt|html|hta)$", re.I),
    re.compile(r"^decrypt[_\s-]?(instructions?|me|files?)", re.I),
    re.compile(r"^recovery[_\s-]?(instructions?|files?)", re.I),
    re.compile(r"^restore[_\s-]?(your[_\s-]?)?files", re.I),
    re.compile(r"^\$?_?help[_\s-]?(decrypt|instructions?|recover)", re.I),
    re.compile(r"^!?your[_\s-]?files[_\s-]?(are[_\s-]?)?encrypted", re.I),
    re.compile(r"^[\!_]+(read[_\s-]?me|attention|warning)", re.I),
    re.compile(r"^locked\.txt$", re.I),
    # Family-specific
    re.compile(r"^how_to_back_files\.html$", re.I),                # Locky
    re.compile(r"^_locky_recover_instructions\.(txt|bmp)$", re.I), # Locky
    re.compile(r"^!recovery_\w+\.txt$", re.I),                      # Cerber
    re.compile(r"^\#decrypt[_\s-]?my[_\s-]?files\#", re.I),        # CryptoWall
    re.compile(r"^lockbit[-_]?note\.txt$", re.I),                   # LockBit
    re.compile(r"^conti[-_]?readme\.txt$", re.I),                   # Conti
]


def detect_mft(mft_path: Path) -> bool:
    """Cheap routing check — staged-suffix or bare $MFT name."""
    n = mft_path.name.lower()
    return n.endswith("$mft") or n.endswith("__mft__$mft") or "__mft__" in n


def detect_usn(usn_path: Path) -> bool:
    """Cheap routing check — staged-suffix or bare $J name."""
    n = usn_path.name.lower()
    return n.endswith("$j") or "__usnjrnl__" in n


def detect_recycle(rb_path: Path) -> bool:
    """Cheap routing check — staged $I file (form `<image>__recycle__<sid>_<name>`)."""
    n = rb_path.name.lower()
    return "__recycle__" in n


def _normalize_mft_path(parent_path: str, filename: str) -> str:
    r"""Convert MFTECmd's `.\Users\foo` parent + filename to a canonical `c:\users\foo\bar.exe`.

    MFTECmd emits paths rooted at the volume — `.\Users\nromanoff\Desktop\spinlock.exe`. We
    drop the leading `.` (or `.\`), prefix with `c:` (single-volume assumption matching
    prefetch_agent's `_normalize_volume_path`), normalize separators to backslashes, and
    lowercase for cross-domain comparison consistency.
    """
    pp = (parent_path or "").lstrip(".").lstrip("\\").lstrip("/")
    fn = (filename or "").strip()
    if not fn:
        return ""
    full = pp.replace("/", "\\").rstrip("\\")
    full = f"c:\\{full}\\{fn}" if full else f"c:\\{fn}"
    return full.lower()


# Folders ransomware targets (user document directories). Excludes AppData and similar
# application-data dirs that have high baseline write activity from legitimate apps
# (wallpaper transcoding, Windows Mail stationery, Skype thumbnails, etc.).
RANSOMWARE_TARGET_USER_DIRS = {
    "documents", "desktop", "downloads", "pictures", "music", "videos",
    "onedrive", "dropbox", "google drive",
}


def _extract_user_tree(parent_path: str) -> str | None:
    r"""Aggregate parent paths to the user document folder for ransomware burst detection.

    `c:\users\bob\documents\reports\q4` → `c:\users\bob\documents`
    `c:\users\bob\documents`            → `c:\users\bob\documents`
    `c:\users\bob\desktop\stuff`         → `c:\users\bob\desktop`
    `c:\users\bob\appdata\local\foo`    → None (AppData is high-baseline app cache, not ransomware target)
    `c:\windows\temp\foo`                → None (not a user dir)

    Without this aggregation, ransomware that walks subdirectories would never trip
    a single-parent threshold — encryption is spread across many leaf folders. The
    target-dir restriction matches the threat model: ransomware encrypts user
    documents/photos/etc., not Windows-internal AppData caches.
    """
    if not parent_path or not parent_path.startswith("c:\\users\\"):
        return None
    parts = parent_path.split("\\")
    # parts[0]='c:', parts[1]='users', parts[2]='<user>', parts[3]='<top-level dir>'
    if len(parts) < 4:
        return None
    if parts[3].lower() not in RANSOMWARE_TARGET_USER_DIRS:
        return None
    return "\\".join(parts[:4])


def _parse_mft_timestamp(s: str) -> datetime | None:
    """MFTECmd emits `2012-04-03 22:59:43.1469179` (7-digit fraction; FILETIME 100-ns ticks).
    Python's fromisoformat accepts up to 6 digits; truncate before parsing."""
    if not s or not isinstance(s, str):
        return None
    s = s.strip()
    if not s:
        return None
    # Replace space separator and trim sub-microsecond precision
    iso = s.replace(" ", "T", 1)
    if "." in iso:
        head, frac = iso.split(".", 1)
        iso = f"{head}.{frac[:6]}"
    try:
        return datetime.fromisoformat(iso).replace(tzinfo=UTC)
    except ValueError:
        return None


def _fmt_iso(dt: datetime | None) -> str | None:
    return dt.isoformat().replace("+00:00", "Z") if dt else None


async def _run_mftecmd(mft_path: Path) -> Path | None:
    """Invoke MFTECmd via local subprocess; return the path to its produced .csv file.

    INTENTIONAL EXCEPTION to the route-through-Chisel rule — see evtx_agent
    .run_evtxecmd for full rationale. Short version: MFTECmd.dll lives at
    /opt/zimmermantools/MFTECmd.dll which is outside Chisel's --root, and Chisel's
    path-confinement rejects the .dll path argument. We accept the audit-log gap
    for this tool in exchange for keeping the agent simple.
    """
    out_dir = Path(tempfile.mkdtemp(prefix="mftecmd_"))
    proc = await asyncio.create_subprocess_exec(
        *MFTECMD, "-f", str(mft_path), "--csv", str(out_dir), "--csvf", "mft.csv",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    await proc.communicate()
    csv_file = out_dir / "mft.csv"
    if not csv_file.exists():
        return None
    return csv_file


async def _run_mftecmd_usn(usn_path: Path, mft_path: Path | None) -> Path | None:
    """Invoke MFTECmd on a $J file via local subprocess. Pass `-m <MFT>` so MFTECmd
    resolves parent FRNs to human-readable paths in the `ParentPath` column. Without
    `-m` we get useless `pathunknown\\directory with id 0xNNNN-NNNN` placeholders.

    Direct-subprocess exception per evtx_agent.run_evtxecmd rationale (MFTECmd.dll
    lives at /opt/zimmermantools/, outside Chisel --root).
    """
    out_dir = Path(tempfile.mkdtemp(prefix="mftecmd_usn_"))
    cmd = [*MFTECMD, "-f", str(usn_path), "--csv", str(out_dir), "--csvf", "usn.csv"]
    if mft_path and mft_path.exists():
        cmd += ["-m", str(mft_path)]
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    await proc.communicate()
    csv_file = out_dir / "usn.csv"
    if not csv_file.exists():
        return None
    return csv_file


def _find_companion_mft(usn_path: Path) -> Path | None:
    """Locate the matching $MFT for a USN file. The disk_image_agent always stages MFT and
    USN side-by-side as `<image_stem>__mft__$MFT` and `<image_stem>__usnjrnl__$J`. The MFT
    is dispatched first, so by the time the USN agent runs the MFT has moved to processed/.
    Probe both new/ and processed/.
    """
    name = usn_path.name
    if "__usnjrnl__" not in name:
        return None
    image_stem = name.split("__usnjrnl__", 1)[0]
    mft_filename = f"{image_stem}__mft__$MFT"
    for d in (EVIDENCE_NEW, EVIDENCE_ROOT / "processed"):
        candidate = d / mft_filename
        if candidate.exists():
            return candidate
    return None


def detect_mft_anomalies(csv_path: Path) -> tuple[list[dict], int, int]:
    """Stream the MFT CSV, apply detectors, return (findings, total_rows, filtered_rows).

    Streams (csv.DictReader on the open file) to keep peak memory bounded — the win7 case
    produces a 57MB CSV; reading it whole into a list pushes RSS over 1GB.
    """
    findings: list = []
    total = 0
    kept = 0  # rows that survived directory/system filter (i.e. could be candidates)

    with open(csv_path, encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            total += 1
            if (row.get("IsDirectory") or "").strip().lower() == "true":
                continue
            ext = (row.get("Extension") or "").strip().lower()
            if ext and ext not in EXECUTABLE_EXTS:
                # Non-executable rows still count toward total but skip the rest of the
                # detector pipeline — every detector is gated on EXECUTABLE_EXTS.
                continue
            kept += 1

            full_path = _normalize_mft_path(row.get("ParentPath") or "", row.get("FileName") or "")
            if not full_path:
                continue
            try:
                file_size = int((row.get("FileSize") or "0").strip() or "0")
            except ValueError:
                file_size = 0
            in_use = (row.get("InUse") or "").strip().lower() == "true"
            is_ads = (row.get("IsAds") or "").strip().lower() == "true"
            sifn = (row.get("SI<FN") or "").strip().lower() == "true"

            si_created = _parse_mft_timestamp(row.get("Created0x10") or "")
            fn_created = _parse_mft_timestamp(row.get("Created0x30") or "")
            si_modified = _parse_mft_timestamp(row.get("LastModified0x10") or "")
            si_accessed = _parse_mft_timestamp(row.get("LastAccess0x10") or "")
            si_mft_changed = _parse_mft_timestamp(row.get("LastRecordChange0x10") or "")

            common = {
                "path": full_path, "parent_path": (row.get("ParentPath") or "").lower(),
                "file_size": file_size, "in_use": in_use,
                "entry_number": row.get("EntryNumber"),
                "extension": ext,
                "created_si": _fmt_iso(si_created),
                "created_fn": _fmt_iso(fn_created),
                "modified_si": _fmt_iso(si_modified),
                "accessed_si": _fmt_iso(si_accessed),
                "mft_changed_si": _fmt_iso(si_mft_changed),
            }

            in_user_writable = any(h in full_path for h in USER_WRITABLE_HINTS)
            in_browser_cache = any(b in full_path for b in BROWSER_CACHE_HINTS)

            # Detector 1: timestomping — REQUIRES user-writable path (the attacker threat model:
            # SetFileTime to backdate a dropped binary). Pre-packaged installer redist (Adobe,
            # MSI, WinSxS, .NET assembly cache) lives in Program Files/Windows/ProgramData and
            # has SI<FN by design — not anti-forensics. Skipping system paths cuts FP from
            # ~3000 → tens. The exclusion list still matters because some installers extract
            # to ProgramData/Adobe/ARM (which IS in USER_WRITABLE_HINTS via \programdata\).
            if (sifn and in_user_writable and not in_browser_cache
                    and si_created and fn_created
                    and (fn_created - si_created) >= TIMESTOMP_MIN_SKEW
                    and not any(p in full_path for p in TIMESTOMP_EXCLUSION_PATHS)):
                findings.append({
                    "type": "mft_timestomping_detected",
                    **common,
                    "skew_seconds": int((fn_created - si_created).total_seconds()),
                })

            # Detector 2/3: suspicious-path executable creation. Browser caches are explicitly
            # excluded — they're noisy and benign. Tiny files (<1 KB) are usually marker/lock files.
            if in_user_writable and not in_browser_cache and file_size >= 1024:
                if not in_use:
                    findings.append({"type": "mft_deleted_executable_user_writable", **common})
                else:
                    findings.append({"type": "mft_executable_dropped_user_writable", **common})

            # Detector 4: executable inside the recycle bin (regardless of InUse).
            if "\\$recycle.bin\\" in full_path and ext in EXECUTABLE_EXTS:
                findings.append({"type": "mft_executable_in_recycle_bin", **common})

            # Detector 5: alternate data stream that is itself executable.
            if is_ads:
                findings.append({"type": "mft_alternate_data_stream_executable", **common})

    return findings, total, kept


def _prioritize_and_cap(findings: list[dict], cap: int) -> list[dict]:
    """Order by severity then recency; truncate at cap.

    Tier ordering (highest first):
      1. timestomping (anti-forensics is a near-definitive signal)
      2. deleted executable in user-writable path (attacker cleanup)
      3. ADS executable (hiding trick)
      4. recycle bin executable (drop-via-recycle-bin trick)
      5. live executable in user-writable path
    Within tiers, newest creation first — analysts usually want the freshest activity.
    """
    severity = {
        "mft_timestomping_detected": 0,
        "mft_deleted_executable_user_writable": 1,
        "mft_alternate_data_stream_executable": 2,
        "mft_executable_in_recycle_bin": 3,
        "mft_executable_dropped_user_writable": 4,
    }
    findings.sort(key=lambda f: (severity.get(f["type"], 99), -(_isokey(f.get("created_si")))))
    return findings[:cap]


def _isokey(s: str | None) -> int:
    """Sort key for ISO8601 — newer wins. Returns 0 for missing/unparseable."""
    if not s:
        return 0
    try:
        return int(datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp())
    except ValueError:
        return 0


def _entities_from_findings(findings: list[dict], host_id: str) -> list[str]:
    out: set = set()
    for f in findings:
        path = f.get("path")
        if path:
            out.add(f"file:{host_id}:{path}")
    return sorted(out)


def _file_attrs_from_findings(findings: list[dict], host_id: str) -> dict:
    """Build per-File ProcessExecution-style attrs map. First finding for a path wins
    (subsequent detectors emitting the same file just confirm the existing record)."""
    attrs: dict = {}
    for f in findings:
        path = f.get("path")
        if not path:
            continue
        ent = f"file:{host_id}:{path}"
        if ent in attrs:
            continue
        attrs[ent] = {
            "created_time": f.get("created_si"),
            "modified_time": f.get("modified_si"),
            "accessed_time": f.get("accessed_si"),
            "mft_modified_time": f.get("mft_changed_si"),
            "file_size": f.get("file_size"),
            "is_deleted": not f.get("in_use", True),
            "parent_path": f.get("parent_path"),
            "entry_number": f.get("entry_number"),
        }
    return attrs


def _format_finding(f: dict) -> str:
    t = f["type"]
    path = f.get("path", "?")
    size = f.get("file_size", 0)
    if t == "mft_timestomping_detected":
        skew_days = (f.get("skew_seconds") or 0) // 86400
        return (f"- **mft_timestomping_detected** `{path}` "
                f"— SI.created={f.get('created_si')} FN.created={f.get('created_fn')} "
                f"(skew: {skew_days}d) ⚠️ ANTI-FORENSICS")
    if t == "mft_deleted_executable_user_writable":
        return f"- **mft_deleted_executable_user_writable** `{path}` (deleted; was {size:,} bytes)"
    if t == "mft_executable_dropped_user_writable":
        return f"- **mft_executable_dropped_user_writable** `{path}` (created {f.get('created_si')}, {size:,} bytes)"
    if t == "mft_executable_in_recycle_bin":
        return f"- **mft_executable_in_recycle_bin** `{path}` (created {f.get('created_si')}, {size:,} bytes)"
    if t == "mft_alternate_data_stream_executable":
        return f"- **mft_alternate_data_stream_executable** `{path}` (ADS, {size:,} bytes)"
    return f"- **{t}** {f}"


# ─────────────────────────────────────────────────────────────
# USN journal — lifecycle detectors (drop-then-delete, burst-create, rename)
# ─────────────────────────────────────────────────────────────

def detect_usn_anomalies(csv_path: Path) -> tuple[list[dict], int, int]:
    """Stream the USN CSV, apply lifecycle + ransomware detectors, return (findings, total, exec_rows).

    Streams the CSV to keep peak memory bounded — USN can be 100MB+ with hundreds of
    thousands of records. Per-(parent, name) state machine tracks first-seen create/delete
    timestamps for executables; per-user-tree DataOverwrite counter tracks ransomware
    encryption sweeps. All sliding-window state evicts entries older than USN_BURST_WINDOW
    each iteration so memory stays bounded.

    Detectors run on different extension subsets:
    - Executable-extension only: drop-then-delete, burst-create, rename
    - User-data-extension only: ransomware overwrite burst
    - Known-ransomware-extension only: ransomware extension rename burst
    """
    findings: list = []
    total = 0
    exec_rows = 0

    # Per-(parent, name) lifecycle state — only kept for executables.
    lifecycle: dict[tuple[str, str], dict] = {}
    # Per-parent recent FileCreate timestamps for burst detection.
    recent_creates: dict[str, list[datetime]] = {}
    burst_emitted: dict[str, datetime] = {}
    # Pending RenameOldName events — keyed by EntryNumber.
    rename_pending: dict[str, dict] = {}
    # Per user-dir-tree DataOverwrite timestamps for ransomware detection.
    overwrite_ts_by_user_tree: dict[str, list[datetime]] = {}
    overwrite_exts_by_user_tree: dict[str, set[str]] = {}  # sample of extensions hit
    ransomware_overwrite_emitted: dict[str, datetime] = {}
    # Global rename-to-ransomware-ext counter (dir-agnostic).
    ransomware_rename_ts: list[datetime] = []
    ransomware_rename_paths: list[str] = []
    ransomware_rename_emitted: list[datetime | None] = [None]  # mutable holder

    with open(csv_path, encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            total += 1
            ext = (row.get("Extension") or "").strip().lower()
            name = (row.get("Name") or "").strip()
            # Ransom notes (.txt/.html/.hta) sit OUTSIDE our standard extension sets;
            # check filename pattern up front so they don't get filtered out.
            is_ransom_note = bool(name and any(p.match(name) for p in RANSOM_NOTE_PATTERNS))
            # Triage by extension set — every detector cares about exactly one.
            in_exec = ext in EXECUTABLE_EXTS
            in_user_data = ext in USER_DATA_EXTS
            in_ransom_ext = ext in KNOWN_RANSOMWARE_EXTS
            if not (in_exec or in_user_data or in_ransom_ext or is_ransom_note):
                continue

            parent_path_raw = row.get("ParentPath") or ""
            if not name:
                continue
            full_path = _normalize_mft_path(parent_path_raw, name)
            parent_lower = full_path.rsplit("\\", 1)[0] if "\\" in full_path else ""

            # Skip browser caches and orphaned-parent (`pathunknown`) records — both are
            # too noisy to be useful for any detector.
            if any(b in full_path for b in BROWSER_CACHE_HINTS):
                continue
            if "\\pathunknown\\" in full_path:
                continue

            ts = _parse_mft_timestamp(row.get("UpdateTimestamp") or "")
            if ts is None:
                continue
            reasons_raw = row.get("UpdateReasons") or ""
            reasons = {r.strip() for r in reasons_raw.split("|") if r.strip()}
            entry_no = (row.get("EntryNumber") or "").strip()

            # ── Ransomware detector 0: ransom-note filename ────
            # No legitimate file is named HOW_TO_DECRYPT.txt / _README.html / etc.
            # Single-event Tier-A signal — fires on FileCreate of any matching name.
            if is_ransom_note and "FileCreate" in reasons:
                findings.append({
                    "type": "usn_ransom_note_created",
                    "path": full_path,
                    "parent_path": parent_lower,
                    "name": name,
                    "created_time": _fmt_iso(ts),
                    "matched_pattern": next(
                        p.pattern for p in RANSOM_NOTE_PATTERNS if p.match(name)
                    )[:60],
                })

            # ── Ransomware detector 1: DataOverwrite burst on user-data files ────
            if in_user_data and "DataOverwrite" in reasons:
                user_tree = _extract_user_tree(parent_lower)
                if user_tree:
                    bucket = overwrite_ts_by_user_tree.setdefault(user_tree, [])
                    cutoff = ts - USN_BURST_WINDOW
                    bucket[:] = [t for t in bucket if t >= cutoff]
                    bucket.append(ts)
                    exts_seen = overwrite_exts_by_user_tree.setdefault(user_tree, set())
                    exts_seen.add(ext)
                    last_emit = ransomware_overwrite_emitted.get(user_tree)
                    if (len(bucket) >= RANSOMWARE_OVERWRITE_THRESHOLD
                            and (last_emit is None or (ts - last_emit) >= USN_BURST_WINDOW)):
                        findings.append({
                            "type": "usn_ransomware_overwrite_burst",
                            "user_tree": user_tree,
                            "overwrite_count": len(bucket),
                            "window_minutes": int(USN_BURST_WINDOW.total_seconds() / 60),
                            "first_overwrite": _fmt_iso(bucket[0]),
                            "last_overwrite": _fmt_iso(bucket[-1]),
                            "extensions_hit": sorted(exts_seen),
                        })
                        ransomware_overwrite_emitted[user_tree] = ts

            # ── Ransomware detector 2: rename to known-ransomware extension ──────
            if in_ransom_ext and "RenameNewName" in reasons:
                cutoff = ts - USN_BURST_WINDOW
                ransomware_rename_ts[:] = [t for t in ransomware_rename_ts if t >= cutoff]
                ransomware_rename_ts.append(ts)
                if len(ransomware_rename_paths) < 10:
                    ransomware_rename_paths.append(full_path)
                last_rrenm = ransomware_rename_emitted[0]
                if (len(ransomware_rename_ts) >= RANSOMWARE_RENAME_THRESHOLD
                        and (last_rrenm is None or (ts - last_rrenm) >= USN_BURST_WINDOW)):
                    findings.append({
                        "type": "usn_ransomware_extension_burst",
                        "rename_count": len(ransomware_rename_ts),
                        "window_minutes": int(USN_BURST_WINDOW.total_seconds() / 60),
                        "first_rename": _fmt_iso(ransomware_rename_ts[0]),
                        "last_rename": _fmt_iso(ransomware_rename_ts[-1]),
                        "ransomware_extension": ext,
                        "sample_paths": list(ransomware_rename_paths),
                    })
                    ransomware_rename_emitted[0] = ts
                    ransomware_rename_paths.clear()

            # Executable-extension detectors only — skip the rest for non-exe rows.
            if not in_exec:
                continue
            exec_rows += 1

            in_user_writable = any(h in full_path for h in USER_WRITABLE_HINTS)
            if not in_user_writable:
                continue  # remaining USN detectors require user-writable parent

            key = (parent_lower, name.lower())

            # ── Detector 1: drop-then-delete ───────────────────────────────
            if "FileCreate" in reasons:
                state = lifecycle.setdefault(key, {})
                state.setdefault("first_create", ts)
                state["last_reasons"] = reasons_raw
                # Burst-create tracking
                bucket = recent_creates.setdefault(parent_lower, [])
                # Evict timestamps older than burst window
                cutoff = ts - USN_BURST_WINDOW
                bucket[:] = [t for t in bucket if t >= cutoff]
                bucket.append(ts)
                # ── Detector 2: burst-create ──
                last_emit = burst_emitted.get(parent_lower)
                if (len(bucket) >= USN_BURST_MIN_COUNT
                        and (last_emit is None or (ts - last_emit) >= USN_BURST_WINDOW)):
                    findings.append({
                        "type": "usn_burst_create_executables_user_writable",
                        "parent_path": parent_lower,
                        "create_count": len(bucket),
                        "window_minutes": USN_BURST_WINDOW.total_seconds() // 60,
                        "first_create": _fmt_iso(bucket[0]),
                        "last_create": _fmt_iso(bucket[-1]),
                    })
                    burst_emitted[parent_lower] = ts

            if "FileDelete" in reasons:
                state = lifecycle.get(key)
                if state and state.get("first_create"):
                    create_t = state["first_create"]
                    lifetime = ts - create_t
                    if timedelta(0) <= lifetime <= USN_DROP_DELETE_MAX_LIFETIME:
                        findings.append({
                            "type": "usn_drop_then_delete_executable",
                            "path": full_path,
                            "parent_path": parent_lower,
                            "name": name,
                            "created_time": _fmt_iso(create_t),
                            "deleted_time": _fmt_iso(ts),
                            "lifetime_seconds": int(lifetime.total_seconds()),
                            "usn_reasons": (state.get("last_reasons") or "") + ", " + reasons_raw,
                        })
                        # Don't keep the state — second delete of the same name is a separate sequence
                        del lifecycle[key]

            # ── Detector 3: executable rename ──────────────────────────────
            if "RenameOldName" in reasons:
                rename_pending[entry_no] = {"old_name": name, "old_parent": parent_lower, "ts": ts}
            elif "RenameNewName" in reasons:
                pending = rename_pending.pop(entry_no, None)
                # New name path uses current row's parent + name
                findings.append({
                    "type": "usn_executable_renamed_user_writable",
                    "old_path": _normalize_mft_path((pending or {}).get("old_parent") or "",
                                                    (pending or {}).get("old_name") or "?"),
                    "new_path": full_path,
                    "rename_time": _fmt_iso(ts),
                })

    return findings, total, exec_rows


def _format_usn_finding(f: dict) -> str:
    t = f["type"]
    if t == "usn_drop_then_delete_executable":
        secs = f.get("lifetime_seconds", 0)
        # Pretty lifetime
        if secs < 60:
            life = f"{secs}s"
        elif secs < 3600:
            life = f"{secs // 60}m{secs % 60}s"
        else:
            life = f"{secs // 3600}h{(secs % 3600) // 60}m"
        return (f"- **usn_drop_then_delete_executable** `{f['path']}` "
                f"— created {f.get('created_time')}, deleted {f.get('deleted_time')} "
                f"(lived {life}) ⚠️ DROPPER PATTERN")
    if t == "usn_burst_create_executables_user_writable":
        return (f"- **usn_burst_create_executables_user_writable** `{f['parent_path']}` "
                f"— {f['create_count']} executables created in {int(f['window_minutes'])}min window "
                f"({f.get('first_create')} → {f.get('last_create')})")
    if t == "usn_executable_renamed_user_writable":
        return (f"- **usn_executable_renamed_user_writable** `{f.get('old_path')}` → "
                f"`{f.get('new_path')}` (renamed at {f.get('rename_time')})")
    if t == "usn_ransomware_overwrite_burst":
        exts = ", ".join(f.get("extensions_hit") or []) or "?"
        return (f"- **usn_ransomware_overwrite_burst** `{f.get('user_tree')}` "
                f"— {f.get('overwrite_count')} DataOverwrite events on user-data files "
                f"in {f.get('window_minutes')}min window (extensions: {exts}; "
                f"{f.get('first_overwrite')} → {f.get('last_overwrite')}) "
                f"🚨 ENCRYPTION SWEEP")
    if t == "usn_ransomware_extension_burst":
        samples = f.get("sample_paths") or []
        sample_str = ", ".join(f"`{p}`" for p in samples[:3])
        more = f" (+{len(samples) - 3} more)" if len(samples) > 3 else ""
        return (f"- **usn_ransomware_extension_burst** `{f.get('ransomware_extension')}` "
                f"— {f.get('rename_count')} files renamed in {f.get('window_minutes')}min window "
                f"({f.get('first_rename')} → {f.get('last_rename')}); samples: {sample_str}{more} "
                f"🚨 RANSOMWARE EXTENSION RENAME")
    if t == "usn_ransom_note_created":
        return (f"- **usn_ransom_note_created** `{f.get('path')}` "
                f"created {f.get('created_time')} (matched pattern: `{f.get('matched_pattern')}`) "
                f"🚨 RANSOM NOTE")
    return f"- **{t}** {f}"


def _file_attrs_from_usn_findings(findings: list[dict], host_id: str) -> dict:
    """Same `file:<host>:<path>` shape as MFT findings — auto-merges in the graph.
    Only the drop-then-delete detector produces per-file attrs (burst/rename are
    parent-dir-scoped). Encodes deleted_time + lifetime as additional fields the
    File node stores via the extractor."""
    attrs: dict = {}
    for f in findings:
        if f["type"] != "usn_drop_then_delete_executable":
            continue
        path = f.get("path")
        if not path:
            continue
        ent = f"file:{host_id}:{path}"
        if ent in attrs:
            continue
        attrs[ent] = {
            "created_time": f.get("created_time"),
            "modified_time": None,  # USN doesn't track modify per record this way
            "accessed_time": None,
            "is_deleted": True,
            "parent_path": f.get("parent_path"),
            # Custom fields the report agent surfaces but the extractor ignores (File
            # node doesn't have these columns — they're claim-frontmatter-only metadata)
            "usn_deleted_time": f.get("deleted_time"),
            "usn_lifetime_seconds": f.get("lifetime_seconds"),
            "usn_reasons": f.get("usn_reasons"),
        }
    return attrs


def _entities_from_usn_findings(findings: list[dict], host_id: str) -> list[str]:
    out: set = set()
    for f in findings:
        path = f.get("path") or f.get("new_path") or f.get("old_path")
        if path and not path.startswith("c:\\"):
            continue  # malformed path
        if path:
            out.add(f"file:{host_id}:{path}")
        # Burst-create findings emit a parent-dir-scoped entity for traceability
        if f["type"] == "usn_burst_create_executables_user_writable":
            parent = f.get("parent_path")
            if parent:
                out.add(f"file:{host_id}:{parent}")
    return sorted(out)


def generate_usn_claim(usn_path: Path, findings: list[dict], total_rows: int, exec_rows: int) -> str:
    timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    cid_key = f"{usn_path.name}:{total_rows}:" + "|".join(
        f"{f['type']}:{f.get('path','') or f.get('parent_path','')}" for f in findings[:50]
    )
    cid = "usn-" + hashlib.md5(cid_key.encode()).hexdigest()[:14]
    host_id = derive_host_id(usn_path.name)

    # Cap at MAX_ENTITIES_PER_CLAIM, prioritizing ransomware first (most consequential),
    # then drop-then-delete, then everything else.
    severity = {
        "usn_ransom_note_created": 0,
        "usn_ransomware_overwrite_burst": 0,
        "usn_ransomware_extension_burst": 0,
        "usn_drop_then_delete_executable": 1,
        "usn_burst_create_executables_user_writable": 2,
        "usn_executable_renamed_user_writable": 3,
    }
    findings_sorted = sorted(findings, key=lambda f: (severity.get(f["type"], 99),
                                                       -(_isokey(f.get("created_time") or f.get("rename_time") or f.get("first_create") or f.get("first_overwrite") or f.get("first_rename")))))
    capped = findings_sorted[:MAX_ENTITIES_PER_CLAIM]

    entities = _entities_from_usn_findings(capped, host_id) or [f"host:{host_id}"]
    file_attrs = _file_attrs_from_usn_findings(capped, host_id)

    has_ransomware = any(f["type"] in ("usn_ransomware_overwrite_burst",
                                       "usn_ransomware_extension_burst",
                                       "usn_ransom_note_created") for f in capped)
    has_drop_delete = any(f["type"] == "usn_drop_then_delete_executable" for f in capped)
    if has_ransomware:
        confidence = 0.95
    elif has_drop_delete:
        confidence = 0.90
    else:
        confidence = 0.75 if capped else 0.5

    rel = str(usn_path.relative_to(EVIDENCE_ROOT)) if usn_path.is_relative_to(EVIDENCE_ROOT) else usn_path.name

    fm = {
        "claim_id": cid,
        "status": "new",
        "generated_by": "mft-agent",  # same agent emits both MFT and USN claims
        "host": host_id,
        "usn_journal_path": rel,
        "records_total": total_rows,
        "records_executable_filtered": exec_rows,
        "entities": entities,
        "evidence_refs": [rel],
        "confidence": confidence,
        "timestamp": timestamp,
        "anomaly_count": len(capped),
        "anomaly_count_pre_cap": len(findings),
    }
    if file_attrs:
        fm["file_attrs"] = file_attrs

    by_type: dict = {}
    for f in capped:
        by_type.setdefault(f["type"], []).append(f)

    body_lines = [
        "**USN Journal Analysis (NTFS change history)**",
        "",
        f"Source: `{usn_path.name}` ({total_rows:,} USN records, {exec_rows:,} executable-extension rows after filtering)",
        f"Findings (capped): {len(capped)} of {len(findings)} pre-cap",
        "",
    ]
    if not capped:
        body_lines.append("_No USN lifecycle anomalies detected by this rule set._")
    else:
        readable_titles = {
            "usn_ransom_note_created": "🚨 RANSOMWARE — ransom note(s) created",
            "usn_ransomware_overwrite_burst": "🚨 RANSOMWARE — DataOverwrite encryption sweep",
            "usn_ransomware_extension_burst": "🚨 RANSOMWARE — extension-rename burst",
            "usn_drop_then_delete_executable": "Drop-then-delete executables (DROPPER TRADECRAFT)",
            "usn_burst_create_executables_user_writable": "Burst-create executables in user-writable paths",
            "usn_executable_renamed_user_writable": "Executable rename events in user-writable paths",
        }
        for t in ("usn_ransom_note_created",
                  "usn_ransomware_overwrite_burst",
                  "usn_ransomware_extension_burst",
                  "usn_drop_then_delete_executable",
                  "usn_burst_create_executables_user_writable",
                  "usn_executable_renamed_user_writable"):
            sub = by_type.get(t) or []
            if not sub:
                continue
            body_lines.append(f"_{readable_titles[t]} ({len(sub)}):_")
            for f in sub[:25]:
                body_lines.append(_format_usn_finding(f))
            if len(sub) > 25:
                body_lines.append(f"_…({len(sub) - 25} more of this type)_")
            body_lines.append("")

    body_lines += [
        "> _USN journal records every NTFS change (create/delete/rename/data-write/security). "
        "Drop-then-delete is dropper tradecraft: write binary, execute, delete — minimizing "
        "post-mortem disk artifacts. MFT alone shows only the post-deletion state; USN preserves "
        "the full create→delete sequence as separate timestamped records. Ransomware encryption "
        "sweeps appear as dense bursts of DataOverwrite events on user-data files in a single "
        "user-dir tree, often followed by RenameNewName events to a known ransomware extension._",
        "",
    ]
    if has_ransomware:
        body_lines += [
            "**🚨 IMMEDIATE ACTION:** Ransomware activity detected. Recommend host isolation. "
            "Cross-reference the affected user-dir tree with prefetch/memory for the encryptor "
            "process; check registry HKLM\\...\\Run for persistence; look at evtx for initial "
            "access vector. Consider pulling Volume Shadow Copies if VSS hasn't been deleted.",
        ]
    else:
        body_lines += [
            "**Hypothesis:** Pivot drop-then-delete file paths to evtx 4688 (process create) for the "
            "executing PID — that's the dropper-of-the-dropper. File creation timestamps anchor the "
            "temporal correlation rule alongside MFT/registry/prefetch evidence.",
        ]

    return f"---\n{yaml.dump(fm, sort_keys=False)}---\n" + "\n".join(body_lines) + "\n"


# ─────────────────────────────────────────────────────────────
# Recycle bin — RBCmd $I-file detectors (original-path + deletion timestamp)
# ─────────────────────────────────────────────────────────────

# Restored-from-staging glob: every $I file we pull out of the recycle bin lands as
# `<image>__recycle__<sid>_<name>` in evidence/new/. RBCmd takes a directory, so we
# stage the entire batch into a tmpdir per claim.

async def _run_rbcmd(staged_dir: Path) -> Path | None:
    """Invoke RBCmd -d on a directory of $I files via local subprocess; return path
    to the produced CSV.

    `_dollar_` filename mangling (from disk_image staging) stays in place — RBCmd
    doesn't care about the source filename, only the file content (binary $I record).

    Direct-subprocess exception per evtx_agent.run_evtxecmd rationale (RBCmd.dll
    lives at /opt/zimmermantools/, outside Chisel --root).
    """
    out_dir = Path(tempfile.mkdtemp(prefix="rbcmd_"))
    proc = await asyncio.create_subprocess_exec(
        *RBCMD, "-d", str(staged_dir), "--csv", str(out_dir), "--csvf", "rb.csv",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    await proc.communicate()
    csv_file = out_dir / "rb.csv"
    if not csv_file.exists():
        return None
    return csv_file


def _normalize_recycle_path(filename: str) -> str:
    """RBCmd emits `C:\\Users\\nromanoff\\Documents\\foo.zip` — lowercase + backslash-normalize
    to match the path shape every other agent in this system uses."""
    if not filename:
        return ""
    return filename.replace("/", "\\").lower()


def detect_recycle_anomalies(csv_path: Path, staged_filename_to_sid: dict[str, str]) -> tuple[list[dict], int]:
    """Parse RBCmd CSV and apply detectors. Returns (findings, row_count).

    `staged_filename_to_sid` maps staged-filename basenames back to their per-user SID
    (recovered from disk_image_agent's staging convention) so each finding carries the
    user the file was deleted by.

    Detectors:
    - `recycle_executable_user_writable_origin` — exe deleted from a user-writable path
      (e.g., dropper recovered into recycle bin from \\Users\\<u>\\Desktop\\)
    - `recycle_masquerade_origin` — basename matches MASQUERADE_TARGETS but original path
      isn't the canonical system path
    Both are 0.80 confidence — execution-suggestive (file was on disk + deleted via UI).
    """
    findings: list = []
    row_count = 0
    with open(csv_path, encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            row_count += 1
            if (row.get("FileType") or "").strip() != "$I":
                continue  # Skip INFO2 (legacy) entries — only FileType=$I gives us full path
            original_path = _normalize_recycle_path(row.get("FileName") or "")
            if not original_path:
                continue
            try:
                size = int((row.get("FileSize") or "0").strip() or "0")
            except ValueError:
                size = 0
            deleted_on = (row.get("DeletedOn") or "").strip() or None
            source_name = (row.get("SourceName") or "").strip()
            sid = staged_filename_to_sid.get(Path(source_name).name)

            basename = original_path.rsplit("\\", 1)[-1]
            ext = "." + basename.rsplit(".", 1)[-1] if "." in basename else ""

            common = {
                "original_path": original_path,
                "basename": basename,
                "size": size,
                "deleted_on": deleted_on,
                "sid": sid,
            }

            # Detector 1: executable deleted from user-writable path
            if ext in EXECUTABLE_EXTS and any(h in original_path for h in USER_WRITABLE_HINTS):
                findings.append({"type": "recycle_executable_user_writable_origin", **common})

            # Detector 2: masquerade (basename in MASQUERADE_TARGETS but path != canonical)
            expected = MASQUERADE_TARGETS.get(basename)
            if expected and expected.lower() not in original_path:
                findings.append({
                    "type": "recycle_masquerade_origin",
                    **common, "expected_path": expected,
                })

    return findings, row_count


# Reuse registry_agent's MASQUERADE_TARGETS via direct duplicate (avoid cross-agent imports —
# matches the duplicate-vs-import precedent already established in this codebase).
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


def _format_recycle_finding(f: dict) -> str:
    t = f["type"]
    sid_str = f" (deleted by {f.get('sid')})" if f.get('sid') else ""
    if t == "recycle_executable_user_writable_origin":
        return (f"- **recycle_executable_user_writable_origin** `{f['original_path']}` "
                f"({f.get('size', 0):,} bytes; deleted {f.get('deleted_on')}){sid_str}")
    if t == "recycle_masquerade_origin":
        return (f"- **recycle_masquerade_origin** `{f['original_path']}` "
                f"(basename `{f.get('basename')}` should be at `{f.get('expected_path')}`; "
                f"deleted {f.get('deleted_on')}){sid_str}")
    return f"- **{t}** {f}"


def _entities_from_recycle_findings(findings: list[dict], host_id: str) -> list[str]:
    out: set = set()
    for f in findings:
        path = f.get("original_path")
        if path:
            out.add(f"file:{host_id}:{path}")
    return sorted(out)


def _file_attrs_from_recycle_findings(findings: list[dict], host_id: str) -> dict:
    """Each $I record gives us a deletion timestamp + original path. Auto-merges with
    USN drop-then-delete File nodes for the same path; first source to populate wins."""
    attrs: dict = {}
    for f in findings:
        path = f.get("original_path")
        if not path:
            continue
        ent = f"file:{host_id}:{path}"
        if ent in attrs:
            continue
        attrs[ent] = {
            "deleted_time": f.get("deleted_on"),
            "is_deleted": True,
            "file_size": f.get("size"),
            # Custom fields the report agent surfaces but extractor ignores
            "recycle_sid": f.get("sid"),
        }
    return attrs


def generate_recycle_claim(staged_files: list[Path], findings: list[dict], row_count: int) -> str:
    timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    # Use first staged file as the host-derivation source — they all share the image stem.
    sample = staged_files[0] if staged_files else Path("recycle.unknown")
    host_id = derive_host_id(sample.name)
    cid_key = f"recycle:{host_id}:{row_count}:" + "|".join(
        f"{f['type']}:{f.get('original_path','')}" for f in findings[:50]
    )
    cid = "recycle-" + hashlib.md5(cid_key.encode()).hexdigest()[:14]

    entities = _entities_from_recycle_findings(findings, host_id) or [f"host:{host_id}"]
    file_attrs = _file_attrs_from_recycle_findings(findings, host_id)

    confidence = 0.80 if findings else 0.5

    fm = {
        "claim_id": cid,
        "status": "new",
        "generated_by": "mft-agent",  # same agent emits MFT/USN/recycle claims
        "host": host_id,
        "recycle_files_scanned": len(staged_files),
        "recycle_records_total": row_count,
        "entities": entities,
        "evidence_refs": [str(p.relative_to(EVIDENCE_ROOT)) if p.is_relative_to(EVIDENCE_ROOT) else p.name
                          for p in staged_files],
        "confidence": confidence,
        "timestamp": timestamp,
        "anomaly_count": len(findings),
    }
    if file_attrs:
        fm["file_attrs"] = file_attrs

    body_lines = [
        "**Recycle Bin Analysis ($I metadata via RBCmd)**",
        "",
        f"Scanned {len(staged_files)} `$I` file(s); {row_count} record(s) parsed; {len(findings)} flagged.",
        "",
    ]
    if not findings:
        body_lines.append("_No suspicious recycle-bin entries detected by this rule set._")
    else:
        by_type: dict = {}
        for f in findings:
            by_type.setdefault(f["type"], []).append(f)
        readable_titles = {
            "recycle_executable_user_writable_origin": "Executables deleted from user-writable paths",
            "recycle_masquerade_origin": "Masquerade-binary deletions (basename mismatch with canonical path)",
        }
        for t in ("recycle_masquerade_origin", "recycle_executable_user_writable_origin"):
            sub = by_type.get(t) or []
            if not sub:
                continue
            body_lines.append(f"_{readable_titles[t]} ({len(sub)}):_")
            for f in sub[:25]:
                body_lines.append(_format_recycle_finding(f))
            if len(sub) > 25:
                body_lines.append(f"_…({len(sub) - 25} more of this type)_")
            body_lines.append("")

    body_lines += [
        "> _Recycle bin `$I` files capture the original full path + deletion timestamp of "
        "every file the user (or attacker) sent to the recycle bin. When the bin is emptied "
        "the `$I` files vanish but USN journal still records the create+delete sequence — "
        "the two sources are complementary._",
        "",
        "**Hypothesis:** Cross-reference `original_path` with MFT `mft_executable_in_recycle_bin` "
        "findings (which only know the recycle-bin location) and USN drop-then-delete findings "
        "(which capture the create+delete timing). File nodes auto-merge on path, so the analyst's "
        "view of the affected exe shows: original location + deletion timestamp + USN lifecycle "
        "+ MFT deletion record + execution evidence (prefetch/shimcache/amcache).",
    ]

    return f"---\n{yaml.dump(fm, sort_keys=False)}---\n" + "\n".join(body_lines) + "\n"


def generate_claim(mft_path: Path, findings: list[dict], total_rows: int, kept_rows: int) -> str:
    timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    cid_key = f"{mft_path.name}:{total_rows}:" + "|".join(
        f"{f['type']}:{f.get('path','')}" for f in findings[:50]
    )
    cid = "mft-" + hashlib.md5(cid_key.encode()).hexdigest()[:14]
    host_id = derive_host_id(mft_path.name)

    capped = _prioritize_and_cap(findings, MAX_ENTITIES_PER_CLAIM)
    entities = _entities_from_findings(capped, host_id) or [f"host:{host_id}"]
    file_attrs = _file_attrs_from_findings(capped, host_id)

    has_timestomping = any(f["type"] == "mft_timestomping_detected" for f in capped)
    confidence = 0.95 if has_timestomping else (0.85 if capped else 0.5)

    rel = str(mft_path.relative_to(EVIDENCE_ROOT)) if mft_path.is_relative_to(EVIDENCE_ROOT) else mft_path.name

    fm = {
        "claim_id": cid,
        "status": "new",
        "generated_by": "mft-agent",
        "host": host_id,
        "mft_path": rel,
        "records_total": total_rows,
        "records_executable_filtered": kept_rows,
        "entities": entities,
        "evidence_refs": [rel],
        "confidence": confidence,
        "timestamp": timestamp,
        "anomaly_count": len(capped),
        "anomaly_count_pre_cap": len(findings),
    }
    if file_attrs:
        fm["file_attrs"] = file_attrs

    # Explicit list of paths flagged by the timestomping detector — gives the
    # correlation agent's standalone timestomping rule an unambiguous signal
    # without inferring from claim confidence (which can drift across versions).
    timestomped_paths = sorted({f["path"] for f in capped if f["type"] == "mft_timestomping_detected"})
    if timestomped_paths:
        fm["timestomped_paths"] = timestomped_paths

    # Group capped findings by type for readable rendering.
    by_type: dict = {}
    for f in capped:
        by_type.setdefault(f["type"], []).append(f)

    body_lines = [
        "**MFT Analysis**",
        "",
        f"Source: `{mft_path.name}` ({total_rows:,} records, {kept_rows:,} executable candidates after filtering)",
        f"Findings (capped): {len(capped)} of {len(findings)} pre-cap",
        "",
    ]
    if not capped:
        body_lines.append("_No MFT anomalies detected by this rule set._")
    else:
        readable_titles = {
            "mft_timestomping_detected": "Timestomping (anti-forensics)",
            "mft_deleted_executable_user_writable": "Deleted executables in user-writable paths",
            "mft_alternate_data_stream_executable": "Alternate Data Stream executables",
            "mft_executable_in_recycle_bin": "Executables in recycle bin",
            "mft_executable_dropped_user_writable": "Executables in user-writable paths",
        }
        for t in ("mft_timestomping_detected",
                  "mft_deleted_executable_user_writable",
                  "mft_alternate_data_stream_executable",
                  "mft_executable_in_recycle_bin",
                  "mft_executable_dropped_user_writable"):
            sub = by_type.get(t) or []
            if not sub:
                continue
            body_lines.append(f"_{readable_titles[t]} ({len(sub)}):_")
            for f in sub[:25]:
                body_lines.append(_format_finding(f))
            if len(sub) > 25:
                body_lines.append(f"_…({len(sub) - 25} more of this type)_")
            body_lines.append("")

    body_lines += [
        "> _MFT $StandardInformation timestamps can be modified via SetFileTime "
        "(anti-forensics); $FileName timestamps are kernel-only. SI<FN divergence is "
        "direct evidence of timestomping._",
        "",
        "**Hypothesis:** Pivot file paths to registry/prefetch/shimcache claims for the "
        "same exe — File nodes auto-merge in the graph and inherit MFT timestamps. "
        "File `created_time` anchors the temporal correlation rule and should cluster "
        "near RDP logons and process starts during the compromise window.",
    ]

    return f"---\n{yaml.dump(fm, sort_keys=False)}---\n" + "\n".join(body_lines) + "\n"


async def _run_recycle_path(rb_path: Path, chisel: Chisel) -> None:
    """Recycle-bin code path: gather ALL `*__recycle__*` files from evidence/new + processed/
    into a single tmpdir, run RBCmd -d to parse them as a batch, emit one claim covering the
    whole recycle-bin contents.

    Triggered on the FIRST `__recycle__` file the dispatcher sees; subsequent recycle files
    in the same image batch are no-op'd (we already processed them in the first run). This
    "claim_already_emitted" check uses the staged image_stem prefix common to all related files.
    """
    # Image stem = everything before `__recycle__` — all recycle files from one image share it.
    image_stem = rb_path.name.split("__recycle__", 1)[0]

    # Gather all matching files from new/ and processed/ — the dispatcher fires per-file and
    # may have moved earlier ones; collect everything before invoking RBCmd.
    candidates: list[Path] = []
    for d in (EVIDENCE_NEW, EVIDENCE_ROOT / "processed"):
        if not d.exists():
            continue
        for p in d.iterdir():
            if p.is_file() and p.name.startswith(f"{image_stem}__recycle__"):
                candidates.append(p)

    # Dedup-by-name (in case a file is in both new/ and processed/)
    seen: set = set()
    unique = []
    for p in candidates:
        if p.name not in seen:
            seen.add(p.name)
            unique.append(p)
    candidates = unique

    print(f"🗑️  Recycle bin: {len(candidates)} $I file(s) for image `{image_stem}`")
    if not candidates:
        return

    # Build SID-recovery map from staged filenames: `<stem>__recycle__<sid>_<dollar-encoded-name>`
    # → sid is the segment between `__recycle__` and the next `_dollar_`.
    staged_filename_to_sid: dict[str, str] = {}

    # Stage all $I files into a tmpdir so RBCmd can scan with -d. Restore the original
    # `$I*` filenames RBCmd expects (undo the `_dollar_` mangling).
    with tempfile.TemporaryDirectory(prefix="rbcmd_in_") as in_dir:
        in_path = Path(in_dir)
        for src in candidates:
            tail = src.name.split("__recycle__", 1)[1]  # e.g. "S-1-5-...-1109__dollar__IPFXZSB"
            # Recover SID + original name
            if "_dollar_" in tail:
                sid_part, name_part = tail.split("_dollar_", 1)
                sid = sid_part.rstrip("_")
                original_name = "$" + name_part
            else:
                sid = tail
                original_name = tail
            dest = in_path / original_name
            # Avoid name collision across SIDs by prefixing with a short SID hash if duplicates
            if dest.exists():
                dest = in_path / f"{sid[-8:]}_{original_name}"
            dest.write_bytes(src.read_bytes())
            staged_filename_to_sid[dest.name] = sid

        csv_path = await _run_rbcmd(in_path)
        if csv_path is None:
            print("   ❌ RBCmd produced no output — emitting provenance-only claim")
            chisel.call("create_directory", {"path": str(CLAIMS_TODO)})
            claim = generate_recycle_claim(candidates, [], 0)
            ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
            chisel.call("write_file", {"path": str(CLAIMS_TODO / f"recycle_{image_stem}_{ts}.md"), "content": claim})
            return

        try:
            findings, row_count = detect_recycle_anomalies(csv_path, staged_filename_to_sid)
            print(f"   {row_count} $I record(s), {len(findings)} suspicious")
            for f in findings[:5]:
                print("   " + _format_recycle_finding(f).lstrip("- ").lstrip())
        finally:
            try:
                csv_path.unlink()
                csv_path.parent.rmdir()
            except OSError:
                pass

    chisel.call("create_directory", {"path": str(CLAIMS_TODO)})
    claim = generate_recycle_claim(candidates, findings, row_count)
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    claim_path = CLAIMS_TODO / f"recycle_{image_stem}_{ts}.md"
    chisel.call("write_file", {"path": str(claim_path), "content": claim})
    print(f"✅ Claim written → {claim_path.name}")


async def _run_usn_path(usn_path: Path, chisel: Chisel) -> None:
    """USN journal code path: locate the companion $MFT (if staged), run MFTECmd with -m,
    apply the lifecycle detectors, emit a usn_<host>_<ts>.md claim."""
    companion_mft = _find_companion_mft(usn_path)
    if companion_mft:
        print(f"   companion MFT: {companion_mft.name}")
    else:
        print("   ⚠️  no companion $MFT found — parent paths will be 'pathunknown' and "
              "most user-writable detectors will skip; emitting provenance claim only")
    print(f"📂 Parsing USN {usn_path.name} ({usn_path.stat().st_size // (1024*1024)} MB)")
    csv_path = await _run_mftecmd_usn(usn_path, companion_mft)
    if csv_path is None:
        print("   ❌ MFTECmd produced no USN output — emitting provenance-only claim")
        chisel.call("create_directory", {"path": str(CLAIMS_TODO)})
        claim = generate_usn_claim(usn_path, [], 0, 0)
        ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        chisel.call("write_file", {"path": str(CLAIMS_TODO / f"usn_{usn_path.stem}_{ts}.md"), "content": claim})
        return

    try:
        findings, total, exec_rows = detect_usn_anomalies(csv_path)
        print(f"   {total:,} USN records, {exec_rows:,} executable rows, {len(findings)} findings")
        for f in findings[:5]:
            print("   " + _format_usn_finding(f).lstrip("- ").lstrip())
    finally:
        try:
            csv_path.unlink()
            csv_path.parent.rmdir()
        except OSError:
            pass

    chisel.call("create_directory", {"path": str(CLAIMS_TODO)})
    claim = generate_usn_claim(usn_path, findings, total, exec_rows)
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    claim_path = CLAIMS_TODO / f"usn_{usn_path.stem}_{ts}.md"
    chisel.call("write_file", {"path": str(claim_path), "content": claim})
    print(f"✅ Claim written → {claim_path.name}")


async def run_mft_analysis(mft: Path | None = None):
    """Standalone entrypoint — also called in-process by the orchestrator dispatcher.

    Dispatches by filename: $MFT files → MFT snapshot detectors; $UsnJrnl:$J files →
    USN journal lifecycle detectors. The `mft` parameter name is retained for backward
    compatibility with the dispatcher; both file types route through here.
    """
    print("📁 MFT/USN Agent starting (Chisel-confined, MFTECmd CSV)...")
    chisel = Chisel(CHISEL_URL, CHISEL_SECRET)
    chisel.connect()
    print(f"🔒 Chisel session → {chisel.endpoint} (sid={chisel.session_id[:8]}…)")

    if mft is None:
        listing = chisel.shell("ls", ["-1", str(EVIDENCE_NEW)])
        # Prefer USN files when both are present (USN run depends on MFT being already
        # processed; in standalone mode either order works since we look in processed/ too).
        usn_candidates = [EVIDENCE_NEW / n.strip() for n in listing.splitlines()
                          if n.strip() and detect_usn(EVIDENCE_NEW / n.strip())]
        mft_candidates = [EVIDENCE_NEW / n.strip() for n in listing.splitlines()
                          if n.strip() and detect_mft(EVIDENCE_NEW / n.strip())]
        mft = (usn_candidates or mft_candidates or [None])[0]
        if mft is None:
            print("❌ no $MFT or $UsnJrnl in evidence/new/")
            return

    # Dispatch by filename
    if detect_usn(mft):
        await _run_usn_path(mft, chisel)
        return
    if detect_recycle(mft):
        await _run_recycle_path(mft, chisel)
        return

    print(f"📂 Parsing MFT {mft.name} ({mft.stat().st_size // (1024*1024)} MB)")
    csv_path = await _run_mftecmd(mft)
    if csv_path is None:
        print("   ❌ MFTECmd produced no output — emitting provenance-only claim")
        chisel.call("create_directory", {"path": str(CLAIMS_TODO)})
        claim = generate_claim(mft, [], 0, 0)
        ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        chisel.call("write_file", {"path": str(CLAIMS_TODO / f"mft_{mft.stem}_{ts}.md"), "content": claim})
        return

    try:
        findings, total, kept = detect_mft_anomalies(csv_path)
        print(f"   {total:,} records, {kept:,} executable candidates, {len(findings)} pre-cap findings")
        for f in _prioritize_and_cap(findings, 5):
            print("   " + _format_finding(f).lstrip("- ").lstrip())
    finally:
        # MFTECmd CSV can be huge — drop it as soon as we're done.
        try:
            csv_path.unlink()
            csv_path.parent.rmdir()
        except OSError:
            pass

    chisel.call("create_directory", {"path": str(CLAIMS_TODO)})
    claim = generate_claim(mft, findings, total, kept)
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    claim_path = CLAIMS_TODO / f"mft_{mft.stem}_{ts}.md"
    chisel.call("write_file", {"path": str(claim_path), "content": claim})
    print(f"✅ Claim written → {claim_path.name}")


if __name__ == "__main__":
    asyncio.run(run_mft_analysis())
