# agents/disk_image_agent/agent.py
"""
Disk Image Agent — extracts canonical Windows artifacts from an EnCase E01.

Pipeline:
  ewfmount E01 → mount/ewf1 (raw bytes) → mmls finds NTFS → fls/icat extracts
  registry hives → drops them into evidence/new/ for downstream analysers.

Standalone CLI:  python -m agents.disk_image_agent.agent
Orchestrator:    await run_disk_image_extraction(image=Path(...))
"""

import asyncio
import hashlib
import os
from datetime import UTC, datetime
from pathlib import Path

import yaml

from agents._chisel import Chisel
from cognee_schema.schema import derive_host_id

EVIDENCE_ROOT = Path(os.environ.get("EVIDENCE_ROOT", "/home/sansforensics/dfirskills2/evidence"))
EVIDENCE_NEW = EVIDENCE_ROOT / "new"
EVIDENCE_EXTRACTED = EVIDENCE_ROOT / "extracted"
EVIDENCE_MOUNTS = EVIDENCE_ROOT / "mounts"
CLAIMS_TODO = EVIDENCE_ROOT / "claims/todo"

CHISEL_URL = os.environ.get("CHISEL_URL", "http://127.0.0.1:3000")
CHISEL_SECRET = os.environ["CHISEL_SECRET"]

# Canonical hive locations under \Windows\System32\config\
SYSTEM_HIVES = ("SYSTEM", "SOFTWARE", "SAM", "SECURITY", "COMPONENTS")

# Stage only these high-signal event logs into evidence/new/ for agent processing.
# Everything else (Win7 ships with ~140 per-feature logs, mostly empty) still gets
# extracted to evidence/extracted/<image>/evtx/ for analyst review on demand.
EVTX_STAGE_ALLOWLIST = {
    "Security.evtx",
    "System.evtx",
    "Application.evtx",
    "Microsoft-Windows-PowerShell%4Operational.evtx",
    "Microsoft-Windows-TaskScheduler%4Operational.evtx",
    "Microsoft-Windows-Windows Defender%4Operational.evtx",
    "Microsoft-Windows-Sysmon%4Operational.evtx",
    "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx",
    # AD/DC: 4662 (object access for DCSync replication-rights detection) and
    # 5136-5141 (DS object modify/delete) live here, not in Security.evtx.
    "Microsoft-Windows-Directory-Service%4Operational.evtx",
}


# Module-level Chisel singleton — set by run_disk_image_extraction at start.
# disk_image_agent has ~15 helper functions that call forensic tools; threading
# chisel through every signature would be invasive. Singleton scoped to one
# process / one extraction run is the pragmatic alternative; helpers access it
# via _run() below.
_CHISEL: "Chisel | None" = None


def _set_chisel(c: "Chisel") -> None:
    global _CHISEL
    _CHISEL = c


async def _run(cmd: list[str], **kw) -> tuple[int, bytes, bytes]:
    """Chisel-routed forensic-tool execution. Drop-in replacement for the
    previous direct-subprocess _run. Routes the FIRST element of `cmd` as the
    tool name, the rest as args. Returns (rc, stdout_bytes, stderr_bytes) for
    backward-compatible signature with existing callers.

    The `**kw` is accepted-but-ignored — the previous _run took kwargs like
    `cwd=` for subprocess.create_subprocess_exec. Chisel runs in its server-side
    cwd; if a caller depended on a specific cwd it would have already been broken.
    """
    if _CHISEL is None:
        raise RuntimeError("disk_image_agent _run called before _set_chisel()")
    try:
        result = _CHISEL.exec_tool(cmd[0], cmd[1:], agent_name="disk-image-agent")
    except RuntimeError as e:
        print(f"   ❌ {cmd[0]} failed (Chisel error): {e}")
        return 1, b"", str(e).encode()
    return (
        result["exit_code"],
        result["stdout"].encode("utf-8", errors="replace"),
        result["stderr"].encode("utf-8", errors="replace"),
    )


async def mount_e01(image: Path, mount_dir: Path) -> bool:
    mount_dir.mkdir(parents=True, exist_ok=True)
    # ewfmount daemonises after a successful mount; Chisel still sees clean exit_code=0.
    rc, _, stderr = await _run(["ewfmount", str(image), str(mount_dir)])
    if rc != 0:
        print(f"   ❌ ewfmount failed (exit {rc}): {stderr.decode(errors='replace')[:300]}")
        return False
    return (mount_dir / "ewf1").exists()


async def unmount_e01(mount_dir: Path):
    # fusermount now in Chisel allowlist — routes through _run for full audit coverage.
    rc, _, stderr = await _run(["fusermount", "-u", str(mount_dir)])
    if rc != 0:
        print(f"   ⚠️  unmount warning: {stderr.decode(errors='replace')[:200]}")
    try:
        mount_dir.rmdir()
    except OSError:
        pass


async def find_ntfs_partition(raw_image: Path) -> tuple[int, int] | None:
    """Return (start_sector, length_sectors) of the largest NTFS partition, or None."""
    rc, stdout, _ = await _run(["mmls", str(raw_image)])
    if rc != 0:
        # No partition table — try treating whole image as a single NTFS volume at offset 0
        rc2, _, _ = await _run(["fsstat", "-o", "0", str(raw_image)])
        return (0, 0) if rc2 == 0 else None
    parts: list = []
    for line in stdout.decode(errors="replace").splitlines():
        if "NTFS" not in line and "exFAT" not in line:
            continue
        toks = line.split()
        try:
            start = int(toks[2])
            length = int(toks[4])
            parts.append((start, length))
        except (ValueError, IndexError):
            continue
    return max(parts, key=lambda p: p[1]) if parts else None


async def navigate(image: Path, offset: int, parent_inode: str | None, target_name: str) -> str | None:
    """List parent_inode (or root) via fls; return the inode of `target_name` (case-insensitive)."""
    args = ["-o", str(offset), str(image)]
    if parent_inode is not None:
        args.append(str(parent_inode))
    rc, stdout, _ = await _run(["fls", *args])
    if rc != 0:
        return None
    target_l = target_name.lower()
    for line in stdout.decode(errors="replace").splitlines():
        if "\t" not in line:
            continue
        meta, name = line.split("\t", 1)
        # name format: "SYSTEM" or "SYSTEM (deleted)" or "SYSTEM:<some-stream>"
        clean = name.split(":")[0].split(" (")[0].strip()
        if clean.lower() == target_l:
            inode = meta.strip().split()[-1].rstrip(":")
            return inode
    return None


async def extract_file(image: Path, offset: int, inode: str, dest: Path) -> int:
    """Extract one file from the disk image via icat. Streams icat stdout DIRECTLY
    to the destination file via local subprocess — does NOT route through Chisel.

    INTENTIONAL EXCEPTION to the route-through-Chisel rule. icat output for `$MFT`
    and `$J` is routinely 100s of MB to 1+ GB. Routing through Chisel would force
    the Chisel server to buffer the entire stdout in its Rust process before
    HTTP-encoding the JSON-RPC response — verified to crash Chisel mid-extraction
    during the win7-32-nromanoff live run on 2026-04-26 ~21:22 UTC (no OOM kill,
    just a Chisel-internal panic on the large stdout buffer; 315 audit entries
    succeeded, then ConnectionRefusedError for every subsequent call).

    Audit-log gap is bounded: `icat` is the only large-binary-output tool in the
    pipeline. Every other Chisel-routed tool (`vol`, `EvtxECmd`, `MFTECmd`, `RBCmd`,
    `log2timeline.py`, etc.) emits MB-scale parser output, not GB-scale raw file
    content. The extracted file's existence + size is implicitly captured via
    every downstream agent's claim citing the extracted artifact path in
    `evidence_refs`, so 'what got extracted' is recoverable from the claim corpus.

    Sister exception precedent: `unmount_e01` was previously also direct-subprocess
    until `fusermount` was added to the Chisel allowlist. `icat` could be similarly
    promoted later via Option B (extending Chisel with a stream-to-file MCP method),
    but this Option-A revert is the safe immediate fix.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    with open(dest, "wb") as f:
        proc = await asyncio.create_subprocess_exec(
            "icat", "-o", str(offset), str(image), str(inode),
            stdout=f, stderr=asyncio.subprocess.PIPE,
        )
        await proc.wait()
    return dest.stat().st_size if dest.exists() else 0


async def find_user_ntuser_files(raw: Path, offset: int) -> list[tuple[str, str]]:
    """Return [(username, ntuser_inode), ...] for Users/<u>/NTUSER.DAT entries that exist."""
    users_inode = await navigate(raw, offset, None, "Users")
    if users_inode is None:
        return []
    rc, stdout, _ = await _run(["fls", "-o", str(offset), str(raw), users_inode])
    if rc != 0:
        return []
    out: list = []
    for line in stdout.decode(errors="replace").splitlines():
        if "\t" not in line or not line.startswith("d/"):
            continue
        meta, name = line.split("\t", 1)
        username = name.split(":")[0].split(" (")[0].strip()
        if username in {"Default", "Default User", "Public", "All Users", ".", ".."}:
            continue
        user_inode = meta.strip().split()[-1].rstrip(":")
        ntuser = await navigate(raw, offset, user_inode, "NTUSER.DAT")
        if ntuser:
            out.append((username, ntuser))
    return out


async def extract_all_hives(image: Path, raw: Path, extract_dir: Path) -> tuple[dict, int]:
    """Extract canonical hives + per-user NTUSER.DAT. Returns ({logical: (path, size)}, partition_offset)."""
    part = await find_ntfs_partition(raw)
    if part is None:
        print("   ❌ no NTFS partition found")
        return {}, -1
    offset, _ = part
    print(f"   NTFS partition at sector {offset}")
    extract_dir.mkdir(parents=True, exist_ok=True)
    extracted: dict = {}

    # Walk to \Windows\System32\config\
    win = await navigate(raw, offset, None, "Windows")
    sys32 = await navigate(raw, offset, win, "System32") if win else None
    config = await navigate(raw, offset, sys32, "config") if sys32 else None
    if config is None:
        print("   ❌ \\Windows\\System32\\config\\ not found")
        return {}, offset

    for hive in SYSTEM_HIVES:
        inode = await navigate(raw, offset, config, hive)
        if inode is None:
            print(f"   ⚠️  hive {hive} not found")
            continue
        dest = extract_dir / hive
        size = await extract_file(raw, offset, inode, dest)
        extracted[hive] = (dest, size)
        print(f"   extracted {hive}: {size:,} bytes")

    # Per-user NTUSER.DAT
    for username, inode in await find_user_ntuser_files(raw, offset):
        logical = f"NTUSER.DAT_{username}"
        dest = extract_dir / logical
        size = await extract_file(raw, offset, inode, dest)
        extracted[logical] = (dest, size)
        print(f"   extracted {logical}: {size:,} bytes")

    # Event logs under \Windows\System32\winevt\Logs\
    evtx_extracted = await extract_all_evtx(raw, offset, sys32, extract_dir)
    extracted.update(evtx_extracted)

    # Prefetch under \Windows\Prefetch\ — naturally bounded (≤128 on Win7+),
    # every entry is high-signal so no allowlist needed.
    prefetch_extracted = await extract_all_prefetch(raw, offset, win, extract_dir)
    extracted.update(prefetch_extracted)

    # $MFT — NTFS inode 0. Single file, big payoff: file creation timestamps + timestomping.
    mft_extracted = await extract_mft(raw, offset, extract_dir)
    extracted.update(mft_extracted)

    # $UsnJrnl:$J — NTFS change history. Lives at \$Extend\$UsnJrnl as a named ADS;
    # captures the create-then-delete tradecraft MFT alone can't see. Absence is normal
    # (USN can be disabled or the journal can be empty on quiescent systems).
    usn_extracted = await extract_usnjrnl(raw, offset, extract_dir)
    extracted.update(usn_extracted)

    # Amcache.hve under \Windows\AppCompat\Programs\ — Win7-SP1+KB2952664 onwards.
    # Absent on pre-KB2952664 hosts; absence is normal and not an error.
    amcache_extracted = await extract_amcache(raw, offset, win, extract_dir)
    extracted.update(amcache_extracted)

    # Recycle bin $I metadata files under \$Recycle.Bin\<SID>\ — original-path + deletion-time
    # for everything currently in (or recently emptied from) the recycle bin. RBCmd parses these.
    recycle_extracted = await extract_recycle_bin(raw, offset, extract_dir)
    extracted.update(recycle_extracted)

    return extracted, offset


async def extract_all_evtx(raw: Path, offset: int, sys32_inode: str | None, extract_dir: Path) -> dict:
    """Extract every *.evtx under \\Windows\\System32\\winevt\\Logs\\.
    Returns {logical_name: (path, size)} keyed as `evtx_<LogName>` to disambiguate from hives.
    """
    if sys32_inode is None:
        return {}
    winevt = await navigate(raw, offset, sys32_inode, "winevt")
    if winevt is None:
        print("   ⚠️  \\Windows\\System32\\winevt\\ not found — skipping evtx extraction")
        return {}
    logs = await navigate(raw, offset, winevt, "Logs")
    if logs is None:
        print("   ⚠️  \\Windows\\System32\\winevt\\Logs\\ not found")
        return {}

    evtx_dir = extract_dir / "evtx"
    evtx_dir.mkdir(parents=True, exist_ok=True)
    rc, stdout, _ = await _run(["fls", "-o", str(offset), str(raw), logs])
    if rc != 0:
        return {}

    out: dict = {}
    for line in stdout.decode(errors="replace").splitlines():
        if "\t" not in line or not line.startswith("r/r"):
            continue
        meta, name = line.split("\t", 1)
        clean = name.split(":")[0].split(" (")[0].strip()
        if not clean.lower().endswith(".evtx"):
            continue
        inode = meta.strip().split()[-1].rstrip(":")
        dest = evtx_dir / clean
        size = await extract_file(raw, offset, inode, dest)
        if size > 0:
            logical = f"evtx_{clean}"  # keep .evtx so staged filename ends correctly for routing
            out[logical] = (dest, size)
            print(f"   extracted evtx {clean}: {size:,} bytes")
    print(f"   evtx total: {len(out)} log file(s)")
    return out


async def extract_mft(raw: Path, offset: int, extract_dir: Path) -> dict:
    """Extract NTFS $MFT (inode 0). Returns {'mft': (path, size)} or {} on failure.

    The MFT is always at inode 0; no fls walk needed. Single file, but big — typically
    10-200 MB. Worth it: gives us file creation timestamps + timestomping detection
    across the entire volume.
    """
    mft_dir = extract_dir / "mft"
    mft_dir.mkdir(parents=True, exist_ok=True)
    dest = mft_dir / "$MFT"
    size = await extract_file(raw, offset, "0", dest)
    if size <= 0:
        print("   ⚠️  $MFT extraction failed (icat produced 0 bytes)")
        return {}
    print(f"   extracted $MFT: {size:,} bytes")
    return {"mft": (dest, size)}


async def extract_usnjrnl(raw: Path, offset: int, extract_dir: Path) -> dict:
    """Extract \\$Extend\\$UsnJrnl:$J. Returns {'usnjrnl': (path, size)} or {}.

    $Extend is at fixed NTFS inode 11. fls -o <offset> <raw> 11 lists every file under
    it, including named ADS streams in `r/r <inode>-<attr_type>-<attr_id>:<stream_name>`
    form. We grep for the `$UsnJrnl:$J` entry and feed the inode-type-id triple straight
    to icat — no separate istat probe needed.

    Absence is normal (USN can be disabled) — emit a soft skip rather than failing.
    """
    rc, stdout, _ = await _run(["fls", "-o", str(offset), str(raw), "11"])
    if rc != 0:
        print("   ℹ️  $Extend (inode 11) listing failed — skipping USN")
        return {}

    j_ref = None  # e.g. "41519-128-3"
    for line in stdout.decode(errors="replace").splitlines():
        if "\t" not in line:
            continue
        meta, name = line.split("\t", 1)
        if name.split(" (")[0].strip() != "$UsnJrnl:$J":
            continue
        # meta looks like "r/r 41519-128-3:" — strip the trailing colon
        j_ref = meta.strip().split()[-1].rstrip(":")
        break
    if j_ref is None:
        print("   ℹ️  $UsnJrnl:$J not present (USN disabled?) — skipping")
        return {}

    usn_dir = extract_dir / "usnjrnl"
    usn_dir.mkdir(parents=True, exist_ok=True)
    dest = usn_dir / "$J"
    size = await extract_file(raw, offset, j_ref, dest)
    if size <= 0:
        print("   ⚠️  $UsnJrnl:$J extraction produced 0 bytes — empty journal? skipping")
        return {}
    print(f"   extracted $UsnJrnl:$J ({j_ref}): {size:,} bytes")
    return {"usnjrnl": (dest, size)}


async def extract_recycle_bin(raw: Path, offset: int, extract_dir: Path) -> dict:
    r"""Extract every \$Recycle.Bin\<SID>\$I* metadata file. Returns {logical: (path, size)}.

    Walks the recycle-bin root, then each per-user-SID subdir, staging only `$I*` files
    (the metadata records — original path + deletion timestamp). The companion `$R*` files
    contain the actual deleted content; we don't need them for correlation. Empty recycle
    bins are normal — we return {} silently.
    """
    rb_inode = await navigate(raw, offset, None, "$Recycle.Bin")
    if rb_inode is None:
        print("   ℹ️  \\$Recycle.Bin\\ not found — skipping recycle bin")
        return {}

    rc, stdout, _ = await _run(["fls", "-o", str(offset), str(raw), rb_inode])
    if rc != 0:
        return {}

    recycle_dir = extract_dir / "recycle"
    recycle_dir.mkdir(parents=True, exist_ok=True)
    out: dict = {}
    sid_count = 0
    file_count = 0

    for line in stdout.decode(errors="replace").splitlines():
        if "\t" not in line or not line.startswith("d/d"):
            continue
        meta, name = line.split("\t", 1)
        sid = name.split(":")[0].split(" (")[0].strip()
        if not sid.startswith("S-"):
            continue
        sid_inode = meta.strip().split()[-1].rstrip(":")
        sid_count += 1
        rc2, sub_stdout, _ = await _run(["fls", "-o", str(offset), str(raw), sid_inode])
        if rc2 != 0:
            continue
        for sub_line in sub_stdout.decode(errors="replace").splitlines():
            if "\t" not in sub_line or not sub_line.startswith("r/r"):
                continue
            sub_meta, sub_name = sub_line.split("\t", 1)
            clean = sub_name.split(":")[0].split(" (")[0].strip()
            if not clean.startswith("$I"):
                continue
            inode_ref = sub_meta.strip().split()[-1].rstrip(":")
            # Stage filename embeds SID + original $I name so the per-SID context is preserved.
            # Replace `$` (reserved on Windows but legal on POSIX) with `_dollar_` to keep
            # the staged filename portable across analyst hand-off scenarios.
            safe_name = clean.replace("$", "_dollar_")
            dest = recycle_dir / f"{sid}_{safe_name}"
            size = await extract_file(raw, offset, inode_ref, dest)
            if size > 0:
                logical = f"recycle_{sid}_{clean}"
                out[logical] = (dest, size)
                file_count += 1
    print(f"   recycle bin: {file_count} $I file(s) across {sid_count} SID(s)")
    return out


async def extract_amcache(raw: Path, offset: int, win_inode: str | None, extract_dir: Path) -> dict:
    """Extract \\Windows\\AppCompat\\Programs\\Amcache.hve. Returns {'amcache': (path, size)} or {}.

    Amcache was introduced with Win7 SP1 + KB2952664; pre-KB2952664 hosts have only
    RecentFileCache.bcf at this location. Treat absence as normal — no error raised.
    """
    if win_inode is None:
        return {}
    appcompat = await navigate(raw, offset, win_inode, "AppCompat")
    if appcompat is None:
        print("   ℹ️  \\Windows\\AppCompat\\ not found — skipping Amcache")
        return {}
    programs = await navigate(raw, offset, appcompat, "Programs")
    if programs is None:
        print("   ℹ️  \\Windows\\AppCompat\\Programs\\ not found — skipping Amcache")
        return {}
    amcache_inode = await navigate(raw, offset, programs, "Amcache.hve")
    if amcache_inode is None:
        print("   ℹ️  Amcache.hve not present (pre-KB2952664 Win7) — skipping")
        return {}
    amcache_dir = extract_dir / "amcache"
    amcache_dir.mkdir(parents=True, exist_ok=True)
    dest = amcache_dir / "Amcache.hve"
    size = await extract_file(raw, offset, amcache_inode, dest)
    if size <= 0:
        print("   ⚠️  Amcache.hve extraction failed (icat produced 0 bytes)")
        return {}
    print(f"   extracted Amcache.hve: {size:,} bytes")
    return {"amcache": (dest, size)}


async def extract_all_prefetch(raw: Path, offset: int, win_inode: str | None, extract_dir: Path) -> dict:
    """Extract every *.pf under \\Windows\\Prefetch\\.
    Returns {logical_name: (path, size)} keyed as `prefetch_<filename>` to disambiguate.
    Prefetch is disabled on servers — absence is normal and not an error.
    """
    if win_inode is None:
        return {}
    prefetch_inode = await navigate(raw, offset, win_inode, "Prefetch")
    if prefetch_inode is None:
        print("   ℹ️  \\Windows\\Prefetch\\ not present (disabled SKU or absent dir) — skipping")
        return {}

    pf_dir = extract_dir / "prefetch"
    pf_dir.mkdir(parents=True, exist_ok=True)
    rc, stdout, stderr = await _run(["fls", "-o", str(offset), str(raw), prefetch_inode])
    if rc != 0:
        # Surface the failure instead of silently returning {} — analyst sees what's wrong.
        err_snip = stderr.decode(errors="replace")[:240].strip()
        print(f"   ⚠️  prefetch fls failed (rc={rc} inode={prefetch_inode}): {err_snip!r}")
        return {}

    raw_lines = stdout.decode(errors="replace").splitlines()
    rr_lines = [ln for ln in raw_lines if ln.startswith("r/r")]

    out: dict = {}
    skipped_non_pf = 0
    skipped_empty = 0
    for line in rr_lines:
        if "\t" not in line:
            continue
        meta, name = line.split("\t", 1)
        clean = name.split(":")[0].split(" (")[0].strip()
        if not clean.lower().endswith(".pf"):
            skipped_non_pf += 1
            continue
        inode = meta.strip().split()[-1].rstrip(":")
        dest = pf_dir / clean
        size = await extract_file(raw, offset, inode, dest)
        if size > 0:
            logical = f"prefetch_{clean}"  # keep .pf so staged filename ends correctly for routing
            out[logical] = (dest, size)
        else:
            skipped_empty += 1

    if rr_lines and not out:
        # Diagnostic: prefetch dir had entries but extracted nothing. Surface the first
        # few lines + skip counts so the analyst can pinpoint the filter or extraction failure.
        print(f"   ⚠️  prefetch dir had {len(rr_lines)} r/r entries but 0 .pf extracted "
              f"(skipped: non-pf={skipped_non_pf}, empty={skipped_empty}). First lines:")
        for ln in rr_lines[:5]:
            print(f"     {ln}")
    print(f"   prefetch total: {len(out)} .pf file(s)")
    return out


def stage_for_watcher(extracted: dict, image_stem: str) -> list[Path]:
    """Copy extracted artifacts into evidence/new/ for the watcher.

    Hives + per-user NTUSER.DAT are always staged. Event logs are filtered through
    EVTX_STAGE_ALLOWLIST so the orchestrator doesn't dispatch hundreds of empty
    diagnostic logs (the originals stay in evidence/extracted/ for analyst use).
    Prefetch is staged in full (≤128 entries, all high-signal).
    """
    EVIDENCE_NEW.mkdir(parents=True, exist_ok=True)
    out: list = []
    for logical, (src, _size) in extracted.items():
        if logical.startswith("evtx_"):
            log_filename = logical[len("evtx_"):]  # strip the prefix → e.g. 'Security.evtx'
            if log_filename not in EVTX_STAGE_ALLOWLIST:
                continue
        if logical.startswith("prefetch_"):
            # Stage as <image_stem>__prefetch__<original.pf> so the watcher's `*.pf`
            # glob picks it up and the dispatcher can route by extension.
            pf_filename = logical[len("prefetch_"):]
            target = EVIDENCE_NEW / f"{image_stem}__prefetch__{pf_filename}"
        elif logical == "mft":
            # Stage as <image_stem>__mft__$MFT — watcher's `*__mft__*` glob picks it up,
            # dispatcher routes by the literal `__mft__` substring.
            target = EVIDENCE_NEW / f"{image_stem}__mft__$MFT"
        elif logical == "amcache":
            # Stage as <image_stem>__Amcache.hve — `__AMCACHE.HVE` suffix routes through
            # detect_hive_kind to the registry_agent's AMCACHE branch.
            target = EVIDENCE_NEW / f"{image_stem}__Amcache.hve"
        elif logical == "usnjrnl":
            # Stage as <image_stem>__usnjrnl__$J — watcher's `*__usnjrnl__*` glob picks it
            # up; dispatcher routes to mft_agent which detects the USN code path by filename.
            target = EVIDENCE_NEW / f"{image_stem}__usnjrnl__$J"
        elif logical.startswith("recycle_"):
            # Stage every $I file individually as <image_stem>__recycle__<sid>_<name>.
            # Watcher's `*__recycle__*` glob batches them by name pattern; dispatcher routes
            # to mft_agent which discovers + parses the whole batch via RBCmd -d.
            sid_and_name = logical[len("recycle_"):]  # e.g. "S-1-5-21-...$IPFXZSB"
            safe = sid_and_name.replace("$", "_dollar_")
            target = EVIDENCE_NEW / f"{image_stem}__recycle__{safe}"
        else:
            target = EVIDENCE_NEW / f"{image_stem}__{logical}"
        target.write_bytes(src.read_bytes())
        out.append(target)
    return out


def generate_extraction_claim(image: Path, extracted: dict, staged: list, partition_offset: int) -> str:
    timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    content_key = "|".join(f"{k}:{v[1]}" for k, v in sorted(extracted.items()))
    cid = "disk-extract-" + hashlib.md5(f"{image.name}:{content_key}".encode()).hexdigest()[:14]
    host_id = derive_host_id(image.name)

    # Use the actual extracted file's path (not the logical key) so refs always point at
    # a real file. Hives live at extracted/<image>/<HIVE>; evtx files live at the nested
    # extracted/<image>/evtx/<filename>.evtx — different layouts, single source of truth.
    refs = [f"evidence/new/{image.name}"]
    refs += [
        f"evidence/{path.relative_to(EVIDENCE_ROOT)}"
        for _logical, (path, _size) in sorted(extracted.items())
    ]

    fm = {
        "claim_id": cid,
        "status": "new",
        "generated_by": "disk-image-agent",
        "host": host_id,
        "entities": [f"host:{host_id}"],  # the manifest claim asserts the host's existence
        "evidence_refs": refs,
        "confidence": 1.0,
        "timestamp": timestamp,
        "source_image": image.name,
        "partition_start_sector": partition_offset,
        "extracted_hives": {logical: {"size": size, "path": str(path.relative_to(EVIDENCE_ROOT))}
                             for logical, (path, size) in sorted(extracted.items())},
        "staged_for_watcher": [str(p.relative_to(EVIDENCE_ROOT)) for p in staged],
    }
    body_lines = [
        "**Disk Image Extraction**",
        "",
        f"Source: `{image.name}`",
        f"NTFS partition starts at sector {partition_offset}.",
        "",
        f"**Extracted hives ({len(extracted)}):**",
    ]
    for logical, (_, size) in sorted(extracted.items()):
        body_lines.append(f"- {logical}: {size:,} bytes")
    body_lines += ["", f"**Staged for downstream agents ({len(staged)}):**"]
    for p in staged:
        body_lines.append(f"- `evidence/new/{p.name}`")
    body_lines += ["", "**Next:** registry_agent will fire on each hive within 2s."]
    return f"---\n{yaml.dump(fm, sort_keys=False)}---\n" + "\n".join(body_lines) + "\n"


async def run_disk_image_extraction(image: Path | None = None):
    print("💿 Disk Image Agent starting (E01 → hives)...")
    chisel = Chisel(CHISEL_URL, CHISEL_SECRET)
    chisel.connect()
    print(f"🔒 Chisel session → {chisel.endpoint} (sid={chisel.session_id[:8]}…)")
    # Make chisel available to module-level _run() (used by all forensic-tool helpers).
    _set_chisel(chisel)

    if image is None:
        listing = chisel.shell("ls", ["-1", str(EVIDENCE_NEW)])
        candidates = [
            EVIDENCE_NEW / n.strip()
            for n in listing.splitlines()
            if n.strip().lower().endswith((".e01", ".ex01"))
        ]
        image = candidates[0] if candidates else None
        if image is None:
            print("❌ no E01 in evidence/new/")
            return

    print(f"📂 Mounting: {image.name}")
    mount_dir = EVIDENCE_MOUNTS / image.stem
    extract_dir = EVIDENCE_EXTRACTED / image.stem

    if not await mount_e01(image, mount_dir):
        return

    try:
        extracted, partition_offset = await extract_all_hives(image, mount_dir / "ewf1", extract_dir)
        if not extracted:
            print("❌ no hives extracted")
            return

        staged = stage_for_watcher(extracted, image.stem)
        print(f"📤 Staged {len(staged)} artifact(s) in evidence/new/ for downstream pickup")

        chisel.call("create_directory", {"path": str(CLAIMS_TODO)})
        claim = generate_extraction_claim(image, extracted, staged, partition_offset)
        ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        claim_path = CLAIMS_TODO / f"disk_extract_{image.stem}_{ts}.md"
        chisel.call("write_file", {"path": str(claim_path), "content": claim})
        print(f"✅ Claim written → {claim_path.name}")
    finally:
        await unmount_e01(mount_dir)
        print("🔓 unmounted")


if __name__ == "__main__":
    asyncio.run(run_disk_image_extraction())
