# orchestrator/main.py
"""
FindEvil Thin Orchestrator
~300 LOC total across all files.
Pure directory-state-machine over the evidence root.
Never lets agents touch Cognee directly.

CLI:
    python -m orchestrator.main              # process current evidence, settle, report, exit
    python -m orchestrator.main --watch      # watch forever (legacy behavior)
    python -m orchestrator.main --quiet-period 60   # require 60s of inactivity to settle
"""

import argparse
import asyncio
import logging
import os
import sys
from datetime import datetime, UTC
from pathlib import Path
from typing import Dict

from dotenv import load_dotenv

# Load .env first so EVIDENCE_ROOT is available for the per-case path below.
load_dotenv()

# Per-case Cognee isolation. Each orchestrator run gets its own graph + vector
# store under evidence/audit/<CASE_ID>/cognee_{system,data}, so an analyst can
# later open any case in the Cognee web UI via scripts/open_case_in_cognee.sh.
# These env vars MUST be set before `import cognee` because cognee's import
# path calls load_dotenv(override=True); for that reason SYSTEM_ROOT_DIRECTORY
# and DATA_ROOT_DIRECTORY MUST NOT appear in .env (they would clobber these).
# FINDEVIL_CASE_ID, if already set in the environment, is respected so child
# processes inherit the parent's CASE_ID.
# Disable cognee 1.0's default multi-user access control: the orchestrator
# ingests without an authenticated user, so leaving this on hides all data
# from the unauthenticated GUI session. setdefault so the shell can force it
# back on by exporting ENABLE_BACKEND_ACCESS_CONTROL=true.
os.environ.setdefault("ENABLE_BACKEND_ACCESS_CONTROL", "false")

CASE_ID = os.environ.get("FINDEVIL_CASE_ID") or datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
os.environ["FINDEVIL_CASE_ID"] = CASE_ID
_EVIDENCE_ROOT_EARLY = Path(os.getenv("EVIDENCE_ROOT", "/evidence"))
_CASE_AUDIT_DIR = _EVIDENCE_ROOT_EARLY / "audit" / CASE_ID
os.environ["SYSTEM_ROOT_DIRECTORY"] = str(_CASE_AUDIT_DIR / "cognee_system")
os.environ["DATA_ROOT_DIRECTORY"] = str(_CASE_AUDIT_DIR / "cognee_data")
(_CASE_AUDIT_DIR / "cognee_system").mkdir(parents=True, exist_ok=True)
(_CASE_AUDIT_DIR / "cognee_data").mkdir(parents=True, exist_ok=True)
print(f"📋 CASE_ID={CASE_ID}  (cognee state: {_CASE_AUDIT_DIR})")

import cognee

from cognee_schema.schema import register_forensice_schema

# Mute cognee's per-DataPoint extraction info logs — they flood the orchestrator's own
# print() output (~10k+ lines per win7 run). Cognee warnings/errors still surface.
logging.getLogger("cognee").setLevel(logging.WARNING)

# Local modules
from .watcher import EvidenceWatcher
from .extractor import extract_entities_to_cognee
from .validator import run_self_correction_loop
from .manifest import write_initial_manifest, verify_and_write_final_manifest
from agents.memory_agent.agent import run_memory_analysis
from agents.correlation_agent.agent import run_correlation
from agents.disk_image_agent.agent import run_disk_image_extraction
from agents.registry_agent.agent import run_registry_analysis, detect_hive_kind
from agents.evtx_agent.agent import run_evtx_analysis
from agents.prefetch_agent.agent import run_prefetch_analysis, detect_prefetch
from agents.mft_agent.agent import run_mft_analysis, detect_mft

# ─────────────────────────────────────────────────────────────
# CONFIG (edit in .env or here)
# ─────────────────────────────────────────────────────────────
EVIDENCE_ROOT = Path(os.getenv("EVIDENCE_ROOT", "/evidence"))
CLAIMS_TODO = EVIDENCE_ROOT / "claims/todo"
CLAIMS_DOING = EVIDENCE_ROOT / "claims/doing"
CLAIMS_DONE = EVIDENCE_ROOT / "claims/done"
CLAIMS_REJECTED = EVIDENCE_ROOT / "claims/rejected"  # spot-check failures land here (no re-queue)
EVIDENCE_NEW = EVIDENCE_ROOT / "new"
EVIDENCE_PROCESSED = EVIDENCE_ROOT / "processed"
EVIDENCE_BASELINES = EVIDENCE_ROOT / "baselines"
EVIDENCE_DUMPS = EVIDENCE_ROOT / "dumps"          # vol3 vadinfo --dump scratch space
EVIDENCE_EXTRACTED = EVIDENCE_ROOT / "extracted"  # disk_image_agent extraction output
EVIDENCE_MOUNTS = EVIDENCE_ROOT / "mounts"        # ewfmount FUSE mountpoints
EVIDENCE_AUDIT = EVIDENCE_ROOT / "audit"          # chisel.exec_tool() invocation log (jsonl)
REPORTS_ROOT = EVIDENCE_ROOT.parent / "reports"   # report_agent output (case_*.md + case_graph_*.html)

# Make sure directories exist (created by the orchestrator UID, not Chisel — vol3
# and ewfmount scratch dirs MUST be agent-writable, and Chisel may run as root).
for d in [CLAIMS_TODO, CLAIMS_DOING, CLAIMS_DONE, CLAIMS_REJECTED,
          EVIDENCE_NEW, EVIDENCE_PROCESSED, EVIDENCE_BASELINES,
          EVIDENCE_DUMPS, EVIDENCE_EXTRACTED, EVIDENCE_MOUNTS, EVIDENCE_AUDIT,
          REPORTS_ROOT]:
    d.mkdir(parents=True, exist_ok=True)


# Chain-of-custody: snapshot SHA256 of every file in evidence/new/ before any
# agent touches them. Verified at end of main(). Manifests land in the per-case
# audit dir alongside the chisel exec log.
_pre_manifest_path, _pre_manifest_count = write_initial_manifest(CASE_ID, EVIDENCE_NEW, _CASE_AUDIT_DIR)
if _pre_manifest_count:
    print(f"🔒 Evidence manifest (pre): hashed {_pre_manifest_count} file(s) → {_pre_manifest_path.name}")


# Background correlation tasks — tracked here so settle-detection can wait for them
# to complete before deciding the pipeline is idle. Without this, settle-check could
# trigger while a correlation pass is mid-write, and we'd miss the resulting claim.
_CORRELATION_TASKS: set[asyncio.Task] = set()


def _track_correlation_task(task: asyncio.Task) -> None:
    _CORRELATION_TASKS.add(task)
    task.add_done_callback(_CORRELATION_TASKS.discard)


async def process_new_claim(claim_path: Path):
    """Core loop for every claim emitted by an agent."""
    print(f"🔄 Processing claim: {claim_path.name}")

    # 1. Move to doing (atomic POSIX rename)
    doing_path = CLAIMS_DOING / claim_path.name
    claim_path.rename(doing_path)

    # 2. Run self-correction validator
    is_valid, error_msg = await run_self_correction_loop(doing_path)

    if is_valid:
        # 3. Extract entities deterministically into Cognee
        await extract_entities_to_cognee(doing_path)

        # 4. Move to done
        done_path = CLAIMS_DONE / claim_path.name
        doing_path.rename(done_path)
        print(f"✅ Claim validated and ingested: {claim_path.name}")

        # 5. Trigger correlation agent (skip its own outputs to prevent recursion).
        # Tracked in _CORRELATION_TASKS so settle-detection waits for it.
        if not claim_path.name.startswith("correlation_"):
            _track_correlation_task(asyncio.create_task(_run_correlation_safe()))
    else:
        # Move to rejected/ — spot-check failures aren't transient (the graph won't
        # change to make a contradicting claim valid). Re-queueing creates infinite
        # loops, especially for ProcessExecution conflicts where multiple .pf files
        # share a basename but have different paths/timestamps. The first claim wins
        # and writes its values to the graph; subsequent conflicting claims are
        # rejected here instead of looping.
        rejected_path = CLAIMS_REJECTED / claim_path.name
        doing_path.rename(rejected_path)
        print(f"❌ Claim REJECTED (not re-queued): {error_msg} → claims/rejected/{claim_path.name}")


async def _run_correlation_safe():
    """Background-fire the correlation agent; never let its failure crash the orchestrator."""
    try:
        await run_correlation()
    except Exception as e:
        print(f"❌ Correlation agent failed: {e!r}")


async def dispatch_for_evidence(evidence_path: Path):
    """Route a newly-arrived evidence file by filename heuristic.

    - Contains 'baseline' → register to evidence/baselines/.
    - .E01 / .Ex01 → disk_image_agent (mount + extract hives → drops them back into evidence/new/).
    - Otherwise → memory agent against the latest registered baseline.

    TODO: registry hives → registry_agent (next iteration).
    TODO: pcaps → network_agent.
    """
    name_l = evidence_path.name.lower()

    if "baseline" in name_l:
        dest = EVIDENCE_BASELINES / evidence_path.name
        evidence_path.rename(dest)
        print(f"📦 Baseline registered: {dest.name}")
        return

    if name_l.endswith((".e01", ".ex01")):
        print(f"💿 Dispatching disk image agent for {evidence_path.name}")
        try:
            await run_disk_image_extraction(image=evidence_path)
        except Exception as e:
            print(f"❌ Disk image agent failed for {evidence_path.name}: {e!r} — leaving in evidence/new/")
            return
        dest = EVIDENCE_PROCESSED / evidence_path.name
        evidence_path.rename(dest)
        print(f"✅ Evidence moved to processed/: {dest.name}")
        return

    # Evtx routing must run BEFORE hive routing (some hive substrings appear in
    # event-log names, e.g. `__evtx_System` would otherwise match the SYSTEM hive glob).
    if name_l.endswith(".evtx") or "__evtx_" in name_l:
        print(f"📜 Dispatching evtx agent for {evidence_path.name}")
        try:
            await run_evtx_analysis(evtx=evidence_path)
        except Exception as e:
            print(f"❌ Evtx agent failed for {evidence_path.name}: {e!r} — leaving in evidence/new/")
            return
        dest = EVIDENCE_PROCESSED / evidence_path.name
        evidence_path.rename(dest)
        print(f"✅ Evidence moved to processed/: {dest.name}")
        return

    # MFT/USN/recycle routing must run BEFORE hive routing (staged `__mft__$MFT`,
    # `__usnjrnl__$J`, and `__recycle__*` filenames have substrings that could loosely match
    # hive-shaped globs; explicit-prefix routing wins). All three funnel through mft_agent
    # which dispatches internally via detect_mft / detect_usn / detect_recycle.
    if ("__mft__" in name_l or name_l.endswith("$mft")
            or "__usnjrnl__" in name_l or name_l.endswith("$j")
            or "__recycle__" in name_l):
        print(f"📁 Dispatching MFT/USN/recycle agent for {evidence_path.name}")
        try:
            await run_mft_analysis(mft=evidence_path)
        except Exception as e:
            print(f"❌ MFT/USN/recycle agent failed for {evidence_path.name}: {e!r} — leaving in evidence/new/")
            return
        dest = EVIDENCE_PROCESSED / evidence_path.name
        evidence_path.rename(dest)
        print(f"✅ Evidence moved to processed/: {dest.name}")
        return

    # Prefetch routing — bare *.pf or staged __prefetch__ form. Cheap to dispatch
    # (pyscca parses an entire .pf in <10ms); the orchestrator processes them serially.
    if name_l.endswith(".pf") or "__prefetch__" in name_l:
        print(f"⚡ Dispatching prefetch agent for {evidence_path.name}")
        try:
            await run_prefetch_analysis(prefetch=evidence_path)
        except Exception as e:
            print(f"❌ Prefetch agent failed for {evidence_path.name}: {e!r} — leaving in evidence/new/")
            return
        dest = EVIDENCE_PROCESSED / evidence_path.name
        evidence_path.rename(dest)
        print(f"✅ Evidence moved to processed/: {dest.name}")
        return

    if detect_hive_kind(evidence_path):
        print(f"🗝️  Dispatching registry agent for {evidence_path.name}")
        try:
            await run_registry_analysis(hive=evidence_path)
        except Exception as e:
            print(f"❌ Registry agent failed for {evidence_path.name}: {e!r} — leaving in evidence/new/")
            return
        dest = EVIDENCE_PROCESSED / evidence_path.name
        evidence_path.rename(dest)
        print(f"✅ Evidence moved to processed/: {dest.name}")
        return

    print(f"🧠 Dispatching memory agent for {evidence_path.name} (baseline_dir={EVIDENCE_BASELINES})")
    try:
        await run_memory_analysis(dump=evidence_path, baseline_dir=EVIDENCE_BASELINES)
    except Exception as e:
        print(f"❌ Memory agent failed for {evidence_path.name}: {e!r} — leaving in evidence/new/")
        return
    dest = EVIDENCE_PROCESSED / evidence_path.name
    evidence_path.rename(dest)
    print(f"✅ Evidence moved to processed/: {dest.name}")


def _print_run_summary() -> None:
    """One-screen view of what the run produced. Called after settle-detection."""
    print("\n" + "=" * 60)
    print("📊 RUN SUMMARY")
    print("=" * 60)
    counts: dict[str, int] = {}
    for prefix in ("memory", "disk_extract", "registry", "evtx", "prefetch",
                   "mft", "usn", "recycle", "correlation"):
        counts[prefix] = sum(1 for _ in CLAIMS_DONE.glob(f"{prefix}_*.md"))
    total = sum(counts.values())
    print(f"  Claims processed: {total}")
    for k, v in counts.items():
        if v:
            print(f"    {k}: {v}")
    rejected = sum(1 for _ in CLAIMS_REJECTED.glob("*.md"))
    if rejected:
        print(f"  ❌ Rejected: {rejected} (see claims/rejected/)")
    pending = sum(1 for f in EVIDENCE_NEW.iterdir() if f.is_file())
    if pending:
        print(f"  ⚠️  Still pending in evidence/new/: {pending} "
              "(orchestrator gave up — investigate logs)")
    print("=" * 60 + "\n")


async def _release_kuzu_lock() -> None:
    """Close the orchestrator's KuzuAdapter so the report subprocess can open its own.
    Kuzu uses OS-level file locking — even subprocess isolation doesn't bypass it
    if the parent process still holds the connection. Best-effort: any failure here
    is non-fatal (the worst case is the report subprocess loses its graph viz, like
    the 2026-04-19 first run).
    """
    try:
        from cognee.infrastructure.databases.unified import get_unified_engine
        unified = await get_unified_engine()
        if hasattr(unified.graph, "close"):
            close_fn = unified.graph.close
            if asyncio.iscoroutinefunction(close_fn):
                await close_fn()
            else:
                close_fn()
            print("🔓 Released Kuzu file lock for report subprocess")
    except Exception as e:
        print(f"⚠️  Best-effort Kuzu close failed (graph viz may be skipped in report): {e!r}")


async def _run_plaso_subprocess() -> int:
    """Run plaso_agent as a subprocess. plaso_agent runs log2timeline.py + psort.py
    against the staged evtx files and emits lateral-movement detection claims into
    claims/todo/. Those claims are picked up by the watcher's re-entered settle loop
    so they flow through validator → extractor → correlation_agent → report_agent
    normally. Returns the subprocess's exit code (0 on success).

    Skipped silently if no evidence/extracted/<image>/evtx/ directory exists yet
    (e.g., memory-only cases with no disk image)."""
    if not any(EVIDENCE_EXTRACTED.glob("*/evtx")):
        print("⏭️  Plaso agent skipped (no extracted evtx/ directory under evidence/extracted/)")
        return 0
    print("🕒 Generating Plaso super-timeline + lateral-movement detection...")
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "agents.plaso_agent.agent",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
    )
    out_bytes, _ = await proc.communicate()
    out = out_bytes.decode(errors="replace")
    # Echo the last few lines (cache-hit indicator + finding count + claim path)
    tail = [ln for ln in out.splitlines() if ln.strip()][-8:]
    for line in tail:
        print(line)
    return proc.returncode or 0


async def _run_report_subprocess() -> int:
    """Run report_agent as a subprocess so the orchestrator's cognee/kuzu lock releases
    first. Returns the subprocess's exit code (0 on success).
    """
    print("📝 Generating final report...")
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "agents.report_agent.agent",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
    )
    out_bytes, _ = await proc.communicate()
    out = out_bytes.decode(errors="replace")
    # Echo the last few lines (success indicator + report path + tier counts)
    tail = [ln for ln in out.splitlines() if ln.strip()][-6:]
    for line in tail:
        print(line)
    return proc.returncode or 0


async def _run_forensic_analyst_subprocess() -> int:
    """Run forensic_analyst as a subprocess. The analyst is an LLM-driven
    agentic loop that loads SKILLS.md + ref_SKILLS.md as its system prompt,
    reads the post-baseline state of the case (claims/done/, the graph, the
    audit log), and emits ADDITIONAL claims via write_claim into claims/todo/.
    Those claims go through the standard validator path — the LLM cannot
    introduce findings that disagree with the baseline graph. Non-fatal on
    failure (SDK / Claude Code CLI unavailable → silent skip).
    """
    print("🧠 Running forensic analyst (LLM deep-dive)...")
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "agents.forensic_analyst.agent",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
    )
    out_bytes, _ = await proc.communicate()
    out = out_bytes.decode(errors="replace")
    tail = [ln for ln in out.splitlines() if ln.strip()][-10:]
    for line in tail:
        print(line)
    return proc.returncode or 0


async def _run_coverage_explorer_subprocess() -> int:
    """Run coverage_explorer as a subprocess after the report agent. Non-fatal —
    a failure here does not block the case from completing. The agent makes no
    forensic claims about the case; it only writes a meta-coverage report to
    reports/coverage_review_<ts>.md describing what tools the pipeline ran vs.
    what was available.
    """
    print("🔎 Generating coverage review...")
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "agents.coverage_explorer.agent",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
    )
    out_bytes, _ = await proc.communicate()
    out = out_bytes.decode(errors="replace")
    tail = [ln for ln in out.splitlines() if ln.strip()][-4:]
    for line in tail:
        print(line)
    return proc.returncode or 0


async def main(run_until_settled: bool = True, quiet_period_s: float = 30.0,
               with_analyst: bool = True) -> int:
    """Main orchestrator entrypoint. Returns process exit code."""
    print("🚀 FindEvil Orchestrator starting...")

    # Register the forensic schema once
    await register_forensice_schema()

    # Start the directory watcher
    watcher = EvidenceWatcher(
        claims_todo_dir=CLAIMS_TODO,
        evidence_new_dir=EVIDENCE_NEW,
        on_new_claim=process_new_claim,
        on_new_evidence=dispatch_for_evidence,
    )

    print("👀 Watching evidence directories...")
    await watcher.start(run_until_settled=run_until_settled, quiet_period_s=quiet_period_s)

    # Wait for any straggler correlation tasks (fire-and-forget from process_new_claim)
    if _CORRELATION_TASKS:
        print(f"⏳ Waiting for {len(_CORRELATION_TASKS)} background correlation task(s) to complete...")
        await asyncio.gather(*_CORRELATION_TASKS, return_exceptions=True)

    if not run_until_settled:
        return 0  # --watch mode: nothing more to do (loop only exits via stop())

    # Plaso lateral-movement pass — runs AFTER first settle (so disk_image_agent has
    # extracted evtx files) but BEFORE report_agent (so the LM claims can flow through
    # validator → extractor → correlation_agent → report normally). plaso_agent emits
    # claims into claims/todo/; the re-entered watcher picks them up automatically.
    plaso_rc = await _run_plaso_subprocess()
    if plaso_rc == 0 and any(CLAIMS_TODO.glob("plaso_*.md")):
        print("🔁 Re-entering settle loop to process plaso_agent's emitted claims...")
        await watcher.start(run_until_settled=True, quiet_period_s=quiet_period_s)
        if _CORRELATION_TASKS:
            print(f"⏳ Waiting for {len(_CORRELATION_TASKS)} background correlation task(s) (post-plaso)...")
            await asyncio.gather(*_CORRELATION_TASKS, return_exceptions=True)

    # Forensic analyst (LLM) deep-dive — runs AFTER the deterministic baseline
    # + plaso so it sees the full graph the validator will spot-check against.
    # Emits claims into claims/todo/; re-entered settle loop picks them up so
    # they flow through validator → extractor → correlation → report normally.
    # Default ON; skip with `--no-analyst`.
    if with_analyst:
        analyst_rc = await _run_forensic_analyst_subprocess()
        if analyst_rc == 0 and any(CLAIMS_TODO.glob("analyst_*.md")):
            print("🔁 Re-entering settle loop to process forensic_analyst's emitted claims...")
            await watcher.start(run_until_settled=True, quiet_period_s=quiet_period_s)
            if _CORRELATION_TASKS:
                print(f"⏳ Waiting for {len(_CORRELATION_TASKS)} background correlation task(s) (post-analyst)...")
                await asyncio.gather(*_CORRELATION_TASKS, return_exceptions=True)
    else:
        print("⏭️  Forensic analyst pass skipped (--no-analyst).")

    _print_run_summary()

    # Chain-of-custody verification — re-hash every file in the pre-manifest
    # BEFORE the report subprocess so the report can embed the integrity table.
    # Non-UNCHANGED status flips the orchestrator exit code regardless of the
    # report's success.
    integrity = verify_and_write_final_manifest(CASE_ID, _CASE_AUDIT_DIR, EVIDENCE_ROOT)
    integrity_rc = 0
    if integrity["checked"] == 0:
        print("🔒 Evidence integrity: nothing to verify")
    elif integrity["modified"] == 0 and integrity["missing"] == 0:
        print(f"🔒 Evidence integrity: {integrity['unchanged']}/{integrity['checked']} files UNCHANGED")
    else:
        print(f"❌ Evidence integrity FAILED: {integrity['modified']} MODIFIED, {integrity['missing']} MISSING")
        integrity_rc = 1

    await _release_kuzu_lock()
    rc = await _run_report_subprocess()

    # Coverage review — non-fatal meta-analysis after report. Surfaces tool
    # coverage gaps for the next pipeline iteration; never blocks case completion.
    ce_rc = await _run_coverage_explorer_subprocess()
    if ce_rc != 0:
        print(f"⚠️  coverage_explorer exited with rc={ce_rc} (non-fatal — case report still valid)")

    print("🏁 Done.")
    return rc or integrity_rc


def main_cli() -> int:
    p = argparse.ArgumentParser(description="FindEvil orchestrator")
    p.add_argument("--watch", action="store_true",
                   help="Watch forever instead of settling. Default: process current evidence and exit.")
    p.add_argument("--quiet-period", type=float, default=30.0,
                   help="Seconds of inactivity before considering the pipeline settled (default 30).")
    p.add_argument("--no-analyst", action="store_true",
                   help="Skip the LLM-driven forensic analyst deep-dive pass. Default: analyst runs after plaso.")
    args = p.parse_args()
    return asyncio.run(main(
        run_until_settled=not args.watch,
        quiet_period_s=args.quiet_period,
        with_analyst=not args.no_analyst,
    ))


if __name__ == "__main__":
    sys.exit(main_cli())
