# orchestrator/watcher.py
"""
Evidence-directory state-machine watcher.
Polls for new claims and new evidence. Zero extra dependencies.
"""

import asyncio
from pathlib import Path
from typing import Callable, Awaitable

# Evidence globs — broad on purpose; dispatch_for_evidence does the precise routing.
# Memory dumps + baselines + E01 disk images + raw registry hives.
MEMORY_DUMP_GLOBS = (
    "*memory*", "*raw*", "*baseline*",
    "*.[0-9][0-9][0-9]", "*.[rR][aA][wW]",
    "*.[iI][mM][gG]", "*.[mM][eE][mM]",
    "*.[eE]01", "*.[eE][xX]01",
    # Hive filenames — bare and staged-suffix forms (case-insensitive)
    "*[Ss][Yy][Ss][Tt][Ee][Mm]", "*[Ss][Oo][Ff][Tt][Ww][Aa][Rr][Ee]",
    "*[Ss][Aa][Mm]", "*[Ss][Ee][Cc][Uu][Rr][Ii][Tt][Yy]",
    "*[Cc][Oo][Mm][Pp][Oo][Nn][Ee][Nn][Tt][Ss]",
    "*[Nn][Tt][Uu][Ss][Ee][Rr].[Dd][Aa][Tt]*",
    "*.[hH][iI][vV][eE]",
    # Event logs (bare and disk_image_agent-staged forms)
    "*.[eE][vV][tT][xX]", "*__evtx_*",
    # Prefetch (bare and disk_image_agent-staged forms)
    "*.[pP][fF]", "*__prefetch__*",
    # NTFS $MFT (disk_image_agent-staged form). Bare `$MFT` is a forensic-tool convention,
    # not something a user typically drops, but we accept it for standalone operation.
    "*__mft__*", "*$MFT", "*$mft",
    # NTFS $UsnJrnl:$J — change-history journal. Same dispatcher branch as MFT (mft_agent
    # handles both file types; routes by detect_usn vs detect_mft inside).
    "*__usnjrnl__*", "*$J",
    # NTFS recycle bin $I metadata files. Same mft_agent dispatch — routes via detect_recycle.
    "*__recycle__*",
    # Amcache.hve (bare and disk_image_agent-staged forms). Routes through detect_hive_kind
    # → registry_agent dispatch (no new dispatch branch needed).
    "*[Aa][Mm][Cc][Aa][Cc][Hh][Ee].[Hh][Vv][Ee]*",
)


class EvidenceWatcher:
    # Concurrency limit on agent dispatch. N=2 lets the initial E01 + memory dump pair
    # run in parallel but caps fan-out when disk_image_agent stages ~120 derived files
    # (prefetch + MFT + USN + recycle) into new/ at once. Without this bound, the watcher
    # creates one fire-and-forget task per file, the event loop gets ~120 concurrent
    # Chisel-and-subprocess invocations, and the whole thing deadlocks.
    MAX_CONCURRENT_DISPATCHES = 2

    def __init__(
        self,
        claims_todo_dir: Path,
        evidence_new_dir: Path,
        on_new_claim: Callable[[Path], Awaitable[None]],
        on_new_evidence: Callable[[Path], Awaitable[None]] | None = None,
    ):
        self.claims_todo_dir = claims_todo_dir
        self.evidence_new_dir = evidence_new_dir
        self.on_new_claim = on_new_claim
        self.on_new_evidence = on_new_evidence
        self.running = False
        self._seen_evidence: set[Path] = set()
        self._dispatch_sem: asyncio.Semaphore | None = None  # lazy-init in start()
        # Settle-detection state
        self._in_flight_dispatches: set[asyncio.Task] = set()
        self._last_activity: float = 0.0  # event-loop time of last claim/dispatch event

    def in_flight_count(self) -> int:
        """Active dispatch tasks (semaphore-bounded but counted before/after sem acquire)."""
        return len(self._in_flight_dispatches)

    def _on_dispatch_done(self, task: asyncio.Task) -> None:
        """Done-callback fired when a _bounded_dispatch coroutine finishes (success or
        failure). Removes from in-flight set and updates last-activity timestamp."""
        self._in_flight_dispatches.discard(task)
        try:
            self._last_activity = asyncio.get_event_loop().time()
        except RuntimeError:
            pass  # called outside running loop (e.g. during shutdown) — safe to ignore

    async def _bounded_dispatch(self, evidence_file: Path):
        """Wrap on_new_evidence with the semaphore so over-the-limit calls queue cleanly
        instead of all running concurrently. On dispatch failure, REMOVE from _seen_evidence
        so the next poll cycle picks the file up again — without this, a transient failure
        (Chisel 429, network hiccup) leaves the file stuck in evidence/new/ forever even
        though the dispatch's `dispatch_for_evidence` already left it there for retry."""
        async with self._dispatch_sem:
            try:
                await self.on_new_evidence(evidence_file)
            except Exception as e:
                print(f"❌ Bounded dispatch error for {evidence_file.name}: {e!r} — clearing seen-set entry for retry")
                self._seen_evidence.discard(evidence_file)
                return
            # Success path: if the file is still in evidence/new/ (i.e., the dispatcher
            # decided not to move it — which happens when an agent raises an exception
            # caught inside dispatch_for_evidence), allow retry on next poll.
            if evidence_file.exists():
                self._seen_evidence.discard(evidence_file)

    async def start(self, run_until_settled: bool = False, quiet_period_s: float = 30.0):
        """Run the polling loop.

        When `run_until_settled=True` (the orchestrator's command-line default), the loop
        exits after `quiet_period_s` seconds of inactivity AND zero pending evidence AND
        zero pending claims AND zero in-flight dispatches. The orchestrator can then run
        report_agent and exit cleanly.

        When `run_until_settled=False` (--watch mode), loops forever until `stop()` is
        called or the process is interrupted.
        """
        self.running = True
        # Construct the semaphore inside the running event loop (asyncio primitives
        # bind to the loop they were created in)
        self._dispatch_sem = asyncio.Semaphore(self.MAX_CONCURRENT_DISPATCHES)
        loop = asyncio.get_event_loop()
        self._last_activity = loop.time()
        mode = "settle-and-exit" if run_until_settled else "watch-forever"
        print(f"👀 EvidenceWatcher started ({mode}, max {self.MAX_CONCURRENT_DISPATCHES} concurrent dispatches"
              + (f", quiet_period={quiet_period_s:.0f}s)" if run_until_settled else ")"))
        while self.running:
            # Process any new claims
            claim_files = list(self.claims_todo_dir.glob("*.md"))
            if claim_files:
                self._last_activity = loop.time()
            for claim_file in claim_files:
                await self.on_new_claim(claim_file)
                self._last_activity = loop.time()

            # Dispatch agents on new evidence (semaphore-bounded — at most
            # MAX_CONCURRENT_DISPATCHES agents run at once; over-the-limit dispatches queue)
            if self.on_new_evidence is not None:
                for evidence_file in self._scan_new_evidence():
                    if evidence_file in self._seen_evidence:
                        continue
                    self._seen_evidence.add(evidence_file)
                    print(f"🆕 Evidence detected: {evidence_file.name}")
                    task = asyncio.create_task(self._bounded_dispatch(evidence_file))
                    self._in_flight_dispatches.add(task)
                    task.add_done_callback(self._on_dispatch_done)
                    self._last_activity = loop.time()

            # Settle check — only relevant in --no-watch mode
            if run_until_settled and self._is_settled(loop, quiet_period_s):
                elapsed_quiet = loop.time() - self._last_activity
                print(f"⚙️  Settled (no activity for {elapsed_quiet:.0f}s, queues empty) — exiting watcher loop")
                self.running = False
                break

            await asyncio.sleep(2)  # 2-second poll — fast enough for hackathon

    def _is_settled(self, loop: asyncio.AbstractEventLoop, quiet_period_s: float) -> bool:
        """All four conditions must hold: no pending evidence, no todo claims, no in-flight
        dispatches, and at least `quiet_period_s` since the last claim or dispatch event.

        The new-evidence check filters against `_seen_evidence` — disk_image_agent
        re-extracts staged artifacts back into evidence/new/ during a rerun; those files
        are already in the seen-set and won't dispatch again, so they must NOT block settle.
        Without this filter, the watcher loops forever on the same redundant file."""
        if len(self._in_flight_dispatches) > 0:
            return False
        if any(self.claims_todo_dir.glob("*.md")):
            return False
        if self.on_new_evidence is not None:
            unseen = [p for p in self._scan_new_evidence() if p not in self._seen_evidence]
            if unseen:
                return False
        return (loop.time() - self._last_activity) >= quiet_period_s

    def _scan_new_evidence(self) -> list[Path]:
        seen: set[Path] = set()
        out: list[Path] = []
        for pat in MEMORY_DUMP_GLOBS:
            for p in self.evidence_new_dir.glob(pat):
                if p.is_file() and p not in seen:
                    seen.add(p); out.append(p)
        return out

    def stop(self):
        self.running = False
