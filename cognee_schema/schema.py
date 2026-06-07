# schema.py
"""
Cognee typed graph schema for FindEvil.
Follows the exact three-layer architecture:
- Every node inherits ForensicDataPoint → carries evidence_refs
- Every relationship uses typed Edge with confidence + derived_from
- Schema is the contract — memory agents start populating now,
  disk/network agents plug in later with zero migration.
"""

import os
import re
from pathlib import Path
from typing import List, Any
from pydantic import Field, SkipValidation

import cognee
from cognee.infrastructure.engine import DataPoint
from cognee.infrastructure.engine.models.Edge import Edge


# Strip these suffixes (longest first) when deriving a host id from a filename.
# Order matters — multi-segment matches must precede single-segment ones.
_HOST_ID_STRIP_SUFFIXES = (
    "-memory-raw", "-memory", "-c-drive", "-d-drive", "-e-drive", "-raw",
)


def derive_host_id(source_filename: str) -> str:
    """Derive a stable, normalized host identifier from an evidence filename.

    Heuristic: strip extension, strip the staged-artifact prefix (`__`-separator),
    strip common evidence-type suffixes (`-memory-raw`, `-c-drive`, etc.), normalize.

    Examples (all → `win7-32-nromanoff`):
      - 'win7-32-nromanoff-memory-raw.001'                → 'win7-32-nromanoff'
      - 'win7-32-nromanoff-c-drive.E01'                   → 'win7-32-nromanoff'
      - 'win7-32-nromanoff-c-drive__SOFTWARE'             → 'win7-32-nromanoff'
      - 'win7-32-nromanoff-c-drive__evtx_Security.evtx'   → 'win7-32-nromanoff'

    Different host examples:
      - 'Win7SP1x86-baseline.img'                          → 'win7sp1x86-baseline'
      - 'test-trigger.raw'                                 → 'test-trigger'
    """
    if not source_filename:
        return "unknown-host"
    name = Path(source_filename).name
    # Staged artifact: <image_stem>__<artifact>  → take the image_stem
    if "__" in name:
        name = name.split("__", 1)[0]
    # Strip extension(s) — handles `.001`, `.E01`, `.evtx`, etc.
    name = name.split(".")[0]
    # Strip common evidence-type suffixes
    name_l = name.lower()
    for suffix in _HOST_ID_STRIP_SUFFIXES:
        if name_l.endswith(suffix):
            name = name[: -len(suffix)]
            break
    # Normalize: lowercase + collapse non-alphanumeric to hyphens
    name = re.sub(r"[^a-z0-9-]+", "-", name.lower())
    name = re.sub(r"-+", "-", name).strip("-")
    return name or "unknown-host"


class ForensicDataPoint(DataPoint):
    """Base class for ALL forensic entities.
    Guarantees every node in the graph can trace back to an evidence file.
    """
    evidence_refs: List[str] = Field(
        default_factory=list,
        description="List of evidence paths + version hashes that this entity was extracted from"
    )


# ─────────────────────────────────────────────────────────────
# ENTITIES (Nodes)
# ─────────────────────────────────────────────────────────────

class Process(ForensicDataPoint):
    pid: int
    name: str
    command_line: str | None = None
    ppid: int | None = None
    create_time: str | None = None
    # Relationships (will be set to Edge(...) or target node)
    parent: SkipValidation[Any] = None          # PARENT_OF
    loaded_modules: SkipValidation[Any] = None  # LOADED
    opened_files: SkipValidation[Any] = None    # OPENED
    network_connections: SkipValidation[Any] = None


class Module(ForensicDataPoint):
    name: str
    path: str | None = None
    base_address: str | None = None
    size: int | None = None
    # Relationships
    loaded_by: SkipValidation[Any] = None       # LOADED (reverse)


class File(ForensicDataPoint):
    path: str
    sha256: str | None = None
    mtime: str | None = None
    size: int | None = None
    # MFT-derived timestamps (ISO8601). `created_time` is the $StandardInformation
    # creation time — the most useful "first dropped on disk" anchor. `accessed_time`
    # is unreliable on Win7+ (NtfsDisableLastAccessUpdate is on by default since Vista).
    created_time: str | None = None
    accessed_time: str | None = None
    mft_modified_time: str | None = None  # $SI MFT-record-change time
    # Deletion timestamp. Populated by USN drop-then-delete (file lifecycle) and by
    # RBCmd `$I` parsing (recycle bin drop time). When both fire on the same path
    # the first source to populate wins; sources are content-equivalent for this field.
    deleted_time: str | None = None
    # Relationships
    written_by: SkipValidation[Any] = None      # WROTE (reverse)
    opened_by: SkipValidation[Any] = None


class User(ForensicDataPoint):
    username: str
    sid: str | None = None
    # Relationships
    authenticated_as: SkipValidation[Any] = None


class Host(ForensicDataPoint):
    hostname: str
    os: str | None = None
    # Relationships (top-level container)
    processes: SkipValidation[Any] = None
    files: SkipValidation[Any] = None


class NetworkEndpoint(ForensicDataPoint):
    ip: str
    port: int | None = None
    protocol: str | None = None
    # Relationships
    connected_to: SkipValidation[Any] = None


class RegistryKey(ForensicDataPoint):
    path: str
    value: str | None = None
    value_type: str | None = None
    # ISO8601 RECmd LastWriteTimestamp on the parent key — temporal anchor for
    # persistence-wiring events (used by correlation_agent's temporal rule).
    last_write_time: str | None = None
    # Relationships
    written_by: SkipValidation[Any] = None


class Credential(ForensicDataPoint):
    username: str | None = None
    password_hash: str | None = None
    domain: str | None = None
    # Relationships
    authenticated_by: SkipValidation[Any] = None


class TimelineEvent(ForensicDataPoint):
    timestamp: str
    event_type: str
    description: str
    # Relationships
    related_to: SkipValidation[Any] = None


class Event(ForensicDataPoint):
    """Windows event-log record (one per evtx record number).
    Identity: (channel, record_number) is unique per host's event log."""
    channel: str
    record_number: int
    event_id: int | None = None
    time_created: str | None = None
    # Relationships
    observed_in: SkipValidation[Any] = None  # OBSERVED_IN claim/source


class ProcessExecution(ForensicDataPoint):
    """Multi-source execution record. Identity: (host, executable_name).

    Populated independently by prefetch_agent (run history), registry_agent's
    ShimCache + Amcache detectors, etc. — same UUID across sources via _stable_id.
    Per-field LISTS preserve all observations across multiple source claims (a
    given basename like `svchost.exe` legitimately has many .pf files, each with
    its own path / last-run-time / run-count, plus possibly a masquerade variant
    at a non-canonical path). The extractor merges new values into the existing
    graph node on each write — see orchestrator/extractor.py's `process_execution`
    branch. Without this list-of-observations design, the graph would be
    first-write-wins and lose 90%+ of the prefetch evidence on collision-prone
    basenames (svchost.exe ×9, dllhost.exe ×8, rundll32.exe ×9 on win7-nromanoff).
    """
    executable_name: str
    executable_paths: List[str] = Field(default_factory=list)
    last_run_times: List[str] = Field(default_factory=list)
    run_counts: List[int] = Field(default_factory=list)
    run_times: List[str] = Field(default_factory=list)
    sha1s: List[str] = Field(default_factory=list)
    publishers: List[str] = Field(default_factory=list)
    # Per-agent source discriminator already set in claim frontmatter's execution_attrs
    # (`prefetch`, `shimcache`, `amcache`). Aggregated here so a graph query like
    # `len(sources) >= 3` cleanly identifies binaries triangulated by multiple
    # forensic domains. The memory_agent doesn't contribute (it deals in PIDs not
    # basenames) so memory-derived ProcessExecution evidence won't appear here.
    sources: List[str] = Field(default_factory=list)
    # Relationships
    executed_files: SkipValidation[Any] = None


class Service(ForensicDataPoint):
    """Windows service. Populated by memory_agent (windows.svcscan), registry_agent
    (HKLM\\System\\CurrentControlSet\\Services), and evtx-agent (event 7045 install
    records). Multiple agents emit the same `service:<host>:<name>` entity → the
    extractor first-write-wins, so cross-domain agreement is established by the
    entity ID alone. Fields are set by whichever claim arrives first."""
    name: str
    display_name: str | None = None
    image_path: str | None = None
    state: str | None = None        # Running / Stopped / Paused
    start_mode: str | None = None   # Auto / Manual / Disabled


# ─────────────────────────────────────────────────────────────
# TYPED EDGES (used when setting relationships)
# ─────────────────────────────────────────────────────────────

class PARENT_OF(Edge):
    confidence: float = 1.0
    derived_from: List[str] = Field(default_factory=list)


class LOADED(Edge):
    confidence: float = 1.0
    derived_from: List[str] = Field(default_factory=list)


class CONNECTED_TO(Edge):
    confidence: float = 1.0
    derived_from: List[str] = Field(default_factory=list)


class WROTE(Edge):
    confidence: float = 1.0
    derived_from: List[str] = Field(default_factory=list)


class AUTHENTICATED_AS(Edge):
    confidence: float = 1.0
    derived_from: List[str] = Field(default_factory=list)


class OBSERVED_IN(Edge):
    confidence: float = 1.0
    derived_from: List[str] = Field(default_factory=list)


# Optional helper to register everything with Cognee (call once at startup)
async def register_forensice_schema():
    """Initialise Cognee storage. Idempotent — preserves data across orchestrator restarts.

    Set FINDEVIL_COGNEE_RESET=1 to force a wipe (dev only).
    """
    if os.environ.get("FINDEVIL_COGNEE_RESET") == "1":
        await cognee.prune.prune_data()
        await cognee.prune.prune_system(metadata=True)
        print("⚠️  Cognee data + system PRUNED (FINDEVIL_COGNEE_RESET=1)")
    await cognee.low_level.setup()
    print("✅ FindEvil forensic schema registered with Cognee (persistent)")
