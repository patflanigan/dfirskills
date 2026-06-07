# orchestrator/extractor.py
"""
Deterministic entity extraction layer.
Never uses LLM for structured forensic data.
Parses claim frontmatter + referenced evidence files → typed Cognee nodes/edges.
"""

import asyncio
import os
import uuid
from pathlib import Path
from uuid import UUID, uuid4

import yaml
from pydantic import BaseModel as _PydBaseModel

from cognee.tasks.storage import add_data_points
from cognee.modules.users.methods import get_default_user
from cognee.modules.data.methods import create_authorized_dataset
from cognee.modules.pipelines.models import PipelineContext
from cognee_schema.schema import Process, Module, File, RegistryKey, User, Event, Host, ProcessExecution, Service, PARENT_OF, LOADED


class _CaseDataItem(_PydBaseModel):
    """Minimal data-item shape — add_data_points only reads .id from it."""
    id: UUID


def _stable_id(s: str) -> uuid.UUID:
    """Deterministic UUID for an entity identifier so re-ingestion dedupes naturally."""
    return uuid.uuid5(uuid.NAMESPACE_OID, s)


def _parse_entity(entity_ref: str) -> tuple[str, str, str] | None:
    """Parse the host-namespaced entity shape `<type>:<host>:<rest>`.
    Returns (type, host, rest), or None for malformed / pre-host-namespacing format."""
    if not isinstance(entity_ref, str):
        return None
    parts = entity_ref.split(":", 2)
    if len(parts) != 3:
        return None
    return parts[0], parts[1], parts[2]


async def extract_entities_to_cognee(claim_path: Path):
    """Deterministic extraction — entity-prefix → typed schema node.

    Recognised prefixes (matches what the agents emit):
      process:<pid>            → Process
      registry_key:<path>      → RegistryKey
      file:<path>              → File
      service:<name>           → no schema node yet (counted only)
      hive:<name>              → provenance marker (counted only)
    Unknown prefixes are counted under `unknown[<prefix>]` so they're visible.
    """
    print(f"🔬 Extracting entities from claim: {claim_path.name}")

    with open(claim_path, "r", encoding="utf-8") as f:
        content = f.read()

    if not content.startswith("---"):
        print("   ⚠️  No frontmatter — nothing to extract")
        return
    frontmatter = yaml.safe_load(content.split("---", 2)[1]) or {}

    counts: dict[str, int] = {}
    nodes: list = []
    process_pids_in_claim: set[tuple[str, int]] = set()  # (host, pid) for PARENT_OF edge filtering

    # Per-entity asserted attributes (option A: 4b). Agents serialize these into
    # claim frontmatter; extractor uses them to populate real node fields instead
    # of placeholders. Validator's spot-check (5a) compares them against the graph.
    pid_attrs = frontmatter.get("pid_attrs") or {}     # {pid: {name, ppid, create_time, command_line}}
    key_attrs = frontmatter.get("key_attrs") or {}     # {host-namespaced entity: {value, value_type, path}}
    event_attrs = frontmatter.get("event_attrs") or {} # {host-namespaced entity: {channel, ...}}
    execution_attrs = frontmatter.get("execution_attrs") or {}  # {host-namespaced entity: {executable_path, ...}}
    file_attrs = frontmatter.get("file_attrs") or {}   # {host-namespaced entity: {created_time, modified_time, ...}}
    service_attrs = frontmatter.get("service_attrs") or {}  # {host-namespaced entity: {display_name, image_path, state, start_mode}}
    claim_host = frontmatter.get("host")               # source-of-truth claims now carry host context

    # Always create the Host node for any source-of-truth claim. Lets cross-host
    # disambiguation work and gives the graph an anchor for per-host queries.
    if claim_host:
        nodes.append(Host(
            id=_stable_id(f"host:{claim_host}"),
            hostname=claim_host,
            evidence_refs=[str(claim_path)],
        ))
        counts["Host"] = counts.get("Host", 0) + 1

    for entity_ref in frontmatter.get("entities", []) or []:
        parsed = _parse_entity(entity_ref)
        if parsed is None:
            # Pre-host-namespacing format (legacy 2-segment) or malformed.
            counts["unknown[malformed]"] = counts.get("unknown[malformed]", 0) + 1
            continue
        prefix, host, rest = parsed
        if prefix == "process":
            try:
                pid = int(rest)
            except ValueError:
                continue
            attrs = pid_attrs.get(pid) or pid_attrs.get(str(pid))
            if not attrs:
                continue
            asserted_name = attrs.get("name")
            if not asserted_name or str(asserted_name).strip().lower() in (
                "", "unknown", "placeholder_from_extractor", "?", "-", "n/a"
            ):
                continue
            nodes.append(Process(
                id=_stable_id(f"process:{host}:{pid}"),
                pid=pid,
                name=asserted_name,
                ppid=attrs.get("ppid"),
                create_time=attrs.get("create_time"),
                command_line=attrs.get("command_line"),
                evidence_refs=[str(claim_path)],
            ))
            process_pids_in_claim.add((host, pid))
            counts["Process"] = counts.get("Process", 0) + 1
        elif prefix == "registry_key":
            attrs = key_attrs.get(entity_ref)
            if not attrs:
                continue
            nodes.append(RegistryKey(
                id=_stable_id(f"registry_key:{host}:{rest}"),
                path=rest,
                value=attrs.get("value"),
                value_type=attrs.get("value_type"),
                last_write_time=attrs.get("last_write_time"),
                evidence_refs=[str(claim_path)],
            ))
            counts["RegistryKey"] = counts.get("RegistryKey", 0) + 1
        elif prefix == "file":
            attrs = file_attrs.get(entity_ref) or {}
            nodes.append(File(
                id=_stable_id(f"file:{host}:{rest}"),
                path=rest,
                created_time=attrs.get("created_time"),
                mtime=attrs.get("modified_time"),
                accessed_time=attrs.get("accessed_time"),
                mft_modified_time=attrs.get("mft_modified_time"),
                deleted_time=attrs.get("deleted_time"),
                size=attrs.get("file_size"),
                evidence_refs=[str(claim_path)],
            ))
            counts["File"] = counts.get("File", 0) + 1
        elif prefix == "user":
            nodes.append(User(
                id=_stable_id(f"user:{host}:{rest}"),
                username=rest,
                evidence_refs=[str(claim_path)],
            ))
            counts["User"] = counts.get("User", 0) + 1
        elif prefix == "event":
            # rest is "<channel>:<record_number>"
            try:
                channel, record_str = rest.split(":", 1)
                record_number = int(record_str)
            except (ValueError, AttributeError):
                continue
            attrs = event_attrs.get(entity_ref)
            if not attrs:
                continue
            nodes.append(Event(
                id=_stable_id(f"event:{host}:{channel}:{record_number}"),
                channel=channel, record_number=record_number,
                event_id=attrs.get("event_id"),
                time_created=attrs.get("time_created"),
                evidence_refs=[str(claim_path)],
            ))
            counts["Event"] = counts.get("Event", 0) + 1
        elif prefix == "process_execution":
            attrs = execution_attrs.get(entity_ref)
            if not attrs:
                continue
            node_id = _stable_id(f"process_execution:{host}:{rest}")
            # Fetch existing — the extractor runs once per claim, so without merging,
            # the graph node would be overwritten by each of N claims for the same
            # basename (svchost.exe ×9, dllhost.exe ×8 on win7). Lazy-import to mirror
            # validator's pattern. Any fetch failure → treat as first write.
            existing: dict = {}
            try:
                from cognee.infrastructure.databases.unified import get_unified_engine
                unified = await get_unified_engine()
                existing = (await unified.graph.get_node(str(node_id))) or {}
            except Exception:
                existing = {}

            def _append_unique(prior, new_value):
                out = list(prior or [])
                if new_value in (None, "") or new_value in out:
                    return out
                out.append(new_value)
                return out

            new_run_times = attrs.get("run_times") or []
            merged_run_times = sorted(set((existing.get("run_times") or []) + new_run_times))
            merged_evidence = sorted(set((existing.get("evidence_refs") or []) + [str(claim_path)]))

            nodes.append(ProcessExecution(
                id=node_id,
                executable_name=attrs.get("executable_name") or rest,
                executable_paths=_append_unique(existing.get("executable_paths"), attrs.get("executable_path")),
                last_run_times=_append_unique(existing.get("last_run_times"), attrs.get("last_run_time")),
                run_counts=_append_unique(existing.get("run_counts"), attrs.get("run_count")),
                run_times=merged_run_times,
                sha1s=_append_unique(existing.get("sha1s"), attrs.get("sha1")),
                publishers=_append_unique(existing.get("publishers"), attrs.get("publisher")),
                sources=_append_unique(existing.get("sources"), attrs.get("source")),
                evidence_refs=merged_evidence,
            ))
            counts["ProcessExecution"] = counts.get("ProcessExecution", 0) + 1
        elif prefix == "host":
            # Already created above (only one Host node per claim, deduped by ID).
            pass
        elif prefix == "service":
            # rest is the lowercased service name. Multiple agents (memory svcscan,
            # registry CurrentControlSet\Services, evtx 7045) can emit the same
            # service:<host>:<name> entity — _stable_id() dedupes by full ID, so
            # the first writer creates the node and later ones are no-ops at the
            # graph level (their evidence_refs accumulate via cross_domain_service_persistence).
            attrs = service_attrs.get(entity_ref) or {}
            nodes.append(Service(
                id=_stable_id(f"service:{host}:{rest}"),
                name=attrs.get("name") or rest,
                display_name=attrs.get("display_name"),
                image_path=attrs.get("image_path"),
                state=attrs.get("state"),
                start_mode=attrs.get("start_mode"),
                evidence_refs=[str(claim_path)],
            ))
            counts["Service"] = counts.get("Service", 0) + 1
        elif prefix == "hive":
            counts["Hive (provenance)"] = counts.get("Hive (provenance)", 0) + 1
        else:
            counts[f"unknown[{prefix}]"] = counts.get(f"unknown[{prefix}]", 0) + 1

    # Build typed PARENT_OF edges from memory-agent claims that ship a pid_parents map.
    # Both PIDs are scoped to claim_host (memory_agent emits pid_parents only for its host).
    edges: list = []
    pid_parents = frontmatter.get("pid_parents") or {}
    if isinstance(pid_parents, dict) and claim_host:
        for pid, parent_pid in pid_parents.items():
            try:
                pid_i = int(pid)
                parent_pid_i = int(parent_pid)
            except (TypeError, ValueError):
                continue
            if (claim_host, pid_i) not in process_pids_in_claim or \
               (claim_host, parent_pid_i) not in process_pids_in_claim:
                continue
            child_id = str(_stable_id(f"process:{claim_host}:{pid_i}"))
            parent_id = str(_stable_id(f"process:{claim_host}:{parent_pid_i}"))
            edges.append((parent_id, child_id, "PARENT_OF", {
                "confidence": 1.0,
                "derived_from": [str(claim_path)],
            }))

    if nodes:
        try:
            # Build PipelineContext so add_data_points fires upsert_nodes/edges
            # in cognee's relational metadata. Without ctx, nodes go to kuzu but
            # the dataset never registers, and the GUI dashboard stays empty.
            # User + dataset lookups are idempotent (cache + get-or-create).
            _user = await get_default_user()
            _dataset = await create_authorized_dataset(
                dataset_name=os.environ["FINDEVIL_CASE_ID"],
                user=_user,
            )
            await add_data_points(
                nodes,
                custom_edges=edges if edges else None,
                ctx=PipelineContext(
                    user=_user,
                    dataset=_dataset,
                    data_item=_CaseDataItem(id=uuid4()),
                ),
            )
        except Exception as e:
            print(f"   ⚠️  Cognee write failed: {e!r}")
        else:
            edge_str = f" + {len(edges)} edge(s)" if edges else ""
            print(f"   → committed {len(nodes)} node(s){edge_str} to Cognee")

    if counts:
        for kind, n in sorted(counts.items()):
            print(f"   → {n} × {kind} entity reference(s)")
    else:
        print("   → no entities to extract")
    print(f"✅ Deterministic extraction complete for {claim_path.name}")
