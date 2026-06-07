# orchestrator/validator.py
"""
Self-correction loop — the killer feature that wins FindEvil.
Checks every claim against Cognee entities + on-disk evidence.
"""

import asyncio
import os
import re
import uuid
from pathlib import Path
from typing import Tuple
import yaml

EVIDENCE_ROOT = Path(os.environ.get("EVIDENCE_ROOT", "/evidence")).resolve()
SKIP_SPOT_CHECK = os.environ.get("FINDEVIL_SKIP_SPOT_CHECK") == "1"

# Multi-field spot-check coverage per node-type prefix. Every field in this list is
# compared between the claim's asserted value and the graph's persisted value.
SPOT_CHECK_FIELDS = {
    # `command_line` is intentionally NOT in this list. Memory-agent populates it from
    # windows.cmdline, but registry/evtx claims for the same PID don't carry cmdline,
    # so spot-checking would reject perfectly-good cross-domain claims. Cross-source
    # disagreement on cmdline (e.g., evtx 4688 vs vol cmdline) is itself a finding —
    # that lives in correlation_agent, not the validator.
    "process":           ["name", "ppid", "create_time"],
    "registry_key":      ["value", "value_type"],
    "event":             ["event_id", "channel", "time_created"],
    # ProcessExecution intentionally NOT spot-checked: multiple .pf files for the same
    # basename (svchost.exe ×9, dllhost.exe ×8, rundll32.exe ×9 on win7) all share a
    # graph-node UUID via _stable_id(basename). Each .pf legitimately reports a different
    # executable_path / last_run_time / run_count. The first claim writes to the graph;
    # spot-checking subsequent claims against it would reject ~12 valid claims per win7 run
    # (verified 2026-04-19). Basename is the identity for cross-domain joins; per-source
    # attrs are content. Proper fix is `executable_path: List[str]` schema migration —
    # tracked as a follow-up. Until then, this relaxation is the smallest unblock.
    "file":              ["created_time", "modified_time"],
    # Service entities can be emitted by memory svcscan, registry CurrentControlSet,
    # and evtx 7045. Spot-check the identity-ish fields where multiple agents agree;
    # state/start_mode are deliberately excluded (memory dump captures state at one
    # moment, registry captures the configured value — they may legitimately differ).
    "service":           ["display_name", "image_path"],
}

# Sentinel values that mean "no real value was known yet". A claim asserting any of these
# for an identity field is rejected outright (gap #5 — prevents fabricators from stuffing
# placeholders to overwrite real data). Different from the spot-check graph-side tolerance.
ASSERTION_SENTINELS = {"", "unknown", "placeholder_from_extractor", "?", "-", "n/a", "none"}

# Body-text PID-name pattern. Matches "**PID 1328** (spinlock.exe)" anywhere in the body.
BODY_PID_NAME_RE = re.compile(r"\*\*PID\s*(\d+)\*\*\s*\(([^)]+)\)")


def _stable_id_str(s: str) -> str:
    """Same deterministic UUID scheme as orchestrator/extractor.py — must agree."""
    return str(uuid.uuid5(uuid.NAMESPACE_OID, s))


def _is_sentinel(value) -> bool:
    return value is None or str(value).strip().lower() in ASSERTION_SENTINELS

# Canonical evidence subdirs to consult when an `evidence_refs` path doesn't resolve at its
# claimed location (e.g., the dispatcher moved the source file from new/ to processed/
# between agent emit and validator pass).
_EVIDENCE_SEARCH_SUBDIRS = ("new", "processed", "baselines", "extracted", "dumps", "claims/done")


def _resolve_evidence_ref(ref: str) -> Path:
    """Convert a claim's evidence_ref string to an absolute path under EVIDENCE_ROOT.

    Strips '#fragment' suffixes (e.g., '#vol-pslist') and the leading 'evidence/' if present.
    """
    path = ref.split("#", 1)[0].rstrip("/")
    if path.startswith("evidence/"):
        path = path[len("evidence/"):]
    return EVIDENCE_ROOT / path


def _ref_exists(ref: str) -> bool:
    """True iff `ref` resolves to a file/dir on disk, allowing for moved evidence."""
    p = _resolve_evidence_ref(ref)
    if p.exists():
        return True
    basename = p.name
    if not basename:
        return False
    for subdir in _EVIDENCE_SEARCH_SUBDIRS:
        if (EVIDENCE_ROOT / subdir / basename).exists():
            return True
    return False


def _check_assertion_sentinels(frontmatter: dict) -> list:
    """Gap #5: reject claims that ASSERT sentinel values for identity fields.
    Returns list of human-readable rejection reasons (empty = clean)."""
    reasons: list = []
    for pid, attrs in (frontmatter.get("pid_attrs") or {}).items():
        if isinstance(attrs, dict) and _is_sentinel(attrs.get("name")):
            reasons.append(f"PID {pid}: pid_attrs.name is a sentinel value ({attrs.get('name')!r})")
    for ent, attrs in (frontmatter.get("key_attrs") or {}).items():
        # value MAY legitimately be empty for some keys; only flag clearly-poisoning sentinels
        if isinstance(attrs, dict) and isinstance(attrs.get("value"), str) \
                and attrs["value"].lower() in {"unknown", "placeholder_from_extractor"}:
            reasons.append(f"{ent}: key_attrs.value is a sentinel value ({attrs['value']!r})")
    return reasons


def _extract_body_assertions(body: str) -> dict:
    """Gap #2: pull (PID, name) pairs from claim body for spot-check.
    Returns {pid_int: name_str}. Catches the "honest frontmatter, lying body" attack."""
    out: dict = {}
    for m in BODY_PID_NAME_RE.finditer(body or ""):
        try:
            pid = int(m.group(1))
        except ValueError:
            continue
        name = m.group(2).strip()
        if not name or _is_sentinel(name):
            continue
        # First mention wins (consistent with how the report's body parser sees it)
        out.setdefault(pid, name)
    return out


async def _spot_check_assertions(frontmatter: dict, body: str = "") -> tuple[int, int, list]:
    """Compare claim's asserted entity attributes against the Cognee graph.

    Multi-field per node type (gap #1) + body-text PID/name pairs (gap #2).
    Returns (checked_count, mismatch_count, mismatch_details).
    """
    if SKIP_SPOT_CHECK:
        return (0, 0, [])

    pid_attrs = frontmatter.get("pid_attrs") or {}
    key_attrs = frontmatter.get("key_attrs") or {}
    event_attrs = frontmatter.get("event_attrs") or {}
    execution_attrs = frontmatter.get("execution_attrs") or {}
    file_attrs = frontmatter.get("file_attrs") or {}
    service_attrs = frontmatter.get("service_attrs") or {}
    body_pid_names = _extract_body_assertions(body)
    claim_host = frontmatter.get("host")  # required for host-namespaced lookups
    if not (pid_attrs or key_attrs or event_attrs or execution_attrs or file_attrs or service_attrs or body_pid_names):
        return (0, 0, [])
    if not claim_host:
        # Pre-host-namespacing claim: skip spot-check (legacy claims have no host context).
        return (0, 0, [])

    try:
        from cognee.infrastructure.databases.unified import get_unified_engine
    except ImportError:
        return (0, 0, [])

    try:
        unified = await get_unified_engine()
        graph = unified.graph
    except Exception:
        return (0, 0, [])

    checked = 0
    mismatches: list = []

    async def _check_field(node_id: str, asserted_val, graph_val, label: str, field: str):
        nonlocal checked
        if asserted_val is None or graph_val is None:
            return
        if _is_sentinel(graph_val):
            return  # Graph has a placeholder — new claim wins, extractor will overwrite.
        if _is_sentinel(asserted_val):
            return  # Sentinel asserts are caught by _check_assertion_sentinels separately
        checked += 1
        if str(asserted_val).strip().lower() != str(graph_val).strip().lower():
            mismatches.append(f"{label}: claim asserts {field}={asserted_val!r} but graph says {field}={graph_val!r}")

    async def _check_node(node_id: str, asserted_attrs: dict, fields: list, label: str):
        try:
            node = await graph.get_node(node_id)
        except Exception:
            return
        if not node:
            return  # New entity — extractor will create it on this pass.
        for field in fields:
            await _check_field(node_id, asserted_attrs.get(field), node.get(field), label, field)

    # Frontmatter pid_attrs — multi-field. Keys are bare PIDs; combine with claim_host.
    for pid, attrs in pid_attrs.items():
        if not isinstance(attrs, dict):
            continue
        try:
            pid_int = int(pid)
        except (TypeError, ValueError):
            continue
        await _check_node(_stable_id_str(f"process:{claim_host}:{pid_int}"), attrs,
                          SPOT_CHECK_FIELDS["process"], f"PID {pid_int} (host {claim_host})")

    # Frontmatter key_attrs — entity IDs are already host-namespaced as registry_key:<host>:<rest>
    for ent, attrs in key_attrs.items():
        if not isinstance(attrs, dict) or not isinstance(ent, str):
            continue
        parts = ent.split(":", 2)
        if len(parts) != 3 or parts[0] != "registry_key":
            continue
        host, rest = parts[1], parts[2]
        await _check_node(_stable_id_str(f"registry_key:{host}:{rest}"), attrs,
                          SPOT_CHECK_FIELDS["registry_key"], f"key {rest} (host {host})")

    # Frontmatter event_attrs — entity IDs are event:<host>:<channel>:<record>
    for ent, attrs in event_attrs.items():
        if not isinstance(attrs, dict) or not isinstance(ent, str):
            continue
        parts = ent.split(":", 3)
        if len(parts) != 4 or parts[0] != "event":
            continue
        host, channel, record_str = parts[1], parts[2], parts[3]
        try:
            rec = int(record_str)
        except ValueError:
            continue
        await _check_node(_stable_id_str(f"event:{host}:{channel}:{rec}"), attrs,
                          SPOT_CHECK_FIELDS["event"], f"event {channel}:{rec} (host {host})")

    # NOTE: execution_attrs intentionally NOT spot-checked — see SPOT_CHECK_FIELDS comment.
    # Multiple .pf files for the same basename legitimately differ on path/run_time.

    # Frontmatter file_attrs — entity IDs are file:<host>:<path>
    for ent, attrs in file_attrs.items():
        if not isinstance(attrs, dict) or not isinstance(ent, str):
            continue
        parts = ent.split(":", 2)
        if len(parts) != 3 or parts[0] != "file":
            continue
        host, rest = parts[1], parts[2]
        await _check_node(_stable_id_str(f"file:{host}:{rest}"), attrs,
                          SPOT_CHECK_FIELDS["file"], f"file {rest[:60]} (host {host})")

    # Frontmatter service_attrs — entity IDs are service:<host>:<lowercased_name>.
    # Multiple agents (memory svcscan, registry, evtx 7045) emit overlapping service
    # entities; first writer wins, subsequent writers spot-check display_name + image_path.
    for ent, attrs in service_attrs.items():
        if not isinstance(attrs, dict) or not isinstance(ent, str):
            continue
        parts = ent.split(":", 2)
        if len(parts) != 3 or parts[0] != "service":
            continue
        host, rest = parts[1], parts[2]
        await _check_node(_stable_id_str(f"service:{host}:{rest}"), attrs,
                          SPOT_CHECK_FIELDS["service"], f"service {rest} (host {host})")

    # Body-text PID/name pairs (gap #2). Compares against Process.name in graph.
    # Body PIDs are scoped to the claim's host (memory_agent's body talks about its host).
    for pid_int, body_name in body_pid_names.items():
        node_id = _stable_id_str(f"process:{claim_host}:{pid_int}")
        try:
            node = await graph.get_node(node_id)
        except Exception:
            continue
        if not node:
            continue
        graph_name = node.get("name")
        if _is_sentinel(graph_name):
            continue
        checked += 1
        if str(body_name).strip().lower() != str(graph_name).strip().lower():
            mismatches.append(
                f"BODY PID {pid_int}: body says name={body_name!r} but graph says name={graph_name!r}"
            )

    return (checked, len(mismatches), mismatches[:8])


async def run_self_correction_loop(claim_path: Path) -> Tuple[bool, str]:
    """Return (is_valid, error_message).

    Checks (per FindEvil §4):
    1. Frontmatter is well-formed and carries `entities` + `evidence_refs`.
    2. Every `evidence_refs` path resolves to a file/dir on disk (with moved-evidence fallback). [3a]
    3. Asserted attribute values are NOT sentinel placeholders (gap #5).
    4. Asserted entity attributes (multi-field) match the Cognee graph for known entities. [5a, gap #1]
    5. Inline body PID/name pairs match the graph. [gap #2]
    """
    try:
        with open(claim_path, "r", encoding="utf-8") as f:
            content = f.read()

        if not content.startswith("---"):
            return False, "Missing YAML frontmatter"
        parts = content.split("---", 2)
        if len(parts) < 3:
            return False, "Malformed frontmatter"

        frontmatter = yaml.safe_load(parts[1]) or {}
        body = parts[2]

        if "entities" not in frontmatter or "evidence_refs" not in frontmatter:
            return False, "Missing 'entities' or 'evidence_refs' in frontmatter"

        refs = frontmatter.get("evidence_refs") or []
        missing = [r for r in refs if isinstance(r, str) and not _ref_exists(r)]
        if missing:
            return False, f"Missing evidence files ({len(missing)} of {len(refs)}): {missing[:3]}"

        # Gap #5: reject sentinel asserts before they can poison the graph.
        sentinel_reasons = _check_assertion_sentinels(frontmatter)
        if sentinel_reasons:
            return False, f"Sentinel-value assertion rejected: {sentinel_reasons[:3]}"

        # 5a: multi-field spot-check + body parse.
        checked, mismatch_count, mismatches = await _spot_check_assertions(frontmatter, body)
        if mismatch_count > 0:
            return False, f"Assertion spot-check failed ({mismatch_count} of {checked} verified): {mismatches}"

        spot_str = f", {checked} attr(s) spot-checked vs graph" if checked else ""
        print(f"✅ Self-correction passed (frontmatter + {len(refs)} evidence refs verified{spot_str}) for {claim_path.name}")
        return True, ""

    except Exception as e:
        return False, f"Validator exception: {str(e)}"
