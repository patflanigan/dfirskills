"""
Forensic Analyst Agent — LLM-driven deep-dive over the post-baseline pipeline state.

Standalone CLI:  python -m agents.forensic_analyst.agent
Orchestrator:    spawned as subprocess after plaso pass, before report_agent.

Architecture:
  1. Loads SKILLS.md (behavioral / architectural guardrails) and ref_SKILLS.md
     (per-domain forensic playbook) into the system prompt at startup. Prompt-
     cached so per-case cost is just the user message + per-turn results.

  2. Agentic loop (Claude Agent SDK, claude-opus-4-7, capped at 150 chisel-
     touching tool calls). Standard Anthropic tool-use protocol.

  3. Tools:
       list_dir / read_file / grep / find_files — lifted from coverage_explorer
       exec_forensic_tool — run any allowlisted forensic tool via Chisel
       query_graph        — read-only Cognee node lookup by natural ID
       write_claim        — validate frontmatter + write to claims/todo/
       done               — signal completion; optional summary for the report

  4. Truth-enforcement: every claim the LLM writes goes through the standard
     orchestrator validator (claims/todo/ → run_self_correction_loop). The LLM
     cannot introduce a finding that disagrees with the baseline graph.

  5. No deterministic fallback. The analyst is opt-out (--no-analyst); if the
     SDK / Claude Code CLI is unavailable, the pass is skipped silently.
"""

import asyncio
import json
import os
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path

import yaml

from agents._chisel import Chisel

# ───────────────────────────────────────────────────────────────────────────
# Constants & paths
# ───────────────────────────────────────────────────────────────────────────

EVIDENCE_ROOT = Path(os.environ.get(
    "EVIDENCE_ROOT", "/home/sansforensics/dfirskills2/evidence",
))
CLAIMS_TODO  = EVIDENCE_ROOT / "claims/todo"
CLAIMS_DONE  = EVIDENCE_ROOT / "claims/done"
CLAIMS_REJECTED = EVIDENCE_ROOT / "claims/rejected"
AUDIT_DIR    = EVIDENCE_ROOT / "audit"

CHISEL_URL    = os.environ.get("CHISEL_URL", "http://127.0.0.1:3000")
CHISEL_SECRET = os.environ["CHISEL_SECRET"]

# Repo root — for loading SKILLS.md and ref_SKILLS.md
_REPO_ROOT = Path(__file__).resolve().parents[2]
_SKILLS_PATH     = _REPO_ROOT / "SKILLS.md"
_REF_SKILLS_PATH = _REPO_ROOT / "ref_SKILLS.md"

_AGENT_NAME      = "forensic-analyst"
_DEFAULT_MODEL   = "claude-opus-4-7"

# Hard cap on chisel-touching tool calls. The `done` tool does NOT count
# against this. At _WRAP_UP_THRESHOLD a reminder is injected.
_TOOL_CALL_CAP     = int(os.environ.get("FINDEVIL_ANALYST_TURNS", "150"))
_WRAP_UP_THRESHOLD = max(10, _TOOL_CALL_CAP - 10)

# Per-tool-result truncation. Forensic-tool stdout (vol pslist JSON, etc.) can
# be huge — cap to keep prompt growth bounded.
_TOOL_RESULT_MAX_BYTES = 16384

# MCP server name — LLM sees tools as mcp__analyst__<short_name>
_MCP_SERVER_NAME = "analyst"

# Multi-line refusal returned when a tool is called with a path outside the
# Chisel --root. Same shape coverage_explorer uses.
_PATH_REFUSAL_MSG = f"""refused: path must be under {{evidence_root}}. Useful starting points:
  {{evidence_root}}/audit/        — chisel audit log (jsonl)
  {{evidence_root}}/claims/done/  — validated claims from the baseline pipeline
  {{evidence_root}}/claims/rejected/ — claims rejected by the validator (read these to learn why)
  {{evidence_root}}/extracted/    — extracted artifacts (per-host subdirs)
  {{evidence_root}}/dumps/        — VAD memory dumps (per-host subdirs)
  {{evidence_root}}/new/          — incoming raw evidence (E01, .001 dumps, etc.)
  {{evidence_root}}/processed/    — evidence that's been processed by deterministic agents"""


# ───────────────────────────────────────────────────────────────────────────
# System prompt assembly — load SKILLS.md + ref_SKILLS.md at import time
# ───────────────────────────────────────────────────────────────────────────

def _load_skills_text(path: Path, label: str) -> str:
    """Read a skill file. If missing or empty, return a marker so the prompt
    is still well-formed (and the LLM knows the file wasn't found)."""
    try:
        text = path.read_text(encoding="utf-8").strip()
    except OSError:
        return f"_({label} not found at {path})_"
    return text or f"_({label} was empty)_"


_SKILLS_MD     = _load_skills_text(_SKILLS_PATH,     "SKILLS.md")
_REF_SKILLS_MD = _load_skills_text(_REF_SKILLS_PATH, "ref_SKILLS.md")


_SYSTEM_PROMPT = f"""You are a senior DFIR analyst running a deep-dive review of a forensic case. The deterministic per-domain agents (memory, registry, evtx, prefetch, mft, disk_image, correlation, plaso) have already run; their validated claims are in {CLAIMS_DONE} and the typed Cognee entities have been extracted into the case graph.

Your job is to act like a human expert: read what's there, identify the most interesting / anomalous / unresolved signals, pivot on them using the same Chisel-routed forensic tools the deterministic agents use, and emit ADDITIONAL claims for findings the baseline sweep missed. Cross-source corroboration is your defense — a single-source observation is a lead, two-domain independence is a finding.

The orchestrator validator will spot-check every claim you emit:
  - evidence_refs paths must resolve under {EVIDENCE_ROOT}
  - identity fields (Process: name+ppid+create_time; Event: event_id+channel+time_created; RegistryKey: value+value_type; Service: display_name+image_path; File: created_time+modified_time) must MATCH any entity already in the graph
  - sentinel placeholders (`unknown`, `?`, `-`, `n/a`, `none`, empty) are auto-rejected
  - inline body PID/name patterns must match the frontmatter

You CANNOT introduce a finding that disagrees with what the deterministic pipeline already established. You CAN add new findings the baseline missed — that is your entire purpose. If your claim is rejected, the rejection reason is written to {CLAIMS_REJECTED}/<your-filename>. Read it, learn, retry with a better-grounded claim.

==== Behavioral & architectural rules (SKILLS.md) ====
{_SKILLS_MD}

==== Forensic playbook (ref_SKILLS.md) ====
{_REF_SKILLS_MD}

==== Pipeline-specific context ====
- All filesystem paths must be ABSOLUTE under {EVIDENCE_ROOT}. The kickoff user message names the exact subdirs you'll use most.
- Claim filenames you emit MUST start with `analyst_` (so the watcher routes them to the validator and the orchestrator can tell your claims apart). Format: `analyst_<short-topic>_<TIMESTAMP>.md`.
- Claim format: YAML frontmatter (between two `---` lines) then Markdown body. See examples in {CLAIMS_DONE}/.
- Required frontmatter fields: `claim_id` (unique, e.g. `analyst-<8-hex>`), `status: new`, `host` (e.g. win7-32-nromanoff), `entities` (list of strings), `evidence_refs` (list of repo-relative paths), `confidence` (0..1).
- Use `write_claim()` to emit findings. Use `done(summary)` to terminate when you've exhausted the interesting leads or your tool-call budget is tight.

Tool-call budget: {_TOOL_CALL_CAP}. The `done` tool does not count against the budget. Pace yourself — broad sweep of the baseline first (claims/done/, the audit log, the graph), then focused pivots on the highest-signal leads.

Use forensic language freely — name malware families, threat actor TTPs, MITRE techniques as appropriate. Your output goes through the same validator as the deterministic agents; the validator catches lies, not vocabulary.
"""


# ───────────────────────────────────────────────────────────────────────────
# Helpers
# ───────────────────────────────────────────────────────────────────────────

def _truncate(s: str, n: int = _TOOL_RESULT_MAX_BYTES) -> str:
    if not isinstance(s, str):
        s = str(s)
    if len(s) <= n:
        return s
    return s[:n] + f"\n…[truncated; original was {len(s)} bytes]"


def _safe_under_evidence(path: str) -> bool:
    """Defense-in-depth: Chisel enforces --root confinement, but reject obvious
    escapes here too so the LLM sees a clean error."""
    try:
        resolved = Path(path).resolve()
    except (OSError, ValueError):
        return False
    return str(resolved).startswith(str(EVIDENCE_ROOT.resolve()))


def _stable_id_str(s: str) -> str:
    """Match validator's stable-id scheme so the LLM can compose graph IDs."""
    return str(uuid.uuid5(uuid.NAMESPACE_OID, s))


# ───────────────────────────────────────────────────────────────────────────
# Tool implementations — all chisel-routed where they touch the FS
# ───────────────────────────────────────────────────────────────────────────

def _tool_list_dir(chisel: Chisel, args: dict) -> str:
    path = args.get("path", "")
    if not _safe_under_evidence(path):
        return _PATH_REFUSAL_MSG.format(evidence_root=EVIDENCE_ROOT)
    try:
        out = chisel.shell("ls", ["-la", path])
        return _truncate(out)
    except Exception:
        try:
            out = chisel.shell("ls", ["-1", path])
            return _truncate(out)
        except Exception as e:
            return f"error: {e}"


def _tool_read_file(chisel: Chisel, args: dict) -> str:
    path = args.get("path", "")
    max_bytes = int(args.get("max_bytes", _TOOL_RESULT_MAX_BYTES))
    max_bytes = max(1, min(max_bytes, _TOOL_RESULT_MAX_BYTES))
    if not _safe_under_evidence(path):
        return _PATH_REFUSAL_MSG.format(evidence_root=EVIDENCE_ROOT)
    try:
        out = chisel.shell("head", ["-c", str(max_bytes), path])
        return _truncate(out, max_bytes)
    except Exception as e:
        return f"error: {e}"


def _tool_grep(chisel: Chisel, args: dict) -> str:
    pattern   = args.get("pattern", "")
    path      = args.get("path", "")
    recursive = bool(args.get("recursive", True))
    if not pattern:
        return "refused: pattern is required"
    if not _safe_under_evidence(path):
        return _PATH_REFUSAL_MSG.format(evidence_root=EVIDENCE_ROOT)
    flags = "-rE" if recursive else "-E"
    try:
        out = chisel.shell("grep", [flags, pattern, path])
        return _truncate(out)
    except Exception as e:
        msg = str(e)
        if "exit=1" in msg:
            return "(no matches)"
        return f"error: {msg}"


def _tool_find_files(chisel: Chisel, args: dict) -> str:
    dir_  = args.get("dir", "")
    glob_ = args.get("name_glob", "")
    if not _safe_under_evidence(dir_):
        return _PATH_REFUSAL_MSG.format(evidence_root=EVIDENCE_ROOT)
    if not glob_:
        return "refused: name_glob is required"
    try:
        out = chisel.shell("find", [dir_, "-name", glob_])
        return _truncate(out) if out.strip() else "(no matches)"
    except Exception as e:
        return f"error: {e}"


def _tool_exec_forensic_tool(chisel: Chisel, args: dict) -> str:
    """Run an allowlisted forensic tool via Chisel. Chisel's server-side
    WHITELIST is the source of truth for which tools / argument patterns are
    permitted. Returns stdout (or stderr on non-zero exit), truncated."""
    tool  = args.get("tool", "")
    targs = list(args.get("args", []))
    if not tool:
        return "refused: tool is required"
    try:
        result = chisel.exec_tool(tool, targs, agent_name=_AGENT_NAME)
        # exec_tool returns stdout as the parsed JSON / text from chisel's
        # shell_exec wrapper. Surface stderr if stdout is empty.
        if isinstance(result, dict):
            out = result.get("stdout") or result.get("stderr") or ""
            exit_code = result.get("exit_code", 0)
            elapsed = result.get("elapsed_ms", "?")
            prefix = f"[exit={exit_code} elapsed_ms={elapsed}]\n"
            return prefix + _truncate(out)
        return _truncate(str(result))
    except Exception as e:
        return f"error: {e}"


async def _tool_query_graph_async(args: dict) -> str:
    """Read-only Cognee graph lookup by natural entity ID (e.g.
    'process:win7-32-nromanoff:1328'). Returns the node's attribute dict as
    JSON, or '(not found)'. Async because we're already inside the SDK's
    event loop when the tool is invoked."""
    entity_id = args.get("entity_id", "")
    if not entity_id:
        return "refused: entity_id is required (format like 'process:<host>:<pid>')"
    node_id = _stable_id_str(entity_id)
    try:
        from cognee.infrastructure.databases.unified import get_unified_engine  # noqa: PLC0415
    except ImportError:
        return "error: cognee not importable; graph queries unavailable"
    try:
        unified = await get_unified_engine()
        node = await unified.graph.get_node(node_id)
    except Exception as e:
        return f"error: {e}"
    if not node:
        return f"(not found in graph: {entity_id})"
    try:
        return json.dumps(dict(node), default=str, indent=2)
    except Exception:
        return repr(node)


def _validate_claim_filename(name: str) -> tuple[bool, str]:
    if not name:
        return False, "filename is required"
    if not name.startswith("analyst_"):
        return False, "filename must start with 'analyst_' (so the orchestrator can identify analyst claims)"
    if not name.endswith(".md"):
        return False, "filename must end with '.md'"
    if "/" in name or "\\" in name:
        return False, "filename must not contain path separators"
    return True, ""


def _validate_claim_content(content: str) -> tuple[bool, str]:
    if not content or "---" not in content:
        return False, "claim must begin with YAML frontmatter delimited by '---' lines"
    parts = content.split("---", 2)
    if len(parts) < 3:
        return False, "claim must have two '---' delimiters (open + close of YAML frontmatter), then a Markdown body"
    raw_fm = parts[1].strip()
    body   = parts[2].strip()
    if not body:
        return False, "claim body (after closing '---') must not be empty"
    try:
        fm = yaml.safe_load(raw_fm)
    except yaml.YAMLError as e:
        return False, f"YAML frontmatter parse error: {e}"
    if not isinstance(fm, dict):
        return False, "YAML frontmatter must parse to a mapping"
    required = ("claim_id", "status", "host", "entities", "evidence_refs")
    missing  = [k for k in required if k not in fm]
    if missing:
        return False, f"frontmatter missing required fields: {missing}"
    if not isinstance(fm.get("entities"), list) or not fm["entities"]:
        return False, "frontmatter 'entities' must be a non-empty list"
    if not isinstance(fm.get("evidence_refs"), list) or not fm["evidence_refs"]:
        return False, "frontmatter 'evidence_refs' must be a non-empty list"
    return True, ""


def _tool_write_claim(chisel: Chisel, args: dict) -> str:
    """Validate frontmatter format then write the claim to claims/todo/.
    The orchestrator's watcher will pick it up and run it through the
    validator (which spot-checks against the graph and the evidence FS).

    Format errors are returned to the LLM so it can retry. Validator
    rejections happen later (asynchronously) and land in claims/rejected/
    — the LLM can read those to understand why."""
    name    = args.get("filename", "")
    content = args.get("content", "")
    ok, msg = _validate_claim_filename(name)
    if not ok:
        return f"refused: {msg}"
    ok, msg = _validate_claim_content(content)
    if not ok:
        return f"refused: {msg}"
    target_path = str(CLAIMS_TODO / name)
    try:
        chisel.call("create_directory", {"path": str(CLAIMS_TODO)})
        chisel.call("write_file", {"path": target_path, "content": content})
        return f"claim written → {target_path} (will be validated asynchronously; check {CLAIMS_REJECTED} for any rejections)"
    except Exception as e:
        return f"error: {e}"


# ───────────────────────────────────────────────────────────────────────────
# Initial user message — case context + baseline claim summary
# ───────────────────────────────────────────────────────────────────────────

def _baseline_summary(chisel: Chisel) -> str:
    """Count claims by agent prefix in claims/done/. Gives the LLM a quick
    read on what the baseline pipeline produced without burning tool calls."""
    try:
        listing = chisel.shell("ls", ["-1", str(CLAIMS_DONE)])
    except Exception:
        return "(could not enumerate claims/done/)"
    counts: dict[str, int] = {}
    for line in listing.splitlines():
        line = line.strip()
        if not line.endswith(".md"):
            continue
        prefix = line.split("_", 1)[0]
        counts[prefix] = counts.get(prefix, 0) + 1
    if not counts:
        return "(no validated claims found in claims/done/ — baseline pipeline produced nothing)"
    return ", ".join(
        f"`{prefix}` ({n})" for prefix, n in sorted(counts.items(), key=lambda kv: -kv[1])
    )


def _initial_user_message(chisel: Chisel) -> str:
    case_id = os.environ.get("FINDEVIL_CASE_ID", "(unknown)")
    return (
        f"You are reviewing case `{case_id}`.\n\n"
        f"Paths you will use most:\n"
        f"  - Evidence root: {EVIDENCE_ROOT}\n"
        f"  - Validated claims (baseline output): {CLAIMS_DONE}\n"
        f"  - Pending validation: {CLAIMS_TODO}\n"
        f"  - Rejected by validator: {CLAIMS_REJECTED}\n"
        f"  - Forensic-tool audit log: {AUDIT_DIR} (chisel_exec_<UTCDATE>.jsonl)\n\n"
        f"Baseline claim count by agent: {_baseline_summary(chisel)}\n\n"
        "Standard opening moves a human analyst would make:\n"
        "  1. `list_dir` claims/done/ to see what the baseline emitted\n"
        "  2. `read_file` the highest-confidence / most anomalous claims\n"
        "  3. `query_graph` for entities the claims reference (use IDs like "
        "`process:<host>:<pid>` or `registry_key:<host>:<key>`)\n"
        "  4. Identify ≥1 lead that warrants deeper investigation — a malfind "
        "PID with bad parent, a registry persistence value pointing at a "
        "user-writable path, a 4625 burst clustered in time, a service install "
        "with a suspicious ImagePath\n"
        "  5. Pivot with `exec_forensic_tool` — e.g. re-run `vol windows.handles "
        "--pid <X>`, dump a VAD, parse a specific registry key, query EVTX for "
        "a specific record ID\n"
        "  6. Emit `write_claim` for each finding that survives your scrutiny — "
        "use the confidence rubric in ref_SKILLS.md\n"
        "  7. Call `done` when you've exhausted the interesting leads or your "
        "budget gets tight\n\n"
        "Be exploratory. The validator catches lies — it does not gate "
        "exploration. Single-source findings are fine at the right confidence; "
        "let the deterministic correlator find the partner."
    )


# ───────────────────────────────────────────────────────────────────────────
# Agentic loop — Claude Agent SDK
# ───────────────────────────────────────────────────────────────────────────

async def run_agentic_loop(chisel: Chisel, model: str = _DEFAULT_MODEL) -> tuple[str | None, list[dict]]:
    """Run the LLM agentic loop. Returns (summary_markdown_or_None, tool_trail).
    Summary is the content of `done(summary)`; None on catastrophic SDK failure.
    Claims are written via `write_claim()` directly into claims/todo/."""
    try:
        from claude_agent_sdk import (  # noqa: PLC0415
            ClaudeAgentOptions, CLINotFoundError, ProcessError,
            ResultMessage, AssistantMessage, TextBlock,
            create_sdk_mcp_server, query, tool,
        )
    except ImportError:
        print("ℹ️  claude-agent-sdk not installed — skipping forensic_analyst pass.")
        return None, []

    state: dict = {
        "calls":      0,
        "summary":    None,
        "final_text": None,
        "trail":      [],
    }

    def _record(tool_short_name: str, args: dict, result_text: str) -> None:
        n = len(state["trail"]) + 1
        is_error = result_text.startswith(("error:", "refused:"))
        if is_error:
            preview = result_text.replace("\n", " ⏎ ")
        else:
            preview = result_text[:280].replace("\n", " ⏎ ")
        state["trail"].append({
            "n":              n,
            "tool":           tool_short_name,
            "args_summary":   json.dumps(args, default=str)[:120],
            "result_preview": preview,
        })
        print(f"  [#{n:03d}] {tool_short_name}({json.dumps(args, default=str)[:80]}) "
              f"→ {result_text[:80].replace(chr(10), ' ')}…", flush=True)

    def _result(text: str) -> dict:
        return {"content": [{"type": "text", "text": text}]}

    def _budget_refusal() -> dict:
        return _result(
            f"refused: tool-call budget ({_TOOL_CALL_CAP}) exhausted. "
            "Call done(summary) now with whatever you have."
        )

    def _wrap_up_reminder() -> str:
        return (
            f" [system: {_TOOL_CALL_CAP - state['calls']} call(s) left in your budget; "
            f"wrap up and call done() soon]"
        )

    def _maybe_reminder(out: str) -> str:
        if state["calls"] >= _WRAP_UP_THRESHOLD:
            return out + _wrap_up_reminder()
        return out

    @tool("list_dir", "List a directory under the evidence root (returns `ls -la` output).",
          {"path": str})
    async def t_list_dir(args):
        if state["calls"] >= _TOOL_CALL_CAP:
            return _budget_refusal()
        state["calls"] += 1
        out = _tool_list_dir(chisel, args)
        _record("list_dir", args, out)
        return _result(_maybe_reminder(out))

    @tool("read_file",
          "Read up to max_bytes from the start of a file under the evidence root. "
          f"Capped at {_TOOL_RESULT_MAX_BYTES} bytes regardless of max_bytes.",
          {"path": str, "max_bytes": int})
    async def t_read_file(args):
        if state["calls"] >= _TOOL_CALL_CAP:
            return _budget_refusal()
        state["calls"] += 1
        out = _tool_read_file(chisel, args)
        _record("read_file", args, out)
        return _result(_maybe_reminder(out))

    @tool("grep",
          "Search files under the evidence root for an extended-regex pattern. "
          "If recursive=true, searches a directory; if false, expects a single file.",
          {"pattern": str, "path": str, "recursive": bool})
    async def t_grep(args):
        if state["calls"] >= _TOOL_CALL_CAP:
            return _budget_refusal()
        state["calls"] += 1
        out = _tool_grep(chisel, args)
        _record("grep", args, out)
        return _result(_maybe_reminder(out))

    @tool("find_files",
          "Find files by name glob under a directory (uses `find <dir> -name <glob>`).",
          {"dir": str, "name_glob": str})
    async def t_find_files(args):
        if state["calls"] >= _TOOL_CALL_CAP:
            return _budget_refusal()
        state["calls"] += 1
        out = _tool_find_files(chisel, args)
        _record("find_files", args, out)
        return _result(_maybe_reminder(out))

    @tool("exec_forensic_tool",
          "Run an allowlisted forensic tool via Chisel. The Chisel server's "
          "whitelist enforces which tools/args are permitted. Examples: "
          "tool='vol', args=['-f', '<dump>', '-r', 'json', 'windows.handles', '--pid', '1328']; "
          "tool='dotnet', args=['/opt/zimmermantools/EvtxeCmd/EvtxECmd.dll', '-f', '<evtx>']; "
          "tool='fls', args=['-r', '-o', '<offset>', '<image>']. Each invocation is logged "
          "to evidence/audit/chisel_exec_<DATE>.jsonl.",
          {"tool": str, "args": list})
    async def t_exec_forensic_tool(args):
        if state["calls"] >= _TOOL_CALL_CAP:
            return _budget_refusal()
        state["calls"] += 1
        out = _tool_exec_forensic_tool(chisel, args)
        _record("exec_forensic_tool", args, out)
        return _result(_maybe_reminder(out))

    @tool("query_graph",
          "Look up a single node in the Cognee case graph by its NATURAL entity ID. "
          "Format: '<type>:<host>:<key>' — e.g. 'process:win7-32-nromanoff:1328', "
          "'registry_key:win7-32-nromanoff:SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\bad', "
          "'event:win7-32-nromanoff:Security:4112233'. Returns the node's attribute "
          "dict as JSON, or '(not found)'. Read-only.",
          {"entity_id": str})
    async def t_query_graph(args):
        if state["calls"] >= _TOOL_CALL_CAP:
            return _budget_refusal()
        state["calls"] += 1
        out = await _tool_query_graph_async(args)
        _record("query_graph", args, out)
        return _result(_maybe_reminder(out))

    @tool("write_claim",
          "Emit a forensic claim. Filename must start with 'analyst_' and end with '.md'. "
          "Content must be YAML frontmatter (delimited by '---') with required fields "
          "(claim_id, status: new, host, entities, evidence_refs) then a Markdown body. "
          "The orchestrator validator will spot-check the claim asynchronously; rejections "
          "land in claims/rejected/ with the reason in the body — read those to learn.",
          {"filename": str, "content": str})
    async def t_write_claim(args):
        if state["calls"] >= _TOOL_CALL_CAP:
            return _budget_refusal()
        state["calls"] += 1
        out = _tool_write_claim(chisel, args)
        _record("write_claim", args, out)
        return _result(_maybe_reminder(out))

    @tool("done",
          "Signal that you've finished. Optional `summary` (markdown) is appended to the "
          "case report as the 'Analyst Notes' section — use it for analyst commentary, "
          "open questions, and cross-cutting observations that don't fit a single claim.",
          {"summary": str})
    async def t_done(args):
        state["summary"] = (args.get("summary") or "").strip() or None
        return _result("acknowledged; the loop will terminate.")

    mcp_server = create_sdk_mcp_server(
        name=_MCP_SERVER_NAME,
        tools=[
            t_list_dir, t_read_file, t_grep, t_find_files,
            t_exec_forensic_tool, t_query_graph, t_write_claim, t_done,
        ],
    )

    prefixed = lambda short: f"mcp__{_MCP_SERVER_NAME}__{short}"
    allowed = [prefixed(n) for n in (
        "list_dir", "read_file", "grep", "find_files",
        "exec_forensic_tool", "query_graph", "write_claim", "done",
    )]

    options = ClaudeAgentOptions(
        model=model,
        system_prompt=_SYSTEM_PROMPT,
        mcp_servers={_MCP_SERVER_NAME: mcp_server},
        allowed_tools=allowed,
        tools=[],
        permission_mode="bypassPermissions",
        max_turns=400,
    )

    gen = query(prompt=_initial_user_message(chisel), options=options)
    try:
        async for message in gen:
            if isinstance(message, AssistantMessage):
                texts = [b.text for b in message.content if isinstance(b, TextBlock)]
                if texts:
                    state["final_text"] = "\n".join(texts).strip() or state["final_text"]
            if isinstance(message, ResultMessage):
                break
    except CLINotFoundError as e:
        print(f"ℹ️  Claude Code CLI not found ({e}) — skipping forensic_analyst pass.")
        return None, state["trail"]
    except ProcessError as e:
        print(f"⚠️  Claude SDK process error: {e} — skipping forensic_analyst pass.")
        return None, state["trail"]
    except Exception as e:
        print(f"⚠️  Unexpected SDK error after {state['calls']} tool call(s): {e!r}")
        return None, state["trail"]
    finally:
        try:
            await gen.aclose()
        except Exception:
            pass

    return state["summary"] or state["final_text"], state["trail"]


# ───────────────────────────────────────────────────────────────────────────
# Main entry point
# ───────────────────────────────────────────────────────────────────────────

async def run_forensic_analyst() -> int:
    """Standalone + orchestrator entry point. Returns 0 on success (SDK ran or
    skipped cleanly), non-zero on hard failure."""
    print("🧠 Forensic Analyst Agent (agentic loop) starting...")
    print(f"   model={_DEFAULT_MODEL}  tool_budget={_TOOL_CALL_CAP}")
    print(f"   SKILLS.md     loaded: {len(_SKILLS_MD):,} chars")
    print(f"   ref_SKILLS.md loaded: {len(_REF_SKILLS_MD):,} chars")

    chisel = Chisel(CHISEL_URL, CHISEL_SECRET)
    chisel.connect()
    print(f"🔒 Chisel session → {chisel.endpoint} (sid={chisel.session_id[:8]}…)")

    CLAIMS_TODO.mkdir(parents=True, exist_ok=True)

    summary, trail = await run_agentic_loop(chisel)

    if summary is None and not trail:
        print("ℹ️  Forensic analyst pass skipped (SDK / CLI unavailable).")
        return 0

    print(f"✅ Forensic analyst pass complete: {len(trail)} tool call(s).")
    # Persist a record of what the analyst did — for operator review and as
    # the source of the report's "Analyst Notes" section.
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    case_id = os.environ.get("FINDEVIL_CASE_ID", "unknown")
    log_dir = AUDIT_DIR / case_id
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"forensic_analyst_{ts}.json"
    log_path.write_text(json.dumps({
        "case_id":     case_id,
        "timestamp":   datetime.now(UTC).isoformat(),
        "model":       _DEFAULT_MODEL,
        "tool_budget": _TOOL_CALL_CAP,
        "tool_calls":  len(trail),
        "trail":       trail,
        "summary":     summary,
    }, default=str, indent=2), encoding="utf-8")
    print(f"   trail+summary → {log_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(run_forensic_analyst()))
