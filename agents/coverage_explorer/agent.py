"""
Coverage Explorer Agent — agentic-loop meta-reviewer for the FindEvil pipeline.

Standalone CLI:  python -m agents.coverage_explorer.agent
Orchestrator:    spawned as subprocess after report_agent (non-fatal on failure).

This agent gives an LLM a small set of read-only Chisel-routed tools and lets
it explore the case freely to identify TOOL/CAPABILITY COVERAGE gaps. It does
NOT make forensic conclusions about the case — only meta-observations about
what the pipeline did vs. could have done.

Architecture:
  1. Pre-context (deterministic): hardcoded list of 7 documented audit
     exceptions injected into the LLM's first user message — tools that
     bypass Chisel by design and won't appear in the audit log. Without this,
     the LLM might wrongly conclude "MFTECmd was never run" because it isn't
     in chisel_exec_*.jsonl.

  2. Agentic loop (LLM-driven, capped at 50 tool calls): standard Anthropic
     tool-use protocol. The LLM decides what to read, grep, list, or query.
     At call N=45 a system reminder is injected ("5 calls left"); at N=50 the
     non-`done` tools refuse and force the LLM to call `done()` with whatever
     it has.

  3. Output validation (deterministic): forbidden-phrase regex narrowly
     targets forensic-conclusion language. Sentences matching are replaced
     with [REDACTED]. Case-specific numbers and tool/agent references pass
     through unchanged.

  4. Tool-call audit trail appended to the report so the operator can spot-
     check that observations are grounded in actual chisel calls.

  5. Fallback when ANTHROPIC_API_KEY unset: minimal "what ran" dump (audit
     log counts only, no prescriptive recommendations). The orchestrator
     always produces SOME coverage review.
"""

import asyncio
import json
import os
import re
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from agents._chisel import Chisel

# Claude Agent SDK — the LLM-driven path uses Claude Code's OAuth credentials
# (no ANTHROPIC_API_KEY needed). Imported lazily inside run_agentic_loop()
# so the deterministic fallback still works on systems where the SDK isn't
# installed or `claude` CLI isn't on PATH.

# ───────────────────────────────────────────────────────────────────────────
# Constants & paths
# ───────────────────────────────────────────────────────────────────────────

EVIDENCE_ROOT = Path(os.environ.get(
    "EVIDENCE_ROOT", "/home/sansforensics/dfirskills2/evidence",
))
AUDIT_DIR    = EVIDENCE_ROOT / "audit"
CLAIMS_DONE  = EVIDENCE_ROOT / "claims/done"
REPORTS_ROOT = EVIDENCE_ROOT.parent / "reports"

CHISEL_URL    = os.environ.get("CHISEL_URL", "http://127.0.0.1:3000")
CHISEL_SECRET = os.environ["CHISEL_SECRET"]

_AGENT_NAME    = "coverage-explorer"
_DEFAULT_MODEL = "claude-sonnet-4-6"

# Hard cap on chisel-touching tool calls per LLM exploration. The `done` tool
# does NOT count against this. At _WRAP_UP_THRESHOLD a reminder is injected.
_TOOL_CALL_CAP        = 50
_WRAP_UP_THRESHOLD    = 45

# Per-tool-result truncation. Keeps token usage bounded if the LLM reads a
# large file or runs a wide grep. The LLM can request more by reading from a
# different offset (head -c with different N).
_TOOL_RESULT_MAX_BYTES = 8192

# Documented audit exceptions — tools that BYPASS Chisel because their
# binaries / rule files live outside chisel's --root. These do NOT appear in
# evidence/audit/chisel_exec_*.jsonl by design. The LLM must be aware of
# them so it doesn't false-claim "X was never run" when it just isn't logged.
_AUDIT_EXCEPTIONS = [
    {"tool": "EvtxECmd",             "agent_module": "evtx_agent"},
    {"tool": "RECmd",                "agent_module": "registry_agent"},
    {"tool": "AppCompatCacheParser", "agent_module": "registry_agent"},
    {"tool": "AmcacheParser",        "agent_module": "registry_agent"},
    {"tool": "MFTECmd",              "agent_module": "mft_agent"},
    {"tool": "RBCmd",                "agent_module": "mft_agent"},
    {"tool": "yara/yarac",           "agent_module": "memory_agent"},
]

# Multi-line refusal returned when a tool is called with a path outside the
# Chisel --root. Includes useful starting points so the LLM doesn't have to
# burn another tool call to discover where it CAN look.
_PATH_REFUSAL_MSG = f"""refused: path must be under {{evidence_root}}. Useful starting points:
  {{evidence_root}}/audit/        — chisel audit logs (chisel_exec_*.jsonl)
  {{evidence_root}}/claims/done/  — validated claims emitted by all agents
  {{evidence_root}}/extracted/    — extracted artifacts (per-host subdirs)
  {{evidence_root}}/dumps/        — VAD memory dumps (per-host subdirs)
  {{evidence_root}}/new/          — incoming raw evidence (E01, .001 dumps, etc.)
  {{evidence_root}}/baselines/    — baseline pslist images for memory diff"""

# Capability-discovery allow-list (client-side). The LLM's `query_capability`
# tool can only invoke these (tool, args) patterns. Chisel's server-side
# allowlist is the second line of defense.
_CAPABILITY_DISCOVERY_ALLOWED = [
    ("vol",            lambda a: a in (["--help"], ["-h"])),
    ("log2timeline.py", lambda a: a in (
        ["--help"],
        ["--parsers", "list"],
        ["--filters", "list"],
        ["--formatters", "list"],
    )),
    ("psort.py",       lambda a: a in (["--help"], ["--output-list"])),
    ("pinfo.py",       lambda a: a == ["--help"] or
                                  (len(a) >= 2 and a[0] == "--info")),
]

# Forbidden-phrase regex — strict on forensic-conclusion language only.
# Case-specific numbers and tool/agent/path references are explicitly allowed.
_FORBIDDEN_PHRASE_RE = re.compile(
    r"\b("
    # named threat actors / malware families in declarative voice
    r"(?:cobalt strike|meterpreter|mimikatz|emotet|trickbot|lockbit|conti|"
    r"ryuk|sliver|brute ?ratel|qakbot|icedid)|"
    r"\bapt\d+\b|\bfin\d+\b|"
    # explicit forensic-conclusion phrasings
    r"evidence of (?:compromise|attack|intrusion)|"
    r"signs? of (?:compromise|attack|intrusion)|"
    r"indicates? (?:compromise|attack|persistence|lateral movement|c2|backdoor)|"
    r"this (?:host|case|machine|endpoint) (?:is|was|has been) "
    r"(?:compromised|infected|backdoored)|"
    r"the attacker (?:did|established|installed|ran|executed|used|deployed)|"
    r"confirmed (?:c2|command-and-control|backdoor|persistence|lateral)"
    r")\b",
    re.IGNORECASE,
)


# Tool schemas are defined inside run_agentic_loop() as @tool-decorated async
# closures so they can capture the per-run Chisel client + state dict. See the
# Claude Agent SDK section below.


_SYSTEM_PROMPT = """You are a coverage reviewer for a DFIR pipeline. The pipeline ran on a forensic case; many forensic agents emitted claims into the validated-claims directory. Your job is to identify TOOL/CAPABILITY COVERAGE gaps — things the pipeline did not do that it could have, given the tools available.

ALL paths you pass to tools must be ABSOLUTE filesystem paths under the evidence root. The exact path strings will be given in the kickoff user message (Evidence root, Audit log dir, Claims dir). Do NOT use shorthand like "/evidence" — that does not resolve to anything.

You have read-only tools to:
  - list directories under the evidence root
  - read bounded chunks of files (audit log, claim files, manifests)
  - grep across files
  - find files by glob
  - query forensic-tool capabilities (vol --help, log2timeline.py --parsers list, ...)
  - call done(report_markdown) when you're confident you have enough to write

Your tool-call budget is 50. Use it to investigate, not to inventory. Prefer reading samples over reading whole files.

Out of scope (do NOT recommend):
  - Anything in /opt/zimmermantools/ (EZ Tools — bypass the audit log)
  - icat usage patterns (also bypasses audit log)
  These tools' invocations don't appear in chisel_exec_*.jsonl by design.

In scope:
  - Volatility 3 plugins not run (compare audit log to vol --help)
  - Plaso parsers / formatters / output modules not exercised
  - Evidence artifacts on disk that no agent processed
  - Mismatches: e.g., 123 .pf files extracted but only N prefetch claims emitted
  - Sleuth-kit usage gaps
  - Coverage of the audit log itself (which agents are silent? which tools are only ever called once vs. many times?)

CRITICAL — about language:
  - You make NO forensic conclusions about the CASE. You do not name malware families, threat actors, or attack patterns. You do not say "this looks like X", "evidence of Y", "the attacker did Z".
  - Meta-observations using case-specific numbers ARE fine and useful:
      ✅ "memory_agent emitted 1 claim from 1 dump"
      ✅ "the audit log shows no log2timeline run against the staged `$J` file despite mft_agent emitting a USN claim — worth checking why"
      ❌ "this is a Cobalt Strike intrusion"
      ❌ "evidence of compromise on this host"
  You speak about the PIPELINE, not the EVIDENCE.

Output format: a markdown report. Structure is up to you, but it should be SCANNABLE — operator should be able to read it in under 2 minutes and identify the top 3-5 things worth doing differently in the next pipeline iteration.

When ready, call done(report_markdown) with the full report. Do not put the report in your final assistant message — only via the done tool.
"""


def _initial_user_message(chisel: Chisel) -> str:
    """Build the kickoff user message — the LLM's primer with platform facts
    it can't discover on its own. Includes a pre-computed audit-log summary so
    the LLM doesn't burn budget re-grepping the same audit log slice ~10 times
    (observed pattern in the first live run).

    All filesystem access for the pre-computed summary routes through Chisel
    (via _fallback_audit_summary / _fallback_claim_counts) — same allowlist +
    audit-log guarantees as every other tool call in this agent."""
    audit_block = "\n".join(
        f"  - {ex['tool']} (used by {ex['agent_module']})"
        for ex in _AUDIT_EXCEPTIONS
    )

    # Pre-computed audit + claim summaries. Reuses the same helpers the
    # deterministic-fallback report uses, so the LLM gets the same baseline
    # facts without having to discover them via grep.
    audit = _fallback_audit_summary(chisel)
    claims = _fallback_claim_counts(chisel)

    audit_summary_lines: list[str] = []
    audit_summary_lines.append("## Audit log summary (pre-computed across all chisel_exec_*.jsonl)")
    audit_summary_lines.append(f"- Total invocations: {audit['total']}")
    if audit["by_agent"]:
        agents_str = ", ".join(
            f"`{a}` ({n})" for a, n in sorted(audit["by_agent"].items(), key=lambda kv: -kv[1])
        )
        audit_summary_lines.append(f"- By agent: {agents_str}")
    if audit["by_tool"]:
        tools_str = ", ".join(
            f"`{t}` ({n})" for t, n in sorted(audit["by_tool"].items(), key=lambda kv: -kv[1])
        )
        audit_summary_lines.append(f"- By tool: {tools_str}")
    if audit["vol_plugins"]:
        audit_summary_lines.append(
            f"- Volatility plugins seen ({len(audit['vol_plugins'])}): "
            + ", ".join(f"`{p}`" for p in audit["vol_plugins"])
        )
    audit_summary_lines.append(
        f"- Plaso (`log2timeline.py` / `psort.py`) invoked: "
        f"{'yes' if audit['plaso_seen'] else 'no'}"
    )

    if claims:
        claims_summary = ", ".join(
            f"`{prefix}` ({n})" for prefix, n in sorted(claims.items(), key=lambda kv: -kv[1])
        )
        audit_summary_lines.append(f"- Claims emitted by agent: {claims_summary}")

    audit_summary_lines.append("")
    audit_summary_lines.append(
        "_You can still grep / read the raw audit log files for details, but "
        "use this summary as your starting point — it answers the most common "
        "coverage questions without burning tool calls._"
    )
    audit_summary = "\n".join(audit_summary_lines)

    return (
        "Please review the pipeline's tool/capability coverage on this case.\n\n"
        f"Evidence root: {EVIDENCE_ROOT}\n"
        f"Audit log dir: {AUDIT_DIR} (one chisel_exec_<UTCDATE>.jsonl per day)\n"
        f"Claims dir:    {CLAIMS_DONE}\n\n"
        f"All paths you pass to tools must be ABSOLUTE filesystem paths under "
        f"`{EVIDENCE_ROOT}`. The pipeline never extracts artifacts outside that "
        f"tree. Do not use shorthand like `/evidence` — use the full path above.\n\n"
        f"{audit_summary}\n\n"
        "Known platform context — these tools BYPASS the chisel audit log by "
        "design. If you don't see them in chisel_exec_*.jsonl, that is normal "
        "and expected. Do NOT recommend anything about them:\n"
        f"{audit_block}\n\n"
        f"Start from the summary above. Use your tools to dig into the SPECIFIC "
        f"gaps it suggests — e.g., `query_capability(vol, [--help])` to see "
        f"plugins not invoked, "
        f"`list_dir({EVIDENCE_ROOT}/extracted/<host>/)` to see what artifacts "
        f"exist, etc. When you've identified meaningful coverage gaps, call "
        f"done(report_markdown)."
    )


# ───────────────────────────────────────────────────────────────────────────
# Tool dispatch — all chisel-routed
# ───────────────────────────────────────────────────────────────────────────

def _truncate(s: str, n: int = _TOOL_RESULT_MAX_BYTES) -> str:
    """Trim string to n bytes, append a marker if truncated."""
    if not isinstance(s, str):
        s = str(s)
    if len(s) <= n:
        return s
    return s[:n] + f"\n…[truncated; original was {len(s)} bytes]"


def _safe_under_evidence(path: str) -> bool:
    """Defense-in-depth: chisel enforces --root confinement, but reject
    obvious escapes here too so the LLM gets a clean error."""
    try:
        resolved = Path(path).resolve()
    except (OSError, ValueError):
        return False
    return str(resolved).startswith(str(EVIDENCE_ROOT.resolve()))


def _tool_list_dir(chisel: Chisel, args: dict) -> str:
    path = args.get("path", "")
    if not _safe_under_evidence(path):
        return _PATH_REFUSAL_MSG.format(evidence_root=EVIDENCE_ROOT)
    # Fallback chain: ls -la is the most informative but its output may exceed
    # Chisel's stdout cap on very large dirs (the win7-32 corpus has 227 files
    # in claims/done — ~25KB which trips the failure). Degrade gracefully:
    #   1. ls -la <path>           — full info
    #   2. ls -1 <path>            — names-only (smaller output)
    #   3. ls -1 <path> | head -100 — capped to 100 names if still too big
    # Whichever succeeds first wins. If all fail, return the chisel error so
    # the LLM (and operator) sees the underlying cause.
    last_err: str = ""
    for cmd, cmd_args in (
        ("ls", ["-la", path]),
        ("ls", ["-1", path]),
    ):
        try:
            out = chisel.shell(cmd, cmd_args)
            return _truncate(out)
        except Exception as e:
            last_err = str(e)
            continue
    # Final attempt: ls -1 piped through head -100 via a single shell-style
    # invocation. Chisel doesn't pipe, so emulate by capturing then truncating.
    try:
        out = chisel.shell("ls", ["-1", path])
        capped = "\n".join(out.splitlines()[:100])
        if len(out.splitlines()) > 100:
            capped += f"\n…[capped at 100 of {len(out.splitlines())} entries]"
        return capped
    except Exception as e:
        return f"error (all ls fallbacks failed): {e} | earlier: {last_err}"


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
    pattern = args.get("pattern", "")
    path    = args.get("path", "")
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
        # grep exits non-zero on no match — chisel.shell raises. Return a clean
        # tool result so the LLM sees "no matches" rather than a stack trace.
        msg = str(e)
        if "exit=1" in msg:
            return "(no matches)"
        return f"error: {msg}"


def _tool_find_files(chisel: Chisel, args: dict) -> str:
    dir_   = args.get("dir", "")
    glob_  = args.get("name_glob", "")
    if not _safe_under_evidence(dir_):
        return _PATH_REFUSAL_MSG.format(evidence_root=EVIDENCE_ROOT)
    if not glob_:
        return "refused: name_glob is required"
    try:
        out = chisel.shell("find", [dir_, "-name", glob_])
        return _truncate(out) if out.strip() else "(no matches)"
    except Exception as e:
        return f"error: {e}"


def _tool_query_capability(chisel: Chisel, args: dict) -> str:
    tool = args.get("tool", "")
    targs = list(args.get("args", []))
    # Client-side allow-list check
    allowed = False
    for allowed_tool, matcher in _CAPABILITY_DISCOVERY_ALLOWED:
        if tool == allowed_tool and matcher(targs):
            allowed = True
            break
    if not allowed:
        return (
            f"refused: only capability-discovery args allowed. "
            f"Allowed: vol --help; log2timeline.py --help|--parsers list|"
            f"--filters list|--formatters list; psort.py --help|--output-list; "
            f"pinfo.py --help|--info <storage>"
        )
    try:
        result = chisel.exec_tool(tool, targs, agent_name=_AGENT_NAME)
        out = result["stdout"] or result["stderr"]
        return _truncate(out)
    except Exception as e:
        return f"error: {e}"


# ───────────────────────────────────────────────────────────────────────────
# Agentic loop — Claude Agent SDK (uses Claude Code OAuth, no API key required)
# ───────────────────────────────────────────────────────────────────────────

# Server name used to namespace our MCP tools. The LLM sees them as
# `mcp__<server>__<tool>`. Short name keeps prompt + audit trail readable.
_MCP_SERVER_NAME = "coverage"


async def run_agentic_loop(chisel: Chisel, model: str = _DEFAULT_MODEL) -> tuple[str | None, list[dict]]:
    """Run the LLM agentic loop via the Claude Agent SDK.

    Returns (report_markdown_or_None, tool_call_trail). The trail is a list of
    {n, tool, args_summary, result_preview} dicts for rendering the audit-trail
    appendix.

    Returns (None, trail) on any catastrophic failure: SDK not installed,
    Claude Code CLI missing or unauthenticated, or any other unexpected error.
    Caller falls back to the deterministic dump.
    """
    # Lazy import — keeps the deterministic-fallback path working on systems
    # where the SDK isn't installed.
    try:
        from claude_agent_sdk import (  # noqa: PLC0415
            ClaudeAgentOptions, CLINotFoundError, ProcessError,
            ResultMessage, AssistantMessage, ToolUseBlock, TextBlock,
            create_sdk_mcp_server, query, tool,
        )
    except ImportError:
        print("ℹ️  claude-agent-sdk not installed — using deterministic fallback.")
        return None, []

    # Per-run state captured by closures inside the @tool functions.
    state: dict = {
        "calls":       0,        # count of non-`done` tool invocations
        "report":      None,     # set when LLM calls done()
        "final_text":  None,     # last assistant text (fallback if no done())
        "trail":       [],       # ordered list of {n, tool, args_summary, result_preview}
    }

    def _record(tool_short_name: str, args: dict, result_text: str) -> None:
        n = len(state["trail"]) + 1
        # Errors stay uncapped — they're rare and the diagnostic matters more
        # than table width. Successful results truncate at 280 chars (was 120,
        # too short to be useful in either operator log or final markdown table).
        is_error = result_text.startswith(("error:", "refused:"))
        if is_error:
            preview = result_text.replace("\n", " ⏎ ")
        else:
            preview = result_text[:280].replace("\n", " ⏎ ")
        state["trail"].append({
            "n":              n,
            "tool":           tool_short_name,
            "args_summary":   json.dumps(args)[:80],
            "result_preview": preview,
        })
        # Live progress so the operator sees activity.
        print(f"  [#{n:02d}] {tool_short_name}({json.dumps(args)[:70]}) "
              f"→ {result_text[:60].replace(chr(10), ' ')}…", flush=True)

    def _result(text: str) -> dict:
        return {"content": [{"type": "text", "text": text}]}

    def _budget_refusal() -> dict:
        return _result(
            f"refused: tool-call budget ({_TOOL_CALL_CAP}) exhausted. "
            "Call done(report_markdown) now with whatever you have."
        )

    # ── Tool definitions — async @tool wrappers around the sync chisel calls.
    # Each enforces the budget cap, records to the trail, returns MCP-shaped result.

    @tool("list_dir", "List a directory under the evidence root (returns `ls -la` output).",
          {"path": str})
    async def t_list_dir(args):
        if state["calls"] >= _TOOL_CALL_CAP:
            return _budget_refusal()
        state["calls"] += 1
        out = _tool_list_dir(chisel, args)
        _record("list_dir", args, out)
        return _result(out)

    @tool("read_file",
          "Read up to max_bytes from the start of a file under the evidence root. "
          f"Output capped at {_TOOL_RESULT_MAX_BYTES} bytes regardless of max_bytes.",
          {"path": str, "max_bytes": int})
    async def t_read_file(args):
        if state["calls"] >= _TOOL_CALL_CAP:
            return _budget_refusal()
        state["calls"] += 1
        out = _tool_read_file(chisel, args)
        _record("read_file", args, out)
        return _result(out)

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
        return _result(out)

    @tool("find_files",
          "Find files by name glob under a /evidence directory. Uses `find <dir> -name <glob>`.",
          {"dir": str, "name_glob": str})
    async def t_find_files(args):
        if state["calls"] >= _TOOL_CALL_CAP:
            return _budget_refusal()
        state["calls"] += 1
        out = _tool_find_files(chisel, args)
        _record("find_files", args, out)
        return _result(out)

    @tool("query_capability",
          "Run a forensic-tool capability-discovery command. Restricted to: "
          "vol --help/-h; log2timeline.py --help/--parsers list/--filters list/--formatters list; "
          "psort.py --help/--output-list; pinfo.py --help/--info <storage>. Anything else is refused.",
          {"tool": str, "args": list})
    async def t_query_capability(args):
        if state["calls"] >= _TOOL_CALL_CAP:
            return _budget_refusal()
        state["calls"] += 1
        out = _tool_query_capability(chisel, args)
        _record("query_capability", args, out)
        return _result(out)

    @tool("done",
          "Submit your final coverage-review markdown. Calling this terminates the agent. "
          "Report should be SCANNABLE — operator reads it in under 2 minutes.",
          {"report_markdown": str})
    async def t_done(args):
        state["report"] = (args.get("report_markdown") or "").strip() or None
        return _result("report received; the loop will terminate.")

    # Build in-process MCP server bundling all 6 tools.
    mcp_server = create_sdk_mcp_server(
        name=_MCP_SERVER_NAME,
        tools=[t_list_dir, t_read_file, t_grep, t_find_files, t_query_capability, t_done],
    )

    # Allowed-tool list — must match the MCP-prefixed names the LLM will see.
    prefixed = lambda short: f"mcp__{_MCP_SERVER_NAME}__{short}"
    allowed = [prefixed(n) for n in (
        "list_dir", "read_file", "grep", "find_files", "query_capability", "done",
    )]

    options = ClaudeAgentOptions(
        model=model,
        system_prompt=_SYSTEM_PROMPT,
        mcp_servers={_MCP_SERVER_NAME: mcp_server},
        allowed_tools=allowed,
        # Empty list disables built-in tools (Read/Write/Bash/etc.) — the LLM
        # gets ONLY our chisel-routed MCP tools.
        tools=[],
        # No interactive prompts; we control authorization via tool definitions.
        permission_mode="bypassPermissions",
        # Generous turn limit; real cap is enforced inside our @tool wrappers.
        max_turns=200,
    )

    # Bind the generator explicitly so we can aclose() it cleanly. Breaking out
    # of `async for` mid-iteration without aclose() triggers
    # "RuntimeError: aclose(): asynchronous generator is already running" when
    # the SDK and our code race to tear it down. The try/finally guarantees
    # we yield back to the SDK's cleanup before our async function returns.
    gen = query(prompt=_initial_user_message(chisel), options=options)
    try:
        async for message in gen:
            # Capture last assistant text in case the LLM ends without calling done()
            if isinstance(message, AssistantMessage):
                texts = [b.text for b in message.content if isinstance(b, TextBlock)]
                if texts:
                    state["final_text"] = "\n".join(texts).strip() or state["final_text"]
            # Stop iterating once the agent finishes its work
            if isinstance(message, ResultMessage):
                break
    except CLINotFoundError as e:
        print(f"ℹ️  Claude Code CLI not found ({e}) — using deterministic fallback.")
        return None, state["trail"]
    except ProcessError as e:
        print(f"⚠️  Claude SDK process error: {e} — falling back to deterministic.")
        return None, state["trail"]
    except Exception as e:
        print(f"⚠️  Unexpected SDK error after {state['calls']} tool call(s): {e}")
        return None, state["trail"]
    finally:
        # Always aclose() the SDK's async generator so its background tasks
        # tear down before we exit. Idempotent: safe even if it already closed.
        try:
            await gen.aclose()
        except Exception:
            pass  # already closed / never started — no-op

    # Prefer the explicit done() report; fall back to last assistant text.
    final_report = state["report"] or state["final_text"]
    if final_report and not state["report"]:
        print(f"ℹ️  LLM ended without calling done() — using final assistant text "
              f"as report ({len(final_report)} chars).")
    return final_report, state["trail"]


# ───────────────────────────────────────────────────────────────────────────
# Output validation
# ───────────────────────────────────────────────────────────────────────────

def validate_report(text: str) -> tuple[str, int]:
    """Replace any sentence containing a forbidden phrase with [REDACTED].
    Returns (cleaned_text, redaction_count). Sentence-splitting is loose
    (split on `. `/`! `/`? ` after a closing punctuation) — good enough for
    short prose; perfect would require an NLP tokenizer.

    Operates LINE-BY-LINE so list bullets and paragraph breaks are preserved.
    """
    cleaned_lines: list[str] = []
    redactions = 0
    for line in text.splitlines():
        if not line.strip():
            cleaned_lines.append(line)
            continue
        parts = re.split(r"(?<=[.!?])\s+", line)
        kept: list[str] = []
        for p in parts:
            if _FORBIDDEN_PHRASE_RE.search(p):
                kept.append("[REDACTED]")
                redactions += 1
            else:
                kept.append(p)
        cleaned_lines.append(" ".join(kept))
    return "\n".join(cleaned_lines), redactions


def render_audit_trail(trail: list[dict]) -> str:
    """Append a tool-call audit table to the bottom of the report."""
    if not trail:
        return ""
    lines = [
        "",
        "---",
        "",
        "## Tool-call audit trail",
        "",
        f"_The LLM made {len(trail)} chisel call(s) during this review. Spot-check "
        f"that observations above are grounded in these calls. Every call is also "
        f"logged independently in `evidence/audit/chisel_exec_<date>.jsonl`._",
        "",
        "| # | Tool | Args (first 80 chars) | Result preview |",
        "|---|---|---|---|",
    ]
    for entry in trail:
        # Escape pipes inside cells so they don't break markdown table rendering
        args_cell    = entry["args_summary"].replace("|", "\\|")
        result_cell  = entry["result_preview"].replace("|", "\\|")
        lines.append(
            f"| {entry['n']} | `{entry['tool']}` | `{args_cell}` | {result_cell} |"
        )
    lines.append("")
    return "\n".join(lines)


# ───────────────────────────────────────────────────────────────────────────
# Deterministic fallback (no LLM available)
# ───────────────────────────────────────────────────────────────────────────

def _fallback_audit_summary(chisel: Chisel) -> dict:
    """Walk the chisel audit log and aggregate counts. NO recommendations
    are produced — those require LLM judgment.

    All filesystem access routes through Chisel (`shell ls` to enumerate
    audit files, `shell cat` to read each one). This keeps the coverage
    agent's pre-computed summary subject to the same allowlist + audit
    guarantees as every other tool call. The deterministic fallback path
    also benefits — no separate code path bypasses chisel.
    """
    by_agent: Counter = Counter()
    by_tool: Counter  = Counter()
    vol_plugins: set  = set()
    total = 0
    plaso_seen = False

    # Enumerate audit JSONL files via chisel `ls`.
    try:
        listing = chisel.shell("ls", ["-1", str(AUDIT_DIR)])
    except Exception:
        return {"total": 0, "by_agent": {}, "by_tool": {},
                "vol_plugins": [], "plaso_seen": False}

    log_files = sorted(
        f for f in listing.splitlines()
        if f.startswith("chisel_exec_") and f.endswith(".jsonl")
    )

    for fname in log_files:
        path = str(AUDIT_DIR / fname)
        try:
            content = chisel.shell("cat", [path])
        except Exception:
            continue
        for raw in content.splitlines():
            raw = raw.strip()
            if not raw:
                continue
            try:
                entry = json.loads(raw)
            except json.JSONDecodeError:
                continue
            total += 1
            by_agent[entry.get("agent", "?")] += 1
            tool = entry.get("tool", "?")
            by_tool[tool] += 1
            if tool == "vol":
                for arg in entry.get("args", []) or []:
                    if isinstance(arg, str) and re.match(
                        r"^(?:windows|linux|mac|framework)\."
                        r"[a-z][a-z0-9_.]*$", arg,
                    ):
                        vol_plugins.add(arg)
                        break
            if tool in ("log2timeline.py", "psort.py"):
                plaso_seen = True

    return {
        "total":        total,
        "by_agent":     dict(by_agent),
        "by_tool":      dict(by_tool),
        "vol_plugins":  sorted(vol_plugins),
        "plaso_seen":   plaso_seen,
    }


def _fallback_claim_counts(chisel: Chisel) -> dict:
    """Count claim files by their leading agent prefix. Routes through
    chisel `ls` so the read is allowlist-checked and audit-logged like
    any other forensic-tree access."""
    out: Counter = Counter()
    try:
        listing = chisel.shell("ls", ["-1", str(CLAIMS_DONE)])
    except Exception:
        return {}
    for line in listing.splitlines():
        line = line.strip()
        if not line.endswith(".md"):
            continue
        prefix = line.split("_", 1)[0]
        out[prefix] += 1
    return dict(out)


def render_fallback_report(chisel: Chisel, now_ts: str) -> str:
    """Minimal deterministic report when no LLM is available. Counts only —
    no prescriptive recommendations. All filesystem access routes through
    Chisel."""
    audit  = _fallback_audit_summary(chisel)
    claims = _fallback_claim_counts(chisel)

    lines = []
    lines.append(f"# Coverage Review (deterministic fallback)")
    lines.append("")
    lines.append(
        f"*Generated {now_ts}. The LLM-driven coverage explorer is "
        f"unavailable (`ANTHROPIC_API_KEY` not set). This is a minimal "
        f"counts-only summary; no recommendations are produced. Set the "
        f"key to enable agentic exploration on the next run.*"
    )
    lines.append("")
    lines.append("## Audit log facts")
    lines.append("")
    lines.append(f"- Total chisel-routed invocations: {audit['total']}")
    if audit["by_agent"]:
        agents_str = ", ".join(
            f"`{a}` ({n})" for a, n in sorted(audit["by_agent"].items(), key=lambda kv: -kv[1])
        )
        lines.append(f"- Invocations by agent: {agents_str}")
    if audit["by_tool"]:
        tools_str = ", ".join(
            f"`{t}` ({n})" for t, n in sorted(audit["by_tool"].items(), key=lambda kv: -kv[1])
        )
        lines.append(f"- Invocations by tool: {tools_str}")
    if audit["vol_plugins"]:
        plugin_str = ", ".join(f"`{p}`" for p in audit["vol_plugins"])
        lines.append(f"- Volatility plugins seen: {plugin_str}")
    lines.append(f"- Plaso (`log2timeline.py`/`psort.py`) seen: "
                 f"{'yes' if audit['plaso_seen'] else 'no'}")
    lines.append("")
    lines.append("## Claim counts (`evidence/claims/done/`)")
    lines.append("")
    if claims:
        for prefix, n in sorted(claims.items(), key=lambda kv: -kv[1]):
            lines.append(f"- {prefix}: {n}")
    else:
        lines.append("_(none)_")
    lines.append("")
    lines.append("## Documented audit exceptions (context)")
    lines.append("")
    lines.append(
        "_The following tools bypass chisel by design and do NOT appear in "
        "the audit log. If their absence above looks like a coverage gap, "
        "it isn't — these are infrastructure exceptions:_"
    )
    lines.append("")
    for ex in _AUDIT_EXCEPTIONS:
        lines.append(f"- `{ex['tool']}` (used by `{ex['agent_module']}`)")
    lines.append("")
    return "\n".join(lines)


# ───────────────────────────────────────────────────────────────────────────
# Main entry point
# ───────────────────────────────────────────────────────────────────────────

async def run_coverage_explorer():
    """Standalone + orchestrator entry point."""
    print("🔎 Coverage Explorer Agent (agentic loop) starting...")

    chisel = Chisel(CHISEL_URL, CHISEL_SECRET)
    chisel.connect()
    print(f"🔒 Chisel session → {chisel.endpoint} (sid={chisel.session_id[:8]}…)")

    now_ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    fname_ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")

    report, trail = await run_agentic_loop(chisel)

    if report is None:
        print("ℹ️  LLM exploration unavailable — emitting deterministic fallback.")
        final_report = render_fallback_report(chisel, now_ts)
        redactions = 0
    else:
        cleaned, redactions = validate_report(report)
        # Prepend a generated-on header so the operator always sees provenance
        header = (
            f"# Coverage Review\n\n"
            f"*Generated {now_ts}. Source: agentic LLM exploration "
            f"({len(trail)} tool call(s) used of {_TOOL_CALL_CAP} budget). "
            f"Output validation redacted {redactions} sentence(s) for "
            f"forensic-conclusion language.*\n\n---\n\n"
        )
        final_report = header + cleaned + render_audit_trail(trail)

    REPORTS_ROOT.mkdir(parents=True, exist_ok=True)
    out_path = REPORTS_ROOT / f"coverage_review_{fname_ts}.md"
    out_path.write_text(final_report, encoding="utf-8")
    print(f"✅ Coverage review written → {out_path}")
    print(
        f"   {len(final_report):,} chars; "
        f"LLM tool calls: {len(trail)}; redactions: {redactions}"
    )


if __name__ == "__main__":
    asyncio.run(run_coverage_explorer())
