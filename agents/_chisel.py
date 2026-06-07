"""Minimal MCP-over-HTTP client for Chisel — shared by all FindEvil agents.

Per FindEvil §5: agents read evidence and write claims only through Chisel,
so the agent's filesystem reach is kernel-confined to the Chisel root.

Includes retry/backoff on HTTP 429 (rate limiting) — the orchestrator's bounded
dispatch can still hit Chisel's rate limit when multiple agents run concurrently
(memory_agent fires hundreds of chisel.call writes during VAD dump triage; many
prefetch agents run back-to-back). Without retry, a single 429 fails the whole
agent and leaves its evidence file stuck in evidence/new/ unretried.

Also exposes `exec_tool()` — the canonical entry point for forensic-tool
invocations (vol, dotnet EZ Tools, log2timeline.py, fls, etc.). Routing through
Chisel gives us:
  - Allowlist enforcement (Chisel-server-side WHITELIST gates command names)
  - Centralized audit log: every invocation written to evidence/audit/<date>.jsonl
  - Single point for retry / rate-limit / observability hooks
Direct subprocess.run() / asyncio.create_subprocess_exec() bypasses all three —
should not be used for forensic tools (only for invoking our own Python subagents
from orchestrator/main.py).
"""
import json
import os
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path


# Retry policy: exponential backoff with cap. 6 attempts → max ~12s wait per call,
# enough for transient bursts but bounded to keep agents from hanging indefinitely.
_RETRY_MAX_ATTEMPTS = 6
_RETRY_BASE_DELAY = 0.4  # seconds; doubled each attempt: 0.4, 0.8, 1.6, 3.2, 6.4
_RETRY_DELAY_CAP = 6.4


class Chisel:
    """Thin synchronous Chisel/MCP client. Streamable-HTTP transport, SSE responses."""

    def __init__(self, url: str, secret: str):
        self.endpoint = f"{url.rstrip('/')}/mcp"
        self._headers = {
            "Authorization": f"Bearer {secret}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        self.session_id: str | None = None
        self._next_id = 0

    def _post(self, body: dict) -> tuple:
        h = dict(self._headers)
        if self.session_id:
            h["Mcp-Session-Id"] = self.session_id
        data = json.dumps(body).encode()
        delay = _RETRY_BASE_DELAY
        last_err: Exception | None = None
        for attempt in range(_RETRY_MAX_ATTEMPTS):
            req = urllib.request.Request(self.endpoint, data=data, headers=h)
            try:
                with urllib.request.urlopen(req, timeout=60) as r:
                    return r.headers, r.read().decode()
            except urllib.error.HTTPError as e:
                # Retry only on 429 (rate limit) and 503 (service unavailable).
                # Other HTTPErrors are likely auth or method failures — fail fast.
                if e.code not in (429, 503):
                    raise
                last_err = e
                if attempt < _RETRY_MAX_ATTEMPTS - 1:
                    time.sleep(delay)
                    delay = min(delay * 2, _RETRY_DELAY_CAP)
        # Exhausted retries
        raise last_err if last_err else RuntimeError("Chisel retries exhausted (no error captured)")

    @staticmethod
    def _parse_sse(raw: str) -> dict | None:
        for line in raw.splitlines():
            if line.startswith("data: "):
                try:
                    return json.loads(line[6:])
                except json.JSONDecodeError:
                    continue
        return None

    def _rpc(self, method: str, params: dict | None = None) -> dict:
        self._next_id += 1
        body = {"jsonrpc": "2.0", "id": self._next_id, "method": method}
        if params is not None:
            body["params"] = params
        headers, raw = self._post(body)
        if not self.session_id:
            self.session_id = headers.get("mcp-session-id")
        msg = self._parse_sse(raw)
        if msg is None:
            raise RuntimeError(f"Chisel: empty response for {method}: {raw[:200]}")
        if "error" in msg:
            raise RuntimeError(f"Chisel {method} error: {msg['error']}")
        return msg.get("result", {})

    def connect(self):
        self._rpc("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "findevil-agent", "version": "0.1"},
        })
        # notifications/initialized has no id and returns 202 with empty body
        self._post({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})

    def call(self, tool: str, arguments: dict) -> str:
        result = self._rpc("tools/call", {"name": tool, "arguments": arguments})
        if result.get("isError"):
            raise RuntimeError(f"Chisel tool {tool!r} failed: {result.get('content')}")
        parts = [c.get("text", "") for c in result.get("content", []) if c.get("type") == "text"]
        return "\n".join(parts)

    def shell(self, command: str, args: list[str]) -> str:
        """Run a whitelisted command via shell_exec; return stdout, raise on non-zero exit.

        For forensic-tool invocations (vol, dotnet, log2timeline.py, fls, etc.)
        prefer `exec_tool()` instead — it returns structured output (no need to
        re-raise on exit_code) and writes an audit-log entry."""
        parsed = _parse_shell_output(self.call("shell_exec", {"command": command, "args": args}))
        if parsed["exit_code"] != 0:
            raise RuntimeError(f"Chisel shell {command} {args} exit={parsed['exit_code']} stderr={parsed['stderr']}")
        return parsed["stdout"]

    def exec_tool(self, tool: str, args: list[str], *,
                  agent_name: str,
                  capture_stderr_bytes: int = 4096) -> dict:
        """Execute a forensic tool through Chisel (subject to server allowlist) AND
        write a structured audit-log entry. Returns:
            {"exit_code": int, "stdout": str, "stderr": str, "elapsed_ms": int}

        Raises RuntimeError ONLY on Chisel-side failure (allowlist rejection,
        transport error). Does NOT raise on non-zero `exit_code` — caller decides
        how to handle (some tools exit non-zero in expected scenarios, e.g. grep
        no-match). Audit-log entry written regardless of exit_code.

        Use this for ALL forensic tool invocations. Direct subprocess.run() /
        asyncio.create_subprocess_exec() bypasses the audit + allowlist guarantees
        and should only be used for invoking our own Python subagents.
        """
        start = time.time()
        out_str = self.call("shell_exec", {"command": tool, "args": args})
        elapsed_ms = int((time.time() - start) * 1000)
        parsed = _parse_shell_output(out_str)
        _write_audit_entry(agent_name=agent_name, tool=tool, args=args,
                           exit_code=parsed["exit_code"],
                           stdout_bytes=len(parsed["stdout"]),
                           stderr=parsed["stderr"],
                           elapsed_ms=elapsed_ms)
        return {
            "exit_code": parsed["exit_code"],
            "stdout": parsed["stdout"],
            "stderr": parsed["stderr"][:capture_stderr_bytes],
            "elapsed_ms": elapsed_ms,
        }


# ─── Module-level helpers (no Chisel instance state needed) ─────────────────

def _parse_shell_output(out: str) -> dict:
    """Parse Chisel shell_exec response format:
        "exit_code: N\\nstdout:\\n<...>\\nstderr:\\n<...>"
    into {"exit_code": int, "stdout": str, "stderr": str}."""
    lines = out.split("\n")
    if not lines or not lines[0].startswith("exit_code: "):
        raise RuntimeError(f"Chisel shell unexpected output: {out[:200]}")
    exit_code = int(lines[0][len("exit_code: "):])
    try:
        so_idx = lines.index("stdout:")
        se_idx = lines.index("stderr:", so_idx)
    except ValueError as e:
        raise RuntimeError(f"Chisel shell malformed output: {out[:200]}") from e
    return {
        "exit_code": exit_code,
        "stdout": "\n".join(lines[so_idx + 1:se_idx]).rstrip("\n"),
        "stderr": "\n".join(lines[se_idx + 1:]).rstrip("\n"),
    }


# Audit log: one JSONL file per UTC date, append-only. Lives outside claims/
# because it's metadata, not evidence — validator/extractor never read it.
# Path is computed at write time (not import time) so the date rolls correctly
# on long-running orchestrator processes.
_EVIDENCE_ROOT = Path(os.environ.get(
    "EVIDENCE_ROOT", "/home/sansforensics/dfirskills2/evidence",
))


def _audit_log_path() -> Path:
    return _EVIDENCE_ROOT / "audit" / f"chisel_exec_{datetime.now(UTC).strftime('%Y%m%d')}.jsonl"


def _write_audit_entry(*, agent_name: str, tool: str, args: list[str],
                       exit_code: int, stdout_bytes: int, stderr: str,
                       elapsed_ms: int) -> None:
    """Append one JSONL record to the daily audit log. Stderr capped to 512
    bytes so a runaway stderr can't bloat the log. stdout is NOT logged
    (size only) — the actual output goes to claims via the agent."""
    entry = {
        "ts": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "agent": agent_name,
        "tool": tool,
        "args": args,
        "exit_code": exit_code,
        "stdout_bytes": stdout_bytes,
        "stderr_summary": stderr[:512],
        "elapsed_ms": elapsed_ms,
    }
    path = _audit_log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
