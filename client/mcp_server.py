#!/usr/bin/env python3
"""OSE Auditor - MCP Server (client/mcp_server.py).

Exposes OSE Auditor as a Model Context Protocol (MCP) tool over stdio so
that any MCP-compatible AI client (Claude Code, Cursor, Cline, Aider-via-
MCP-bridge, etc.) can call `ose_audit` directly during a coding session.

This module does NOT reimplement the audit pipeline. It is a thin
JSON-RPC 2.0 / stdio adapter around `client.orchestrator.run_audit`,
which already does parsing, FSA analysis, contract validation, and the
(optional) call to the OSE Server for patches.

Transport: JSON-RPC 2.0 messages, one per line, over stdin/stdout
("stdio" transport per the MCP spec). All logging and diagnostics MUST
go to stderr -- stdout is reserved exclusively for JSON-RPC frames, or
MCP clients will fail to parse the stream.

Environment variables:
    OSE_API_KEY:    Bearer token for the OSE Server (required for any
                     audit that produces findings; not needed for the
                     "no findings" path).
    OSE_SERVER_URL: Override for the OSE Server endpoint. Defaults to
                     the production URL baked into orchestrator.py.

Typical client (e.g. Claude Code / Cursor) MCP config entry::

    {
      "mcpServers": {
        "ose-auditor": {
          "command": "python3",
          "args": ["-m", "client.mcp_server"],
          "env": {
            "OSE_API_KEY": "sk-ose-...",
            "OSE_SERVER_URL": "https://ose.crestsek.com/v1/audit"
          }
        }
      }
    }

License: MIT (this adapter only -- it imports the proprietary `fsa`
package at runtime the same way orchestrator.py does, but contains no
proprietary logic itself).
"""

from __future__ import annotations

import json
import logging
import os
import sys
import tempfile
import traceback
from pathlib import Path
from typing import Any, Dict, Optional

try:
    from client import orchestrator
except ImportError:  # pragma: no cover - direct script execution fallback
    import orchestrator  # type: ignore

# ---------------------------------------------------------------------------
# Logging -- stderr ONLY. Never let anything touch stdout except JSON-RPC.
# ---------------------------------------------------------------------------

logger = logging.getLogger("ose.mcp")
logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] ose.mcp: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# ---------------------------------------------------------------------------
# MCP / JSON-RPC constants
# ---------------------------------------------------------------------------

#: MCP protocol revision this server speaks. Clients negotiate down to a
#: mutually supported version during `initialize`; 2024-11-05 is the
#: widest-supported baseline across current MCP hosts.
PROTOCOL_VERSION = "2024-11-05"

SERVER_NAME = "ose-auditor"
SERVER_VERSION = "1.0.0"

# JSON-RPC 2.0 standard error codes (+ MCP convention of using these as-is).
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

TOOLS = [
    {
        "name": "ose_audit",
        "description": (
            "Run OSE Auditor's Financial Semantic Analyzer against a local "
            "Node.js/TypeScript project to find financial-logic "
            "vulnerabilities (broken auth, missing access control, "
            "privilege escalation, unchecked external calls, double-spend "
            "races, invalid state transitions, and similar business-logic "
            "flaws). Use this before completing or merging changes that "
            "touch payment, wallet, balance, order, or auth-related code. "
            "Requires the project path to be a local directory containing "
            "JavaScript/TypeScript source files."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_path": {
                    "type": "string",
                    "description": (
                        "Absolute or relative filesystem path to the "
                        "project root to audit."
                    ),
                },
                "track": {
                    "type": "string",
                    "enum": ["web2", "web3", "quant"],
                    "description": (
                        "Which findings/patch track to request from the "
                        "OSE Server. Defaults to 'web2' (Node.js)."
                    ),
                },
            },
            "required": ["project_path"],
        },
    }
]

# ---------------------------------------------------------------------------
# stdout framing helpers
# ---------------------------------------------------------------------------


def _send(message: Dict[str, Any]) -> None:
    """Write a single JSON-RPC message to stdout, newline-delimited.

    :param message: The JSON-RPC message dict to serialize and send.
    :type message: Dict[str, Any]
    :return: ``None``
    :rtype: None
    """
    try:
        line = json.dumps(message, ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        logger.error("Failed to serialize outgoing message: %s", exc)
        return
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def _send_result(request_id: Any, result: Dict[str, Any]) -> None:
    """Send a successful JSON-RPC response.

    :param request_id: The id from the originating request.
    :param result: The JSON-RPC ``result`` payload.
    :return: ``None``
    """
    _send({"jsonrpc": "2.0", "id": request_id, "result": result})


def _send_error(request_id: Any, code: int, message: str, data: Optional[Any] = None) -> None:
    """Send a JSON-RPC error response.

    :param request_id: The id from the originating request (may be
        ``None`` if the request itself could not be parsed).
    :param code: A JSON-RPC error code.
    :param message: A short, human-readable error description.
    :param data: Optional additional structured error data.
    :return: ``None``
    """
    error: Dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    _send({"jsonrpc": "2.0", "id": request_id, "error": error})


# ---------------------------------------------------------------------------
# Method handlers
# ---------------------------------------------------------------------------


def _handle_initialize(request_id: Any, params: Dict[str, Any]) -> None:
    """Handle the MCP `initialize` handshake.

    :param request_id: JSON-RPC request id.
    :param params: Client-supplied initialize params (protocol version,
        client info, capabilities). Not currently inspected beyond
        logging, since this server only exposes tools.
    :return: ``None``
    """
    client_info = params.get("clientInfo", {}) if isinstance(params, dict) else {}
    logger.info(
        "MCP client connected: %s %s",
        client_info.get("name", "unknown"),
        client_info.get("version", ""),
    )
    _send_result(
        request_id,
        {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
        },
    )


def _handle_tools_list(request_id: Any, params: Dict[str, Any]) -> None:
    """Handle `tools/list`: advertise the `ose_audit` tool.

    :param request_id: JSON-RPC request id.
    :param params: Unused; present for signature consistency.
    :return: ``None``
    """
    _send_result(request_id, {"tools": TOOLS})


def _run_audit_for_mcp(project_path: str, track: str) -> Dict[str, Any]:
    """Run the OSE audit pipeline and return a JSON-serializable result.

    Always routes the report through a temporary file rather than stdout,
    since `orchestrator.run_audit` prints the report to stdout when no
    output file is given -- and stdout is reserved for JSON-RPC frames in
    this process.

    :param project_path: Path to the project to audit.
    :param track: Analysis track ("web2", "web3", "quant"). Currently
        informational; the underlying orchestrator always targets web2
        until multi-track support lands client-side.
    :return: A dict with ``exit_code`` and either ``report`` (parsed JSON)
        or ``raw_output`` (if the report file could not be parsed as JSON).
    :raises FileNotFoundError: If ``project_path`` does not exist (raised
        by the orchestrator's own validation, surfaced to the caller).
    """
    with tempfile.TemporaryDirectory(prefix="ose-mcp-") as tmp_dir:
        report_path = str(Path(tmp_dir) / "report.json")

        # orchestrator.run_audit configures its own stderr-only logging
        # via _configure_logging(); debug=False keeps the noise down for
        # an MCP tool call.
        exit_code = orchestrator.run_audit(project_path, report_path, False)

        report_file = Path(report_path)
        if not report_file.exists():
            return {
                "exit_code": exit_code,
                "report": None,
                "raw_output": None,
                "note": "Audit completed but no report file was produced.",
            }

        raw_text = report_file.read_text(encoding="utf-8")
        try:
            report = json.loads(raw_text)
        except json.JSONDecodeError:
            return {"exit_code": exit_code, "report": None, "raw_output": raw_text}

        return {"exit_code": exit_code, "report": report, "raw_output": None}


def _handle_tools_call(request_id: Any, params: Dict[str, Any]) -> None:
    """Handle `tools/call` for the `ose_audit` tool.

    :param request_id: JSON-RPC request id.
    :param params: Must contain ``name`` and ``arguments``; ``arguments``
        must contain ``project_path``.
    :return: ``None``
    """
    if not isinstance(params, dict):
        _send_error(request_id, INVALID_PARAMS, "params must be an object")
        return

    tool_name = params.get("name")
    arguments = params.get("arguments") or {}

    if tool_name != "ose_audit":
        _send_error(request_id, INVALID_PARAMS, f"Unknown tool: {tool_name!r}")
        return

    project_path = arguments.get("project_path")
    if not project_path or not isinstance(project_path, str):
        _send_error(
            request_id,
            INVALID_PARAMS,
            "Tool argument 'project_path' (string) is required.",
        )
        return

    track = arguments.get("track", "web2")

    resolved = Path(project_path).expanduser()
    if not resolved.exists():
        _send_result(
            request_id,
            {
                "content": [
                    {
                        "type": "text",
                        "text": f"Project path does not exist: {project_path}",
                    }
                ],
                "isError": True,
            },
        )
        return

    try:
        outcome = _run_audit_for_mcp(str(resolved), track)
    except Exception as exc:  # noqa: BLE001 - tool calls must never crash the server
        logger.exception("ose_audit failed for %s", project_path)
        _send_result(
            request_id,
            {
                "content": [
                    {
                        "type": "text",
                        "text": f"OSE audit failed: {exc}",
                    }
                ],
                "isError": True,
            },
        )
        return

    is_error = outcome["exit_code"] not in (0,)
    if outcome["report"] is not None:
        summary = outcome["report"].get("summary") or {}
        status_label = outcome["report"].get("status", "OK")
        text_summary = (
            f"OSE audit status: {status_label}. "
            f"Findings: total={summary.get('total_findings', 0)}, "
            f"critical={summary.get('critical', 0)}, "
            f"high={summary.get('high', 0)}, "
            f"medium={summary.get('medium', 0)}, "
            f"low={summary.get('low', 0)}."
        )
        content = [
            {"type": "text", "text": text_summary},
            {
                "type": "text",
                "text": json.dumps(outcome["report"], indent=2, ensure_ascii=False),
            },
        ]
    else:
        content = [
            {
                "type": "text",
                "text": outcome.get("raw_output")
                or outcome.get("note")
                or "OSE audit produced no report.",
            }
        ]

    _send_result(request_id, {"content": content, "isError": is_error})


def _handle_ping(request_id: Any, params: Dict[str, Any]) -> None:
    """Respond to MCP keep-alive pings.

    :param request_id: JSON-RPC request id.
    :param params: Unused.
    :return: ``None``
    """
    _send_result(request_id, {})


_METHOD_HANDLERS = {
    "initialize": _handle_initialize,
    "tools/list": _handle_tools_list,
    "tools/call": _handle_tools_call,
    "ping": _handle_ping,
}

# Notifications (no `id`, no response expected) that we simply acknowledge
# by doing nothing -- most hosts send `notifications/initialized` right
# after a successful `initialize` response.
_IGNORED_NOTIFICATIONS = {
    "notifications/initialized",
    "notifications/cancelled",
}


def _dispatch(message: Dict[str, Any]) -> None:
    """Route a single decoded JSON-RPC message to the right handler.

    :param message: The decoded JSON-RPC request/notification object.
    :return: ``None``
    """
    method = message.get("method")
    request_id = message.get("id")
    params = message.get("params") or {}

    if method in _IGNORED_NOTIFICATIONS:
        logger.debug("Ignoring notification: %s", method)
        return

    handler = _METHOD_HANDLERS.get(method)
    if handler is None:
        if request_id is not None:
            _send_error(request_id, METHOD_NOT_FOUND, f"Method not found: {method}")
        else:
            logger.debug("Ignoring unknown notification: %s", method)
        return

    try:
        handler(request_id, params)
    except Exception as exc:  # noqa: BLE001 - one bad message must not kill the loop
        logger.error("Handler for %s raised: %s\n%s", method, exc, traceback.format_exc())
        if request_id is not None:
            _send_error(request_id, INTERNAL_ERROR, f"Internal error: {exc}")


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------


def main() -> int:
    """Run the stdio JSON-RPC read/dispatch loop.

    Reads newline-delimited JSON-RPC messages from stdin until EOF,
    dispatching each to the appropriate handler. Malformed lines produce
    a JSON-RPC parse error response (when possible) rather than crashing
    the process, so one bad frame doesn't take down the whole session.

    :return: Process exit code (``0`` on clean EOF shutdown).
    :rtype: int
    """
    logger.info("OSE Auditor MCP server starting (stdio transport).")

    if not os.environ.get("OSE_API_KEY"):
        logger.warning(
            "OSE_API_KEY is not set. Audits with findings will fail when "
            "contacting the OSE Server; set it in the MCP client's env config."
        )

    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue

        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse incoming JSON-RPC line: %s", exc)
            _send_error(None, PARSE_ERROR, "Parse error")
            continue

        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            _send_error(
                message.get("id") if isinstance(message, dict) else None,
                INVALID_REQUEST,
                "Invalid Request: expected JSON-RPC 2.0 object",
            )
            continue

        _dispatch(message)

    logger.info("stdin closed; OSE Auditor MCP server shutting down.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
