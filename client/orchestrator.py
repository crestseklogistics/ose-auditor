"""
OSE Auditor - Local Pipeline Conductor

This module coordinates the entire audit workflow:
    1. Calls parser.py to build the Project Source Index (Contract A).
    2. Validates Contract A.
    3. Calls the FSA (or a local mock) to build the Vulnerability
       Manifest (Contract B).
    4. Validates Contract B.
    5. If there are findings, sends the manifest to the OSE Server over
       HTTPS (with retries) to obtain AI-generated patches and credit
       status.
    6. Builds a final audit report combining the manifest and the
       server's patches.
    7. Saves a local cache (file hashes only -- never raw source code)
       for future change-detection.
    8. Returns the final report to the CLI (ose.py), printed to stdout
       or written to an output file.

The orchestrator performs no analysis itself; it is purely a workflow
conductor between the CLI, the local parser/FSA, and the remote OSE
Server.
"""

import json
import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger("ose.orchestrator")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

OSE_SERVER_URL = os.environ.get("OSE_SERVER_URL", "https://api.crestsek.com/v1/audit")
# OSE_SERVER_URL = "http://localhost:8000/v1/audit"
CLIENT_VERSION = "1.0.0"

CONFIG_DIR = Path.home() / ".ose"
CACHE_DIR = CONFIG_DIR / "cache"
CONFIG_FILE = CONFIG_DIR / "config.json"

MAX_RETRIES = 4
RETRY_DELAYS = [0, 1, 2, 4]  # seconds, indexed by attempt number - 1
RETRYABLE_STATUS_CODES = {429, 502, 503, 504}
DEFAULT_TIMEOUT_SECONDS = 30.0

EXIT_SUCCESS = 0
EXIT_GENERAL_ERROR = 1
EXIT_AUDIT_FAILURE = 2

try:
    import httpx  # noqa: F401  (presence check only; imported again where used)
    _HAS_HTTPX = True
except ImportError:
    _HAS_HTTPX = False


class ServerCommunicationError(Exception):
    """Raised when the OSE Server cannot be reached after all retries,
    or when it returns a response the orchestrator cannot use."""


@dataclass
class _HttpResult:
    """The outcome of a single HTTP POST attempt.

    Attributes:
        status_code: The HTTP status code, or None if the request never
            reached the server (timeout / network error).
        body: The parsed JSON response body, or None if unavailable.
        error: A short description of a transport-level failure
            ("timeout" or "network_error: ..."), or None if the HTTP
            exchange completed (regardless of status code).
    """

    status_code: Optional[int]
    body: Optional[Dict[str, Any]]
    error: Optional[str]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_audit(project_path: str, output_file: Optional[str], debug: bool) -> int:
    """
    Main entry point called by ose.py.

    Runs the full audit pipeline: parse -> validate Contract A -> run
    FSA -> validate Contract B -> (if findings exist) call the OSE
    Server for patches -> build and output the final report.

    Args:
        project_path: Absolute or relative path to the project root.
        output_file: Path to save the final report, or None for stdout.
        debug: Enable debug logging.

    Returns:
        Exit code: 0 on success, 1 on general error, 2 on audit failure.
    """
    _configure_logging(debug)
    logger.debug("Starting OSE Auditor run for project: %s", project_path)

    # Step 2/3: Parse the project and validate Contract A.
    try:
        project_index = _call_parser(project_path)
    except Exception as exc:
        logger.error("Failed to parse project at '%s': %s", project_path, exc)
        return EXIT_GENERAL_ERROR

    try:
        validated_index = _validate_contract_a(project_index)
    except Exception as exc:
        logger.error("Contract A validation failed: %s", exc)
        return EXIT_GENERAL_ERROR

    # Step 4/5: Run the FSA (or mock) and validate Contract B.
    try:
        manifest = _call_fsa(validated_index)
    except Exception as exc:
        logger.error("FSA analysis failed: %s", exc)
        return EXIT_GENERAL_ERROR

    try:
        validated_manifest = _validate_contract_b(manifest)
    except Exception as exc:
        logger.error("Contract B validation failed: %s", exc)
        return EXIT_GENERAL_ERROR

    project_hash = validated_manifest.get("project_hash") or validated_index.get(
        "project_identifier", ""
    )

    # Step 12: Save the local cache (file hashes only) regardless of
    # whether findings exist, so future scans have a baseline to diff
    # against.
    try:
        file_hashes = {
            f["path_relative"]: f["hash"] for f in validated_index.get("files", [])
        }
        _save_cache(project_hash, file_hashes)
    except Exception as exc:
        logger.warning("Could not save local cache: %s", exc)

    # Step 6: No findings -> short-circuit. No cloud call, no credit spend.
    findings = validated_manifest.get("findings", [])
    if len(findings) == 0:
        logger.info("No vulnerabilities detected; skipping server call.")
        report: Dict[str, Any] = {
            "status": "NO_FINDINGS",
            "message": "No vulnerabilities detected.",
            "project_hash": project_hash,
        }
        _write_report(report, output_file)
        return EXIT_SUCCESS

    # Step 7: Load the API key.
    api_key = _load_api_key()
    if not api_key:
        logger.error(
            "No OSE API key found. Set the OSE_API_KEY environment variable "
            "or create %s with {\"api_key\": \"...\"}.",
            CONFIG_FILE,
        )
        return EXIT_GENERAL_ERROR

    # Steps 8-10: Send the manifest to the OSE Server, with retries.
    try:
        server_response = _call_server(validated_manifest, api_key)
    except ServerCommunicationError as exc:
        logger.error("Failed to reach OSE Server: %s", exc)
        return EXIT_GENERAL_ERROR
    except Exception as exc:
        logger.error("Unexpected error communicating with OSE Server: %s", exc)
        return EXIT_GENERAL_ERROR

    if server_response.get("status") == "ERROR":
        logger.error("OSE Server reported an audit failure: %s",
                     server_response)
        return EXIT_AUDIT_FAILURE

    if server_response.get("status") == "CREDIT_EXHAUSTED":
        logger.warning(
            "OSE Server credits exhausted; patches may be incomplete. "
            "See 'checkout_urls' in the report to purchase more credits."
        )

    # Step 11: Build and output the final report.
    try:
        report = _build_final_report(validated_manifest, server_response)
    except Exception as exc:
        logger.error("Failed to build final report: %s", exc)
        return EXIT_GENERAL_ERROR

    _write_report(report, output_file)
    logger.debug("OSE Auditor run complete.")
    return EXIT_SUCCESS


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

def _configure_logging(debug: bool) -> None:
    """Configure the 'ose' logger if the CLI hasn't already done so.

    The CLI (ose.py) is expected to configure logging before calling
    `run_audit`. This only attaches a handler when none exists yet,
    so the orchestrator is also usable standalone (see `__main__`)
    without duplicating log output when run through the CLI.

    Args:
        debug: If True, set the log level to DEBUG; otherwise INFO.
    """
    ose_logger = logging.getLogger("ose")
    if not ose_logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        )
        ose_logger.addHandler(handler)
    ose_logger.setLevel(logging.DEBUG if debug else logging.INFO)


def _call_parser(project_path: str) -> Dict[str, Any]:
    """Call parser.py and return the raw Project Source Index (Contract A).

    Args:
        project_path: Path to the project root to scan.

    Returns:
        The unvalidated Contract A payload produced by `OseParser.scan()`.
    """
    from client.parser import OseParser

    parser = OseParser(project_path)
    return parser.scan()


def _validate_contract_a(data: Dict[str, Any]) -> Dict[str, Any]:
    """Validate Contract A and return the cleaned data.

    Args:
        data: The raw Contract A payload from `_call_parser`.

    Returns:
        The validated, cleaned Contract A payload.

    Raises:
        contracts.contract_a.ValidationError: If `data` is invalid.
    """
    from contracts import contract_a

    return contract_a.validate_contract_a(data)


def _call_fsa(project_index: Dict[str, Any]) -> Dict[str, Any]:
    """Call the FSA (Financial Semantic Analyzer) and return Contract B.

    If the `fsa` package is not installed (e.g. during local development
    of the open-source client, before the proprietary FSA is available),
    a mock manifest is returned instead so the rest of the pipeline can
    still be exercised end-to-end.

    Args:
        project_index: The validated Contract A payload.

    Returns:
        The raw Contract B payload produced by the FSA (or the mock).

    Raises:
        Exception: Any exception raised by the FSA itself is propagated
            to the caller, which is responsible for logging and
            translating it into an exit code.
    """
    try:
        from fsa import analyzer
    except ImportError:
        logger.warning("FSA not installed; using mock analyzer.")
        return _get_mock_manifest(project_index)

    return analyzer.analyze(project_index)


def _validate_contract_b(data: Dict[str, Any]) -> Dict[str, Any]:
    """Validate Contract B and return the cleaned data.

    Args:
        data: The raw Contract B payload from `_call_fsa`.

    Returns:
        The validated, cleaned Contract B payload.

    Raises:
        contracts.contract_b.ValidationError: If `data` is invalid.
    """
    from contracts import contract_b

    return contract_b.validate_contract_b(data)


def _load_api_key() -> Optional[str]:
    """Load the OSE API key from the environment or the user config file.

    Resolution order:
        1. The `OSE_API_KEY` environment variable.
        2. The `api_key` field in `~/.ose/config.json`.

    Returns:
        The API key string, or None if it could not be found.
    """
    api_key = os.environ.get("OSE_API_KEY")
    if api_key:
        return api_key

    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                config = json.load(f)
                return config.get("api_key")
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Could not read config file %s: %s",
                           CONFIG_FILE, exc)

    return None


def _post_once_httpx(
    url: str, payload: Dict[str, Any], headers: Dict[str, str], timeout: float
) -> _HttpResult:
    """Perform a single HTTP POST using httpx."""
    import httpx

    try:
        response = httpx.post(
            url, json=payload, headers=headers, timeout=timeout)
    except httpx.TimeoutException:
        return _HttpResult(status_code=None, body=None, error="timeout")
    except httpx.RequestError as exc:
        return _HttpResult(status_code=None, body=None, error=f"network_error: {exc}")

    try:
        body = response.json()
    except ValueError:
        body = None
    return _HttpResult(status_code=response.status_code, body=body, error=None)


def _post_once_urllib(
    url: str, payload: Dict[str, Any], headers: Dict[str, str], timeout: float
) -> _HttpResult:
    """Perform a single HTTP POST using the standard library as a fallback
    when `httpx` is not installed."""
    import urllib.error
    import urllib.request

    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url, data=data, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            try:
                body = json.loads(raw.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                body = None
            return _HttpResult(status_code=response.status, body=body, error=None)
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            body = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            body = None
        return _HttpResult(status_code=exc.code, body=body, error=None)
    except TimeoutError:
        return _HttpResult(status_code=None, body=None, error="timeout")
    except urllib.error.URLError as exc:
        reason = str(exc.reason) if hasattr(exc, "reason") else str(exc)
        if "timed out" in reason.lower():
            return _HttpResult(status_code=None, body=None, error="timeout")
        return _HttpResult(status_code=None, body=None, error=f"network_error: {reason}")


def _post_once(
    url: str, payload: Dict[str, Any], headers: Dict[str, str], timeout: float
) -> _HttpResult:
    """Perform a single HTTP POST, preferring httpx and falling back to urllib."""
    if _HAS_HTTPX:
        return _post_once_httpx(url, payload, headers, timeout)
    return _post_once_urllib(url, payload, headers, timeout)


def _call_server(manifest: Dict[str, Any], api_key: str) -> Dict[str, Any]:
    """Send the vulnerability manifest to the OSE Server, with retries.

    Uses exponential backoff: attempt 1 is immediate, then waits 1s, 2s,
    and 4s before attempts 2, 3, and 4 respectively (MAX_RETRIES = 4
    total attempts). Retries are performed on request timeouts and on
    HTTP 429/502/503/504 responses; any other failure is treated as
    non-retryable and raised immediately.

    Args:
        manifest: The validated Contract B payload to submit.
        api_key: The bearer token used to authenticate with the server.

    Returns:
        The parsed JSON response body from the OSE Server.

    Raises:
        ServerCommunicationError: If every retry attempt fails, or if
            the server returns a successful status with a body that
            cannot be parsed as JSON.
    """
    payload = {"manifest": manifest, "client_version": CLIENT_VERSION}
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    last_error_desc = "unknown error"

    for attempt in range(1, MAX_RETRIES + 1):
        delay = RETRY_DELAYS[attempt - 1]
        if delay:
            logger.info(
                "Waiting %ds before retrying OSE Server request (attempt %d/%d)...",
                delay, attempt, MAX_RETRIES,
            )
            time.sleep(delay)

        result = _post_once(OSE_SERVER_URL, payload,
                            headers, DEFAULT_TIMEOUT_SECONDS)

        if result.error == "timeout":
            last_error_desc = "request timed out"
            logger.warning(
                "OSE Server request timed out (attempt %d/%d).", attempt, MAX_RETRIES
            )
            continue

        if result.error is not None:
            # Non-timeout transport failures are not in the documented
            # retryable set; fail fast rather than retrying blindly.
            raise ServerCommunicationError(
                f"OSE Server request failed: {result.error}"
            )

        if result.status_code in RETRYABLE_STATUS_CODES:
            last_error_desc = f"HTTP {result.status_code}"
            logger.warning(
                "OSE Server returned retryable status %s (attempt %d/%d).",
                result.status_code, attempt, MAX_RETRIES,
            )
            continue

        if result.status_code is not None and 200 <= result.status_code < 300:
            if result.body is None:
                raise ServerCommunicationError(
                    "OSE Server returned a successful status with a "
                    "non-JSON or empty response body."
                )
            return result.body

        raise ServerCommunicationError(
            f"OSE Server returned non-retryable status {result.status_code}: "
            f"{result.body}"
        )

    raise ServerCommunicationError(
        f"OSE Server request failed after {MAX_RETRIES} attempts: {last_error_desc}"
    )


def _build_final_report(
    manifest: Dict[str, Any], server_response: Optional[Dict[str, Any]]
) -> Dict[str, Any]:
    """Combine the manifest and the server response into the final report.

    Args:
        manifest: The validated Contract B payload (findings without
            patches).
        server_response: The parsed response from the OSE Server,
            containing patches and credit status, or None.

    Returns:
        The final audit report, ready for JSON serialization.
    """
    findings = manifest.get("findings", [])

    patches_by_id: Dict[str, Dict[str, Any]] = {}
    for patch_entry in (server_response or {}).get("findings", []) or []:
        finding_id = patch_entry.get("finding_id")
        if finding_id:
            patches_by_id[finding_id] = patch_entry

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    combined_findings: List[Dict[str, Any]] = []
    for finding in findings:
        severity_key = str(finding.get("severity", "")).lower()
        if severity_key in severity_counts:
            severity_counts[severity_key] += 1

        patch_entry = patches_by_id.get(finding.get("id"), {})
        combined_findings.append(
            {
                "id": finding.get("id"),
                "file_path": finding.get("file_path"),
                "vulnerability_class": finding.get("vulnerability_class"),
                "severity": finding.get("severity"),
                "description": finding.get("description"),
                "patch": patch_entry.get("patch"),
                "explanation": patch_entry.get("explanation"),
            }
        )

    credits = (server_response or {}).get("credits", {})
    checkout_urls = (server_response or {}).get("checkout_urls")

    return {
        "project_hash": manifest.get("project_hash"),
        "scan_time": _utc_now_iso(),
        "summary": {
            "total_findings": len(findings),
            "critical": severity_counts["critical"],
            "high": severity_counts["high"],
            "medium": severity_counts["medium"],
            "low": severity_counts["low"],
        },
        "findings": combined_findings,
        "credits": credits,
        "checkout_urls": checkout_urls,
    }


def _save_cache(project_hash: str, file_hashes: Dict[str, str]) -> None:
    """Save a local cache entry for future change-detection scans.

    Only file paths and content hashes are stored -- never raw source
    code -- so the cache is safe to keep on disk indefinitely.

    Args:
        project_hash: The SHA-256 project identifier from Contract A.
        file_hashes: A mapping of relative file path to the SHA-256
            hash of that file's stripped content.
    """
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_path = CACHE_DIR / f"{project_hash}.json"
    cache_entry = {
        "project_hash": project_hash,
        "last_scan": _utc_now_iso(),
        "file_hashes": file_hashes,
    }
    cache_path.write_text(json.dumps(cache_entry, indent=2), encoding="utf-8")
    logger.debug("Cache saved to %s", cache_path)


def _write_report(report: Dict[str, Any], output_file: Optional[str]) -> None:
    """Write the final report to `output_file`, or print it to stdout.

    Args:
        report: The JSON-serializable report to output.
        output_file: Destination file path, or None to print to stdout.
    """
    text = json.dumps(report, indent=2)
    if output_file:
        try:
            Path(output_file).write_text(text, encoding="utf-8")
            logger.info("Report written to %s", output_file)
            return
        except OSError as exc:
            logger.error(
                "Could not write report to %s: %s; printing to stdout instead.",
                output_file, exc,
            )
    print(text)


def _utc_now_iso() -> str:
    """Return the current UTC time as an ISO 8601 string with a 'Z' suffix."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _get_mock_manifest(project_index: Dict[str, Any]) -> Dict[str, Any]:
    """Return a mock Contract B payload for local development and testing.

    Used in place of the proprietary FSA when the `fsa` package is not
    installed, so the full client pipeline (validation, server call,
    report generation) can be exercised end-to-end before the FSA is
    available.

    Args:
        project_index: The validated Contract A payload.

    Returns:
        A Contract B payload with a single sample BROKEN_AUTH finding.
    """
    return {
        "contract_version": "1.0.0",
        "project_hash": project_index["project_identifier"],
        "generated_at": _utc_now_iso(),
        "analysis_metadata": {
            "scanner_version": "0.0.1-mock",
            "files_analyzed": len(project_index.get("files", [])),
            "analysis_duration_seconds": 0.01,
            "target_tracks": ["web2"],
        },
        "findings": [
            {
                "id": "FSA-BAUTH-001",
                "file_path": "src/controllers/payment.js",
                "line_start": 12,
                "line_end": 18,
                "vulnerability_class": "BROKEN_AUTH",
                "severity": "HIGH",
                "code_snippet": "async function processPayment(amount, userId) { ... }",
                "description": "Mock finding: Missing authorization check.",
                "fix_principle": "Add authentication middleware.",
                "confidence": 0.95,
            }
        ],
    }


# ---------------------------------------------------------------------------
# Standalone execution (for testing)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print(
            "Usage: python orchestrator.py /path/to/project [--output report.json] [--debug]")
        sys.exit(EXIT_GENERAL_ERROR)

    cli_project_path = sys.argv[1]
    cli_output_file: Optional[str] = None
    cli_debug = False

    # Simple arg parsing (not full argparse) -- this block exists only
    # for ad-hoc local testing; the real CLI entry point is ose.py.
    if "--output" in sys.argv:
        idx = sys.argv.index("--output")
        if idx + 1 < len(sys.argv):
            cli_output_file = sys.argv[idx + 1]
    if "--debug" in sys.argv:
        cli_debug = True

    sys.exit(run_audit(cli_project_path, cli_output_file, cli_debug))
