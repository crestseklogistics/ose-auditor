"""OSE Auditor - File System Pre-Processor (parser.py).

This module implements the File System Pre-Processor for the OSE Auditor
project. It traverses a target Node.js (JavaScript/TypeScript) project,
filters out irrelevant directories and files, strips comments and
excessive whitespace from source files, computes cryptographic hashes,
and assembles a Project Source Index (Contract A) JSON payload.

The resulting payload is intended to be consumed locally by the
proprietary Financial Semantic Analyzer (FSA). This module itself is
open source, self-contained, and depends only on the Python standard
library. It performs no network I/O and no telemetry.

License: MIT

Typical standalone usage::

    $ python parser.py /path/to/project --output report.json
    $ python parser.py /path/to/project --dry-run --debug

Typical programmatic usage::

    from client.parser import OseParser

    parser = OseParser("/path/to/project")
    payload = parser.scan()
"""

from __future__ import annotations
import subprocess
import shutil

import argparse
import hashlib
import json
import logging
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

__all__ = ["OseParser"]

#: Module logger. Configured by the CLI entry point; library consumers
#: may configure it themselves.
logger = logging.getLogger("ose.parser")

#: Contract A schema version produced by this parser.
CONTRACT_VERSION = "1.0.0"

#: Directory names that are always skipped during traversal.
IGNORE_DIRS = frozenset(
    {
        "node_modules",
        ".git",
        "dist",
        "build",
        "coverage",
        ".next",
        ".vscode",
        "__tests__",
    }
)

#: File extensions eligible for processing, mapped to their language tag.
ALLOWED_EXTENSIONS: Dict[str, str] = {
    ".js": "js",
    ".ts": "ts",
}

#: Maximum number of files processed in a single scan before truncation.
MAX_FILES = 10_000

#: Path fragments that, if present, mark a file as a test file.
TEST_PATH_MARKERS = ("__tests__", "test/", ".spec.")

#: Path fragments that, if present, mark a file as third-party code.
THIRD_PARTY_PATH_MARKERS = ("vendor/", "third_party/", "external/")

# ---------------------------------------------------------------------------
# Regex patterns used for comment stripping.
#
# The strategy below tokenizes the source on a coarse level: string
# literals (single/double/backtick-quoted), single-line comments, and
# block comments. By matching strings *before* comments in an alternation,
# we ensure that comment-like sequences inside strings are preserved
# untouched, since the regex engine will match and "consume" the string
# token first.
# ---------------------------------------------------------------------------

# Matches (in priority order):
#   1. A double-quoted string (handles escaped characters).
#   2. A single-quoted string (handles escaped characters).
#   3. A backtick template literal (handles escaped characters; does not
#      attempt to parse nested ${...} expressions specially, since for
#      the purposes of comment-stripping this is sufficient).
#   4. A single-line comment.
#   5. A block comment.
_STRING_OR_COMMENT_RE = re.compile(
    r"""
    (?P<dquote>"(?:\\.|[^"\\])*")          # double-quoted string
    |(?P<squote>'(?:\\.|[^'\\])*')         # single-quoted string
    |(?P<backtick>`(?:\\.|[^`\\])*`)       # template literal
    |(?P<line_comment>//[^\n]*)            # single-line comment
    |(?P<block_comment>/\*.*?\*/)          # block comment (non-greedy)
    """,
    re.VERBOSE | re.DOTALL,
)

#: Collapses runs of horizontal whitespace (spaces/tabs) into a single space.
_MULTI_SPACE_RE = re.compile(r"[ \t]+")

#: Matches trailing whitespace at the end of a line.
_TRAILING_WS_RE = re.compile(r"[ \t]+$", re.MULTILINE)

#: Collapses three or more consecutive newlines down to two (i.e., a
#: single blank line) to avoid leaving large gaps where comments were
#: removed.
_MULTI_BLANK_LINE_RE = re.compile(r"\n{3,}")


class OseParser:
    """Traverses a project directory and builds a Project Source Index.

    The :class:`OseParser` is the primary public interface of this module.
    It walks a project's file tree, ignoring known non-source directories,
    reads and normalizes JavaScript/TypeScript source files, and produces
    a JSON-serializable payload conforming to Contract A.

    :param root_path: Absolute or relative path to the project root to
        scan. It is resolved to an absolute path internally.
    :type root_path: str
    :param ignore_dirs: Optional list of additional directory names to
        ignore, merged with the built-in :data:`IGNORE_DIRS` set.
    :type ignore_dirs: Optional[List[str]]
    """

    def __init__(
        self, root_path: str, ignore_dirs: Optional[List[str]] = None
    ) -> None:
        """Initialize the parser with a project root and ignore list.

        :param root_path: Path to the project root directory to scan.
        :type root_path: str
        :param ignore_dirs: Additional directory names to ignore on top
            of the built-in defaults.
        :type ignore_dirs: Optional[List[str]]
        :raises ValueError: If ``root_path`` does not exist or is not a
            directory.
        """
        resolved = Path(root_path).expanduser().resolve()

        if not resolved.exists():
            raise ValueError(f"Project path does not exist: {resolved}")
        if not resolved.is_dir():
            raise ValueError(f"Project path is not a directory: {resolved}")

        self.root_path: Path = resolved
        self._ignore_dirs = set(IGNORE_DIRS)
        if ignore_dirs:
            self._ignore_dirs.update(ignore_dirs)

        # Aggregated counters / collections populated during scan().
        self._errors: List[Dict[str, str]] = []
        self._total_ignored_dirs: int = 0
        self._total_ignored_files: int = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self) -> Dict[str, Any]:
        """Run a full scan of the project and return Contract A payload.

        Traverses the project directory tree, filters out ignored
        directories and non-source files, processes each eligible
        JavaScript/TypeScript file (reading, stripping comments,
        hashing), and assembles the final JSON-serializable result
        dictionary.

        :return: A dictionary conforming to the Contract A schema,
            containing ``contract_version``, ``project_identifier``,
            ``generated_at``, ``project_metadata``, ``files``,
            ``summary``, and ``truncated`` keys.
        :rtype: Dict[str, Any]
        """
        start_time = time.monotonic()
        logger.info("Starting scan of project root: %s", self.root_path)

        # Reset per-scan state in case scan() is called multiple times
        # on the same instance.
        self._errors = []
        self._total_ignored_dirs = 0
        self._total_ignored_files = 0

        candidate_files = self._collect_candidate_files()
        total_discovered = len(candidate_files)

        truncated = False
        if total_discovered > MAX_FILES:
            logger.warning(
                "Discovered %d files, exceeding limit of %d. "
                "Truncating to first %d files (lexicographic order).",
                total_discovered,
                MAX_FILES,
                MAX_FILES,
            )
            candidate_files = candidate_files[:MAX_FILES]
            truncated = True

        file_entries: List[Dict[str, Any]] = []
        total_size_bytes = 0

        for file_path in candidate_files:
            entry = self._process_file(file_path)
            if entry is None:
                # Error already logged/recorded inside _process_file.
                continue
            file_entries.append(entry)
            total_size_bytes += entry["original_size"]

        scan_duration = round(time.monotonic() - start_time, 4)

        payload: Dict[str, Any] = {
            "contract_version": CONTRACT_VERSION,
            "project_identifier": self._compute_project_identifier(),
            "generated_at": self._utc_timestamp(),
            "project_metadata": self._get_project_metadata(),
            "files": file_entries,
            "summary": {
                "total_files": len(file_entries),
                "total_ignored": self._total_ignored_dirs
                + self._total_ignored_files,
                "total_errors": len(self._errors),
                "total_size_bytes": total_size_bytes,
                "scan_duration_seconds": scan_duration,
                "errors": self._errors,
            },
            "truncated": truncated,
        }
        # Optional Semgrep pass — runs only when semgrep is installed and
        # cyber_rules/ exists next to this file. Results are attached under
        # "semgrep_findings" and never alter the files[] list or Contract A
        # validation, so the server pipeline is unaffected if semgrep is absent.
        semgrep_findings = self._run_semgrep()
        if semgrep_findings is not None:
            payload["semgrep_findings"] = semgrep_findings

        logger.info(
            "Scan complete: %d files processed, %d errors, %.4fs elapsed.",
            len(file_entries),
            len(self._errors),
            scan_duration,
        )

        return payload

    # ------------------------------------------------------------------
    # Traversal helpers
    # ------------------------------------------------------------------

    def _collect_candidate_files(self) -> List[Path]:
        """Walk the project tree and collect eligible source files.

        Performs a recursive, depth-first traversal of the project root,
        pruning ignored directories before descending into them, and
        collecting files whose extension is in :data:`ALLOWED_EXTENSIONS`.

        The returned list is sorted in lexicographic order (by relative
        path) so that truncation behavior is deterministic.

        :return: Sorted list of absolute paths to eligible source files.
        :rtype: List[Path]
        """
        collected: List[Path] = []
        self._walk(self.root_path, collected)
        collected.sort(key=lambda p: str(p.relative_to(self.root_path)))
        return collected

    def _walk(self, directory: Path, collected: List[Path]) -> None:
        """Recursively walk ``directory``, appending eligible files.

        :param directory: The directory currently being traversed.
        :type directory: Path
        :param collected: Mutable list accumulating eligible file paths.
        :type collected: List[Path]
        :return: ``None``
        :rtype: None
        """
        try:
            entries = sorted(directory.iterdir(), key=lambda p: p.name)
        except (PermissionError, OSError) as exc:
            logger.error("Could not list directory %s: %s", directory, exc)
            self._errors.append(
                {"path": str(directory), "error": str(exc)}
            )
            return

        for entry in entries:
            if entry.is_dir():
                if self._should_ignore(entry):
                    logger.debug("Skipping ignored directory: %s", entry)
                    self._total_ignored_dirs += 1
                    continue
                self._walk(entry, collected)
            elif entry.is_file():
                if entry.suffix in ALLOWED_EXTENSIONS:
                    collected.append(entry)
                else:
                    self._total_ignored_files += 1

    def _should_ignore(self, path: Path) -> bool:
        """Determine whether a directory should be skipped during scan.

        :param path: The directory path to evaluate.
        :type path: Path
        :return: ``True`` if the directory's name matches an entry in
            the ignore set, ``False`` otherwise.
        :rtype: bool
        """
        return path.name in self._ignore_dirs

    # ------------------------------------------------------------------
    # File processing
    # ------------------------------------------------------------------

    def _process_file(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """Read, normalize, and hash a single source file.

        Reads the file as UTF-8 text, strips comments and excessive
        whitespace, computes a SHA-256 hash of the stripped content,
        and builds the file entry dictionary for Contract A. If the
        file cannot be read (e.g., invalid encoding or permissions
        error), the error is logged and recorded, and ``None`` is
        returned so the caller can skip this file without aborting
        the scan.

        :param file_path: Absolute path to the file to process.
        :type file_path: Path
        :return: A dictionary describing the file per Contract A, or
            ``None`` if the file could not be processed.
        :rtype: Optional[Dict[str, Any]]
        """
        relative_path = file_path.relative_to(self.root_path)
        relative_str = relative_path.as_posix()

        try:
            original_bytes = file_path.read_bytes()
        except (OSError, PermissionError) as exc:
            logger.error("Failed to read file %s: %s", relative_str, exc)
            self._errors.append({"path": relative_str, "error": str(exc)})
            return None

        try:
            content = original_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            logger.error(
                "Failed to decode file %s as UTF-8: %s", relative_str, exc
            )
            self._errors.append({"path": relative_str, "error": str(exc)})
            return None

        original_size = len(original_bytes)

        try:
            stripped_content = self._strip_comments_and_whitespace(content)
        except Exception as exc:  # noqa: BLE001 - defensive per-file guard
            logger.error(
                "Failed to normalize file %s: %s", relative_str, exc
            )
            self._errors.append({"path": relative_str, "error": str(exc)})
            return None

        stripped_bytes = stripped_content.encode("utf-8")
        stripped_size = len(stripped_bytes)
        content_hash = hashlib.sha256(stripped_bytes).hexdigest()

        language = ALLOWED_EXTENSIONS[file_path.suffix]

        logger.debug("Processed file: %s", relative_str)

        return {
            "path_relative": relative_str,
            "language": language,
            "hash": content_hash,
            "stripped_content": stripped_content,
            "original_size": original_size,
            "stripped_size": stripped_size,
            "is_test_file": self._is_test_file(relative_str),
            "is_third_party": self._is_third_party_file(relative_str),
        }

    @staticmethod
    def _is_test_file(relative_path: str) -> bool:
        """Determine whether a relative path indicates a test file.

        :param relative_path: POSIX-style relative path of the file.
        :type relative_path: str
        :return: ``True`` if the path contains any known test markers.
        :rtype: bool
        """
        return any(marker in relative_path for marker in TEST_PATH_MARKERS)

    @staticmethod
    def _is_third_party_file(relative_path: str) -> bool:
        """Determine whether a relative path indicates third-party code.

        :param relative_path: POSIX-style relative path of the file.
        :type relative_path: str
        :return: ``True`` if the path contains any known third-party
            directory markers.
        :rtype: bool
        """
        return any(
            marker in relative_path for marker in THIRD_PARTY_PATH_MARKERS
        )

    # ------------------------------------------------------------------
    # Content normalization
    # ------------------------------------------------------------------

    def _strip_comments_and_whitespace(self, content: str) -> str:
        """Strip comments and collapse excessive whitespace from source.

        Removes JavaScript/TypeScript single-line (``//``) and block
        (``/* ... */``) comments while carefully preserving the contents
        of string literals (single-quoted, double-quoted, and template
        literals) so that comment-like sequences embedded in strings are
        never altered. After comment removal, runs of horizontal
        whitespace are collapsed to a single space, trailing whitespace
        on each line is removed, and runs of three or more consecutive
        blank lines are collapsed to a single blank line.

        :param content: The raw, original file content.
        :type content: str
        :return: The normalized (stripped) content.
        :rtype: str
        """

        def _replace(match: re.Match[str]) -> str:
            # If the match is a string literal, return it unchanged so
            # its contents (which may resemble comments) are preserved.
            if (
                match.group("dquote") is not None
                or match.group("squote") is not None
                or match.group("backtick") is not None
            ):
                return match.group(0)

            # Otherwise, the match is a comment (line or block) and
            # should be removed entirely. A single space is substituted
            # in place of a block comment to avoid accidentally joining
            # adjacent tokens (e.g., `foo/* c */bar` -> `foo bar`).
            if match.group("line_comment") is not None:
                return ""
            if match.group("block_comment") is not None:
                return " "
            return ""

        without_comments = _STRING_OR_COMMENT_RE.sub(_replace, content)

        # Collapse horizontal whitespace runs into a single space.
        collapsed = _MULTI_SPACE_RE.sub(" ", without_comments)

        # Strip trailing whitespace from each line.
        no_trailing_ws = _TRAILING_WS_RE.sub("", collapsed)

        # Collapse 3+ consecutive newlines (i.e., multiple blank lines)
        # down to a single blank line.
        normalized = _MULTI_BLANK_LINE_RE.sub("\n\n", no_trailing_ws)

        return normalized.strip("\n")

    # ------------------------------------------------------------------
    # Metadata helpers
    # ------------------------------------------------------------------

    def _get_project_metadata(self) -> Dict[str, Any]:
        """Build the ``project_metadata`` section of Contract A.

        Attempts to read ``package.json`` from the project root to
        extract the project's ``name`` and ``version``. If
        ``package.json`` is missing, unreadable, or malformed, those
        fields are set to ``None`` and the issue is logged at DEBUG
        level (this is not treated as a scan error since
        ``package.json`` is optional).

        :return: A dictionary with ``name``, ``version``, and
            ``language`` keys.
        :rtype: Dict[str, Any]
        """
        name: Optional[str] = None
        version: Optional[str] = None

        package_json_path = self.root_path / "package.json"
        if package_json_path.is_file():
            try:
                raw = package_json_path.read_text(encoding="utf-8")
                data = json.loads(raw)
                name = data.get("name")
                version = data.get("version")
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                logger.debug(
                    "Could not read project metadata from package.json: %s",
                    exc,
                )

        return {
            "name": name,
            "version": version,
            "language": "nodejs",
        }

    def _run_semgrep(self) -> Optional[List[Dict[str, Any]]]:
        """Run Semgrep with the bundled cyber_rules/ YAML rules, if available.

        Returns a list of finding dicts, or None if semgrep is not installed
        or no rule files exist. Never raises -- errors are logged and swallowed
        so a missing semgrep installation never breaks the core scan.
        """
        if shutil.which("semgrep") is None:
            logger.debug("semgrep not found on PATH; skipping Semgrep pass.")
            return None

        rules_dir = Path(__file__).parent / "cyber_rules"
        if not rules_dir.is_dir():
            logger.debug(
                "client/cyber_rules/ not found; skipping Semgrep pass.")
            return None

        cmd = [
            "semgrep",
            "--config", str(rules_dir),
            "--json",
            "--quiet",
            str(self.root_path),
        ]
        logger.info("Running Semgrep: %s", " ".join(cmd))

        try:
            result = subprocess.run(  # noqa: S603 — cmd is fully constructed here, no user input
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except FileNotFoundError:
            logger.debug("semgrep binary disappeared between check and run.")
            return None
        except subprocess.TimeoutExpired:
            logger.warning("Semgrep timed out after 120s; skipping results.")
            return None
        except OSError as exc:
            logger.warning("Semgrep execution error: %s", exc)
            return None

        # semgrep exits 1 when findings exist
        if result.returncode not in (0, 1):
            logger.warning(
                "Semgrep exited %d; stderr: %s", result.returncode, result.stderr[:400]
            )
            return None

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            logger.warning("Could not parse Semgrep JSON output: %s", exc)
            return None

        raw_results = data.get("results", [])
        findings = []
        for r in raw_results:
            meta = r.get("extra", {}).get("metadata", {})
            findings.append({
                "rule_id": r.get("check_id", ""),
                "file_path": str(
                    Path(r.get("path", "")).relative_to(self.root_path)
                    if r.get("path", "").startswith(str(self.root_path))
                    else r.get("path", "")
                ),
                "line_start": r.get("start", {}).get("line", 0),
                "line_end": r.get("end", {}).get("line", 0),
                "message": r.get("extra", {}).get("message", ""),
                "severity": r.get("extra", {}).get("severity", "WARNING"),
                "ose_class": meta.get("ose_class", ""),
            })

        logger.info("Semgrep pass complete: %d finding(s).", len(findings))
        return findings

    def _compute_project_identifier(self) -> str:
        """Compute an anonymized identifier for the project root.

        The absolute path of the project root is hashed with SHA-256 so
        that the identifier is stable across repeated scans of the same
        project, while never exposing the user's actual file system
        path in the output payload.

        :return: A SHA-256 hex digest derived from the absolute project
            root path.
        :rtype: str
        """
        path_bytes = str(self.root_path).encode("utf-8")
        return hashlib.sha256(path_bytes).hexdigest()

    @staticmethod
    def _utc_timestamp() -> str:
        """Return the current UTC time formatted as ISO 8601.

        :return: Current UTC timestamp, e.g. ``"2026-06-17T12:34:56Z"``.
        :rtype: str
        """
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ---------------------------------------------------------------------------
# Standalone CLI entry point
# ---------------------------------------------------------------------------


def _configure_logging(debug: bool) -> None:
    """Configure logging for standalone execution of this module.

    Logs are sent to ``stderr`` so that JSON output written to
    ``stdout`` remains uncontaminated and pipeable.

    :param debug: Whether to enable DEBUG-level logging.
    :type debug: bool
    :return: ``None``
    :rtype: None
    """
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        stream=sys.stderr,
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def _build_arg_parser() -> argparse.ArgumentParser:
    """Build the argument parser for standalone CLI execution.

    :return: Configured :class:`argparse.ArgumentParser` instance.
    :rtype: argparse.ArgumentParser
    """
    arg_parser = argparse.ArgumentParser(
        prog="parser.py",
        description="OSE Auditor File System Pre-Processor: scans a "
        "Node.js project and produces a Project Source Index (Contract A).",
    )
    arg_parser.add_argument(
        "project_path",
        type=str,
        help="Path to the project to scan.",
    )
    arg_parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="Path to save the JSON report. If omitted, the report is "
        "printed to stdout.",
    )
    arg_parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Print the JSON to stdout and exit without saving a file.",
    )
    arg_parser.add_argument(
        "--debug",
        "-d",
        action="store_true",
        default=False,
        help="Enable debug logging.",
    )
    return arg_parser


def main(argv: Optional[List[str]] = None) -> int:
    """Run the parser as a standalone command-line tool.

    Parses command-line arguments, configures logging, runs a scan via
    :class:`OseParser`, and either prints the resulting JSON payload to
    stdout or writes it to the file specified by ``--output``.

    :param argv: Optional list of argument strings to parse instead of
        ``sys.argv[1:]``. Primarily useful for testing.
    :type argv: Optional[List[str]]
    :return: Process exit code (``0`` on success, ``1`` on error).
    :rtype: int
    """
    arg_parser = _build_arg_parser()
    args = arg_parser.parse_args(argv)

    _configure_logging(debug=args.debug)

    try:
        ose_parser = OseParser(args.project_path)
    except ValueError as exc:
        logger.error("Initialization error: %s", exc)
        return 1

    try:
        payload = ose_parser.scan()
    except Exception:  # noqa: BLE001 - top-level safety net for CLI
        logger.exception("Unexpected error occurred during scan.")
        return 1

    json_output = json.dumps(payload, indent=2, ensure_ascii=False)

    if args.dry_run or not args.output:
        print(json_output)
        return 0

    try:
        output_path = Path(args.output).expanduser().resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json_output, encoding="utf-8")
        logger.info("Report written to: %s", output_path)
    except OSError as exc:
        logger.error("Failed to write output file: %s", exc)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
