#!/usr/bin/env python3
"""OSE Auditor command-line entry point.

This module implements the ``ose`` command-line interface, which is the
primary entry point for running an OSE audit against a target project.
It is responsible solely for argument parsing, logging configuration,
and dispatching to the :mod:`client.orchestrator` module, which contains
the actual audit logic.

Typical usage::

    $ ose audit /path/to/project
    $ ose audit /path/to/project --output report.json
    $ ose audit /path/to/project --debug
    $ ose --version

Exit codes:
    0: Success.
    1: General error (invalid arguments, missing project path, I/O errors).
    2: Audit failure (the orchestrator reported a failed audit run).
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Optional, Sequence

try:
    # Preferred: orchestrator lives alongside this module in the
    # ``client`` package.
    from client import orchestrator
except ImportError:  # pragma: no cover - fallback for direct script execution
    # Allows running `python ose.py` directly from within the `client`
    # directory without the package being on sys.path as `client`.
    import orchestrator  # type: ignore


__version__ = "1.0.0"

#: Exit code constants for clarity and reuse.
EXIT_SUCCESS = 0
EXIT_GENERAL_ERROR = 1
EXIT_AUDIT_FAILURE = 2

logger = logging.getLogger("ose")


def configure_logging(debug: bool) -> None:
    """Configure the root logging handler for the CLI.

    Sets up a stream handler targeting ``stderr`` with a consistent
    timestamped format. The log level is set to ``DEBUG`` when the
    ``debug`` flag is enabled, otherwise ``INFO``.

    :param debug: Whether to enable verbose debug-level logging.
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


def build_parser() -> argparse.ArgumentParser:
    """Build and return the top-level argument parser for the CLI.

    Constructs an :class:`argparse.ArgumentParser` configured with a
    ``--version`` flag and an ``audit`` subcommand. The ``audit``
    subcommand accepts a required positional ``project_path`` along
    with optional ``--output`` and ``--debug`` flags.

    :return: The configured argument parser.
    :rtype: argparse.ArgumentParser
    """
    parser = argparse.ArgumentParser(
        prog="ose",
        description="OSE Auditor: audit a project and produce a report.",
    )
    parser.add_argument(
        "--version",
        "-v",
        action="version",
        version=f"%(prog)s {__version__}",
        help="Show the program's version number and exit.",
    )

    subparsers = parser.add_subparsers(
        title="commands",
        dest="command",
        metavar="<command>",
    )

    audit_parser = subparsers.add_parser(
        "audit",
        help="Run an audit against a project.",
        description="Run an audit against the specified project path.",
    )
    audit_parser.add_argument(
        "project_path",
        type=str,
        help="Path to the project to audit.",
    )
    audit_parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="Path to save the JSON report. If omitted, the report is "
        "printed to stdout.",
    )
    audit_parser.add_argument(
        "--debug",
        "-d",
        action="store_true",
        default=False,
        help="Enable debug logging.",
    )
    audit_parser.set_defaults(command="audit")

    return parser


def validate_project_path(project_path: str) -> Path:
    """Validate that the given project path exists and is a directory.

    :param project_path: The raw path string supplied by the user.
    :type project_path: str
    :raises ValueError: If the path does not exist or is not a directory.
    :return: The resolved, validated :class:`~pathlib.Path` object.
    :rtype: pathlib.Path
    """
    path = Path(project_path).expanduser().resolve()

    if not path.exists():
        raise ValueError(f"Project path does not exist: {path}")
    if not path.is_dir():
        raise ValueError(f"Project path is not a directory: {path}")

    return path


def validate_output_path(output_path: Optional[str]) -> Optional[Path]:
    """Validate that the parent directory of the output path is writable.

    If ``output_path`` is ``None``, this function is a no-op and returns
    ``None``, indicating the report should be printed to stdout.

    :param output_path: The raw output path string supplied by the user,
        or ``None`` if not provided.
    :type output_path: Optional[str]
    :raises ValueError: If the parent directory does not exist or is not
        a directory.
    :return: The resolved :class:`~pathlib.Path` for the output file, or
        ``None`` if no output path was provided.
    :rtype: Optional[pathlib.Path]
    """
    if output_path is None:
        return None

    path = Path(output_path).expanduser().resolve()
    parent = path.parent

    if not parent.exists():
        raise ValueError(f"Output directory does not exist: {parent}")
    if not parent.is_dir():
        raise ValueError(f"Output parent path is not a directory: {parent}")

    return path


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Parse CLI arguments and execute the requested OSE Auditor command.

    This is the primary entry point for the ``ose`` console script. It
    parses command-line arguments, configures logging, validates the
    provided paths, and delegates the actual audit work to
    :func:`client.orchestrator.run_audit`.

    :param argv: Optional sequence of command-line argument strings to
        parse instead of ``sys.argv[1:]``. Primarily useful for testing.
    :type argv: Optional[Sequence[str]]
    :return: The process exit code (0 for success, 1 for general errors,
        2 for audit failures).
    :rtype: int
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    # If no subcommand was given, default to "audit" behavior is not
    # straightforward without a project_path, so we require a command
    # explicitly. If none was provided, show help and exit with an error.
    if getattr(args, "command", None) is None:
        parser.print_help(sys.stderr)
        return EXIT_GENERAL_ERROR

    if args.command == "audit":
        configure_logging(debug=args.debug)

        try:
            project_path = validate_project_path(args.project_path)
        except ValueError as exc:
            logger.error("Invalid project path: %s", exc)
            return EXIT_GENERAL_ERROR

        try:
            output_path = validate_output_path(args.output)
        except ValueError as exc:
            logger.error("Invalid output path: %s", exc)
            return EXIT_GENERAL_ERROR

        output_str = str(output_path) if output_path is not None else None

        logger.debug("Resolved project path: %s", project_path)
        logger.debug("Resolved output path: %s", output_str)
        logger.info("Starting audit for project: %s", project_path)

        try:
            result_code = orchestrator.run_audit(
                str(project_path), output_str, args.debug
            )
        except Exception:  # noqa: BLE001 - top-level safety net for CLI
            logger.exception("Unexpected error occurred during audit.")
            return EXIT_GENERAL_ERROR

        if result_code == 0:
            logger.info("Audit completed successfully.")
            return EXIT_SUCCESS

        logger.error(
            "Audit failed with orchestrator exit code: %s", result_code
        )
        return EXIT_AUDIT_FAILURE

    # Unreachable in practice since argparse restricts valid subcommands,
    # but kept as a defensive fallback.
    parser.print_help(sys.stderr)
    return EXIT_GENERAL_ERROR


if __name__ == "__main__":
    sys.exit(main())
