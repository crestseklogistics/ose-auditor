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
import getpass
import json
import logging
import sys
import time
import urllib.request
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


__version__ = "1.1.6"

# ---------------------------------------------------------------------------
# Terminal output helpers (coloured, no dependencies)
# ---------------------------------------------------------------------------


def _ok(msg: str) -> None:
    """Print a green checkmark success message."""
    sys.stderr.write(f"\033[32m✓\033[0m {msg}\n")


def _info(msg: str) -> None:
    """Print a blue dot informational message."""
    sys.stderr.write(f"\033[36m·\033[0m {msg}\n")


def _warn(msg: str) -> None:
    """Print a yellow exclamation warning message."""
    sys.stderr.write(f"\033[33m!\033[0m {msg}\n")


def _err(msg: str) -> None:
    """Print a red cross error message."""
    sys.stderr.write(f"\033[31m✗\033[0m {msg}\n")


def _dim(msg: str) -> None:
    """Print a dimmed separator line."""
    sys.stderr.write(f"\033[2m│\033[0m {msg}\n")


def _check_for_updates() -> None:
    """Check PyPI for a newer version once per day. Silent on any error.

    Writes to stderr only, and only when stdout is a TTY, so JSON
    piping (``ose audit . > report.json``) is never contaminated.
    """
    if not sys.stdout.isatty():
        return

    config_dir = Path.home() / ".ose"
    config_file = config_dir / "config.json"

    config: dict = {}
    try:
        if config_file.exists():
            with open(config_file, "r", encoding="utf-8") as fh:
                config = json.load(fh)
    except Exception:
        pass

    now = int(time.time())
    if now - config.get("last_update_check", 0) < 86400:
        return

    config["last_update_check"] = now
    try:
        config_dir.mkdir(parents=True, exist_ok=True)
        with open(config_file, "w", encoding="utf-8") as fh:
            json.dump(config, fh, indent=2)
    except Exception:
        pass

    try:
        req = urllib.request.Request(
            "https://pypi.org/pypi/ose-auditor/json",
            headers={"User-Agent": f"ose-auditor/{__version__}/update-check"},
        )
        with urllib.request.urlopen(req, timeout=2) as resp:
            data = json.loads(resp.read().decode())
        latest = data.get("info", {}).get("version", "")
        if not latest:
            return

        def _parse(v: str) -> tuple:
            try:
                return tuple(int(x) for x in v.split("."))
            except Exception:
                return (0,)

        if _parse(latest) > _parse(__version__):
            sys.stderr.write(
                f"\n\033[33m[ose]\033[0m Update available: "
                f"v{__version__} → \033[32mv{latest}\033[0m\n"
                f"      Run: \033[36mpipx upgrade ose-auditor\033[0m\n\n"
            )
    except Exception:
        pass


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
    try:
        from rich.logging import RichHandler
        logging.basicConfig(
            level=level,
            format="%(message)s",
            datefmt="[%X]",
            handlers=[RichHandler(rich_tracebacks=True, show_path=False)],
        )
    except ImportError:
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
        description=(
            "OSE Auditor: audit a project and produce a report.",
            "Detects broken auth, double-spend races, unchecked payment calls, and more."
        ),
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

    subparsers.add_parser(
        "login",
        help="Log in to OSE Auditor and save your API key.",
    ).set_defaults(command="login")

    subparsers.add_parser(
        "signup",
        help="Create a new OSE Auditor account.",
    ).set_defaults(command="signup")

    subparsers.add_parser(
        "logout",
        help="Log out and remove your locally saved API key.",
    ).set_defaults(command="logout")

    subparsers.add_parser(
        "whoami",
        help="Show which account is currently logged in.",
    ).set_defaults(command="whoami")

    subparsers.add_parser(
        "buy",
        help="Purchase a credit pack to run more audits.",
    ).set_defaults(command="buy")

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


def _prompt_credentials() -> tuple[str, str]:
    """Prompt for an email and password on the terminal.

    Uses :func:`getpass.getpass` for the password so it is never echoed
    or left in shell history.

    :return: A ``(email, password)`` tuple.
    :rtype: tuple[str, str]
    """
    sys.stderr.write("\033[2m──────────────────────────────\033[0m\n")
    email = input("Email: ").strip()
    password = getpass.getpass("Password: ")
    sys.stderr.write("\033[2m──────────────────────────────\033[0m\n")
    return email, password


def _run_buy() -> int:
    """Interactive credit pack purchase. Prints a Flutterwave URL to stdout.

    Flow:
      1. Confirm the user is logged in.
      2. Show available packs in a numbered menu.
      3. Confirm selection.
      4. Print the checkout URL — payment is completed in the browser.
      5. The Node.js webhook on api.crestsek.com credits the account
         automatically after payment; the user runs ``ose whoami`` to confirm.
    """
    identity = orchestrator.whoami(verify=False)
    if not identity or not identity.get("user_id"):
        _warn("You must be logged in first.")
        _info("Run: ose login")
        return EXIT_GENERAL_ERROR

    user_id = identity["user_id"]

    # Pack definitions — base URLs are the source of truth in billing.py
    # (server-side). The CLI fetches the personalised URL from the server
    # so there is a single definition of pack links in the codebase.
    PACKS = [
        ("starter",    " $5.00",   50,   "k4vnhabz2rua"),
        ("pro_hacker", "$25.00",  300,   "0uyg1qynjtnf"),
        ("enterprise", "$100.00", 1500,  "sidx1mpgltvx"),
    ]

    sys.stderr.write("\n")
    while True:
        sys.stderr.write("\033[1m  Credit packs\033[0m\n")
        sys.stderr.write(
            "\033[2m  ─────────────────────────────────────────\033[0m\n")
        for i, (name, price, credits, _) in enumerate(PACKS, 1):
            label = name.replace("_", " ").title()
            sys.stderr.write(
                f"  \033[36m[{i}]\033[0m {label:<15} \033[33m{price}\033[0m"
                f"   {credits:>4} credits\n"
            )
        sys.stderr.write("  \033[2m[4] Cancel\033[0m\n")
        sys.stderr.write(
            "\033[2m  ─────────────────────────────────────────\033[0m\n\n")

        choice = input("  Select (1-4): ").strip()
        if choice in ("4", "q", "cancel", ""):
            _info("Cancelled.")
            return EXIT_SUCCESS
        if choice not in ("1", "2", "3"):
            _warn("Please enter 1, 2, 3, or 4.")
            sys.stderr.write("\n")
            continue

        idx = int(choice) - 1
        pack_name, price, credits, slug = PACKS[idx]
        label = pack_name.replace("_", " ").title()

        sys.stderr.write(
            f"\n  You selected: \033[1m{label}\033[0m — "
            f"{credits} credits for \033[33m{price}\033[0m\n\n"
        )
        confirm = input("  Proceed to checkout? (y/n): ").strip().lower()
        if confirm != "y":
            sys.stderr.write("\n")
            continue

        url = f"https://flutterwave.com/pay/{slug}?user_id={user_id}"
        sys.stderr.write("\n")
        sys.stderr.write("  \033[1mPay here:\033[0m\n\n")
        sys.stderr.write(f"    \033[36m{url}\033[0m\n\n")
        _info("After payment your credits update automatically.")
        _info("Run \033[1mose whoami\033[0m to confirm your new balance.")
        sys.stderr.write("\n")
        return EXIT_SUCCESS


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
    _check_for_updates()

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
            _ok("Audit completed successfully.")
            return EXIT_SUCCESS

        _err(f"Audit failed (exit code {result_code}).")
        return EXIT_AUDIT_FAILURE

    if args.command in ("login", "signup"):
        configure_logging(debug=False)
        email, password = _prompt_credentials()

        try:
            if args.command == "signup":
                orchestrator.signup(email, password)
                _ok(f"Account created. Logged in as {email}.")
            else:
                orchestrator.login(email, password)
                _ok(
                    f"Logged in as {email}.")
        except orchestrator.ServerCommunicationError as exc:
            _err(str(exc))
            return EXIT_GENERAL_ERROR
        except Exception:  # noqa: BLE001 - top-level safety net for CLI
            logger.exception("Unexpected error during %s.", args.command)
            return EXIT_GENERAL_ERROR

        return EXIT_SUCCESS

    if args.command == "logout":
        configure_logging(debug=False)
        if orchestrator.logout():
            _ok("Logged out.")
        else:
            _warn("Not logged in.")
        return EXIT_SUCCESS

    if args.command == "whoami":
        configure_logging(debug=False)
        try:
            identity = orchestrator.whoami()
        except Exception:  # noqa: BLE001 - top-level safety net for CLI
            logger.exception("Unexpected error while checking identity.")
            return EXIT_GENERAL_ERROR

        if identity:
            # _ok(f"Logged in as {identity.get('email', 'unknown')}")                            
            _ok(f"Logged in as \033[1m{identity.get('email', 'unknown')}\033[0m")
            credits = identity.get("credits")
            if credits is not None:
                _info(f"Credits remaining: {credits}")
        else:
            _warn("Not logged in. Run `ose login` (or `ose signup`) first.")
        return EXIT_SUCCESS
    if args.command == "buy":
        configure_logging(debug=False)
        return _run_buy()

    # Unreachable in practice since argparse restricts valid subcommands,
    # but kept as a defensive fallback.
    parser.print_help(sys.stderr)
    return EXIT_GENERAL_ERROR


if __name__ == "__main__":
    sys.exit(main())
