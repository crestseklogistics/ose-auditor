#!/usr/bin/env python3
"""OSE Auditor - GitHub App audit bot (github_app/audit_bot.py).

IMPORTANT SCOPE NOTE
---------------------
This script intentionally does NOT search GitHub for arbitrary repositories
to scan. It only audits repositories that have explicitly installed the
"OSE Auditor" GitHub App and granted it access -- i.e. repos whose owners
opted in, the same model Dependabot/Snyk/CodeQL bots use. This is a
deliberate design choice: opening unsolicited PRs on repos you don't
maintain is against GitHub's policies on automated/spam content, and
publicly posting a financial-vulnerability writeup in a PR before the
maintainer has seen it is irresponsible disclosure. Don't repurpose this
script to crawl arbitrary public repos.

What it does, end to end:
    1. Mints a short-lived GitHub App installation access token (JWT ->
       installation token exchange).
    2. Lists the repositories that installation actually has access to
       (this is the consent boundary -- only repos an owner explicitly
       added to the installation appear here).
    3. For each repo: shallow-clones it, runs `ose audit`, and if the
       report contains findings with non-empty patches, opens a single
       PR per repo with the suggested changes on a dedicated branch.
    4. The PR is clearly labeled as an automated suggestion from OSE
       Auditor and explicitly asks for human review -- it is never
       auto-merged.

Required environment variables:
    GITHUB_APP_ID:           Numeric GitHub App ID.
    GITHUB_APP_PRIVATE_KEY_PATH: Path to the App's PEM private key.
    OSE_API_KEY:              OSE Server bearer token (for patch generation).

Optional:
    GITHUB_API_URL:           Defaults to https://api.github.com.
    OSE_BOT_DRY_RUN:          If "1", logs what it would do without
                               pushing branches or opening PRs.

Dependencies: PyJWT, requests, GitPython (or plain `git` CLI via subprocess
-- this implementation shells out to `git` directly to avoid an extra
dependency).
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import jwt  # PyJWT
import requests

logger = logging.getLogger("ose.github_app_bot")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

GITHUB_API_URL = os.environ.get("GITHUB_API_URL", "https://api.github.com")
DRY_RUN = os.environ.get("OSE_BOT_DRY_RUN") == "1"
PR_BRANCH_PREFIX = "ose-auditor/security-suggestions"
BOT_ATTRIBUTION = (
    "This pull request was opened automatically by **OSE Auditor** "
    "(https://ose.crestsek.com) after you installed it on this repository. "
    "It suggests fixes for findings the Financial Semantic Analyzer flagged; "
    "**please review every change carefully before merging** -- these are "
    "AI-assisted suggestions, not guaranteed-correct patches."
)

# ---------------------------------------------------------------------------
# GitHub App authentication
# ---------------------------------------------------------------------------


def _build_app_jwt(app_id: str, private_key_path: str) -> str:
    """Build a short-lived JWT identifying the GitHub App itself.

    :param app_id: The numeric GitHub App ID.
    :param private_key_path: Filesystem path to the App's PEM private key.
    :return: An encoded JWT valid for ~9 minutes (GitHub's max is 10).
    """
    private_key = Path(private_key_path).read_text(encoding="utf-8")
    now = int(time.time())
    payload = {
        "iat": now - 60,  # allow for clock drift
        "exp": now + (9 * 60),
        "iss": app_id,
    }
    return jwt.encode(payload, private_key, algorithm="RS256")


def get_installation_token(app_id: str, private_key_path: str, installation_id: str) -> str:
    """Exchange an App JWT for a scoped installation access token.

    :param app_id: The numeric GitHub App ID.
    :param private_key_path: Path to the App's PEM private key.
    :param installation_id: The installation ID to mint a token for. Each
        repo owner who installs the App gets their own installation_id;
        callers should iterate installations via `list_installations`.
    :return: A short-lived (1 hour) installation access token.
    :raises requests.HTTPError: If GitHub rejects the token request.
    """
    app_jwt = _build_app_jwt(app_id, private_key_path)
    response = requests.post(
        f"{GITHUB_API_URL}/app/installations/{installation_id}/access_tokens",
        headers={
            "Authorization": f"Bearer {app_jwt}",
            "Accept": "application/vnd.github+json",
        },
        timeout=30,
    )
    response.raise_for_status()
    return response.json()["token"]


def list_installations(app_id: str, private_key_path: str) -> List[Dict[str, Any]]:
    """List every installation of this GitHub App (i.e. every org/user that
    explicitly clicked "Install" and granted access).

    :param app_id: The numeric GitHub App ID.
    :param private_key_path: Path to the App's PEM private key.
    :return: A list of installation objects from the GitHub API.
    """
    app_jwt = _build_app_jwt(app_id, private_key_path)
    response = requests.get(
        f"{GITHUB_API_URL}/app/installations",
        headers={
            "Authorization": f"Bearer {app_jwt}",
            "Accept": "application/vnd.github+json",
        },
        timeout=30,
    )
    response.raise_for_status()
    return response.json()


def list_installation_repos(installation_token: str) -> List[Dict[str, Any]]:
    """List repositories a specific installation token actually has access to.

    This is the consent boundary: GitHub only returns repos the installing
    user explicitly selected ("All repositories" or a hand-picked list) when
    they installed the App.

    :param installation_token: A token from `get_installation_token`.
    :return: A list of repository objects.
    """
    repos: List[Dict[str, Any]] = []
    url = f"{GITHUB_API_URL}/installation/repositories"
    headers = {
        "Authorization": f"Bearer {installation_token}",
        "Accept": "application/vnd.github+json",
    }
    while url:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        data = response.json()
        repos.extend(data.get("repositories", []))
        url = response.links.get("next", {}).get("url")
    return repos


# ---------------------------------------------------------------------------
# git / clone helpers
# ---------------------------------------------------------------------------


def _run(cmd: List[str], cwd: Optional[str] = None, check: bool = True) -> subprocess.CompletedProcess:
    """Run a subprocess command, raising on non-zero exit unless told not to.

    :param cmd: Argv list.
    :param cwd: Working directory for the command.
    :param check: Whether to raise on a non-zero return code.
    :return: The completed process.
    """
    logger.debug("Running: %s", " ".join(cmd))
    return subprocess.run(
        cmd, cwd=cwd, check=check, capture_output=True, text=True
    )


def clone_repo(clone_url: str, token: str, dest_dir: str) -> str:
    """Shallow-clone a repo using an installation token for auth.

    :param clone_url: The repo's HTTPS clone URL (e.g. https://github.com/org/repo.git).
    :param token: A GitHub installation access token, used as the HTTP password.
    :param dest_dir: Directory to clone into.
    :return: The path the repo was cloned to.
    """
    authed_url = clone_url.replace("https://", f"https://x-access-token:{token}@")
    _run(["git", "clone", "--depth", "1", authed_url, dest_dir])
    return dest_dir


# ---------------------------------------------------------------------------
# Audit + patch application
# ---------------------------------------------------------------------------


def run_ose_audit(repo_path: str) -> Dict[str, Any]:
    """Run `ose audit` against a cloned repo and return the parsed report.

    Shells out to the installed `ose` CLI rather than importing orchestrator
    directly, so this bot stays decoupled from the client package's
    internal API.

    :param repo_path: Path to the cloned repository.
    :return: The parsed JSON audit report.
    :raises RuntimeError: If the `ose` CLI is not on PATH or fails to run.
    """
    report_path = str(Path(repo_path) / "_ose_report.json")
    result = _run(
        ["ose", "audit", repo_path, "--output", report_path], check=False
    )
    if result.returncode not in (0, 2):  # 2 = audit ran but findings exist
        raise RuntimeError(
            f"ose audit failed (exit {result.returncode}): {result.stderr}"
        )
    if not Path(report_path).exists():
        raise RuntimeError("ose audit produced no report file.")
    return json.loads(Path(report_path).read_text(encoding="utf-8"))


def apply_patches(repo_path: str, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Best-effort application of suggested patches to source files.

    Only applies a patch when the finding's `file_path` exists in the repo
    and a `patch` string is present and non-empty. This performs a
    whole-line-range replacement (line_start..line_end inclusive) rather
    than a fuzzy diff merge -- if the file has drifted since the report
    was generated, this can produce an incorrect result, which is exactly
    why every PR opened by this bot is left unmerged for human review.

    :param repo_path: Path to the cloned repository (patches are applied
        in place on disk before commit).
    :param findings: The `findings` list from the combined audit report
        (each with file_path, patch, explanation -- see orchestrator.py's
        `_build_final_report`).
    :return: The subset of findings that were actually applied, for use
        in the PR description.
    """
    applied: List[Dict[str, Any]] = []

    for finding in findings:
        patch_text = finding.get("patch")
        file_path = finding.get("file_path")
        if not patch_text or not file_path:
            continue

        target = Path(repo_path) / file_path
        if not target.exists():
            logger.warning("Skipping patch for missing file: %s", file_path)
            continue

        # NOTE: the combined report from orchestrator._build_final_report
        # does not currently carry line_start/line_end through to the
        # final per-finding dict (only id/file_path/class/severity/
        # description/patch/explanation). Without a reliable anchor, we
        # do not attempt an automatic in-place splice here. Instead the
        # patch is written to a sibling suggestion file so a human can
        # apply it deliberately. If you extend the report to carry
        # line ranges, replace this block with a real line-range splice.
        suggestion_path = target.with_suffix(target.suffix + f".ose-suggestion-{finding.get('id', 'patch')}.txt")
        suggestion_path.write_text(patch_text, encoding="utf-8")
        applied.append(finding)

    return applied


def open_pull_request(
    token: str,
    owner: str,
    repo: str,
    branch: str,
    base_branch: str,
    title: str,
    body: str,
) -> Dict[str, Any]:
    """Open a PR via the GitHub REST API.

    :param token: Installation access token.
    :param owner: Repo owner login.
    :param repo: Repo name.
    :param branch: Source branch (already pushed).
    :param base_branch: Target branch (e.g. "main").
    :param title: PR title.
    :param body: PR body (markdown).
    :return: The created PR object.
    """
    response = requests.post(
        f"{GITHUB_API_URL}/repos/{owner}/{repo}/pulls",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
        },
        json={"title": title, "head": branch, "base": base_branch, "body": body},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()


def _format_pr_body(report: Dict[str, Any], applied: List[Dict[str, Any]]) -> str:
    """Build the PR description summarizing findings and suggestions.

    :param report: The full audit report.
    :param applied: Findings that had a suggestion file written.
    :return: Markdown PR body.
    """
    summary = report.get("summary", {})
    lines = [
        BOT_ATTRIBUTION,
        "",
        f"**Summary:** {summary.get('total_findings', 0)} finding(s) -- "
        f"{summary.get('critical', 0)} critical, {summary.get('high', 0)} high, "
        f"{summary.get('medium', 0)} medium, {summary.get('low', 0)} low.",
        "",
        "Suggested fixes were written as `*.ose-suggestion-<id>.txt` files "
        "next to the affected source files -- they are **not** applied "
        "automatically. Review each suggestion and merge it into the real "
        "file yourself if it looks correct.",
        "",
        "| ID | Severity | File | Issue |",
        "|----|----------|------|-------|",
    ]
    for finding in applied:
        lines.append(
            f"| {finding.get('id')} | {finding.get('severity')} | "
            f"`{finding.get('file_path')}` | {finding.get('vulnerability_class')} |"
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Per-repo orchestration
# ---------------------------------------------------------------------------


def process_repo(installation_token: str, repo: Dict[str, Any]) -> None:
    """Audit a single consented repo and open a suggestions PR if warranted.

    :param installation_token: Token scoped to this repo's installation.
    :param repo: A repository object from `list_installation_repos`.
    :return: ``None``
    """
    full_name = repo["full_name"]
    owner, name = full_name.split("/", 1)
    default_branch = repo.get("default_branch", "main")
    logger.info("Processing %s (default branch: %s)", full_name, default_branch)

    with tempfile.TemporaryDirectory(prefix="ose-bot-") as tmp_dir:
        try:
            clone_repo(repo["clone_url"], installation_token, tmp_dir)
        except subprocess.CalledProcessError as exc:
            logger.error("Clone failed for %s: %s", full_name, exc.stderr)
            return

        try:
            report = run_ose_audit(tmp_dir)
        except RuntimeError as exc:
            logger.error("Audit failed for %s: %s", full_name, exc)
            return

        findings = report.get("findings", [])
        if not findings:
            logger.info("No findings for %s; nothing to do.", full_name)
            return

        applied = apply_patches(tmp_dir, findings)
        if not applied:
            logger.info(
                "%s had %d finding(s) but no usable patches; skipping PR.",
                full_name, len(findings),
            )
            return

        if DRY_RUN:
            logger.info(
                "[DRY RUN] Would open a PR on %s with %d suggestion(s).",
                full_name, len(applied),
            )
            return

        branch_name = f"{PR_BRANCH_PREFIX}-{int(time.time())}"
        _run(["git", "checkout", "-b", branch_name], cwd=tmp_dir)
        _run(["git", "add", "-A"], cwd=tmp_dir)
        _run(
            ["git", "-c", "user.email=ose-bot@crestsek.com", "-c", "user.name=OSE Auditor",
             "commit", "-m", "OSE Auditor: security suggestions (review required)"],
            cwd=tmp_dir,
        )
        _run(["git", "push", "origin", branch_name], cwd=tmp_dir)

        pr_body = _format_pr_body(report, applied)
        try:
            pr = open_pull_request(
                installation_token, owner, name, branch_name, default_branch,
                title="[OSE Auditor] Security suggestions (please review)",
                body=pr_body,
            )
            logger.info("Opened PR for %s: %s", full_name, pr.get("html_url"))
        except requests.HTTPError as exc:
            logger.error("Failed to open PR for %s: %s", full_name, exc)


def main() -> int:
    """Entry point: process every repo across every consenting installation.

    :return: Process exit code.
    """
    app_id = os.environ.get("GITHUB_APP_ID")
    private_key_path = os.environ.get("GITHUB_APP_PRIVATE_KEY_PATH")
    if not app_id or not private_key_path:
        logger.error(
            "GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY_PATH must be set."
        )
        return 1

    installations = list_installations(app_id, private_key_path)
    logger.info("Found %d installation(s) of the OSE Auditor App.", len(installations))

    for installation in installations:
        installation_id = str(installation["id"])
        account = installation.get("account", {}).get("login", "unknown")
        try:
            token = get_installation_token(app_id, private_key_path, installation_id)
        except requests.HTTPError as exc:
            logger.error("Could not mint token for installation %s (%s): %s", installation_id, account, exc)
            continue

        repos = list_installation_repos(token)
        logger.info("Installation %s (%s) has access to %d repo(s).", installation_id, account, len(repos))

        for repo in repos:
            process_repo(token, repo)

    return 0


if __name__ == "__main__":
    sys.exit(main())
