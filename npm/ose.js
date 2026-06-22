#!/usr/bin/env node
/**
 * ose.js -- npm/npx wrapper for the OSE Auditor Python CLI.
 *
 * Installation strategy (in priority order):
 *   1. pipx install ose-auditor  -- preferred; isolated env, no PEP 668 issues.
 *   2. venv in ~/.ose-venv       -- fallback when pipx is absent.
 *   3. pip install --user        -- last resort; catches PEP 668 error and
 *                                   advises the user to install pipx instead.
 *
 * After installation the CLI is invoked as:
 *   - pipx path: `python -m client.ose` inside the pipx venv, OR
 *   - venv path: `<~/.ose-venv>/bin/python -m client.ose`
 *
 * Environment variables forwarded transparently:
 *   OSE_API_KEY, OSE_SERVER_URL, OSE_NO_AUTO_INSTALL
 *
 * Usage:
 *   npx ose-auditor audit ./my-project
 *   npx ose-auditor audit ./my-project --output report.json
 *   OSE_API_KEY=sk-... npx ose-auditor audit .
 */

"use strict";

const { spawnSync } = require("child_process");
const os = require("os");
const path = require("path");
const fs = require("fs");

const MIN_PYTHON_MAJOR = 3;
const MIN_PYTHON_MINOR = 9;
const PYPI_PACKAGE = "ose-auditor";
const OSE_VENV_DIR = path.join(os.homedir(), ".ose-venv");

// ---------------------------------------------------------------------------
// Generic subprocess helpers
// ---------------------------------------------------------------------------

/**
 * Run a command, capturing output (for probing only -- never for audit output).
 */
// Allowlisted commands that may be used as the executable.
// argv from the user is ONLY ever passed as arguments to these
// fixed executables -- never as the command itself.
const ALLOWED_COMMANDS = new Set([
  "pipx", "python3", "python", "py", "pip", "pip3",
  "ose", "ose-mcp",
]);

function probe(command, args) {
  if (!ALLOWED_COMMANDS.has(command)) {
    return { ok: false, stdout: "", stderr: "disallowed command", status: null };
  }
  const result = spawnSync(command, args, {
    encoding: "utf8",
    windowsHide: true,
  });
  if (result.error) {
    return { ok: false, stdout: "", stderr: String(result.error), status: null };
  }
  return {
    ok: result.status === 0,
    stdout: (result.stdout || "").trim(),
    stderr: (result.stderr || "").trim(),
    status: result.status,
  };
}

/**
 * Run a command with inherited stdio (for install output the user should see).
 * Returns the exit status.
 */
function run(command, args, env) {
  if (!ALLOWED_COMMANDS.has(command)) {
    process.stderr.write(`[ose-auditor] Refused to run disallowed command: ${command}\n`);
    return null;
  }
  const result = spawnSync(command, args, {
    stdio: "inherit",
    windowsHide: true,
    env: env || process.env,
  });
  if (result.error) return null;
  return result.status;
}

// ---------------------------------------------------------------------------
// Python interpreter discovery
// ---------------------------------------------------------------------------

function findPython() {
  const candidates =
    os.platform() === "win32"
      ? ["py", "python", "python3"]
      : ["python3", "python"];

  for (const candidate of candidates) {
    const check = probe(candidate, [
      "-c",
      "import sys; print('%d.%d' % sys.version_info[:2])",
    ]);
    if (!check.ok) continue;
    const [maj, min] = check.stdout.split(".").map(Number);
    if (
      maj > MIN_PYTHON_MAJOR ||
      (maj === MIN_PYTHON_MAJOR && min >= MIN_PYTHON_MINOR)
    ) {
      return candidate;
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// pipx strategy
// ---------------------------------------------------------------------------

function hasPipx() {
  return probe("pipx", ["--version"]).ok;
}

/** Returns the python executable inside the pipx-managed ose-auditor venv. */
function pipxPython() {
  const result = probe("pipx", ["runpip", PYPI_PACKAGE, "show", "--files"]);
  // Simpler: ask pipx for the venv location via environment inspection.
  // pipx stores venvs in ~/.local/pipx/venvs/<package>/
  const pipxHome =
    process.env.PIPX_HOME ||
    path.join(
      process.env.HOME || os.homedir(),
      os.platform() === "win32" ? "AppData\\Local\\pipx\\pipx" : ".local/pipx"
    );
  const venvBin = path.join(
    pipxHome,
    "venvs",
    PYPI_PACKAGE,
    os.platform() === "win32" ? "Scripts" : "bin",
    os.platform() === "win32" ? "python.exe" : "python"
  );
  if (fs.existsSync(venvBin)) return venvBin;
  // Fallback: pipx inject puts it on PATH as `ose`; use that python
  return null;
}

function isOseInstalledViaPipx() {
  // Check if `ose` CLI is available after pipx install
  return probe("pipx", ["list", "--short"]).stdout.includes(PYPI_PACKAGE);
}

function installViaPipx() {
  process.stderr.write(
    `[ose-auditor] Installing '${PYPI_PACKAGE}' via pipx...\n`
  );
  const status = run("pipx", ["install", "--force", PYPI_PACKAGE]);
  return status === 0;
}

// ---------------------------------------------------------------------------
// venv (~/.ose-venv) strategy
// ---------------------------------------------------------------------------

function venvPython() {
  const bin =
    os.platform() === "win32"
      ? path.join(OSE_VENV_DIR, "Scripts", "python.exe")
      : path.join(OSE_VENV_DIR, "bin", "python");
  return fs.existsSync(bin) ? bin : null;
}

function isOseInstalledInVenv(python) {
  return probe(python, ["-c", "import client.ose"]).ok;
}

function createVenv(basePython) {
  process.stderr.write(
    `[ose-auditor] Creating virtual environment at ${OSE_VENV_DIR}...\n`
  );
  const status = run(basePython, ["-m", "venv", OSE_VENV_DIR]);
  return status === 0;
}

function installInVenv(python) {
  process.stderr.write(
    `[ose-auditor] Installing '${PYPI_PACKAGE}' into ${OSE_VENV_DIR}...\n`
  );
  const pip =
    os.platform() === "win32"
      ? path.join(OSE_VENV_DIR, "Scripts", "pip.exe")
      : path.join(OSE_VENV_DIR, "bin", "pip");
  const status = run(pip, ["install", "--upgrade", PYPI_PACKAGE]);
  return status === 0;
}

// ---------------------------------------------------------------------------
// pip --user fallback (last resort)
// ---------------------------------------------------------------------------

function isOseInstalledGlobally(python) {
  return probe(python, ["-c", "import client.ose"]).ok;
}

function installViaPipUser(python) {
  process.stderr.write(
    `[ose-auditor] Attempting pip install --user '${PYPI_PACKAGE}'...\n`
  );
  const result = spawnSync(
    python,
    ["-m", "pip", "install", "--user", "--upgrade", PYPI_PACKAGE],
    { encoding: "utf8", windowsHide: true, stdio: ["ignore", "pipe", "pipe"] }
  );

  const combinedOutput = (result.stdout || "") + (result.stderr || "");
  if (
    combinedOutput.includes("externally-managed-environment") ||
    combinedOutput.includes("PEP 668")
  ) {
    process.stderr.write(
      "\n[ose-auditor] ✗ pip install was blocked by your system Python (PEP 668 / externally-managed-environment).\n" +
      "  Fix: install pipx, then re-run npx ose-auditor:\n\n" +
      "    # macOS\n" +
      "    brew install pipx && pipx ensurepath\n\n" +
      "    # Linux\n" +
      "    sudo apt install pipx && pipx ensurepath\n\n" +
      "    # Windows (PowerShell)\n" +
      "    python -m pip install --user pipx\n\n" +
      "  Then re-run:  npx ose-auditor audit .\n\n"
    );
    return false;
  }

  if (result.status !== 0) {
    process.stderr.write(
      `[ose-auditor] pip install failed (exit ${result.status}).\n` +
      `Try manually: ${python} -m pip install --user ${PYPI_PACKAGE}\n`
    );
    return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function main() {
  const args = process.argv.slice(2);

  // ------------------------------------------------------------------
  // 1. Find a usable base Python interpreter
  // ------------------------------------------------------------------
  const basePython = findPython();
  if (!basePython) {
    process.stderr.write(
      `[ose-auditor] Could not find a Python ${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR}+ interpreter.\n` +
      "Install Python from https://python.org and ensure 'python3' is on your PATH.\n"
    );
    process.exit(1);
  }

  if (process.env.OSE_NO_AUTO_INSTALL === "1") {
    // Skip install entirely; trust that the package is already available.
    const p = venvPython() || basePython;
    if (!isOseInstalledInVenv(p) && !isOseInstalledGlobally(basePython)) {
      process.stderr.write(
        `[ose-auditor] '${PYPI_PACKAGE}' is not installed and OSE_NO_AUTO_INSTALL=1.\n` +
        `Install manually: pipx install ${PYPI_PACKAGE}\n`
      );
      process.exit(1);
    }
    launchCli(p, args);
    return;
  }

  // ------------------------------------------------------------------
  // 2. Strategy A: pipx
  // ------------------------------------------------------------------
  if (hasPipx()) {
    if (!isOseInstalledViaPipx()) {
      const ok = installViaPipx();
      if (!ok) {
        process.stderr.write("[ose-auditor] pipx install failed.\n");
        // fall through to venv strategy
      }
    }
    if (isOseInstalledViaPipx()) {
      // Find the python inside pipx's managed venv
      const pp = pipxPython();
      if (pp) {
        launchCli(pp, args);
        return;
      }
      // pipx puts `ose` on PATH directly; try invoking it that way
      launchOseCli(args);
      return;
    }
  }

  // ------------------------------------------------------------------
  // 3. Strategy B: ~/.ose-venv
  // ------------------------------------------------------------------
  {
    let vPython = venvPython();
    if (!vPython) {
      const created = createVenv(basePython);
      if (!created) {
        process.stderr.write(
          `[ose-auditor] Failed to create venv at ${OSE_VENV_DIR}.\n`
        );
        // fall through to pip --user
      } else {
        vPython = venvPython();
      }
    }

    if (vPython) {
      if (!isOseInstalledInVenv(vPython)) {
        const ok = installInVenv(vPython);
        if (!ok) {
          process.stderr.write("[ose-auditor] venv install failed.\n");
          // fall through
        }
      }
      if (isOseInstalledInVenv(vPython)) {
        launchCli(vPython, args);
        return;
      }
    }
  }

  // ------------------------------------------------------------------
  // 4. Strategy C: pip install --user (last resort)
  // ------------------------------------------------------------------
  {
    const ok = installViaPipUser(basePython);
    if (ok && isOseInstalledGlobally(basePython)) {
      launchCli(basePython, args);
      return;
    }
    process.stderr.write(
      "[ose-auditor] All installation strategies failed. Cannot continue.\n"
    );
    process.exit(1);
  }
}

/** Launch `ose` (the pipx-injected console script) directly. */
function launchOseCli(args) {
  if (!process.env.OSE_API_KEY) {
    process.stderr.write(
      "[ose-auditor] Note: OSE_API_KEY is not set. " +
      "Audits with findings will need it to fetch patches (https://ose.crestsek.com).\n"
    );
  }
  const result = spawnSync("ose", args, {
    stdio: "inherit",
    env: process.env,
    windowsHide: true,
  });
  if (result.error) {
    process.stderr.write(
      `[ose-auditor] Failed to launch 'ose': ${result.error}\n`
    );
    process.exit(1);
  }
  process.exit(result.status === null ? 1 : result.status);
}

/** Launch `python -m client.ose` with the given interpreter. */
function launchCli(python, args) {
  // python is always a value returned by findPython(), which only
  // returns strings from the fixed ALLOWED_COMMANDS set above.
  if (!ALLOWED_COMMANDS.has(python) && !require("fs").existsSync(python)) {
    process.stderr.write(`[ose-auditor] Refused to execute unlisted interpreter: ${python}\n`);
    process.exit(1);
  }
  if (!process.env.OSE_API_KEY) {
    process.stderr.write(
      "[ose-auditor] Note: OSE_API_KEY is not set. " +
      "Audits with findings will need it to fetch patches (https://ose.crestsek.com).\n"
    );
  }
  const result = spawnSync(python, ["-m", "client.ose", ...args], {
    stdio: "inherit",
    env: process.env,
    windowsHide: true,
  });
  if (result.error) {
    process.stderr.write(
      `[ose-auditor] Failed to launch Python CLI: ${result.error}\n`
    );
    process.exit(1);
  }
  process.exit(result.status === null ? 1 : result.status);
}

main();
