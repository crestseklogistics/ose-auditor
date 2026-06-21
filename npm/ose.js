#!/usr/bin/env node
/**
 * ose.js -- npm/npx wrapper for the OSE Auditor Python CLI.
 *
 * This script does NOT reimplement any audit logic. It is a thin launcher
 * that:
 *   1. Locates a usable Python 3 interpreter on the host machine.
 *   2. Checks whether the `ose-auditor` PyPI package (which provides the
 *      `client.ose` module / `ose` console script) is already importable.
 *   3. If not, installs it on first run via `pip install --user ose-auditor`
 *      (can be skipped with OSE_NO_AUTO_INSTALL=1, e.g. in CI images that
 *      pre-bake the dependency).
 *   4. Forwards argv and the current environment (including OSE_API_KEY,
 *      OSE_SERVER_URL) straight through to `python -m client.ose`, and
 *      exits with the same exit code the Python process produced.
 *
 * Usage:
 *   npx ose-auditor audit ./my-project
 *   npx ose-auditor audit ./my-project --output report.json
 *   OSE_API_KEY=sk-... npx ose-auditor audit .
 */

"use strict";

const { spawnSync } = require("child_process");
const os = require("os");

const MIN_PYTHON_MAJOR = 3;
const MIN_PYTHON_MINOR = 9;
const PYPI_PACKAGE = "ose-auditor";

/**
 * Run a command synchronously, capturing stdout/stderr (not inherited),
 * for internal probing only -- never used for the final audit invocation.
 *
 * @param {string} command
 * @param {string[]} args
 * @returns {{ok: boolean, stdout: string, stderr: string, status: number|null}}
 */
function probe(command, args) {
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
 * Find a usable Python 3 interpreter, preferring `python3` then `python`.
 * Verifies the interpreter actually reports Python >= MIN_PYTHON_MAJOR.MIN_PYTHON_MINOR.
 *
 * @returns {string|null} The interpreter command name, or null if none found.
 */
function findPython() {
  const candidates = os.platform() === "win32" ? ["py", "python", "python3"] : ["python3", "python"];

  for (const candidate of candidates) {
    const versionCheck = probe(candidate, [
      "-c",
      "import sys; print('%d.%d' % sys.version_info[:2])",
    ]);
    if (!versionCheck.ok) continue;

    const [majorStr, minorStr] = versionCheck.stdout.split(".");
    const major = parseInt(majorStr, 10);
    const minor = parseInt(minorStr, 10);
    if (
      major > MIN_PYTHON_MAJOR ||
      (major === MIN_PYTHON_MAJOR && minor >= MIN_PYTHON_MINOR)
    ) {
      return candidate;
    }
  }
  return null;
}

/**
 * Check whether `client.ose` is importable with the given interpreter,
 * i.e. whether the ose-auditor package is already installed.
 *
 * @param {string} python
 * @returns {boolean}
 */
function isOseInstalled(python) {
  return probe(python, ["-c", "import client.ose"]).ok;
}

/**
 * Install the ose-auditor package for the current user via pip.
 *
 * @param {string} python
 * @returns {boolean} true on success
 */
function installOse(python) {
  process.stderr.write(
    `[ose-auditor] First run: installing the '${PYPI_PACKAGE}' Python package via pip...\n`
  );
  const result = spawnSync(
    python,
    ["-m", "pip", "install", "--user", "--upgrade", PYPI_PACKAGE],
    { stdio: "inherit", windowsHide: true }
  );
  if (result.status !== 0) {
    process.stderr.write(
      `[ose-auditor] pip install failed (exit code ${result.status}). ` +
        `Try installing manually: ${python} -m pip install --user ${PYPI_PACKAGE}\n`
    );
    return false;
  }
  return true;
}

function main() {
  const args = process.argv.slice(2);

  const python = findPython();
  if (!python) {
    process.stderr.write(
      `[ose-auditor] Could not find a Python ${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR}+ interpreter on PATH.\n` +
        "Install Python from https://python.org and ensure 'python3' is on your PATH, then retry.\n"
    );
    process.exit(1);
  }

  if (!isOseInstalled(python)) {
    if (process.env.OSE_NO_AUTO_INSTALL === "1") {
      process.stderr.write(
        `[ose-auditor] '${PYPI_PACKAGE}' is not installed and OSE_NO_AUTO_INSTALL=1 is set. ` +
          `Install it manually: ${python} -m pip install ${PYPI_PACKAGE}\n`
      );
      process.exit(1);
    }
    const installed = installOse(python);
    if (!installed || !isOseInstalled(python)) {
      process.stderr.write(
        "[ose-auditor] Installation did not succeed; cannot continue.\n"
      );
      process.exit(1);
    }
  }

  if (!process.env.OSE_API_KEY) {
    process.stderr.write(
      "[ose-auditor] Note: OSE_API_KEY is not set. Audits with findings will need it " +
        "to fetch patches (https://ose.crestsek.com). Audits with zero findings still work.\n"
    );
  }

  const result = spawnSync(python, ["-m", "client.ose", ...args], {
    stdio: "inherit",
    env: process.env,
    windowsHide: true,
  });

  if (result.error) {
    process.stderr.write(`[ose-auditor] Failed to launch Python CLI: ${result.error}\n`);
    process.exit(1);
  }

  process.exit(result.status === null ? 1 : result.status);
}

main();
