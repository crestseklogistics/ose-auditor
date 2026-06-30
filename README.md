# OSE Auditor

**OSE Auditor** is an autonomous financial and logic exploit detection engine that uses deterministic code analysis and AI remediation to discover money-losing vulnerabilities before deployment.

It targets **Node.js / TypeScript** backends and surfaces vulnerabilities that generic AI models and traditional SAST tools miss: broken authorization before financial mutations, double-spend races, unchecked external payment calls, privilege escalation via user-controlled roles, invalid order lifecycle transitions, and more.

---

## Quick start

### Option 1 – pipx (recommended for most users)

```bash
# Install pipx if you don't have it
# macOS:
brew install pipx && pipx ensurepath

# Linux:
sudo apt install pipx && pipx ensurepath   # Ubuntu/Debian
# or: python3 -m pip install --user pipx

# Windows (PowerShell):
python -m pip install --user pipx

# Install OSE Auditor
pipx install ose-auditor

# Run an audit
ose signup          # create a free account
ose login           # save your API key to ~/.ose/config.json
ose audit ./your-nodejs-project
```

### Option 2 – npm global install

```bash
npm install -g ose-auditor

# Then use the same CLI:
ose audit ./your-nodejs-project
```

### Option 3 – npx (zero install, auto-detects pipx or creates a venv)

```bash
npx ose-auditor audit ./your-nodejs-project
```

> **Python 3.13 note:** `npx ose-auditor` tries pipx first, falls back to a
> virtual environment at `~/.ose-venv`, and only uses `pip install --user` as
> a last resort. If your system blocks `pip --user` (PEP 668), install pipx
> first and re-run.

---

## Installation summary

| Method | Command | Notes |
|--------|---------|-------|
| pipx | `pipx install ose-auditor` | **Preferred** – isolated, no system Python pollution |
| npm global | `npm install -g ose-auditor` | Good for Node.js-first teams |
| npx | `npx ose-auditor audit .` | Zero install; auto-installs on first run |
| pip (advanced) | `pip install ose-auditor` | Use inside a venv |

---

## Authentication

OSE Auditor uses **per-user API keys** (similar to Snyk). The key is stored in
`~/.ose/config.json` and loaded automatically on every `ose audit` run.

```bash
# Create a free account
ose signup

# Log in (saves your key to ~/.ose/config.json)
ose login

# Confirm you're logged in
ose whoami

# Log out (removes ~/.ose/config.json)
ose logout
```

For **CI/CD**, skip the login flow and set the key via environment variable:

```bash
export OSE_API_KEY=ose_sk_your_key_here
ose audit ./project
```

---

## Usage

```bash
# Audit a project (prints JSON report to stdout)
ose audit /path/to/your/nodejs/project

# Save the report to a file
ose audit /path/to/your/nodejs/project --output report.json

# Verbose / debug output
ose audit /path/to/your/nodejs/project --debug

# Show version
ose --version
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success (including "no findings") |
| `1` | General error (bad path, auth failure, etc.) |
| `2` | Audit ran but the server reported a failure |

---

## What OSE Auditor detects

OSE detects financial and business logic vulnerabilities including:

| Class | Severity | Description |
|-------|----------|-------------|
| `BROKEN_AUTH` | HIGH | Financial state mutated without an authentication/authorization check |
| `BROKEN_ACCESS_CONTROL` | HIGH | Balance/resource mutated without verifying the caller owns it |
| `PRIVILEGE_ESCALATION` | HIGH | Authorization decision derived from user-controlled input (`req.body.role`) |
| `DOUBLE_SPEND` | CRITICAL | Awaited external call suspends execution between a balance read and its update |
| `UNCHECKED_EXTERNAL_CALL` | HIGH | External payment call result not checked before dependent state mutation |
| `INVALID_STATE_TRANSITION` | MEDIUM | Order/subscription marked complete without confirming payment succeeded |
| `SETTLEMENT_BYPASS` | HIGH | Lifecycle state changed without a settlement confirmation check |
| `MISSING_VALIDATION` | MEDIUM | User-supplied amount or field used in financial mutation without validation |
| `LOGIC_FLAW` | MEDIUM | Financial state mutated with no auth, no validation, and no guard at all |
| `SLIPPAGE_OMISSION` | HIGH | Market order placed without a maximum slippage/deviation parameter (Quant) |

---

## MCP server (Claude Code / Cursor / Cline integration)

OSE Auditor ships an MCP server so AI coding assistants can run security audits
as a tool call during a coding session.

### Claude Code configuration

Add to `.claude/settings.json` (or your workspace MCP config):

```json
{
  "mcpServers": {
    "ose-auditor": {
      "command": "ose-mcp",
      "env": {
        "OSE_API_KEY": "ose_sk_your_key_here"
      }
    }
  }
}
```

If `ose-mcp` isn't on PATH yet, use the full path:

```json
{
  "mcpServers": {
    "ose-auditor": {
      "command": "python3",
      "args": ["-m", "client.mcp_server"],
      "env": {
        "OSE_API_KEY": "ose_sk_your_key_here",
        "OSE_SERVER_URL": "https://ose.crestsek.com/v1/audit"
      }
    }
  }
}
```

### Cursor configuration

Add to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "ose-auditor": {
      "command": "ose-mcp",
      "env": {
        "OSE_API_KEY": "ose_sk_your_key_here"
      }
    }
  }
}
```

### Testing the MCP server manually

```bash
# Ping
echo '{"jsonrpc":"2.0","method":"ping","id":1}' | ose-mcp

# List tools
echo '{"jsonrpc":"2.0","method":"tools/list","id":2}' | ose-mcp

# Run an audit via MCP
echo '{"jsonrpc":"2.0","method":"tools/call","id":3,"params":{"name":"ose_audit","arguments":{"project_path":"/path/to/project"}}}' | ose-mcp
```

### ose-security.json (AI agent auto-trigger)

Commit `ose-security.json` to your project root to instruct AI coding agents
(Claude Code, Cursor, Cline) to run an OSE audit automatically before
completing any change that touches financial-logic code. Reference it from
your `AGENTS.md` or `.cursorrules`:

```markdown
Before completing any task that touches files matching `**/payment*`,
`**/wallet*`, `**/balance*`, or similar paths defined in `ose-security.json`,
run the OSE Auditor MCP tool (`ose_audit`) or `ose audit .` and report any
CRITICAL or HIGH findings to me before merging.
```

---

## Credits and billing

| Tier | Credits | Resets |
|------|---------|--------|
| Free | 5 credits | Every 7 days |
| Starter | 50 credits | Never expire |
| Pro Hacker | 300 credits | Never expire |
| Enterprise | 1500 credits | Never expire |

Purchase credits at [https://ose.crestsek.com](https://ose.crestsek.com).

Audits that produce **no findings** do not consume credits — only manifests
sent to the server for AI patch generation do.

---

## Requirements

- Python 3.9 or higher
- Node.js project (JavaScript / TypeScript source files)

---

## Links

- **Homepage:** [https://ose.crestsek.com](https://ose.crestsek.com)
- **Docs:** [https://blogose.crestsek.com/docs](https://blogose.crestsek.com/docs)
- **GitHub:** [https://github.com/crestseklogistics/ose-auditor](https://github.com/crestseklogistics/ose-auditor)
- **Issues:** [https://github.com/crestseklogistics/ose-auditor/issues](https://github.com/crestseklogistics/ose-auditor/issues)
- **npm:** [https://www.npmjs.com/package/ose-auditor](https://www.npmjs.com/package/ose-auditor)
- **PyPI:** [https://pypi.org/project/ose-auditor](https://pypi.org/project/ose-auditor)

---

## License

MIT
