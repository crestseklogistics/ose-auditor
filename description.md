# OSE Auditor

**OSE Auditor** is an autonomous financial and logic exploit detection engine for Node.js and TypeScript backends. It uses deterministic code analysis combined with AI-powered remediation to surface money-losing vulnerabilities before they reach production.

It catches what generic AI models and traditional SAST tools miss: broken authorization gates on financial mutations, double-spend race conditions, unchecked external payment calls, privilege escalation via user-controlled roles, invalid order lifecycle transitions, and more.

---

## Why OSE Auditor?

Most SAST tools find injection and XSS. OSE Auditor finds the bugs that drain your users' money:

- A payment route that processes charges without verifying the caller is authenticated
- A withdrawal endpoint where two concurrent requests can both read the same pre-deducted balance
- A Stripe call whose result is never checked before balance is decremented
- An order marked `completed` before payment has confirmed
- A role check that reads `req.body.role` — set by the attacker

These bugs are invisible to linters, missed by code review, and never caught in unit tests because they require reasoning about *ordering*, *ownership*, and *financial semantics* across an entire function's control flow.

---

## Quick Start

```bash
# Install (pipx recommended — isolated, no PEP 668 conflicts)
pipx install ose-auditor

# Create a free account
ose signup

# Audit your project
ose audit ./your-nodejs-project

# Buy more credits when you need them
ose buy
```

Or with npm/npx — zero Python setup required:

```bash
npm install -g ose-auditor
ose audit ./your-nodejs-project

# or without installing
npx ose-auditor audit ./your-nodejs-project
```

<!-- ---

## What It Detects

| Vulnerability Class | Severity | Description |
|---|---|---|
| `DOUBLE_SPEND` | CRITICAL | Balance checked, async external call suspends execution, balance decremented — concurrent request exploits the window |
| `BROKEN_AUTH` | HIGH | Financial state mutated without any authentication or authorization check |
| `BROKEN_ACCESS_CONTROL` | HIGH | Balance or resource mutated without verifying the caller owns it |
| `PRIVILEGE_ESCALATION` | HIGH | Authorization decision derived from `req.body.role` or other caller-controlled input |
| `UNCHECKED_EXTERNAL_CALL` | HIGH | Payment gateway call result not inspected before dependent state mutation |
| `SETTLEMENT_BYPASS` | HIGH | Lifecycle state changed without confirming settlement succeeded |
| `FINANCIAL_ACTION_ORDERING` | HIGH | Transfer or withdrawal executed without authorization or settlement confirmation |
| `INVALID_STATE_TRANSITION` | MEDIUM | Order or subscription marked complete before payment is confirmed |
| `MISSING_VALIDATION` | MEDIUM | User-supplied amount or field used in financial mutation with no bounds check |
| `LOGIC_FLAW` | MEDIUM | Financial state mutated with no auth, no validation, and no guard of any kind |
| `SLIPPAGE_OMISSION` | HIGH | Market order placed without a maximum slippage/deviation parameter (Quant track) |

--- -->

## How It Works

OSE Auditor runs a three-stage pipeline entirely on your machine before any data leaves:

1. **Parser** — walks your project, strips comments, computes hashes, assembles a normalized source index (Contract A). Open-source, stdlib-only, no network I/O.

2. **Financial Semantic Analyzer (FSA)** — parses every JavaScript/TypeScript file into an AST using tree-sitter, builds a per-function state transition graph (validation nodes, external-call nodes, state-mutation nodes, in source order), then applies deterministic vulnerability signatures. No AI, no false-positive lottery — rules are hardcoded and auditable. The FSA core is compiled and proprietary; the client layer that calls it is MIT-licensed.

3. **Patch Generation (OSE Server)** — if the FSA finds vulnerabilities, the manifest is sent to the OSE Server, which calls a configurable LLM (Claude, GPT-4, or Groq) with track-specific few-shot prompts to generate production-ready code patches. This step consumes one credit. Scans that produce no findings are always free.

---

## Authentication & Credits

```bash
ose signup          # create a free account
ose login           # log in (saves API key to ~/.ose/config.json)
ose whoami          # confirm your identity and credit balance
ose logout          # remove locally saved credentials
ose buy             # interactive credit pack purchase
```

For CI/CD, skip the login flow:

```bash
export OSE_API_KEY=ose_sk_your_key_here
ose audit ./project
```

### Credit Tiers

| Tier | Credits | Resets |
|---|---|---|
| Free | 5 | Every 7 days |
| Starter | 50 | Never expire |
| Pro Hacker | 300 | Never expire |
| Enterprise | 1500 | Never expire |

Audits with **no findings do not consume credits**.

---

<!-- ## MCP Server — Claude Code / Cursor / Cline Integration

OSE Auditor ships an MCP (Model Context Protocol) server so AI coding assistants can trigger security audits as a tool call during a session.

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

Test it manually:

```bash
echo '{"jsonrpc":"2.0","method":"ping","id":1}' | ose-mcp
echo '{"jsonrpc":"2.0","method":"tools/list","id":2}' | ose-mcp
```

---

## `ose-security.json` — Agent Auto-Trigger

Commit `ose-security.json` to your repo root and reference it from `CLAUDE.md` or `.cursorrules` to instruct AI coding agents to run an OSE audit before completing any task that touches financial-logic code:

```markdown
Before completing any task that touches files matching `**/payment*`,
`**/wallet*`, `**/balance*`, or paths defined in `ose-security.json`,
run the OSE Auditor MCP tool (`ose_audit`) or `ose audit .` and report
any CRITICAL or HIGH findings before merging.
```

--- -->

## Installation Options

| Method | Command | Notes |
|---|---|---|
| pipx | `pipx install ose-auditor` | **Recommended** — isolated env |
| npm global | `npm install -g ose-auditor` | Good for Node-first teams |
| npx | `npx ose-auditor audit .` | Zero install, auto-installs on first run |
| pip | `pip install ose-auditor` | Use inside a venv |

Requires Python 3.9+ and a Node.js/TypeScript project to audit.

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Success (including no findings) |
| `1` | General error (bad path, auth failure, network) |
| `2` | Audit ran but the server reported a failure |

---

<!-- ## Links

- **Homepage:** https://ose.crestsek.com
- **Docs:** https://ose.crestsek.com/docs
- **GitHub:** https://github.com/crestseklogistics/ose-auditor
- **npm:** https://www.npmjs.com/package/ose-auditor
- **Issues:** https://github.com/crestseklogistics/ose-auditor/issues

--- -->

## License

MIT — client layer, parser, MCP server, and contracts.
The FSA detection core (`ose-auditor-fsa`) is proprietary and distributed as compiled wheels only.
