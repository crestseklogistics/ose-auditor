# OSE Auditor

**OSE Auditor** helps engineering teams identify business logic and financial security vulnerabilities before software reaches production.

Unlike traditional static analysis tools that primarily focus on language-level vulnerability patterns, OSE Auditor analyzes application behavior to identify risks such as authorization flaws, double-spend race conditions, settlement workflow issues, unsafe external payment handling, privilege escalation, and other business-critical security problems.

Designed for modern **Node.js**, **TypeScript**, **Web3**, and **Quantitative Finance** applications.

---

## Quick Start

### Install with pipx (Recommended)

```bash
# Install pipx (one-time setup)

# macOS
brew install pipx && pipx ensurepath

# Ubuntu / Debian
sudo apt install pipx && pipx ensurepath

# Windows (PowerShell)
python -m pip install --user pipx

# Install OSE Auditor
pipx install ose-auditor

# Authenticate
ose signup
ose login

# Run your first audit
ose audit ./your-project
```

### npm

```bash
npm install -g ose-auditor

ose audit ./your-project
```

### npx

```bash
npx ose-auditor audit ./your-project
```

> **Python 3.13:** `npx` automatically attempts to use `pipx` first and falls back to a managed virtual environment when needed.

---

## Installation Summary

| Method | Command |
|---------|---------|
| pipx (Recommended) | `pipx install ose-auditor` |
| npm | `npm install -g ose-auditor` |
| npx | `npx ose-auditor audit .` |
| pip (advanced) | `pip install ose-auditor` |

---

## Authentication

Create an account once, then authenticate from the CLI.

```bash
ose signup
ose login
ose whoami
```

For CI/CD environments:

```bash
export OSE_API_KEY=ose_sk_your_key_here

ose audit ./project
```

---

## Usage

Run a security audit:

```bash
ose audit ./your-project
```

Save the report:

```bash
ose audit ./your-project --output report.json
```

Enable debug output:

```bash
ose audit ./your-project --debug
```

Display the installed version:

```bash
ose --version
```

---

## What OSE Auditor Detects

OSE Auditor focuses on business logic and financial security analysis, including:

- Authorization and access-control flaws
- Double-spend race conditions
- Settlement and payment workflow issues
- Unsafe external payment handling
- Privilege escalation
- Invalid financial state transitions
- Missing validation on financial operations
- Smart contract business logic risks
- Quantitative trading workflow validation

Each finding includes severity, affected code locations, technical explanation, and remediation guidance.

---

## AI Coding Assistant Integration

OSE Auditor integrates with modern AI coding assistants, including:

- Claude Code
- Cursor
- VS Code
- Cline

Configure OSE once and allow AI coding assistants to run security audits during development.

Complete setup instructions are available in the documentation.

---

## Credits & Billing

| Tier | Credits |
|------|---------:|
| Free | 5 complimentary audits every 7 days |
| Starter | 50 credits |
| Pro Hacker | 300 credits |
| Enterprise | Custom plans |

Scans that produce **no findings** do **not** consume credits.

---

## Documentation

- Getting Started
- CLI Reference
- Credits & Billing
- MCP Integration
- Security Articles

[📖](https://blogose.crestsek.com/docs)

---

## Requirements

- Python 3.9+
- Node.js / TypeScript project

---

## Links

- **[🌐 Homepage:](https://ose.crestsek.com)**
- **[📚 Documentation:](https://blogose.crestsek.com/docs)**
- **[📦 npm:](https://www.npmjs.com/package/ose-auditor)**
- **[🐍 PyPI:](https://pypi.org/project/ose-auditor)**
- **[💻 GitHub:](https://github.com/crestseklogistics/ose-auditor)**
- **[🐞 Issues:](https://github.com/crestseklogistics/ose-auditor/issues)**

---

## License

MIT
