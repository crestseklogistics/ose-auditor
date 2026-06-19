# OSE Auditor — Local Setup & Testing Guide

This guide was built directly from the code in your project (imports, hardcoded
constants, function signatures, endpoint definitions). No `requirements.txt`
was included among the files you shared, so every dependency below was
reverse-engineered from `import` statements — double check it against your
real `requirements.txt` if one exists elsewhere in your repo.

---

## 0. Project layout this guide assumes

Your modules cross-import each other using package paths (`from client import
orchestrator`, `from contracts import contract_a`, `from fsa import
graph_builder`, `from server import billing`). For any of the commands below
to work, your files need to be arranged into packages, not left as loose
files in one folder:

```
ose-auditor/
├── ose.py                     # CLI entry point (top-level, not in a package)
├── client/
│   ├── __init__.py
│   ├── parser.py
│   └── orchestrator.py
├── contracts/
│   ├── __init__.py
│   ├── contract_a.py
│   └── contract_b.py
├── fsa/
│   ├── __init__.py
│   ├── analyzer.py
│   ├── graph_builder.py
│   └── signatures.py
├── server/
│   ├── __init__.py
│   ├── main.py
│   ├── billing.py
│   ├── database.py
│   └── prompts.py
├── .env
└── bvenv/                     # your virtualenv
```

Each `__init__.py` can be empty — it just needs to exist so Python treats the
folder as a package. If your files are currently flat (all in one directory),
move them into this structure first; nothing else in this guide will work
correctly until imports resolve.

---

## 1. Python upgrade instructions (bvenv: 3.12.0 → 3.13.0)

A virtualenv is permanently bound to the interpreter binary it was created
with — you cannot "upgrade" `bvenv` in place. The correct procedure is to
install Python 3.13 system-wide (or via pyenv), then **recreate** the venv
against it and reinstall packages.

### 1a. Check whether Python 3.13 is already installed

```bash
which python3.13
python3.13 --version
```

If that prints `Python 3.13.x`, skip to step 1c.

### 1b. Install Python 3.13 (pick ONE method)

**Option A — pyenv (recommended, works the same on any Linux distro):**

```bash
curl https://pyenv.run | bash

# Add to ~/.bashrc (or ~/.zshrc), then restart your shell:
echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
echo 'command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc
echo 'eval "$(pyenv init -)"' >> ~/.bashrc
exec "$SHELL"

pyenv install 3.13.0
pyenv versions          # confirm 3.13.0 is listed
```

**Option B — Ubuntu/Debian via the deadsnakes PPA:**

```bash
sudo apt update
sudo apt install -y software-properties-common
sudo add-apt-repository -y ppa:deadsnakes/ppa
sudo apt update
sudo apt install -y python3.13 python3.13-venv python3.13-dev
python3.13 --version
```

### 1c. Recreate the virtual environment

```bash
cd ~/Documents/Obatobie/ose-auditor

# Deactivate the current venv if it's active
deactivate 2>/dev/null

# Keep the old one around briefly in case anything goes wrong
mv bvenv bvenv-py312-backup

# Create a fresh venv with the new interpreter
# (use the pyenv shim path if you used Option A, e.g. ~/.pyenv/versions/3.13.0/bin/python3.13)
python3.13 -m venv bvenv

source bvenv/bin/activate
python -m pip install --upgrade pip setuptools wheel
```

### 1d. Verify the upgrade

```bash
python --version          # Python 3.13.0
which python               # should point inside .../ose-auditor/bvenv/bin/python
python -c "import sys; print(sys.version)"
```

Once you've confirmed your dependencies (step 2) install and import cleanly
under 3.13, delete the backup:

```bash
rm -rf bvenv-py312-backup
```

> **Compatibility note:** as of recent releases, `asyncpg` (≥0.30) and the
> `tree-sitter` / `tree-sitter-javascript` / `tree-sitter-typescript`
> packages all publish prebuilt wheels covering Python 3.13, so a normal
> `pip install` should not need to compile anything from source. If `pip
> install` ever falls back to building from source on your machine, it means
> no matching wheel was found for your OS/architecture — install a C
> compiler (`sudo apt install -y build-essential`) as a fallback, or pin to
> the latest released version of the package.

---

## 2. Dependency installation guide

Below is every third-party package actually imported somewhere in your
codebase, split by which part of the system needs it. The standard library
modules (`argparse`, `logging`, `pathlib`, `dataclasses`, `hashlib`, `json`,
`re`, `typing`, etc.) need no installation.

| File | Third-party imports |
|---|---|
| `ose.py`, `contracts/contract_a.py`, `contracts/contract_b.py`, `client/parser.py` | *(stdlib only)* |
| `client/orchestrator.py` | `httpx` (optional — falls back to `urllib` automatically if missing) |
| `fsa/analyzer.py` | `tree_sitter`, `tree_sitter_javascript`, `tree_sitter_typescript` (optional — falls back to mock/regex-light analysis if missing) |
| `fsa/graph_builder.py`, `fsa/signatures.py`, `server/billing.py`, `server/prompts.py` | *(stdlib only)* |
| `server/database.py` | `asyncpg` (**required**) |
| `server/main.py` | `httpx`, `fastapi`, `pydantic` (**required**); also needs `uvicorn` to run it |

### 2a. Create `requirements.txt`

```txt
# --- Server (FastAPI app in server/main.py) ---
fastapi>=0.115
uvicorn[standard]>=0.32
pydantic>=2.9
httpx>=0.27
asyncpg>=0.30
python-dotenv>=1.0       # lets `uvicorn --env-file .env` load your .env

# --- Proprietary FSA engine (fsa/analyzer.py real AST parsing) ---
# Optional: without these, analyzer.py automatically returns a mock
# Contract B manifest instead of real findings. Install them to test
# the real graph_builder.py / signatures.py pipeline.
tree-sitter>=0.23
tree-sitter-javascript>=0.23
tree-sitter-typescript>=0.23
```

### 2b. Install

```bash
source bvenv/bin/activate
pip install -r requirements.txt
```

### 2c. Sanity-check the imports

```bash
python -c "import fastapi, uvicorn, pydantic, httpx, asyncpg; print('server deps OK')"
python -c "import tree_sitter, tree_sitter_javascript, tree_sitter_typescript; print('FSA deps OK')"
```

If the second command fails, that's fine for now — `fsa/analyzer.py` is
written to degrade gracefully (see Section 5) and will just produce mock
findings until those packages are installed.

---

## 3. Full environment setup

### 3a. `.env` file template

Place this at the project root (`~/Documents/Obatobie/ose-auditor/.env`):

```env
# ============================================================
# SHARED SECRET — read by BOTH the server (server/main.py) and
# the client (client/orchestrator.py). The client sends this as
# a Bearer token; the server rejects any request where the
# incoming token doesn't match this exact value. They MUST be
# identical for /v1/audit and /v1/credits to authenticate.
# ============================================================
OSE_API_KEY=replace-with-a-long-random-string

# --- Database (server/database.py) ---
# Use the connection string from your Neon project. See 3c below
# for an important caveat about Neon's pooled vs direct endpoint.
DATABASE_URL=postgresql://USER:PASSWORD@HOST/DBNAME?sslmode=require

# --- LLM provider (server/main.py) ---
LLM_PROVIDER=anthropic
# LLM_MODEL=                      # optional override; leave unset to use
                                   # main.py's built-in default model
ANTHROPIC_API_KEY=sk-ant-replace-me
# OPENAI_API_KEY=sk-replace-me    # only needed if LLM_PROVIDER=openai

# --- Flutterwave webhook (see Section 6 — you'll need to add the
#     receiving endpoint yourself; main.py doesn't define one yet) ---
FLW_SECRET_HASH=replace-with-the-secret-hash-set-in-your-Flutterwave-dashboard
```

### 3b. Client-side config (used when running `ose audit`)

`client/orchestrator.py` looks for the API key in this order:

1. The `OSE_API_KEY` environment variable.
2. `~/.ose/config.json`.

For local testing, the simplest approach is to export the same env var in
the terminal where you run the CLI:

```bash
export OSE_API_KEY="the-same-value-as-in-.env"
```

Or, equivalently, create the config file:

```bash
mkdir -p ~/.ose
cat > ~/.ose/config.json <<'EOF'
{
  "api_key": "the-same-value-as-in-.env"
}
EOF
```

### 3c. Database setup (Neon DB)

1. Create a free project at Neon and copy the **connection string** it gives
   you (Neon → your project → *Connection Details*).
2. Paste it into `DATABASE_URL` in `.env`, keeping `?sslmode=require` at the
   end.
3. **No manual schema/migrations are needed.** `server/main.py`'s `lifespan`
   handler calls `database.init_pool()` then `database.init_schema()` on
   every server startup, and `init_schema()` runs `CREATE TABLE IF NOT
   EXISTS` for `ose_usage_nodes`, `invite_tokens`, and `audit_history`
   (plus a defensive `ALTER TABLE ... ADD COLUMN IF NOT EXISTS
   credit_balance`). Simply starting the server with a valid `DATABASE_URL`
   is enough.
4. To verify the tables were created, open Neon's SQL editor (or `psql`) and
   run:
   ```sql
   SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';
   ```
   You should see `ose_usage_nodes`, `invite_tokens`, and `audit_history`.

> **Important gotcha:** Neon gives you two kinds of connection string — a
> **pooled** one (hostname contains `-pooler`) and a **direct** one. Neon's
> pooler runs PgBouncer in transaction mode, which is known to conflict with
> `asyncpg`'s server-side prepared-statement caching (you'll see errors like
> `prepared statement "__asyncpg_stmt_x__" already exists`). For local
> testing, use the **direct** (non-pooled) connection string in
> `DATABASE_URL` to avoid this entirely.

---

## 4. Running the server locally

### 4a. Start it

```bash
source bvenv/bin/activate
uvicorn server.main:app --reload --host 0.0.0.0 --port 8000 --env-file .env
```

`--env-file .env` requires `python-dotenv` to be installed (already in
`requirements.txt` above) — it loads `.env` into the process environment
before `server/main.py` is imported, which matters because `main.py` reads
`OSE_API_KEY`/`LLM_PROVIDER` at **module import time**, not inside a
request handler.

If you'd rather not rely on `--env-file`, just export the variables in the
same shell before running uvicorn:

```bash
set -a; source .env; set +a
uvicorn server.main:app --reload --port 8000
```

### 4b. Test `/health`

```bash
curl http://localhost:8000/health
```

Expected response:
```json
{"status": "online", "timestamp": 1750000000.123}
```

### 4c. Test `/v1/credits`

```bash
curl -H "Authorization: Bearer $OSE_API_KEY" \
  "http://localhost:8000/v1/credits?user_id=test_user_1"
```

Expected response (first call for a brand-new `user_id` — `get_or_create_user`
is not actually invoked here, but `get_remaining_credits` returns the
free-tier default of 5 for any user it can't find):
```json
{"user_id": "test_user_1", "credits": 5, "tier": "free"}
```

### 4d. Test `/v1/audit`

This route calls a real LLM (Anthropic or OpenAI, per `LLM_PROVIDER`) and
**consumes one credit**, so make sure `ANTHROPIC_API_KEY` (or
`OPENAI_API_KEY`) is set in `.env` before testing it. Save this sample
Contract B manifest (reusing the BROKEN_AUTH example already in your own
`server/prompts.py`) as `sample_manifest.json`:

```json
{
  "manifest": {
    "contract_version": "1.0.0",
    "project_hash": "0000000000000000000000000000000000000000000000000000000000000000",
    "generated_at": "2026-06-19T12:00:00Z",
    "analysis_metadata": {
      "scanner_version": "1.0.0",
      "files_analyzed": 1,
      "analysis_duration_seconds": 0.01,
      "target_tracks": ["web2"]
    },
    "findings": [
      {
        "id": "FSA-BAUTH-001",
        "file_path": "src/controllers/payment.js",
        "line_start": 12,
        "line_end": 18,
        "vulnerability_class": "BROKEN_AUTH",
        "severity": "HIGH",
        "code_snippet": "async function processPayment(amount, userId) {\n  const user = await User.findByPk(userId);\n  const charge = await stripe.charges.create({\n    amount, currency: 'usd', customer: user.stripeId\n  });\n  user.balance -= amount;\n  await user.save();\n}",
        "description": "Function performs a financial state mutation (`user.balance`) without a preceding authentication or authorization check.",
        "fix_principle": "Add an authentication/authorization check before mutating financial state.",
        "confidence": 0.85,
        "false_positive_risk": "LOW"
      }
    ]
  },
  "client_version": "1.0.0",
  "user_id": "test_user_1",
  "track": "web2"
}
```

> Note: `project_hash` above needs to be exactly 64 lowercase hex
> characters to pass Contract B validation if you later run it through
> `contracts/contract_b.py`; the value shown is a placeholder. `main.py`'s
> `/v1/audit` handler itself does **not** call `validate_contract_b` — that
> validation only happens client-side in `orchestrator.py` before
> submission — so the placeholder above is fine for a direct curl test.

```bash
curl -X POST http://localhost:8000/v1/audit \
  -H "Authorization: Bearer $OSE_API_KEY" \
  -H "Content-Type: application/json" \
  -d @sample_manifest.json
```

Expected: a `200` response with `"status": "SUCCESS"` and a `findings` array
containing one `{"finding_id", "patch", "explanation"}` object generated by
the LLM.

---

## 5. Testing the client

### 5a. Create a small test project for `parser.py` to scan

`client/parser.py` only picks up `.js` and `.ts` files (per
`ALLOWED_EXTENSIONS`), so any plain Node-style folder works:

```bash
mkdir -p ~/ose-test-project/src/controllers
cat > ~/ose-test-project/package.json <<'EOF'
{ "name": "ose-test-project", "version": "1.0.0" }
EOF

cat > ~/ose-test-project/src/controllers/payment.js <<'EOF'
async function processPayment(amount, userId) {
  const user = await User.findByPk(userId);
  const charge = await stripe.charges.create({
    amount, currency: 'usd', customer: user.stripeId
  });
  user.balance -= amount;
  await user.save();
}

module.exports = { processPayment };
EOF
```

### 5b. Test `parser.py` alone

```bash
python client/parser.py ~/ose-test-project --dry-run --debug
```

This prints the Contract A JSON (`project_identifier`, `files[]` with
stripped content + SHA-256 hashes, `summary`) to stdout without writing a
file. To save it for use in step 5c:

```bash
python client/parser.py ~/ose-test-project --output contract_a_sample.json
```

### 5c. Test `fsa/analyzer.py`

`analyzer.py` decides between the **real engine** and **mock mode** purely
based on whether `fsa.signatures` and `fsa.graph_builder` are importable
(`_module_available(...)`) — it does *not* check whether tree-sitter is
installed for that decision.

**Real engine** (requires `fsa/graph_builder.py` and `fsa/signatures.py` to
exist in your package, which they do per your project files):

```bash
python fsa/analyzer.py contract_a_sample.json > contract_b_sample.json
cat contract_b_sample.json
```

If `tree-sitter` / `tree-sitter-javascript` aren't installed, AST parsing
silently fails per-file (`_parse_ast` returns `None`) and you'll get **zero
findings** even though you're in "real engine" mode — check the server logs
for `tree-sitter-javascript is not installed` warnings to tell the
difference between "clean code" and "parser unavailable."

**Mock mode** (to deliberately exercise the fallback manifest in
`_get_mock_manifest`, e.g. before `graph_builder.py`/`signatures.py` exist
in your tree, or to verify the fallback path works): temporarily rename
those two files so the import fails, run the same command, then rename them
back:

```bash
mv fsa/graph_builder.py fsa/graph_builder.py.bak
mv fsa/signatures.py fsa/signatures.py.bak
python fsa/analyzer.py contract_a_sample.json   # now returns the mock manifest
mv fsa/graph_builder.py.bak fsa/graph_builder.py
mv fsa/signatures.py.bak fsa/signatures.py
```

### 5d. Test the `ose audit` command end-to-end

There's no `setup.py`/`pyproject.toml` in your shared files, so the
`ose` console command isn't installed yet. For local testing you have two
options:

**Option A — run it directly, no packaging needed:**
```bash
python ose.py audit ~/ose-test-project --output report.json --debug
cat report.json
```

**Option B — install it as a real `ose` command**, add a minimal
`pyproject.toml` at the project root:
```toml
[project]
name = "ose-auditor"
version = "1.0.0"
requires-python = ">=3.9"

[project.scripts]
ose = "ose:main"

[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"
```
then:
```bash
pip install -e .
ose audit ~/ose-test-project --output report.json --debug
```

> **Gotcha — `OSE_SERVER_URL` is hardcoded.** `client/orchestrator.py`
> defines `OSE_SERVER_URL = "https://ose.crestsek.com/v1/audit"` as a
> module-level constant — it always talks to production, not your local
> `uvicorn` server. There's currently no environment variable to redirect
> it. To test the full client → server round trip against your local
> server, temporarily edit that one line to
> `OSE_SERVER_URL = "http://localhost:8000/v1/audit"` in your working copy
> (don't commit that change), or add an `os.environ.get("OSE_SERVER_URL",
> "https://ose.crestsek.com/v1/audit")` override if you want this to be
> a permanent, reusable testing knob.

---

## 6. Webhook testing

**Heads-up:** `server/billing.py` defines `parse_flutterwave_webhook()`, but
none of the files you shared wire it up to an actual FastAPI route in
`server/main.py`. You'll need to add a receiving endpoint before there's
anything to test. A minimal one, using only functions already in your
codebase, looks like this — add it to `server/main.py`:

```python
@app.post("/webhooks/flutterwave")
async def flutterwave_webhook(request: Request):
    # Flutterwave signs webhooks with a `verif-hash` header that must
    # match the secret hash you configured in their dashboard.
    expected_hash = os.environ.get("FLW_SECRET_HASH")
    received_hash = request.headers.get("verif-hash")
    if not expected_hash or received_hash != expected_hash:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                             detail="Invalid webhook signature.")

    payload = await request.json()
    result = billing.parse_flutterwave_webhook(payload.get("data", payload))

    if result is None:
        return {"status": "ignored"}  # not an OSE payment
    if not result["valid"]:
        logger.warning("Invalid OSE webhook: %s", result.get("message"))
        return {"status": "invalid", "message": result.get("message")}

    await database.add_credits(
        user_id=result["user_id"],
        credits=result["credits"],
        flutterwave_ref=result["tx_ref"],
    )
    return {"status": "ok"}
```

### 6a. Expose your local server with ngrok

```bash
# Install ngrok (one-time)
curl -sSL https://ngrok-agent.s3.amazonaws.com/ngrok.asc \
  | sudo tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null
echo "deb https://ngrok-agent.s3.amazonaws.com buster main" \
  | sudo tee /etc/apt/sources.list.d/ngrok.list
sudo apt update && sudo apt install -y ngrok

ngrok config add-authtoken <your-ngrok-authtoken>   # from ngrok.com dashboard

# With uvicorn already running on port 8000 in another terminal:
ngrok http 8000
```

Copy the `https://xxxx.ngrok-free.app` URL ngrok prints out.

### 6b. Configure the webhook in Flutterwave

In the Flutterwave dashboard, set your webhook URL to
`https://xxxx.ngrok-free.app/webhooks/flutterwave`, and set the **Secret
Hash** field to the same value you put in `FLW_SECRET_HASH` in `.env`.
Flutterwave's dashboard has a "Test Webhook" button that fires a sample
event at that URL.

### 6c. Or simulate a payload manually with curl

```bash
curl -X POST https://xxxx.ngrok-free.app/webhooks/flutterwave \
  -H "Content-Type: application/json" \
  -H "verif-hash: $FLW_SECRET_HASH" \
  -d '{
    "event": "charge.completed",
    "data": {
      "id": 123456,
      "tx_ref": "ose_test_user_1_starter",
      "status": "successful",
      "amount": 5.00,
      "currency": "USD",
      "transaction_id": "123456"
    }
  }'
```

That `tx_ref` decodes (per `parse_flutterwave_webhook`'s suffix-matching
logic) to `user_id="test_user_1"`, `pack="starter"`. Verify it worked:

```bash
curl -H "Authorization: Bearer $OSE_API_KEY" \
  "http://localhost:8000/v1/credits?user_id=test_user_1"
# Expect: {"user_id": "test_user_1", "credits": 50, "tier": "premium"}
```

---

## 7. Common issues and fixes

**`ModuleNotFoundError: No module named 'client'` (or `contracts`, `fsa`,
`server`)**
Your files aren't arranged into the package layout in Section 0, or you're
running commands from the wrong directory. Run everything from the project
root, and confirm each package folder has an `__init__.py`.

**`asyncpg.exceptions.InvalidPasswordError` / connection refused to Neon**
Double-check you copied the full connection string (Neon sometimes
truncates it visually in the dashboard) and that `?sslmode=require` is
present.

**`prepared statement "__asyncpg_stmt_x__" already exists` /
`cached plan must not change result type`**
You're using Neon's pooled (`-pooler`) connection string with PgBouncer in
transaction mode, which conflicts with asyncpg's statement caching. Switch
to the direct connection string for local testing (see Section 3c).

**`DatabaseError: DATABASE_URL environment variable not set`**
`.env` wasn't loaded. Confirm you started uvicorn with `--env-file .env`
(and that `python-dotenv` is installed), or `set -a; source .env; set +a`
before starting it.

**`/v1/audit` returns `502` immediately**
Either `ANTHROPIC_API_KEY`/`OPENAI_API_KEY` is missing for your configured
`LLM_PROVIDER`, or the LLM API itself returned an error — check the
uvicorn logs, `_call_anthropic`/`_call_openai` log the HTTP status code.

**`/v1/audit` or `/v1/credits` returns `401 Invalid or missing API key`**
The `Authorization: Bearer <token>` header doesn't match `OSE_API_KEY` in
the server's environment exactly (whitespace, stray quotes from copy-paste,
or you're authenticating against a server process that was started before
you last edited `.env` — restart uvicorn after env changes).

**Zero findings every time from `fsa/analyzer.py`, even on obviously
vulnerable code**
This usually means tree-sitter isn't actually installed/loading, not that
the code is clean. Check for `tree-sitter-javascript is not installed` /
`Failed to initialize JavaScript grammar` warnings in the logs (Section
5c).

**`ose audit` hangs or times out waiting on the server**
You're hitting the hardcoded production `OSE_SERVER_URL`, not your local
server (see the gotcha at the end of Section 5d) — or your local server
genuinely isn't running/reachable on that port.

**Port 8000 already in use**
```bash
lsof -i :8000        # find the PID
kill <pid>
# or just run uvicorn on a different port:
uvicorn server.main:app --reload --port 8001 --env-file .env
```

**`pip install` tries to compile asyncpg / tree-sitter from source and
fails without a compiler**
No prebuilt wheel matched your Python version/OS/architecture combo (rare
on 3.13 for these specific packages, but possible on less common
platforms). Install build tools as a fallback:
```bash
sudo apt install -y build-essential python3.13-dev
```

**httpx not installed, but the client still seems to work**
That's expected — `client/orchestrator.py` only imports `httpx` for a
presence check at module load (`_HAS_HTTPX`) and transparently falls back
to the standard library's `urllib` if it's missing. Install `httpx` anyway
if you want HTTP/2 support and better timeout handling.
