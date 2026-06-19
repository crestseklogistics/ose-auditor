# OSE Auditor — Local Setup & Testing Guide

This guide is written directly against the code you've built so far (`ose.py`,
`orchestrator.py`, `parser.py`, `contract_a.py`, `contract_b.py`, `analyzer.py`,
`signatures.py`, `graph_builder.py`, `main.py`, `database.py`, `prompts.py`,
`billing.py`). A few things below are **gotchas specific to your codebase**,
not generic FastAPI/Python advice — they're called out in bold.

---

## 0. Required Package Layout (do this first)

Your modules import each other as packages, not as loose scripts:

| File | Imports it makes |
|---|---|
| `ose.py` | `from client import orchestrator` (falls back to `import orchestrator`) |
| `orchestrator.py` | `from client.parser import OseParser`, `from contracts import contract_a`, `from contracts import contract_b`, `from fsa import analyzer` |
| `analyzer.py` | `from fsa import graph_builder`, `from fsa import signatures` |
| `main.py` | `from server import database`, `from server import prompts`, `from server.database import ...` |

So your project root must look like this:

```
ose-auditor/
├── client/
│   ├── __init__.py
│   ├── ose.py
│   ├── parser.py
│   └── orchestrator.py
├── contracts/
│   ├── __init__.py
│   ├── contract_a.py
│   └── contract_b.py
├── fsa/
│   ├── __init__.py
│   ├── analyzer.py
│   ├── signatures.py
│   └── graph_builder.py
├── server/
│   ├── __init__.py
│   ├── main.py
│   ├── database.py
│   ├── prompts.py
│   └── billing.py
├── .env
└── requirements.txt
```

```bash
cd ~/Documents/Obatobie/ose-auditor
for d in client contracts fsa server; do
  mkdir -p "$d"
  touch "$d/__init__.py"
done
# move each .py file into its corresponding folder if it isn't already there
```

If `python.py` files are currently flat in the repo root, move them into the
folders above. Everything below assumes this layout and that you run commands
**from the `ose-auditor` root**.

---

## 1. Upgrading `bvenv` to Python 3.13

You cannot upgrade a venv's Python version in place — venvs are tied to the
interpreter that created them. The reliable path is: install 3.13 on the
system (or via pyenv), then **recreate** the venv and reinstall packages.

### 1a. Check what's installed
```bash
python3.13 --version 2>/dev/null || echo "Python 3.13 not found on PATH"
which -a python3.13
```

### 1b. Install Python 3.13 via pyenv (recommended — works on any Linux distro)
```bash
sudo apt update
sudo apt install -y build-essential libssl-dev zlib1g-dev libbz2-dev \
  libreadline-dev libsqlite3-dev curl git libncursesw5-dev xz-utils \
  tk-dev libxml2-dev libxmlsec1-dev libffi-dev liblzma-dev

curl https://pyenv.run | bash

# Add to ~/.bashrc (or ~/.zshrc):
echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
echo 'export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc
echo 'eval "$(pyenv init -)"' >> ~/.bashrc
source ~/.bashrc

pyenv install 3.13.0
pyenv versions   # confirm 3.13.0 is listed
```

### 1c. Recreate the venv
```bash
cd ~/Documents/Obatobie/ose-auditor
deactivate 2>/dev/null
mv bvenv bvenv-py312-backup   # keep the old one until you confirm 3.13 works

~/.pyenv/versions/3.13.0/bin/python3.13 -m venv bvenv
source bvenv/bin/activate
python --version    # should print Python 3.13.0
pip install --upgrade pip
```

Once you've confirmed everything below works on 3.13, delete the backup:
`rm -rf bvenv-py312-backup`.

---

## 2. Dependency Installation

I don't have your current `requirements.txt`, so I can't diff against it —
below is the **complete list derived from every import actually used** across
your files.

| Package | Used by | Why |
|---|---|---|
| `fastapi` | `server/main.py` | the API framework |
| `uvicorn[standard]` | run command | ASGI server |
| `pydantic` | `server/main.py` | request/response models |
| `httpx` | `server/main.py`, `client/orchestrator.py` | LLM HTTP calls + client→server calls |
| `asyncpg` | `server/database.py` | Postgres/Neon driver |
| `tree-sitter` | `fsa/analyzer.py` | AST parsing core |
| `tree-sitter-javascript` | `fsa/analyzer.py` | JS grammar |
| `tree-sitter-typescript` | `fsa/analyzer.py` | TS/TSX grammar |

```bash
pip install \
  "fastapi>=0.110" \
  "uvicorn[standard]>=0.27" \
  "pydantic>=2.5" \
  "httpx>=0.27" \
  "asyncpg>=0.29" \
  "tree-sitter>=0.21" \
  "tree-sitter-javascript>=0.21" \
  "tree-sitter-typescript>=0.21"

pip freeze > requirements.txt
```

**Note:** `client/ose.py`, `client/parser.py`, `contracts/contract_a.py`,
`contracts/contract_b.py`, `fsa/signatures.py`, `fsa/graph_builder.py`, and
`server/prompts.py`/`billing.py` use **only the standard library** — that's
by design per your zero-dependency requirement, so nothing extra is needed
for those.

`httpx` is technically optional in `orchestrator.py` (it falls back to
`urllib` if missing — see `_HAS_HTTPX`), but install it anyway since
`server/main.py` requires it unconditionally.

---

## 3. Environment Configuration

### 3a. `.env` template

```bash
# --- Server auth (must match exactly between client and server for local testing) ---
OSE_API_KEY=local-dev-test-key-12345

# --- LLM provider ---
LLM_PROVIDER=anthropic          # or "openai"
LLM_MODEL=claude-3-5-sonnet-20241022   # optional override; see main.py defaults
ANTHROPIC_API_KEY=sk-ant-...    # required if LLM_PROVIDER=anthropic
OPENAI_API_KEY=sk-...           # required if LLM_PROVIDER=openai

# --- Billing / checkout ---
CHECKOUT_URL_BASE=https://flutterwave.com/pay/ose

# --- Database (Neon) ---
DATABASE_URL=postgresql://USER:PASSWORD@ep-xxxx.region.aws.neon.tech/dbname?sslmode=require
```

**Important — your code does not call `load_dotenv()` anywhere.** Every
`os.environ.get(...)` in `main.py`, `orchestrator.py`, and `database.py`
reads directly from the process environment. A `.env` file on disk does
**nothing by itself**. Pick one:

- **Easiest for the server:** `uvicorn` has a built-in `--env-file` flag
  that loads a dotenv file before starting (covered in Section 4).
- **For the client (`ose audit`):** export the vars in your shell, or
  `source` the file:
  ```bash
  set -a; source .env; set +a
  ```
- **If you want `.env` to "just work" everywhere**, add
  `python-dotenv` to requirements and `load_dotenv()` at the top of
  `server/main.py` and `client/ose.py` — this isn't in your code today,
  so I'm not assuming it; happy to add it if you want.

### 3b. Neon database setup

1. Create a Neon project at console.neon.tech, create a database, and copy
   the pooled connection string (it already includes `sslmode=require`,
   which `asyncpg` understands natively in recent versions).
2. You do **not** need to write any SQL by hand — `database.init_schema()`
   creates `ose_usage_nodes`, `invite_tokens`, and `audit_history` with
   `CREATE TABLE IF NOT EXISTS` on every server startup (see `lifespan()`
   in `main.py`).
3. To sanity-check the connection without starting the full server:
   ```bash
   set -a; source .env; set +a
   python3 -c "
   import asyncio
   from server import database

   async def main():
       await database.init_pool()
       await database.init_schema()
       print('Connected and schema initialized OK')
       await database.close_pool()

   asyncio.run(main())
   "
   ```

---

## 4. Running the Server Locally

```bash
cd ~/Documents/Obatobie/ose-auditor
source bvenv/bin/activate
uvicorn server.main:app --reload --port 8000 --env-file .env
```

(`server.main:app` — not `main:app` — because `main.py` lives in the
`server/` package and is run from the project root.)

### 4a. Test `/health`
```bash
curl http://localhost:8000/health
```

### 4b. Test `/v1/credits`
This endpoint requires the `OSE_API_KEY` Bearer token and a `user_id` query
param:
```bash
set -a; source .env; set +a
curl -H "Authorization: Bearer $OSE_API_KEY" \
  "http://localhost:8000/v1/credits?user_id=test_user_1"
```
A brand-new `user_id` is auto-created on first call only by `/v1/audit`
(`get_or_create_user`) — `/v1/credits` alone returns `0`/`"free"` defaults
for a user that's never been created, since `get_tier`/`get_remaining_credits`
default gracefully when no row exists.

### 4c. Test `/v1/audit`
This is a **real call** — it will deduct a free-tier credit and call your
configured LLM provider (costs tokens/money). Keep it to one finding while
testing.

```bash
set -a; source .env; set +a
PROJECT_HASH=$(python3 -c "import hashlib; print(hashlib.sha256(b'test-project').hexdigest())")
GENERATED_AT=$(python3 -c "from datetime import datetime, timezone; print(datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))")

curl -X POST http://localhost:8000/v1/audit \
  -H "Authorization: Bearer $OSE_API_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"manifest\": {
      \"contract_version\": \"1.0.0\",
      \"project_hash\": \"$PROJECT_HASH\",
      \"generated_at\": \"$GENERATED_AT\",
      \"analysis_metadata\": {
        \"scanner_version\": \"1.0.0\",
        \"files_analyzed\": 1,
        \"analysis_duration_seconds\": 0.05,
        \"target_tracks\": [\"web2\"]
      },
      \"findings\": [
        {
          \"id\": \"FSA-BAUTH-001\",
          \"file_path\": \"src/controllers/payment.js\",
          \"line_start\": 12,
          \"line_end\": 18,
          \"vulnerability_class\": \"BROKEN_AUTH\",
          \"severity\": \"HIGH\",
          \"code_snippet\": \"async function processPayment(amount, userId) { user.balance -= amount; await user.save(); }\",
          \"description\": \"Function performs a financial state mutation without a preceding authorization check.\",
          \"fix_principle\": \"Add an authentication/authorization check before mutating financial state.\",
          \"confidence\": 0.85,
          \"false_positive_risk\": \"LOW\"
        }
      ]
    },
    \"client_version\": \"1.0.0\",
    \"user_id\": \"test_user_1\",
    \"track\": \"web2\"
  }"
```

**Testing tip:** the free tier is capped at 5 requests / 7 days per
`user_id` (`FREE_CREDITS_PER_PERIOD` in `database.py`). You will burn
through this fast while iterating. Promote your test user to unlimited:
```bash
python3 -c "
import asyncio
from server import database

async def main():
    await database.init_pool()
    await database.get_or_create_user('test_user_1')
    await database.update_tier('test_user_1', 'premium')
    print('test_user_1 is now premium (unlimited credits)')

asyncio.run(main())
"
```

---

## 5. Testing the Client

### 5a. `parser.py` alone (no package needed — it's standalone-runnable)
```bash
mkdir -p ~/test-projects/vulnerable-app/src/controllers
cd ~/test-projects/vulnerable-app
cat > package.json << 'EOF'
{ "name": "vulnerable-app", "version": "1.0.0" }
EOF
cat > src/controllers/payment.js << 'EOF'
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

cd ~/Documents/Obatobie/ose-auditor
python -m client.parser ~/test-projects/vulnerable-app --dry-run --debug
```
Confirm the output JSON has one `files` entry, a 64-char `project_identifier`,
and that comments/whitespace were stripped from `stripped_content`.

### 5b. `analyzer.py` in mock mode

**Mock mode only triggers when `fsa.signatures` and `fsa.graph_builder` are
NOT importable** (`_module_available` check in `analyzer.analyze()`). Since
both files already exist in your `fsa/` package, the analyzer runs the
**real** rule engine by default — mock mode is effectively dead code in your
current repo unless you deliberately disable the real modules:

```bash
mv fsa/signatures.py fsa/signatures.py.bak
mv fsa/graph_builder.py fsa/graph_builder.py.bak

python3 -c "
import json
from fsa import analyzer
fake_index = {'project_identifier': '0'*64, 'files': []}
print(json.dumps(analyzer.analyze(fake_index), indent=2))
"
# should print the 2-finding mock manifest from _get_mock_manifest()

mv fsa/signatures.py.bak fsa/signatures.py
mv fsa/graph_builder.py.bak fsa/graph_builder.py
```

### 5c. `analyzer.py` in full (real) mode against the test project
```bash
python3 -c "
import json
from client.parser import OseParser
from fsa import analyzer

idx = OseParser('$HOME/test-projects/vulnerable-app').scan()
result = analyzer.analyze(idx)
print(json.dumps(result, indent=2))
"
```
You should see `BROKEN_AUTH` (no auth check before `user.balance -=`) and
likely `UNCHECKED_EXTERNAL_CALL` (the Stripe charge result isn't checked
before the mutation) fire against `payment.js`.

**Silent-failure gotcha:** if `tree-sitter`/`tree-sitter-javascript` aren't
actually installed, `full_engine_available` is still `True` (it only checks
that `fsa.signatures`/`fsa.graph_builder` *files* exist, not that
tree-sitter itself works) — but `_get_parser()` will return `None` for
every file, `_parse_ast` returns `None`, and `_analyze_file` silently skips
the file with a `WARNING` log. The end result looks identical to "zero
vulnerabilities found." Always run with `--debug` and check the logs the
first time you test a new environment.

### 5d. `ose audit` end-to-end

```bash
python -m client.ose audit ~/test-projects/vulnerable-app --debug
```

**Important:** `orchestrator.py` posts findings to a **hardcoded constant**:
```python
OSE_SERVER_URL = "https://ose.crestsek.com/v1/audit"
```
There is no env var or config override for this in the code you gave me —
running `ose audit` does **not** hit your local `uvicorn` server. Three
options:

1. **Safe default for local testing:** don't set `OSE_API_KEY` in this
   shell. The orchestrator will build and validate the manifest, save the
   cache, then stop with `EXIT_GENERAL_ERROR` right before the network
   call — which is exactly the part you want to test anyway (parsing,
   Contract A/B validation, the rule engine).
2. **Full E2E against your local server:** temporarily edit the constant —
   `OSE_SERVER_URL = "http://localhost:8000/v1/audit"` — run your test,
   then revert before committing.
3. Add a proper config-driven override (e.g. an `OSE_SERVER_URL` env var
   read in `orchestrator.py`) if you want this permanently testable — not
   in your current code, so flagging rather than assuming.

---

## 6. Webhook Testing

**Heads up:** `billing.py` has `parse_flutterwave_webhook()`, but the
`main.py` you gave me only defines `/health`, `/v1/audit`, and
`/v1/credits` — there's no `/webhook` route wired up yet. I'm not going to
invent one for you silently; if you want, tell me and I'll draft a route
that calls `parse_flutterwave_webhook()` → `database.set_premium()`. Until
then, here's how to test the parsing logic directly:

### 6a. Test the parser function in isolation
```bash
python3 -c "
from server import billing
payload = {
    'tx_ref': 'ose_test_user_1_starter',
    'status': 'successful',
    'amount': 5.00,
    'currency': 'USD',
    'transaction_id': 'TX123456'
}
print(billing.parse_flutterwave_webhook(payload))
"
```
Expect `{'valid': True, 'user_id': 'test_user_1', 'pack': 'starter', ...}`.

### 6b. ngrok, for whenever the route exists
```bash
# install (Debian/Ubuntu)
curl -sSL https://ngrok-agent.s3.amazonaws.com/ngrok.asc | sudo tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null
echo "deb https://ngrok-agent.s3.amazonaws.com buster main" | sudo tee /etc/apt/sources.list.d/ngrok.list
sudo apt update && sudo apt install ngrok
ngrok config add-authtoken <your-ngrok-token>

# with the server already running on :8000 in another terminal:
ngrok http 8000
```
Use the printed `https://xxxx.ngrok-free.app/webhook` URL as the Flutterwave
test webhook destination once a route exists.

---

## 7. Common Issues & Fixes

| Symptom | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: No module named 'client'` (or `fsa`/`contracts`/`server`) | Missing `__init__.py`, or not running from project root | See Section 0; run commands from `ose-auditor/`, not from inside a subfolder |
| `ImportError` / `Incompatible Language version` from tree-sitter | `tree-sitter` core and `tree-sitter-javascript`/`tree-sitter-typescript` built against different ABI versions | Reinstall all three together at matching major versions: `pip install -U tree-sitter tree-sitter-javascript tree-sitter-typescript` |
| Findings always empty even on obviously vulnerable code | tree-sitter not actually installed (see 5c) | Run with `--debug`, check for `"Failed to parse AST"` warnings |
| `asyncpg` SSL connection error to Neon | Missing/incorrect SSL params | Confirm `?sslmode=require` is in `DATABASE_URL`; use the Neon **pooled** connection string |
| `/v1/audit` returns 502 "LLM service unavailable" | Missing `ANTHROPIC_API_KEY`/`OPENAI_API_KEY` for the configured `LLM_PROVIDER` | Set the matching key in `.env` |
| `/v1/credits` or `/v1/audit` returns 401 | `OSE_API_KEY` mismatch between client and server | Both sides must hold the **exact same string** — server reads it as an env var, client reads `OSE_API_KEY` env var or `~/.ose/config.json` |
| `CREDIT_EXHAUSTED` during repeated local testing | Free tier = 5 requests / 7 days per `user_id` | Promote your test user to `premium` (Section 4c), or use a fresh `user_id` each test run |
| `.env` values seem ignored | No `load_dotenv()` call anywhere in the code | Use `uvicorn --env-file .env` for the server, `source .env` for the client (Section 3a) |
| `ose audit` exits with `EXIT_GENERAL_ERROR` after manifest looks fine | No `OSE_API_KEY` set, or it's trying to reach production `ose.crestsek.com` | Expected if you haven't set the key — see Section 5d for your options |
| `pip install asyncpg` fails to build on Python 3.13 | Occasionally lags very new Python releases | `pip install -U asyncpg` to get the latest wheel; if it still fails, confirm your pyenv 3.13 build has working SSL headers, or fall back to the 3.12 venv backup while you wait for an updated wheel |

---

### Quick-start checklist
1. Section 0 — package layout + `__init__.py` files
2. Section 1 — recreate `bvenv` on Python 3.13
3. Section 2 — `pip install` the dependency list
4. Section 3 — fill in `.env`, verify Neon connection
5. Section 4 — `uvicorn server.main:app --reload --env-file .env`, hit `/health`
6. Section 5a–5c — test `parser.py` and `analyzer.py` against the sample vulnerable project
7. Section 5d — test `ose audit` *without* `OSE_API_KEY` set first, to validate the pipeline safely
