# OSE AUDITOR – COMPREHENSIVE HANDBOVER DOCUMENT

**Generated from:** Full chat transcript (Ose Auditor focus)
**Date:** 2026-06-17
**Role of document:** To enable any AI or human to fully understand the project history, decisions, and current state without reading the original chat.

---

## SECTION 1: CORE PROJECT OBJECTIVE

| Element | Detail |
| :--- | :--- |
| **What the user is building** | OSE Auditor – an autonomous financial and logic exploit detection engine. It uses deterministic code analysis (via the proprietary Financial Semantic Analyzer) combined with AI-assisted remediation to discover vulnerabilities that can cause financial loss. |
| **Business purpose** | To create a self-sustaining security utility that requires $0 upfront operational capital. It generates its own revenue through credit sales, covering any cloud costs without pulling funds from the user or their primary business (Crestsek Technology Ltd). |
| **End users** | Three groups: <br> • **Web2 developers** – building backend APIs, payment systems, marketplaces, fintech applications. <br> • **Web3 developers** – writing smart contracts (future). <br> • **Quant traders** – writing automated trading scripts (future). <br> **MVP focuses on Web2 (Node.js/TypeScript) developers.** |
| **Platforms and ecosystems** | • **Local CLI** – `ose audit .` <br> • **MCP Server** – integration with Cursor, Aider, Cline (future). <br> • **GitHub App** – automatic PR commenting (future). <br> • **Continuous Monitoring Dashboard** (future). |
| **Commercial model** | • **Free tier:** 5 credits every 7 days (resets automatically). <br> • **Credit consumption:** Web2 = 1 credit, Web3/Quant = 5 credits. <br> • **Credit packs** (Flutterwave, USD): <br>   - Starter: $5 for 50 credits <br>   - Pro Hacker: $25 for 300 credits <br>   - Enterprise Node: $100 for 1,500 credits <br> • **Payment routing:** Flutterwave webhooks go to `api.crestsek.com`, which updates the Neon DB. |

---

## SECTION 2: FULL JOURNEY — HOW WE GOT HERE

### Phase 0: Initial Confusion (Rejected Context)
The conversation began with the assistant mistakenly referring to a **delivery app called Crestsek** and an **SEO bot** — both hallucinated from a different user's context. The user immediately corrected this, stating they are a **Python backend security engineer** building **Ose Auditor**. This initial correction established the need to **strip out all unrelated noise**.

### Phase 1: Product Vision & Architecture Definition
The user laid out the core idea:
- Build an AI code‑review agent that finds critical logic and security vulnerabilities missed by general models.
- Focus on **financial and business logic flaws**, not just syntax or CVEs.
- Separate **open-source components** (parser, CLI, orchestrator) from **proprietary** (FSA, server).
- The **Financial Semantic Analyzer (FSA)** would be the proprietary core that does deterministic analysis; AI is used only for remediation.

**Key documents created (conceptually)**: SAD, PSD, Data Contracts, Positioning Strategy.

### Phase 2: Infrastructure & $0 Budget Design
The user expressed anxiety about costs and domain purchases. We resolved:
- **Hosting:** Render Free Tier + Neon DB (Postgres) + Cloudflare subdomain (`ose.crestsek.com`).
- **Keep‑alive:** cron-job.org pings `/health` every 14 minutes to prevent cold starts.
- **Payment routing:** Flutterwave webhooks go to the existing `api.crestsek.com` (the user’s primary backend) to avoid setting up a new payment endpoint.
- **Domain:** Subdomain CNAME record → no extra domain purchase.

### Phase 3: The Hybrid Local/Cloud Architecture
The user worried about processing large codebases (600+ files) on a free Render instance. We designed:
- **Local client** does all heavy file scanning, stripping, and AST parsing (via tree‑sitter, Bandit, Slither – though these are now optional).
- **Only a tiny JSON payload (<50KB)** is sent to Render.
- This keeps server costs at $0 and maintains privacy.

### Phase 4: Data Contracts & Open Source Boundaries
We defined:
- **Contract A** (Project Source Index) – produced by `parser.py`, consumed by FSA.
- **Contract B** (Vulnerability Manifest) – produced by FSA, consumed by OSE Server.
- **Open Source:** `client/ose.py`, `client/parser.py`, `client/orchestrator.py`.
- **Proprietary:** All `fsa/*` and `server/*` (except maybe public schema definitions).

### Phase 5: Frustration with Documentation Overload
The user repeatedly expressed:
> *"I’m tired of documentation."*
> *"We’re creating documents but not building anything."*

They wanted to **move from planning to code**.

### Phase 6: First Code Generation – `client/ose.py`
We shifted to generating actual files. We created a prompt for DeepSeek to write `client/ose.py` – the CLI entry point. The user reviewed it line‑by‑line and confirmed understanding.

### Phase 7: Adding Communities, GitHub Integration, and Expanded Detection
The user provided three additional segments (the ones attached to the last messages) that:
- Listed communities to target (Discord, Dev.to, Hacker News, OWASP, etc.).
- Defined **GitHub integration levels** (Level 1: manual CLI, Level 2: webhook PR comments, Level 3: continuous monitoring).
- Clarified that **Web2 detection** is **Business Logic + Financial Logic**, not generic SAST.
- Listed **12 vulnerability classes** and **6 business domains** (payments, wallets, marketplaces, etc.).

### Phase 8: Handover Request
The user asked for a comprehensive handover document to allow any AI to pick up the project without reading the whole chat. They also asked three specific questions about `parser.py` implementation, to be answered after this document is produced.

---

## SECTION 3: EVERYTHING DONE AND FIXED

| Problem / Task | Solution | Files / Code Involved | Status |
| :--- | :--- | :--- | :--- |
| **Hallucinated delivery app context** | Explicitly rejected; reset to Ose Auditor focus. | None | ✅ Done |
| **No clear product definition** | Created Positioning & Strategy document: OSE = financial logic exploit detector. | `OSE Auditor - Official Positioning & Product Strategy.docx` | ✅ Done (conceptually) |
| **No architecture blueprint** | Created SAD (System Architecture Document) defining all components, responsibilities, and boundaries. | SAD (written in chat) | ✅ Done |
| **No data contracts** | Created Contract A (Project Source Index) and Contract B (Vulnerability Manifest) with full JSON schemas, validation rules, and examples. | `Ose-ContractsDoc.md` (provided as file) | ✅ Done |
| **Parser requirements unclear** | Created Parser Specification Document (PSD) defining exact duties, non‑duties, performance limits, security, and expansion. | `ose-parserv1.md` (provided as file) | ✅ Done |
| **Cost of hosting** | Chose Render Free Tier, Neon DB Free Tier, Cloudflare subdomain, cron-job.org keep‑alive. | No code; configuration decisions | ✅ Done |
| **Domain cost anxiety** | Subdomain `ose.crestsek.com` via CNAME; no new purchase. | DNS record | ✅ Done |
| **Payment routing complexity** | Flutterwave webhooks point to existing `api.crestsek.com`; it parses `ose_` prefix and updates Neon DB. | Integration with existing Crestsek backend | ✅ Done (architectural decision) |
| **Massive file handling** | Hybrid local/cloud: local parser strips to <50KB payload; server only receives abstracted manifest. | Design decision | ✅ Done |
| **`client/ose.py` CLI** | Generated via DeepSeek prompt; includes argparse, logging, version, exit codes, orchestrator call. | `client/ose.py` | ✅ Generated; not yet tested |
| **Business logic detection focus** | Finalised 12 detection classes and 6 business domains for Web2 v1. | Detection list (see Section 4) | ✅ Defined |

---

## SECTION 4: EVERYTHING PROPOSED BUT NOT YET BUILT

| Item | Description | Why proposed | Approach agreed | Files to change | SQL/DB changes | Dependencies/blockers |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`client/parser.py`** | File system pre‑processor: traverse, ignore, strip, hash, build Contract A. | First step in pipeline. | Use `pathlib`, ignore lists, regex comment stripping, SHA‑256 hashing. | `client/parser.py` | None | Needs confirmation on tree‑sitter vs regex, dry‑run, standalone. |
| **`client/orchestrator.py`** | Coordinates parser, FSA, and server calls. | Glues the local pipeline. | Calls parser, calls FSA, sends manifest to server, returns report. | `client/orchestrator.py` | None | Depends on parser and FSA. |
| **`fsa/analyzer.py`** | Core FSA intelligence: AST parsing, symbol table, state graph, signature matching. | Proprietary detection logic. | Uses tree‑sitter, builds graph, applies rules from signatures.py. | `fsa/analyzer.py` | None | Needs tree‑sitter and graph_builder. |
| **`fsa/signatures.py`** | Hardcoded vulnerability rules (e.g., reentrancy, broken auth). | Detection depends on these rules. | YAML or Python dicts describing patterns. | `fsa/signatures.py` | None | Needs initial rule set. |
| **`fsa/graph_builder.py`** | Builds state transition graph from AST. | Detects ordering flaws. | Tree traversal, node mapping. | `fsa/graph_builder.py` | None | Depends on tree‑sitter. |
| **`server/main.py`** | FastAPI app: receive manifest, validate credits, build prompt, call LLM, return patches. | Cloud API endpoint. | Use FastAPI, asyncpg, httpx. | `server/main.py` | None | Depends on database, prompts, billing. |
| **`server/database.py`** | Neon DB async connection pool. | User credit management. | Use asyncpg. | `server/database.py` | `ose_usage_nodes` table (schema defined in SAD) | None |
| **`server/prompts.py`** | Engineered system prompts for LLM (strict JSON output). | To generate high‑quality patches. | Hardcoded strings with placeholders. | `server/prompts.py` | None | None |
| **`server/billing.py`** | Credit validation, deduction, and Flutterwave webhook handling. | Monetisation. | Functions to check and deduct credits. | `server/billing.py` | Depends on database table. | Needs Flutterwave integration details. |
| **GitHub App integration** | Webhook on PR → clone → scan → comment. | Automation, user acquisition. | Use GitHub API, webhooks, server endpoints. | New `server/github.py` (or similar) | None | Requires GitHub OAuth app registration. |
| **Continuous Monitoring Dashboard** | Visual risk score, trends, history. | Subscription revenue. | React? Not finalised. | New frontend code | Additional DB tables for scan history. | UI design not started. |
| **MCP Server** | Expose OSE as MCP tool for Cursor/Aider. | Ecosystem integration. | Implement JSON‑RPC over stdio. | `client/mcp_server.py` | None | MCP spec may evolve. |
| **Web3 (Solidity) support** | Smart contract auditing (reentrancy, flash loans). | Expansion after Web2. | Add .sol parser, tree‑sitter-solidity, new rules. | `client/parser.py`, `fsa/analyzer.py`, `fsa/signatures.py` | None | Deferred. |
| **Quant (MQL/Python) support** | Trading bot audits (slippage, race conditions). | Expansion after Web3. | Add .mq4/.mq5/.py support, new rules. | As above | None | Deferred. |

---

## SECTION 5: EVERYTHING DEFERRED, IGNORED, OR INTENTIONALLY SKIPPED

| Item | What it is | Why deferred | Who handles | Conditions to resume |
| :--- | :--- | :--- | :--- | :--- |
| **Frontend landing page** | Terminal‑style static site (`static/index.html`). | Core engine must come first. | Future after MVP works. | When parser and server are functional. |
| **Web3 support** | Solidity audit. | Focus on Web2 first. | Future phase. | After Web2 MVP is stable. |
| **Quant support** | Trading bot audit. | Even further. | Future phase. | After Web3 phase. |
| **Paid marketing / ads** | Any paid acquisition. | User wants organic word‑of‑mouth first. | No budget currently. | After product‑market fit. |
| **Stripe payment** | Stripe integration. | Not natively supported in Nigeria without expensive US incorporation. | User prefers Flutterwave. | If Flutterwave becomes problematic. |
| **Traditional VPNs / proxies** | NordVPN, Surfshark for automation. | Rejected due to IP blocks. | Not used. | N/A |
| **GitHub Actions cron** | For keep‑alive. | Rejected due to 6‑hour limit and IP flags. | Replaced by cron‑job.org. | N/A |
| **Exe distribution** | Sending compiled binaries to users. | Trust and reverse‑engineering risks. | Replaced by CLI via pip/PyPI. | N/A |
| **Open‑source FSA** | The FSA code. | Core IP; must remain proprietary. | Not open‑sourced. | Never. |
| **Full code audit of every language** | Starting with all languages. | User chose Node.js first. | Future expansions. | After MVP. |

---

## SECTION 6: APPROACHES THAT FAILED OR WERE REJECTED

| Approach | Why failed / rejected | Replacement |
| :--- | :--- | :--- |
| **Using GitHub Actions to keep Render awake** | 6‑hour limit, IP ranges blocked by Cloudflare. | cron‑job.org pinging `/health` every 14 minutes. |
| **Sending compiled `.exe` to users** | Security trust barrier, easy to reverse‑engineer. | MCP / SaaS API hybrid; core engine stays on server. |
| **Stripe payment gateway** | Requires US incorporation (Stripe Atlas ~$500). | Flutterwave (native to Nigeria, $0 setup). |
| **Traditional commercial VPNs for scraping** | IPs flagged by Cloudflare/Google. | Residential proxies or direct ISP (deferred). |
| **Using `tree-sitter` in parser for comment stripping (decided against for now)** | Adds complexity; simple regex is sufficient for v1. | Custom regex comment stripper. |
| **Adding `Bandit`, `Slither`, `Semgrep` as core dependencies** | Would force users to install external tools; not the moat. | They become optional enrichment; FSA does the core detection. |
| **Building all 3 tracks simultaneously** | Scope overload. | Focus on Web2 first, then Web3, then Quant. |
| **Continuing with endless documentation** | Frustrated the user; no code was being written. | Shift to code generation (`ose.py` first). |

---

## SECTION 7: CURRENT STATE — WHERE EXACTLY ARE WE RIGHT NOW

- **Most recent work:** The user provided three additional segments (communities, GitHub integration, detection classes) and requested a comprehensive handover document. The user also asked **three specific questions about `parser.py` implementation** (see Section 11). These questions have not yet been answered because the user instructed: *"Do this before I can answer your questions"* (referring to this handover document).

- **Immediate next action:** After this handover document is delivered, the next step is to **answer those three questions** (about tree‑sitter vs regex, dry‑run flag, and standalone execution) to finalise the spec for `parser.py`. Then generate the **Claude prompt for `client/parser.py`**.

- **Blocking progress:** The parser prompt is blocked until those questions are answered. No other blocking issues.

- **Delivered but not yet tested:** `client/ose.py` has been generated but not run. No tests have been written or executed for any component.

---

## SECTION 8: TECHNICAL STACK AND SYSTEM ARCHITECTURE

| Layer | Component | Details |
| :--- | :--- | :--- |
| **Client (Local)** | Language | Python 3.10+ |
| | CLI framework | `argparse` (standard library) |
| | Logging | Python `logging` module, output to stderr |
| | File system | `pathlib`, `os.walk` |
| | Comment stripping | Custom regex (for now) – no external dependency |
| | AST for future FSA | `tree-sitter` (planned) |
| | Local HTTP client | `httpx` or `requests` (for orchestrator → server) |
| | Packaging | `pyproject.toml`, `pip` installable |
| **Cloud Server** | Hosting | Render Free Tier |
| | Language | Python 3.10+ |
| | Web framework | FastAPI |
| | Database | Neon DB (PostgreSQL) |
| | Async DB driver | `asyncpg` |
| | LLM integration | Anthropic Claude API / OpenAI GPT via `httpx` |
| | Environment variables | `os.environ.get()` – no hardcoded secrets |
| | Keep‑alive | cron-job.org pinging `/health` |
| **Domain & DNS** | Registrar | Truehost (user’s existing) |
| | DNS management | Cloudflare (free) |
| | Subdomain | `ose.crestsek.com` → Render via CNAME |
| | Proxy | Cloudflare orange cloud (hides Render origin) |
| **Payments** | Gateway | Flutterwave |
| | Currency | USD accepted, settled in NGN or USD domiciliary account |
| | Webhook | Points to `api.crestsek.com` (parent company backend) |
| | Webhook parsing | Detects `ose_` prefix in `tx_ref` to route to Ose DB |
| **Database Schema** | Table | `ose_usage_nodes` |
| | Columns | `user_id` (PK), `credit_tier`, `requests_this_period`, `period_start_time`, `flutterwave_ref` |
| | Invite tokens | (future) `referral_tokens` table |
| **Architectural Rules** | Hybrid local/cloud | Heavy scanning on user machine; only manifest sent to server. |
| | Zero raw source transmission | Server never sees full code, only vulnerable snippets. |
| | Open‑source vs proprietary | Parser, CLI, orchestrator open; FSA and server closed. |

---

## SECTION 9: BUSINESS CONTEXT AND DECISIONS

| Element | Detail |
| :--- | :--- |
| **Parent company** | Crestsek Technology Ltd (user’s existing entity) |
| **Product positioning** | OSE = autonomous financial and logic exploit detection engine. Not a chatbot, not a linter, not a CVE scanner. |
| **Target customers (v1)** | Solo developers, startup engineers, technical founders, freelance backend contractors building fintech, marketplaces, e‑commerce, wallet systems. |
| **Pricing model** | Core Credits (pay‑as‑you‑go): <br> • 5 free credits / 7 days <br> • Web2: 1 credit/file, Web3/Quant: 5 credits/file <br> • Starter: $5 / 50 credits <br> • Pro Hacker: $25 / 300 credits <br> • Enterprise Node: $100 / 1,500 credits |
| **Payment currency** | USD (via Flutterwave) |
| **Sales strategy** | Word‑of‑bot, GitHub PR proof, MCP ecosystem, invite‑only FOMO. No paid ads initially. |
| **Go‑to‑market stages** | 1. Founder outreach (Cursor/Reddit communities) <br> 2. GitHub vulnerability drops (public PRs) <br> 3. MCP registry listings <br> 4. Invite‑only referral tokens. |
| **Communities targeted** | Discord, Dev.to, Hacker News, OWASP, Reddit (r/node, r/typescript), X/Twitter, LinkedIn. |
| **Success metric** | Developers saying: "I don’t deploy AI‑generated code until OSE reviews it." |
| **Expansion roadmap** | Web2 → Web3 (Solidity) → Quant (Python/MQL) |
| **Open‑source strategy** | Open Core: CLI, parser, orchestrator open; FSA and server proprietary. |

---

## SECTION 10: CODING AND FORMAT PREFERENCES (STRICT RULES)

These are non‑negotiable and must be followed by any AI assisting on this project.

| Rule | Detail |
| :--- | :--- |
| **No code unless explicitly asked** | The assistant must not write code directly; it should generate prompts for AI systems (Claude/DeepSeek) that will produce the code. |
| **Code delivery** | For each file, produce a **Claude implementation prompt** that specifies the file, its purpose, inputs, outputs, and constraints. The prompt should be complete and standalone. |
| **Documentation before code** | Architecture, contracts, and specs must be fully defined before generating code. This phase is now complete. |
| **Strict adherence to OSE identity** | OSE is a **financial and logic exploit detection engine**. Not a chatbot, not a generic AI wrapper, not a SAST tool. |
| **$0 infrastructure** | Do not suggest any service that incurs cost (unless the user explicitly asks). Use Render, Neon, Cloudflare, cron‑job.org (all free). |
| **Environment variables** | Never hardcode secrets; use `os.environ.get()`. |
| **Type hints** | All functions must have type hints. |
| **Docstrings** | Every module, class, and function must have a docstring (Google or Sphinx style). |
| **Logging** | Use Python `logging` module; log to stderr; include timestamps. |
| **Exit codes** | CLI must return 0 for success, 1 for general error, 2 for audit failure. |
| **Modularity** | Each file should have a single responsibility. Avoid monolithic files. |
| **Open‑source vs proprietary** | Client components (parser, CLI, orchestrator) may be open; FSA and server must be proprietary. Do not propose opening those. |
| **Communication style** | Be direct, no hype, no sugar‑coating. If something is risky, say so. If something is unrealistic, say so. |
| **Questions before assumptions** | If uncertain, ask the user before proceeding. Never guess. |
| **Terminology** | Use the exact terms the user uses (e.g., "financial logic vulnerability", "business logic", "state transition"). Do not invent new terms. |
| **Repetition is a signal** | If the user repeats a point, prioritise it. Repeated items indicate importance. |

---

## SECTION 11: OPEN QUESTIONS AND UNRESOLVED THREADS

| Question | Context | Status |
| :--- | :--- | :--- |
| **1. Should `parser.py` use `tree-sitter` for comment stripping, or a simpler regex‑based approach?** | Asked by the user after `ose.py` was generated. They want clarity before implementing. | **Not yet answered** – user instructed to produce this handover document first. |
| **2. Should `parser.py` include a `--dry-run` flag to output the JSON without saving?** | User wants to inspect payload before transmission. | **Not yet answered**. |
| **3. Should `parser.py` be runnable as a standalone script, or only importable?** | Determines if `if __name__ == "__main__"` is needed. | **Not yet answered**. |
| **4. What is the exact JSON payload for Flutterwave's `tx_ref` and metadata?** | To ensure webhook mapping on `api.crestsek.com`. | Partially defined in Data Contracts; exact format may need confirmation. |
| **5. How to handle local installation of tree‑sitter and its language parsers?** | For future FSA. | Deferred until FSA development. |
| **6. What is the exact structure of the referral token system?** | Invite‑only growth mechanic. | Concept defined, but no implementation details (generation, expiry, tracking). |
| **7. How will `api.crestsek.com` differentiate OSE webhooks from other Crestsek webhooks?** | Payment routing. | Use `ose_` prefix in `tx_ref` – agreed, but implementation not done. |

---

## SECTION 12: CONTINUATION GUIDANCE FOR THE NEXT AI

### Direct Briefing for the Next AI (or human)

**Assume the following is already done:**
- Product vision, positioning, and strategy.
- System Architecture (SAD) and component responsibilities.
- Data Contract Specification (Contracts A and B, server response).
- Parser Specification Document (PSD).
- `client/ose.py` CLI implementation (ready, but untested).
- Infrastructure choices (Render, Neon, Cloudflare, Flutterwave, cron‑job.org).
- Commercial model and pricing.
- Detection focus (12 classes, 6 business domains).

**What to focus on immediately:**
- Answer the **three open questions** about `parser.py` (tree‑sitter vs regex, dry‑run, standalone).
- Then generate a **Claude prompt** for `client/parser.py` that implements the PSD and Contract A.
- After that, proceed to `client/orchestrator.py`, then `fsa/analyzer.py` (stub), then `server/main.py`.

**What NOT to bring up unless the user raises it:**
- Do not revisit the delivery app or SEO bot context (it was hallucinated and rejected).
- Do not suggest Stripe again (Flutterwave is chosen).
- Do not propose new architecture changes unless the user asks.
- Do not ask about logo, branding, or landing page design (these are lowest priority).
- Do not suggest paid cloud services.

**Communication style with this user:**
- Be **straightforward** and **direct**. The user values honesty over optimism.
- **No hype or sugar‑coating.** If something is risky, say it.
- **Ask questions before assuming.** If uncertain, pause and ask.
- **Keep answers concise** but complete – they dislike fluff.
- **Reference previous decisions** to show you have absorbed the context.

**Warnings / pitfalls to avoid:**
- The user has been **frustrated by excessive documentation** and wants to move to code. Do not generate more spec documents unless explicitly asked.
- The user is **cost‑sensitive** – always prefer free alternatives.
- The user is a **security engineer** – they will scrutinise code for vulnerabilities and reverse‑engineering risks. Ensure code is secure and does not leak secrets.
- The user **owns Crestsek Technology Ltd** – OSE is a subsidiary product; respect that business structure.
- The user has **repeatedly emphasised** that the FSA and server are **proprietary** – do not suggest opening them.

---

**End of Handover Document.**
