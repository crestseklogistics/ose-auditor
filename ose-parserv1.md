# OSE AUDITOR – PARSER SPECIFICATION DOCUMENT (PSD) v1.0

**Document Purpose:**  
This document defines the architectural boundaries, data contracts, performance constraints, and security guarantees for the `parser.py` module and its relationship with the Financial Semantic Analyzer (FSA) and the OSE Server. It is a binding specification for all client-side components.

**Scope:**  
Applies to Version 1 (Node.js/TypeScript support) and is designed to be forward-compatible with Web3 (Solidity) and Quant (MQL/Python trading systems).

---

## SECTION 1 – COMPONENT RESPONSIBILITY BOUNDARIES

### 1.1. `parser.py` Responsibility (Open-Source Client Component)
The `parser.py` module is a **File System Pre-Processor**. Its sole responsibility is to traverse the target directory, filter irrelevant artifacts, and produce a normalized, lossless view of the project's source code structure.

**Exact Duties:**
- Recursive directory traversal using OS-level file system APIs.
- Application of hard-coded and user-configurable ignore lists (e.g., `node_modules`, `.git`, `dist`, `build`, `coverage`, `.next`).
- File type filtering based strictly on extension (`.js`, `.ts` for Version 1).
- Content extraction (reading raw bytes as UTF-8).
- Content normalization (stripping single-line comments, block comments, and excessive whitespace to reduce payload size).
- Generation of cryptographic hashes (SHA-256) of the stripped content for change detection and caching.
- Assembly of a structured JSON payload (the **Project Source Index**) that maps file paths to their normalized content.

**Explicit Non-Responsibilities:**
- Does NOT parse the Abstract Syntax Tree (AST).
- Does NOT evaluate code logic.
- Does NOT detect vulnerabilities.
- Does NOT execute system commands or run subprocesses.
- Does NOT contact external APIs or the OSE Server.

### 1.2. Financial Semantic Analyzer (FSA) Responsibility (Proprietary Client Component)
The FSA is the **Core Intelligence Layer**. It consumes the Project Source Index and performs deterministic, semantic analysis to identify financial logic flaws.

**Exact Duties:**
- Parsing the normalized source code using `tree-sitter` (or equivalent multi-language AST parser).
- Building a **Symbol Table** to identify financial assets (e.g., variables named `balance`, `ledger`, `wallet`, `order`, `position`).
- Constructing a **State Transition Graph** to map the order of operations (validation → state mutation → external call).
- Applying **Invariant Rules** (e.g., "Slippage must be checked before executing a market order").
- Generating a structured **Vulnerability Manifest** containing confirmed exploits, line numbers, and severity scores.

**Explicit Non-Responsibilities:**
- Does NOT traverse directories.
- Does NOT strip comments or whitespace (relies entirely on `parser.py` for this).
- Does NOT generate AI patches.
- Does NOT communicate directly with the OSE Server (transmits via the client orchestrator).

### 1.3. OSE Server Responsibility (Proprietary Cloud Component)
The server consumes the Vulnerability Manifest, applies credit validation, invokes the LLM to generate secure patches, and returns the structured fix report to the client.

---

## SECTION 2 – DATA RESIDENCY & SOVEREIGNTY

To maintain user trust and comply with data privacy standards, data is classified into three zones:

| Zone | Data Type | Storage Location | Transmission |
| :--- | :--- | :--- | :--- |
| **Zone 1 (Local)** | Raw source code, complete AST, absolute file paths, .env files, system environment variables, and any developer-specific machine metadata. | User's machine | NEVER transmitted. |
| **Zone 2 (Transformed)** | Stripped code content, relative file paths (anonymized), file hashes, and file sizes. | Transient memory; stored temporarily only for the duration of the scan. | Transmitted from `parser.py` → FSA only (local IPC). |
| **Zone 3 (Abstracted)** | Vulnerability type, severity, line numbers (relative to file), code snippet of the *offending function only*, and suggested fix principle. | Temporary server memory; not persisted beyond request lifecycle. | Transmitted from FSA → OSE Server (via HTTPS). |

**Critical Rule:** The *entire* source code of the project is **never** transmitted to the OSE Server. Only the isolated context required for the LLM to generate a fix (typically 20–50 lines of surrounding code) is sent.

---

## SECTION 3 – DATA TRANSMISSION SCOPE

| Direction | Data Transmitted | Format |
| :--- | :--- | :--- |
| `parser.py` → FSA (Local) | Project Source Index (list of all files with stripped content, relative paths, and hashes). | JSON |
| FSA → OSE Server (Cloud) | Vulnerability Manifest (vulnerability type, file path, line range, relevant code snippet, and severity). **Explicitly excludes** the rest of the source code. | JSON |
| OSE Server → Client | Patched code block and contextual explanation. | JSON |

---

## SECTION 4 – FORMAL INTERFACE CONTRACTS (DATA STRUCTURES)

### 4.1. Contract A: `parser.py` → FSA (Project Source Index)
This is the primary output of the parser. It is a JSON object with the following top-level fields:

- **`project_identifier`**: A SHA-256 hash derived from the project root path (anonymized).
- **`files`**: An array of file objects, each containing:
  - `path_relative` (string): Path relative to the project root (e.g., `src/controllers/payment.js`).
  - `language` (string): Inferred language (`js`, `ts`, `sol`, etc.).
  - `hash` (string): SHA-256 of the stripped content.
  - `stripped_content` (string): The code with comments/whitespace removed.
  - `original_size` (integer): Size in bytes.
  - `stripped_size` (integer): Size in bytes after stripping.
- **`summary`**: Total files processed, total ignored, total errors.

### 4.2. Contract B: FSA → OSE Server (Vulnerability Manifest)
This is the security intelligence payload. It is a JSON object with:

- **`project_hash`**: The same anonymized project identifier from Contract A.
- **`analysis_metadata`**: Execution time, language targeted, number of files analyzed.
- **`findings`**: An array of vulnerability objects, each containing:
  - `file_path` (string): Relative path to the file.
  - `line_start` / `line_end` (integers): Precise location of the flaw.
  - `vulnerability_class` (string): E.g., `REENTRANCY`, `BROKEN_AUTH`, `SLIPPAGE_OMISSION`, `RACE_CONDITION`.
  - `severity` (enum): `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`.
  - `code_snippet` (string): The exact 10-20 lines of code containing the flaw (sanitized, no absolute paths).
  - `description` (string): Human-readable explanation of the business logic failure.
  - `fix_principle` (string): A high-level instruction for the AI (e.g., "Move the state update before the external call").

---

## SECTION 5 – PERFORMANCE & RESOURCE LIMITS

| Project Size | Maximum Files | Time Constraint | Memory Limit (RSS) | Failure Mode |
| :--- | :--- | :--- | :--- | :--- |
| **Small** | ≤ 100 files | < 2 seconds | < 100 MB | Timeout → process sequentially. |
| **Medium** | ≤ 1,000 files | < 10 seconds | < 300 MB | Chunking if memory exceeds 300 MB. |
| **Large** | ≤ 10,000 files | < 60 seconds (graceful degradation) | < 500 MB (hard cap) | If threshold exceeded, scan is aborted; only a partial index (first 10,000 files) is returned, with a flag indicating truncation. |

**Rule:** For large projects, the parser must implement a **streaming or generator-based approach** to avoid holding all file contents in memory simultaneously.

---

## SECTION 6 – SECURITY & PRIVACY GUARANTEES

1. **Zero Raw Source Transmission:** The OSE Server receives only the Vulnerability Manifest. It never sees the full source code of the project.
2. **Anonymization:** All absolute file paths are stripped of user-specific usernames (e.g., `/Users/john/project` becomes `[PROJECT_ROOT]/`).
3. **No Telemetry:** `parser.py` does not send usage analytics, crash reports, or environment fingerprints to any external endpoint.
4. **Data in Transit:** Communications between the FSA and the OSE Server are encrypted via TLS 1.3.
5. **Temporary Storage:** The OSE Server does not persist any code snippets or manifests beyond the lifecycle of the request (in-memory only).
6. **User Opt-Out:** The user has full control to inspect the payload being generated before it is transmitted (dry-run mode).

---

## SECTION 7 – OPEN-SOURCE VERSUS PROPRIETARY BOUNDARIES

| Component | License | Rationale |
| :--- | :--- | :--- |
| **`parser.py`** | Open Source (Apache 2.0 / MIT) | Allows the community to contribute new file types, improve ignore patterns, and verify security auditing capabilities of the pre-processor. |
| **Financial Semantic Analyzer (FSA)** | Closed Source / Proprietary | The vulnerability detection rules, state graph heuristics, and financial signature database are the core intellectual property of OSE. Distributed as a compiled binary (via PyArmor/Cython) or as a server-side microservice (if local execution is not feasible). |
| **`parser.py` ↔ FSA Interface** | Open Specification | The JSON Contract (Contract A) is publicly documented to encourage community-built parsers for other ecosystems, but the FSA will only accept signed/verified payloads to prevent tampering. |

---

## SECTION 8 – FUTURE EXPANSION REQUIREMENTS

While Version 1 targets Node.js, the architecture must support the following expansions without requiring a rewrite of the parser or the data contracts:

### 8.1. Web3 (Solidity)
- **Parser Adjustment:** Must include `.sol` extensions in the file filter.
- **Stripping Rule:** Must preserve `pragma` directives and `contract` definitions.
- **Contract A Update:** Add `language: "solidity"` and include a `is_contract` boolean flag.
- **FSA Expansion:** The FSA will implement `tree-sitter-solidity` specifically for reentrancy detection, `tx.origin` abuse, and flash loan dependency checks.

### 8.2. Quant Trading Systems (Python / MQL)
- **Parser Adjustment:** Must support `.py` (for Python trading bots) and `.mq4` / `.mq5` (for MetaTrader).
- **Stripping Rule:** Must preserve mathematical expressions (order sizes, stop-loss percentages) to allow the FSA to detect arithmetic overflows.
- **Contract A Update:** Add `language: "python"` and `language: "mql5"`.
- **FSA Expansion:** The FSA will implement multi-thread analysis (for race conditions) and market order parameter validation (for slippage omissions).

### 8.3. Forward Compatibility Guarantee
The top-level structure of Contract A (files array with `path`, `language`, `stripped_content`) will remain **stable** across all language expansions. Adding a new language will only require adding a new `language` enum value and adjusting the FSA's internal parser routing.

---

## SECTION 9 – PRODUCTION READINESS CRITERIA

`parser.py` is considered "production-ready" when:

- It can successfully process a 10,000-file Node.js monorepo (like a large Next.js application) within 45 seconds on an average developer laptop (16GB RAM, 4-core CPU).
- It generates a valid JSON payload that passes schema validation against Contract A.
- It gracefully handles malformed files (invalid UTF-8, empty files) without crashing the parent process.
- It provides clear, actionable log messages for failed file reads or permission errors.
- It passes a suite of unit tests covering all ignore rules, comment stripping, and edge cases (e.g., strings containing `//`, block comments nested in literals).

---

**End of Parser Specification Document.**
