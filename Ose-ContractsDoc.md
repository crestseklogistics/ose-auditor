# OSE DATA CONTRACT SPECIFICATION v1.0

**Document Purpose:** Defines the authoritative JSON schemas, validation rules, versioning strategy, and examples for all data contracts exchanged between OSE Auditor components. This specification is binding for all client and server implementations.

**Versioning Policy:**
- **MAJOR** version increments when backward-incompatible changes are made to required fields or top-level structure.
- **MINOR** version increments when optional fields are added or when new vulnerability classes are introduced.
- **PATCH** version increments for documentation clarifications or bug fixes.

**Current Version:** 1.0.0

---

## CONTRACT A – PROJECT SOURCE INDEX

**Producer:** `client/parser.py` (Open Source)  
**Consumer:** `fsa/analyzer.py` (Proprietary)  
**Transmission:** Local inter-process communication (in-memory JSON)  
**Purpose:** Transmits the normalized, stripped source code of the target project to the FSA for semantic analysis.

### Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://ose.crestsek.com/schemas/contract-a-v1.0.json",
  "title": "Project Source Index",
  "description": "Normalized source code index produced by the OSE parser for consumption by the FSA.",
  "type": "object",
  "required": [
    "contract_version",
    "project_identifier",
    "generated_at",
    "files",
    "summary"
  ],
  "properties": {
    "contract_version": {
      "type": "string",
      "pattern": "^1\\.[0-9]+\\.[0-9]+$",
      "description": "Semantic version of the contract schema. MUST be '1.0.0' for this specification.",
      "example": "1.0.0"
    },
    "project_identifier": {
      "type": "string",
      "pattern": "^[a-f0-9]{64}$",
      "description": "SHA-256 hash of the absolute project root path (anonymized). Used for server-side change detection and caching.",
      "example": "a1b2c3d4e5f67890..."
    },
    "generated_at": {
      "type": "string",
      "format": "date-time",
      "description": "ISO 8601 UTC timestamp of when the index was generated.",
      "example": "2025-01-15T14:30:00Z"
    },
    "project_metadata": {
      "type": "object",
      "description": "Optional metadata about the project.",
      "properties": {
        "name": {
          "type": "string",
          "description": "Project name from package.json (if available)."
        },
        "version": {
          "type": "string",
          "description": "Project version from package.json."
        },
        "language": {
          "type": "string",
          "enum": ["nodejs", "solidity", "python", "mql5"],
          "description": "Primary language of the project."
        }
      },
      "required": ["language"]
    },
    "files": {
      "type": "array",
      "description": "Array of processed source files.",
      "items": {
        "type": "object",
        "required": [
          "path_relative",
          "language",
          "hash",
          "stripped_content",
          "original_size",
          "stripped_size"
        ],
        "properties": {
          "path_relative": {
            "type": "string",
            "description": "File path relative to the project root. MUST NOT contain absolute paths or user-specific directory names.",
            "pattern": "^[^\\/]*\\/.*\\.(js|ts|jsx|tsx|sol|py|mq4|mq5)$",
            "examples": [
              "src/controllers/payment.js",
              "contracts/Token.sol",
              "bots/trading_bot.py"
            ]
          },
          "language": {
            "type": "string",
            "enum": ["js", "ts", "jsx", "tsx", "sol", "py", "mq4", "mq5"],
            "description": "Programming language inferred from file extension."
          },
          "hash": {
            "type": "string",
            "pattern": "^[a-f0-9]{64}$",
            "description": "SHA-256 hash of the stripped_content. Used for change detection."
          },
          "stripped_content": {
            "type": "string",
            "description": "Source code with comments, whitespace, and blank lines removed. Max 1MB per file after stripping.",
            "maxLength": 1048576
          },
          "original_size": {
            "type": "integer",
            "minimum": 0,
            "description": "Original file size in bytes before stripping."
          },
          "stripped_size": {
            "type": "integer",
            "minimum": 0,
            "description": "File size in bytes after stripping."
          },
          "is_test_file": {
            "type": "boolean",
            "description": "True if file path contains '__tests__', 'test/', or 'spec.ts'."
          },
          "is_third_party": {
            "type": "boolean",
            "description": "True if file path contains 'vendor/', 'third_party/', or 'external/'."
          }
        }
      },
      "minItems": 1,
      "maxItems": 10000
    },
    "summary": {
      "type": "object",
      "required": ["total_files", "total_ignored", "total_errors", "total_size_bytes"],
      "properties": {
        "total_files": {
          "type": "integer",
          "minimum": 0,
          "description": "Total number of files processed and included in the index."
        },
        "total_ignored": {
          "type": "integer",
          "minimum": 0,
          "description": "Total number of files skipped due to ignore rules or file size limits."
        },
        "total_errors": {
          "type": "integer",
          "minimum": 0,
          "description": "Total number of files that could not be read or processed."
        },
        "total_size_bytes": {
          "type": "integer",
          "minimum": 0,
          "description": "Sum of original_size across all processed files (before stripping)."
        },
        "ignored_directories": {
          "type": "array",
          "items": {"type": "string"},
          "description": "List of directory names that were ignored (for debug purposes)."
        },
        "scan_duration_seconds": {
          "type": "number",
          "minimum": 0,
          "description": "Elapsed time for the parsing operation."
        }
      }
    },
    "truncated": {
      "type": "boolean",
      "description": "True if the total file count exceeded the 10,000 limit and the payload was truncated.",
      "default": false
    }
  }
}
```

### Validation Rules

| Rule ID | Description | Validation |
| :--- | :--- | :--- |
| A-001 | `files` array MUST contain at least one file. | `minItems: 1` |
| A-002 | `files` array MUST NOT exceed 10,000 items. | `maxItems: 10000` |
| A-003 | Each `stripped_content` MUST NOT exceed 1 MB. | `maxLength: 1048576` |
| A-004 | `path_relative` MUST NOT contain the user's absolute home directory or username. | Regex: `^[^\/]*\/` ensures relative path. |
| A-005 | `language` MUST be one of the allowed enums. | `enum` validation. |
| A-006 | `project_identifier` MUST be a valid SHA-256 hex digest. | `pattern: ^[a-f0-9]{64}$` |
| A-007 | If `truncated` is true, the `files` array SHOULD contain the first 10,000 files in lexicographic order. | Implementation note. |

### Example

```json
{
  "contract_version": "1.0.0",
  "project_identifier": "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef12345678",
  "generated_at": "2025-01-15T14:30:00Z",
  "project_metadata": {
    "name": "payment-gateway",
    "version": "2.1.0",
    "language": "nodejs"
  },
  "files": [
    {
      "path_relative": "src/controllers/payment.js",
      "language": "js",
      "hash": "e5f6789012345678901234567890abcdef1234567890abcdef1234567890abcd",
      "stripped_content": "const stripe = require('stripe'); async function processPayment(amount, userId) { const user = await User.findByPk(userId); if (user.balance < amount) { throw new Error('Insufficient balance'); } const charge = await stripe.charges.create({ amount, currency: 'usd', customer: user.stripeId }); user.balance -= amount; await user.save(); }",
      "original_size": 1024,
      "stripped_size": 350,
      "is_test_file": false,
      "is_third_party": false
    },
    {
      "path_relative": "src/middleware/auth.js",
      "language": "js",
      "hash": "f6789012345678901234567890abcdef1234567890abcdef1234567890abcde",
      "stripped_content": "function requireAuth(req, res, next) { if (!req.session.userId) { return res.status(401).json({ error: 'Unauthorized' }); } next(); }",
      "original_size": 512,
      "stripped_size": 180,
      "is_test_file": false,
      "is_third_party": false
    }
  ],
  "summary": {
    "total_files": 2,
    "total_ignored": 145,
    "total_errors": 0,
    "total_size_bytes": 1536,
    "ignored_directories": ["node_modules", ".git", "dist"],
    "scan_duration_seconds": 1.23
  },
  "truncated": false
}
```

---

## CONTRACT B – VULNERABILITY MANIFEST

**Producer:** `fsa/analyzer.py` (Proprietary)  
**Consumer:** `orchestrator.py` → OSE Server (`server/main.py`)  
**Transmission:** HTTPS to `ose.crestsek.com/v1/audit`  
**Purpose:** Transmits the FSA's findings—confirmed financial logic vulnerabilities—to the OSE Server for credit validation and AI patch generation.

### Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://ose.crestsek.com/schemas/contract-b-v1.0.json",
  "title": "Vulnerability Manifest",
  "description": "Confirmed vulnerability findings generated by the FSA, ready for server-side processing and AI patching.",
  "type": "object",
  "required": [
    "contract_version",
    "project_hash",
    "generated_at",
    "analysis_metadata",
    "findings"
  ],
  "properties": {
    "contract_version": {
      "type": "string",
      "pattern": "^1\\.[0-9]+\\.[0-9]+$",
      "description": "Semantic version of the contract schema. MUST be '1.0.0' for this specification.",
      "example": "1.0.0"
    },
    "project_hash": {
      "type": "string",
      "pattern": "^[a-f0-9]{64}$",
      "description": "The same project_identifier from Contract A. Used for server-side caching.",
      "example": "a1b2c3d4e5f67890..."
    },
    "generated_at": {
      "type": "string",
      "format": "date-time",
      "description": "ISO 8601 UTC timestamp of when the manifest was generated.",
      "example": "2025-01-15T14:30:02Z"
    },
    "analysis_metadata": {
      "type": "object",
      "required": [
        "scanner_version",
        "files_analyzed",
        "analysis_duration_seconds"
      ],
      "properties": {
        "scanner_version": {
          "type": "string",
          "description": "Version of the FSA engine.",
          "example": "1.0.0"
        },
        "files_analyzed": {
          "type": "integer",
          "minimum": 0,
          "description": "Number of files from Contract A that were actually analyzed."
        },
        "analysis_duration_seconds": {
          "type": "number",
          "minimum": 0,
          "description": "Elapsed time for FSA analysis."
        },
        "target_tracks": {
          "type": "array",
          "items": {
            "type": "string",
            "enum": ["web2", "web3", "quant"]
          },
          "description": "Which analysis tracks were executed."
        }
      }
    },
    "findings": {
      "type": "array",
      "description": "Array of confirmed vulnerabilities.",
      "items": {
        "type": "object",
        "required": [
          "id",
          "file_path",
          "line_start",
          "line_end",
          "vulnerability_class",
          "severity",
          "code_snippet",
          "description",
          "fix_principle",
          "confidence"
        ],
        "properties": {
          "id": {
            "type": "string",
            "pattern": "^FSA-[A-Z0-9]{6,8}$",
            "description": "Unique identifier for the finding (FSA engine generated).",
            "example": "FSA-REENT-001"
          },
          "file_path": {
            "type": "string",
            "description": "Relative file path (matches Contract A path_relative).",
            "example": "src/controllers/payment.js"
          },
          "line_start": {
            "type": "integer",
            "minimum": 1,
            "description": "Starting line number of the vulnerability (1-indexed)."
          },
          "line_end": {
            "type": "integer",
            "minimum": 1,
            "description": "Ending line number of the vulnerability. MUST be >= line_start."
          },
          "vulnerability_class": {
            "type": "string",
            "enum": [
              "REENTRANCY",
              "BROKEN_AUTH",
              "SLIPPAGE_OMISSION",
              "RACE_CONDITION",
              "DOUBLE_SPEND",
              "UNCHECKED_EXTERNAL_CALL",
              "MISSING_VALIDATION",
              "TX_ORIGIN_ABUSE",
              "BROKEN_ACCESS_CONTROL",
              "PRIVILEGE_ESCALATION",
              "ARITHMETIC_OVERFLOW",
              "LOGIC_FLAW"
            ],
            "description": "Categorised vulnerability type."
          },
          "severity": {
            "type": "string",
            "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            "description": "Impact assessment of the vulnerability."
          },
          "code_snippet": {
            "type": "string",
            "description": "The exact 10-20 lines of code containing the flaw (sanitized context).",
            "maxLength": 4096,
            "example": "const charge = await stripe.charges.create({ amount, currency: 'usd', customer: user.stripeId }); user.balance -= amount; await user.save();"
          },
          "description": {
            "type": "string",
            "maxLength": 1000,
            "description": "Human-readable explanation of the business logic failure.",
            "example": "Balance is deducted AFTER the external Stripe API call. If the Stripe call succeeds but the database update fails, the user's balance remains incorrect."
          },
          "fix_principle": {
            "type": "string",
            "maxLength": 500,
            "description": "High-level instruction for the AI. Must be action-oriented.",
            "example": "Move user.balance -= amount BEFORE the stripe.charges.create call. Ensure the database update occurs before any external API invocation."
          },
          "confidence": {
            "type": "number",
            "minimum": 0,
            "maximum": 1,
            "description": "Confidence score assigned by the FSA (0.0 to 1.0).",
            "example": 0.92
          },
          "false_positive_risk": {
            "type": "string",
            "enum": ["LOW", "MEDIUM", "HIGH"],
            "description": "Likelihood of false positive based on dynamic heuristics."
          },
          "related_finding_ids": {
            "type": "array",
            "items": {"type": "string"},
            "description": "IDs of related vulnerabilities (for grouping)."
          }
        }
      },
      "minItems": 0,
      "maxItems": 100
    },
    "request_metadata": {
      "type": "object",
      "description": "Optional metadata for the OSE Server.",
      "properties": {
        "client_version": {
          "type": "string",
          "description": "Version of the OSE client."
        },
        "user_id": {
          "type": "string",
          "description": "Anonymized user identifier for credit validation."
        },
        "preferred_model": {
          "type": "string",
          "enum": ["claude-3.5-sonnet", "gpt-4"],
          "description": "Preferred LLM for patch generation (if available)."
        }
      }
    }
  }
}
```

### Validation Rules

| Rule ID | Description | Validation |
| :--- | :--- | :--- |
| B-001 | `file_path` MUST exist in Contract A `files[].path_relative`. | Cross-reference validation on server. |
| B-002 | `line_end` MUST be >= `line_start`. | `minimum` validation on `line_end`. |
| B-003 | `code_snippet` MUST NOT contain absolute paths or user-specific information. | Server-side sanitization check. |
| B-004 | `vulnerability_class` MUST be one of the defined enums. | `enum` validation. |
| B-005 | `confidence` MUST be between 0.0 and 1.0 inclusive. | `minimum` and `maximum` validation. |
| B-006 | `findings` array MUST NOT exceed 100 items (server processing limit). | `maxItems: 100` |
| B-007 | Each `id` MUST be unique within the `findings` array. | Uniqueness check. |
| B-008 | `analysis_metadata.target_tracks` MUST be a non-empty array. | `minItems: 1` |

### Severity Classification Rules (Guidance for FSA)

| Severity | Criteria |
| :--- | :--- |
| **CRITICAL** | Direct financial loss possible (e.g., reentrancy that drains contracts, double-spend in payment processing). |
| **HIGH** | Likely financial loss under specific conditions (e.g., missing slippage check, broken auth in admin routes). |
| **MEDIUM** | Potential financial loss, requires user error or complex exploitation (e.g., race condition in order processing). |
| **LOW** | Defensive best-practice violation, unlikely to cause immediate financial damage (e.g., unused validation function). |

### Example

```json
{
  "contract_version": "1.0.0",
  "project_hash": "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef12345678",
  "generated_at": "2025-01-15T14:30:02Z",
  "analysis_metadata": {
    "scanner_version": "1.0.0",
    "files_analyzed": 2,
    "analysis_duration_seconds": 0.45,
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
      "code_snippet": "async function processPayment(amount, userId) {\n  const user = await User.findByPk(userId);\n  const charge = await stripe.charges.create({ amount, currency: 'usd', customer: user.stripeId });\n  user.balance -= amount;\n  await user.save();\n}",
      "description": "The processPayment function lacks any authentication or authorization check. Any authenticated user can call this endpoint with arbitrary amount and userId values, potentially charging other users' cards.",
      "fix_principle": "Add a `requireAuth` middleware or verify that the session user matches the userId parameter before processing the payment.",
      "confidence": 0.95,
      "false_positive_risk": "LOW"
    },
    {
      "id": "FSA-REENT-002",
      "file_path": "contracts/Token.sol",
      "line_start": 45,
      "line_end": 52,
      "vulnerability_class": "REENTRANCY",
      "severity": "CRITICAL",
      "code_snippet": "function withdraw(uint256 amount) external {\n  require(balances[msg.sender] >= amount);\n  (bool sent,) = msg.sender.call{value: amount}(\"\");\n  require(sent, \"Transfer failed\");\n  balances[msg.sender] -= amount;\n}",
      "description": "The balance is updated AFTER the external call. An attacker can re-enter the function recursively and drain the contract before the state is updated.",
      "fix_principle": "Update the balance BEFORE making the external call to prevent reentrancy attacks.",
      "confidence": 0.98,
      "false_positive_risk": "LOW"
    }
  ],
  "request_metadata": {
    "client_version": "1.0.0",
    "user_id": "usr_abc123",
    "preferred_model": "claude-3.5-sonnet"
  }
}
```

---

## CONTRACT B EXTENDED – RESPONSE PAYLOAD (Server → Client)

**Producer:** `server/main.py` (Proprietary)  
**Consumer:** `client/orchestrator.py`  
**Transmission:** HTTPS response to POST `/v1/audit`  
**Purpose:** Returns the AI-generated secure patch and credit status.

### Schema (Response)

```json
{
  "contract_version": "1.0.0",
  "status": "SUCCESS",
  "findings": [
    {
      "finding_id": "FSA-BAUTH-001",
      "patch": "async function processPayment(amount, userId) {\n  const user = await User.findByPk(userId);\n  if (req.session.userId !== user.id) { throw new Error('Unauthorized'); }\n  const charge = await stripe.charges.create({ amount, currency: 'usd', customer: user.stripeId });\n  user.balance -= amount;\n  await user.save();\n}",
      "explanation": "Added authentication check to ensure only the owner of the account can charge it. The patch uses the session userId to validate authorization before proceeding with payment."
    }
  ],
  "credits": {
    "remaining": 4,
    "total_used": 1,
    "tier": "free"
  },
  "checkout_url": null
}
```

### Status Codes

| Status | Meaning |
| :--- | :--- |
| `SUCCESS` | All vulnerabilities processed, patches generated. |
| `PARTIAL_SUCCESS` | Some vulnerabilities generated, some skipped (user credits exhausted mid-request). |
| `CREDIT_EXHAUSTED` | User has no credits remaining. Manifest rejected. |
| `ERROR` | Internal server error or validation failure. |

---

## VERSIONING STRATEGY

| Scenario | Version Change | Example |
| :--- | :--- | :--- |
| Adding an optional field to an existing object | MINOR | `1.0.0` → `1.1.0` |
| Adding a new vulnerability class enum | MINOR | `1.0.0` → `1.1.0` |
| Changing a required field to optional | MAJOR | `1.0.0` → `2.0.0` |
| Removing a field entirely | MAJOR | `1.0.0` → `2.0.0` |
| Changing the type of an existing field | MAJOR | `1.0.0` → `2.0.0` |
| Clarifying documentation | PATCH | `1.0.0` → `1.0.1` |

**Compatibility Rules:**
- Servers MUST accept manifests with the same MAJOR version.
- Servers SHOULD accept manifests with MINOR version differences (if fields are present).
- Clients MUST support the MAJOR version returned by the server.

---

## VERSION 1.0.0 SIGN-OFF

**Applies To:**
- Contract A (Project Source Index)
- Contract B (Vulnerability Manifest)

**Effective Date:** Date of publication

**Next Review:** When Version 2.0.0 (supporting Solidity and MQL) is drafted.

---

**End of Data Contract Specification v1.0**
