"""
OSE Auditor - Financial Semantic Analyzer (FSA)

This module is the proprietary core intelligence engine of OSE Auditor.
It performs deterministic, semantic analysis to identify financial logic
vulnerabilities that generic AI models and traditional scanners miss.

Input:  Contract A (Project Source Index from parser.py)
Output: Contract B (Vulnerability Manifest)

Pipeline:
    1. Parse code into ASTs using tree-sitter.
    2. Detect financial entities (wallet, balance, payment, etc.) by walking
       the AST and matching identifiers / member expressions against a
       keyword table.
    3. Build a per-function state transition graph (validation nodes,
       state-mutation nodes, external-call nodes), delegating to
       fsa.graph_builder when it is available.
    4. Apply hardcoded vulnerability signatures to the graph, delegating to
       fsa.signatures when it is available.
    5. Emit a structured Vulnerability Manifest (Contract B).

This module is CLOSED SOURCE / PROPRIETARY. The source code is never
disclosed to the public.
"""

from __future__ import annotations

import itertools
import logging
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger("ose.analyzer")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VERSION = "1.0.0"
CONTRACT_VERSION = "1.0.0"

MAX_SNIPPET_LEN = 4096
MAX_DESCRIPTION_LEN = 1000
MAX_FIX_PRINCIPLE_LEN = 500

# Financial keywords -> coarse entity category. Matching is case-insensitive
# and applied to identifiers / property names discovered while walking the
# AST (not to arbitrary substrings of the source text).
FINANCIAL_KEYWORDS: Dict[str, str] = {
    "wallet": "financial_account",
    "balance": "monetary_state",
    "account": "financial_account",
    "ledger": "ledger",
    "funds": "financial_account",
    "credit": "monetary_state",
    "debit": "monetary_state",
    "payment": "transaction",
    "transaction": "transaction",
    "transfer": "transaction",
    "withdraw": "withdrawal",
    "deposit": "deposit",
    "charge": "payment",
    "refund": "refund",
    "invoice": "invoice",
    "order": "order",
    "cart": "order",
    "checkout": "order",
    "purchase": "order",
    "subscription": "subscription",
    "plan": "subscription",
    "billing": "billing",
    "escrow": "escrow",
    "settlement": "settlement",
    "commission": "commission",
    "fee": "fee",
    "provider": "role",
    "customer": "role",
    "buyer": "role",
    "seller": "role",
    "slippage": "risk",
    "spread": "risk",
    "stoploss": "risk",
    "takeprofit": "risk",
    "margin": "risk",
    "leverage": "risk",
}

# Identifiers that, when called, are treated as validation/guard checks.
VALIDATION_CALL_NAMES = {
    "require",
    "assert",
    "invariant",
    "validate",
    "validateinput",
    "ensure",
    "authorize",
    "authenticate",
    "checkauth",
    "isauthorized",
    "can",
}

# Property/identifier fragments that, when seen guarding an `if`, count as an
# authorization / auth check rather than a generic conditional.
AUTH_HINT_FRAGMENTS = {
    "auth",
    "isauthenticated",
    "isauthorized",
    "permission",
    "role",
    "owner",
    "session",
    "token",
    "login",
    "user.id",
}

# Identifier fragments treated as "raw user input" sources for
# MISSING_VALIDATION / PRIVILEGE_ESCALATION detection.
USER_INPUT_FRAGMENTS = {
    "req.body",
    "req.query",
    "req.params",
    "request.body",
    "request.query",
    "request.params",
    "ctx.request.body",
    "ctx.query",
}

SEVERITY_MAP: Dict[str, str] = {
    "DOUBLE_SPEND": "CRITICAL",
    "BROKEN_AUTH": "HIGH",
    "BROKEN_ACCESS_CONTROL": "HIGH",
    "PRIVILEGE_ESCALATION": "HIGH",
    "UNCHECKED_EXTERNAL_CALL": "HIGH",
    "INVALID_STATE_TRANSITION": "MEDIUM",
    "MISSING_VALIDATION": "MEDIUM",
    "LOGIC_FLAW": "MEDIUM",
}

FINDING_ID_ABBREVIATIONS: Dict[str, str] = {
    "BROKEN_AUTH": "BAUTH",
    "BROKEN_ACCESS_CONTROL": "BACCESS",
    "PRIVILEGE_ESCALATION": "PRIVESC",
    "MISSING_VALIDATION": "MISVAL",
    "UNCHECKED_EXTERNAL_CALL": "UNCHK",
    "INVALID_STATE_TRANSITION": "INVST",
    "DOUBLE_SPEND": "DSPEND",
    "LOGIC_FLAW": "LOGIC",
}

# Node types (tree-sitter-javascript / tree-sitter-typescript) that introduce
# a new function scope we analyze independently.
FUNCTION_NODE_TYPES = {
    "function_declaration",
    "function_expression",
    "arrow_function",
    "method_definition",
    "generator_function_declaration",
    "generator_function",
}

ASSIGNMENT_NODE_TYPES = {
    "assignment_expression",
    "augmented_assignment_expression",
}

# ---------------------------------------------------------------------------
# tree-sitter loading (lazy, cached)
# ---------------------------------------------------------------------------

_TS_STATE: Dict[str, Any] = {"checked": False, "available": False, "parsers": {}}


def _load_tree_sitter() -> bool:
    """
    Attempt to load tree-sitter and the JavaScript/TypeScript grammars.

    Populates _TS_STATE["parsers"] with ready-to-use Parser instances keyed
    by language id ("js", "ts", "tsx"). Safe to call multiple times; the
    result is cached after the first attempt.

    Returns:
        True if tree-sitter and at least the JavaScript grammar loaded
        successfully, False otherwise.
    """
    if _TS_STATE["checked"]:
        return _TS_STATE["available"]

    _TS_STATE["checked"] = True

    try:
        from tree_sitter import Language, Parser
    except ImportError:
        logger.warning("tree-sitter is not installed; falling back to regex-based mock analysis.")
        return False

    parsers: Dict[str, Any] = {}

    try:
        import tree_sitter_javascript as tsjs
        js_lang = Language(tsjs.language())
        parsers["js"] = Parser(js_lang)
        parsers["jsx"] = Parser(js_lang)
    except ImportError:
        logger.warning("tree-sitter-javascript is not installed.")
    except Exception as exc:  # pragma: no cover - defensive
        logger.error("Failed to initialize JavaScript grammar: %s", exc)

    try:
        import tree_sitter_typescript as tsts
        ts_lang = Language(tsts.language_typescript())
        tsx_lang = Language(tsts.language_tsx())
        parsers["ts"] = Parser(ts_lang)
        parsers["tsx"] = Parser(tsx_lang)
    except ImportError:
        logger.warning("tree-sitter-typescript is not installed.")
    except Exception as exc:  # pragma: no cover - defensive
        logger.error("Failed to initialize TypeScript grammar: %s", exc)

    _TS_STATE["parsers"] = parsers
    _TS_STATE["available"] = "js" in parsers or "ts" in parsers
    return _TS_STATE["available"]


def _get_parser(language: str) -> Optional[Any]:
    """Return a cached tree-sitter Parser for the given language id, if any."""
    if not _load_tree_sitter():
        return None
    lang_key = (language or "js").lower()
    if lang_key not in _TS_STATE["parsers"]:
        # Reasonable fallbacks: unknown JS-flavored extensions use the JS
        # grammar, unknown TS-flavored extensions use the TS grammar.
        if lang_key in ("mjs", "cjs"):
            lang_key = "js"
        elif lang_key in ("mts", "cts"):
            lang_key = "ts"
    return _TS_STATE["parsers"].get(lang_key)


def _module_available(module_path: str) -> bool:
    """Check whether a module can be imported without actually importing
    it into the running namespace for side effects beyond the check."""
    import importlib.util
    try:
        return importlib.util.find_spec(module_path) is not None
    except (ImportError, ValueError, ModuleNotFoundError):
        return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze(project_index: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run the Financial Semantic Analyzer on the provided Project Source Index.

    Args:
        project_index: Contract A payload from parser.py.

    Returns:
        Contract B payload (Vulnerability Manifest).
    """
    start_time = time.monotonic()

    project_hash = project_index.get("project_identifier", "")
    files = project_index.get("files", [])

    logger.info("Starting FSA analysis for project: %s", project_hash)
    logger.debug("Processing %d files", len(files))

    # Decide once, up front, whether we are running with the real proprietary
    # rule engine or in mock/development mode. This must depend only on
    # module availability -- never on how many findings a real run happens
    # to produce, since "the scan found nothing" and "the engine isn't
    # installed" are very different outcomes that must not look identical.
    signatures_available = _module_available("fsa.signatures")
    graph_builder_available = _module_available("fsa.graph_builder")
    full_engine_available = signatures_available and graph_builder_available

    if not full_engine_available:
        logger.warning(
            "Running in mock mode (signatures_available=%s, graph_builder_available=%s).",
            signatures_available, graph_builder_available,
        )
        return _get_mock_manifest(project_index)

    id_counters: Dict[str, int] = {}
    findings: List[Dict[str, Any]] = []
    files_analyzed = 0
    errors: List[Dict[str, Any]] = []

    for file_entry in files:
        path_relative = file_entry.get("path_relative", "unknown")
        try:
            file_findings = _analyze_file(file_entry, id_counters)
            findings.extend(file_findings)
            files_analyzed += 1
        except Exception as exc:
            logger.error("Error analyzing file %s: %s", path_relative, exc)
            errors.append({"file": path_relative, "error": str(exc)})

    duration = round(time.monotonic() - start_time, 4)

    logger.info(
        "FSA analysis complete: %d findings, %d files analyzed, %.4fs elapsed",
        len(findings), files_analyzed, duration,
    )

    return _build_manifest(
        project_hash=project_hash,
        files_analyzed=files_analyzed,
        duration=duration,
        findings=findings,
        errors=errors,
    )


# ---------------------------------------------------------------------------
# Per-file analysis
# ---------------------------------------------------------------------------

def _analyze_file(file_entry: Dict[str, Any], id_counters: Dict[str, int]) -> List[Dict[str, Any]]:
    """
    Analyze a single file and return findings.

    Args:
        file_entry: A single file object from Contract A.
        id_counters: Mutable per-run counters keyed by vulnerability class,
            used to generate stable, non-colliding finding IDs.

    Returns:
        List of finding dictionaries for this file.
    """
    path_relative = file_entry.get("path_relative", "")
    language = (file_entry.get("language") or "js").lower()
    content = file_entry.get("stripped_content", "")

    if not content or not content.strip():
        logger.debug("Skipping empty file: %s", path_relative)
        return []

    tree = _parse_ast(content, language)
    if tree is None:
        logger.warning("Failed to parse AST for %s", path_relative)
        return []

    source_bytes = content.encode("utf-8")

    symbols = _detect_financial_entities(tree, source_bytes)
    if not symbols:
        logger.debug("No financial entities detected in %s", path_relative)
        return []

    functions = _find_function_nodes(tree.root_node)
    if not functions:
        return []

    findings: List[Dict[str, Any]] = []

    for func_node in functions:
        graph = _build_state_graph(func_node, source_bytes, symbols)
        if not graph or not _graph_has_signal(graph):
            continue

        rule_matches = _apply_signatures(graph, symbols, source_bytes)
        for match in rule_matches:
            vuln_class = match["class"]
            id_counters[vuln_class] = id_counters.get(vuln_class, 0) + 1
            finding = _create_finding(
                file_path=path_relative,
                vulnerability_class=vuln_class,
                line_start=match.get("line_start", func_node.start_point[0] + 1),
                line_end=match.get("line_end", func_node.end_point[0] + 1),
                code_snippet=match.get(
                    "snippet",
                    _slice_source(source_bytes, func_node.start_byte, func_node.end_byte),
                ),
                description=match.get("description", "Vulnerability detected."),
                fix_principle=match.get("fix_principle", "Review and fix the logic."),
                confidence=match.get("confidence", 0.8),
                index=id_counters[vuln_class],
            )
            findings.append(finding)

    return findings


# ---------------------------------------------------------------------------
# AST parsing
# ---------------------------------------------------------------------------

def _parse_ast(content: str, language: str) -> Optional[Any]:
    """
    Parse source code into a tree-sitter Tree.

    Args:
        content: The stripped source code.
        language: The language identifier (e.g., "js", "ts", "tsx").

    Returns:
        The tree-sitter Tree, or None if parsing is unavailable/failed.
    """
    parser = _get_parser(language)
    if parser is None:
        return None
    try:
        return parser.parse(content.encode("utf-8"))
    except Exception as exc:
        logger.error("tree-sitter parse error: %s", exc)
        return None


def _slice_source(source_bytes: bytes, start_byte: int, end_byte: int) -> str:
    """Decode a byte range of the source into text, tolerant of bad input."""
    try:
        return source_bytes[start_byte:end_byte].decode("utf-8", errors="replace")
    except Exception:
        return ""


def _node_text(node: Any, source_bytes: bytes) -> str:
    return _slice_source(source_bytes, node.start_byte, node.end_byte)


def _walk(node: Any) -> Iterable[Any]:
    """Depth-first pre-order traversal over all descendants (incl. self)."""
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        # Push in reverse so traversal order matches document order.
        stack.extend(reversed(current.children))


def _find_function_nodes(root: Any) -> List[Any]:
    """Return every function-like node in the tree (not nested expansion --
    nested functions are returned as their own independent entries too,
    since a vulnerability can live entirely inside a closure)."""
    return [n for n in _walk(root) if n.type in FUNCTION_NODE_TYPES]


# ---------------------------------------------------------------------------
# Financial entity detection (symbol table)
# ---------------------------------------------------------------------------

def _normalize_identifier(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


def _detect_financial_entities(tree: Any, source_bytes: bytes) -> Dict[str, Dict[str, Any]]:
    """
    Walk the AST and build a symbol table of financial entities.

    Identifiers, property names, and dotted member-expression chains
    (e.g. `wallet.balance`) are matched against FINANCIAL_KEYWORDS. This is
    an AST-driven match, not a raw substring search over the source text --
    it will not, for example, match "balance" inside a string literal or a
    comment that talks about page layout.

    Returns:
        Mapping of entity name -> {"type": category, "line": 1-indexed line,
        "context": the line's stripped text}.
    """
    symbols: Dict[str, Dict[str, Any]] = {}
    lines: Optional[List[str]] = None

    def line_context(row: int) -> str:
        nonlocal lines
        if lines is None:
            lines = source_bytes.decode("utf-8", errors="replace").split("\n")
        if 0 <= row < len(lines):
            return lines[row].strip()
        return ""

    relevant_types = {"identifier", "property_identifier", "shorthand_property_identifier"}

    for node in _walk(tree.root_node):
        if node.type not in relevant_types:
            continue
        raw = _node_text(node, source_bytes)
        normalized = _normalize_identifier(raw)
        if not normalized:
            continue
        for keyword, category in FINANCIAL_KEYWORDS.items():
            if keyword in normalized and raw not in symbols:
                symbols[raw] = {
                    "type": category,
                    "line": node.start_point[0] + 1,
                    "context": line_context(node.start_point[0]),
                }
                break

    return symbols


# ---------------------------------------------------------------------------
# State transition graph
# ---------------------------------------------------------------------------

def _member_chain_text(node: Any, source_bytes: bytes) -> str:
    """For a member_expression / identifier node, return its dotted text,
    e.g. `req.body.amount` or `balance`."""
    return _node_text(node, source_bytes)


def _callee_name(call_node: Any, source_bytes: bytes) -> str:
    """Return the textual name of the function/member being called for a
    call_expression node, e.g. `require`, `stripe.charges.create`."""
    for child in call_node.children:
        if child.type in ("identifier", "member_expression"):
            return _node_text(child, source_bytes)
    return ""


def _is_validation_call(name: str) -> bool:
    normalized = _normalize_identifier(name.split(".")[0] if name else "")
    return normalized in VALIDATION_CALL_NAMES


def _contains_auth_hint(text: str) -> bool:
    lowered = text.lower()
    return any(fragment in lowered for fragment in AUTH_HINT_FRAGMENTS)


def _contains_user_input(text: str) -> bool:
    lowered = text.lower()
    return any(fragment in lowered for fragment in USER_INPUT_FRAGMENTS)


def _build_state_graph(
    func_node: Any, source_bytes: bytes, symbols: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """
    Build a state transition graph for a single function.

    Delegates to fsa.graph_builder when available. The fallback
    implementation walks the function body once and classifies each
    statement-level node into one of: validation, external_call,
    state_mutation, user_input_use -- preserving source order, which is
    what later ordering-based signatures (e.g. UNCHECKED_EXTERNAL_CALL,
    DOUBLE_SPEND) depend on.

    Returns:
        A dict with ordered lists of typed nodes, or None if the function
        body is empty / not analyzable.
    """
    try:
        from fsa import graph_builder
        return graph_builder.build_graph(func_node, source_bytes, symbols)
    except ImportError:
        return _fallback_state_graph(func_node, source_bytes, symbols)


def _fallback_state_graph(
    func_node: Any, source_bytes: bytes, symbols: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    financial_names = {_normalize_identifier(name) for name in symbols.keys()}
    if not financial_names:
        return None

    validations: List[Dict[str, Any]] = []
    external_calls: List[Dict[str, Any]] = []
    state_mutations: List[Dict[str, Any]] = []
    user_input_uses: List[Dict[str, Any]] = []

    has_top_level_auth_check = False
    body_start_row = func_node.start_point[0]

    def record(bucket: List[Dict[str, Any]], node: Any, **extra: Any) -> None:
        entry = {
            "line": node.start_point[0] + 1,
            "end_line": node.end_point[0] + 1,
            "text": _node_text(node, source_bytes).strip()[:200],
        }
        entry.update(extra)
        bucket.append(entry)

    for node in _walk(func_node):
        if node.type == "call_expression":
            name = _callee_name(node, source_bytes)
            if _is_validation_call(name):
                record(validations, node, name=name)
                if node.start_point[0] - body_start_row <= 3:
                    has_top_level_auth_check = True
            else:
                args_text = _node_text(node, source_bytes)
                record(
                    external_calls, node, name=name,
                    is_awaited=node.parent is not None and node.parent.type == "await_expression",
                    touches_user_input=_contains_user_input(args_text),
                )

        elif node.type == "if_statement":
            condition = node.child_by_field_name("condition")
            cond_text = _node_text(condition, source_bytes) if condition else ""
            if _contains_auth_hint(cond_text):
                record(validations, node, name="if_auth_check")
                if node.start_point[0] - body_start_row <= 3:
                    has_top_level_auth_check = True

        elif node.type in ASSIGNMENT_NODE_TYPES:
            target = node.children[0] if node.children else None
            target_text = _node_text(target, source_bytes) if target else ""
            normalized_target = _normalize_identifier(target_text)
            touches_financial = any(fn in normalized_target for fn in financial_names) or any(
                kw in normalized_target for kw in FINANCIAL_KEYWORDS
            )
            if touches_financial:
                full_text = _node_text(node, source_bytes)
                record(
                    state_mutations, node,
                    target=target_text,
                    touches_user_input=_contains_user_input(full_text),
                )

        elif node.type in ("identifier", "member_expression"):
            text = _node_text(node, source_bytes)
            if _contains_user_input(text):
                record(user_input_uses, node, text=text[:120])

    if not (validations or external_calls or state_mutations):
        return None

    return {
        "function_line": func_node.start_point[0] + 1,
        "function_end_line": func_node.end_point[0] + 1,
        "function_text": _node_text(func_node, source_bytes),
        "validations": validations,
        "external_calls": external_calls,
        "state_mutations": state_mutations,
        "user_input_uses": user_input_uses,
        "has_top_level_auth_check": has_top_level_auth_check,
    }


def _graph_has_signal(graph: Dict[str, Any]) -> bool:
    """Cheap pre-check so we don't bother running signatures on a graph
    that has no chance of matching anything."""
    return bool(
        graph.get("state_mutations")
        or graph.get("external_calls")
        or graph.get("user_input_uses")
    )


# ---------------------------------------------------------------------------
# Vulnerability signatures
# ---------------------------------------------------------------------------

def _apply_signatures(
    graph: Dict[str, Any], symbols: Dict[str, Any], source_bytes: bytes
) -> List[Dict[str, Any]]:
    """
    Apply vulnerability signatures to a single function's state graph.

    Delegates to fsa.signatures when available. The fallback
    implementation below encodes a conservative subset of the v1
    vulnerability classes directly against the fallback graph shape
    produced by _fallback_state_graph.
    """
    try:
        from fsa import signatures
        return signatures.match_rules(graph, symbols, source_bytes)
    except ImportError:
        return _fallback_matches(graph)


def _fallback_matches(graph: Dict[str, Any]) -> List[Dict[str, Any]]:
    matches: List[Dict[str, Any]] = []

    state_mutations = graph.get("state_mutations", [])
    external_calls = graph.get("external_calls", [])
    user_input_uses = graph.get("user_input_uses", [])
    has_auth = graph.get("has_top_level_auth_check", False)

    # BROKEN_AUTH: function mutates financial state but has no
    # authorization check near the top of the function body.
    if state_mutations and not has_auth:
        first_mutation = state_mutations[0]
        matches.append({
            "class": "BROKEN_AUTH",
            "line_start": graph["function_line"],
            "line_end": first_mutation["end_line"],
            "snippet": graph.get("function_text", "")[:MAX_SNIPPET_LEN],
            "description": (
                "Function performs a financial state mutation "
                f"(`{first_mutation.get('target', first_mutation.get('text', ''))}`) "
                "without a preceding authorization or validation check."
            ),
            "fix_principle": "Add an authentication/authorization check before mutating financial state.",
            "confidence": 0.7,
        })

    # UNCHECKED_EXTERNAL_CALL / ordering risk: an external call occurs
    # before a state mutation that is supposed to depend on its outcome,
    # and the call's result/error is never checked.
    for call in external_calls:
        later_mutations = [m for m in state_mutations if m["line"] > call["line"]]
        if later_mutations:
            first_later = later_mutations[0]
            matches.append({
                "class": "UNCHECKED_EXTERNAL_CALL",
                "line_start": call["line"],
                "line_end": first_later["end_line"],
                "snippet": f"{call['text']}\n...\n{first_later['text']}"[:MAX_SNIPPET_LEN],
                "description": (
                    f"External call `{call.get('name', call['text'])}` occurs before the "
                    "dependent state mutation, with no visible check on its outcome. "
                    "If the call fails, state may become inconsistent."
                ),
                "fix_principle": (
                    "Check the external call's success/failure before mutating state, "
                    "or perform the mutation atomically with the call and roll back on failure."
                ),
                "confidence": 0.65,
            })
            break  # one ordering finding per function keeps fallback noise low

    # PRIVILEGE_ESCALATION / MISSING_VALIDATION: a state mutation's target
    # or value is derived directly from raw user input with no validation
    # call present at all in the function.
    if state_mutations and not graph.get("validations"):
        tainted = [m for m in state_mutations if m.get("touches_user_input")]
        if tainted:
            m = tainted[0]
            matches.append({
                "class": "MISSING_VALIDATION",
                "line_start": m["line"],
                "line_end": m["end_line"],
                "snippet": m["text"][:MAX_SNIPPET_LEN],
                "description": (
                    f"State mutation `{m.get('target', '')}` derives its value directly from "
                    "unvalidated user input with no validation/guard call present in the function."
                ),
                "fix_principle": "Validate and bound-check user-supplied values before using them in state mutations.",
                "confidence": 0.6,
            })

    return matches


def _has_signatures_available() -> bool:
    """Check if the proprietary signatures module is importable."""
    return _module_available("fsa.signatures")


# ---------------------------------------------------------------------------
# Finding / manifest construction
# ---------------------------------------------------------------------------

def _create_finding(
    file_path: str,
    vulnerability_class: str,
    line_start: int,
    line_end: int,
    code_snippet: str,
    description: str,
    fix_principle: str,
    index: int,
    confidence: float = 0.8,
) -> Dict[str, Any]:
    """Create a single finding object for the manifest."""
    finding_id = _generate_finding_id(vulnerability_class, index)

    return {
        "id": finding_id,
        "file_path": file_path,
        "line_start": line_start,
        "line_end": line_end,
        "vulnerability_class": vulnerability_class,
        "severity": SEVERITY_MAP.get(vulnerability_class, "MEDIUM"),
        "code_snippet": code_snippet[:MAX_SNIPPET_LEN],
        "description": description[:MAX_DESCRIPTION_LEN],
        "fix_principle": fix_principle[:MAX_FIX_PRINCIPLE_LEN],
        "confidence": min(1.0, max(0.0, float(confidence))),
        "false_positive_risk": "MEDIUM",
    }


def _generate_finding_id(vulnerability_class: str, index: int) -> str:
    """Generate a stable finding ID in the format FSA-<ABBR>-<index>."""
    abbr = FINDING_ID_ABBREVIATIONS.get(vulnerability_class, "UNKNOWN")
    return f"FSA-{abbr}-{index:03d}"


def _build_manifest(
    project_hash: str,
    files_analyzed: int,
    duration: float,
    findings: List[Dict[str, Any]],
    errors: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Build the Contract B payload."""
    return {
        "contract_version": CONTRACT_VERSION,
        "project_hash": project_hash,
        "generated_at": _utc_now_iso(),
        "analysis_metadata": {
            "scanner_version": VERSION,
            "files_analyzed": files_analyzed,
            "analysis_duration_seconds": duration,
            "target_tracks": ["web2"],
        },
        "findings": findings,
        "errors": errors,
    }


def _utc_now_iso() -> str:
    """Return the current UTC time as an ISO 8601 string with a 'Z' suffix."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _get_mock_manifest(project_index: Dict[str, Any]) -> Dict[str, Any]:
    """
    Return a mock Contract B payload for development.

    Used only when the proprietary fsa.signatures / fsa.graph_builder
    modules are not importable -- never as a substitute for a real scan
    that legitimately produced zero findings.
    """
    return {
        "contract_version": CONTRACT_VERSION,
        "project_hash": project_index.get("project_identifier", ""),
        "generated_at": _utc_now_iso(),
        "analysis_metadata": {
            "scanner_version": f"{VERSION}-mock",
            "files_analyzed": len(project_index.get("files", [])),
            "analysis_duration_seconds": 0.01,
            "target_tracks": ["web2"],
        },
        "findings": [
            {
                "id": "FSA-BAUTH-001",
                "file_path": "src/controllers/payment.js",
                "line_start": 12,
                "line_end": 18,
                "vulnerability_class": "BROKEN_AUTH",
                "severity": "HIGH",
                "code_snippet": "async function processPayment(amount, userId) { ... }",
                "description": "Mock finding: missing authorization check before financial state mutation.",
                "fix_principle": "Add an authentication/authorization check before mutating financial state.",
                "confidence": 0.95,
                "false_positive_risk": "LOW",
            },
            {
                "id": "FSA-UNCHK-002",
                "file_path": "src/controllers/payment.js",
                "line_start": 20,
                "line_end": 24,
                "vulnerability_class": "UNCHECKED_EXTERNAL_CALL",
                "severity": "HIGH",
                "code_snippet": (
                    "await stripe.charges.create({ amount, currency: 'usd', "
                    "customer: user.stripeId });\nuser.balance -= amount;\nawait user.save();"
                ),
                "description": "Mock finding: external call result is not checked before a dependent state mutation.",
                "fix_principle": "Check the external call's success/failure before mutating state.",
                "confidence": 0.92,
                "false_positive_risk": "MEDIUM",
            },
        ],
        "errors": [],
    }


# ---------------------------------------------------------------------------
# Standalone execution (for local testing only)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json
    import sys

    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) < 2:
        print("Usage: python analyzer.py /path/to/contract_a.json")
        sys.exit(1)

    try:
        with open(sys.argv[1], "r", encoding="utf-8") as f:
            contract_a = json.load(f)
    except Exception as exc:
        print(f"Error reading Contract A file: {exc}")
        sys.exit(1)

    result = analyze(contract_a)
    print(json.dumps(result, indent=2))
