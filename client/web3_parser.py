"""OSE Auditor – Web3 Solidity Pre-Processor (client/web3_parser.py).

Parses Solidity (.sol) source files using tree-sitter-solidity and produces
a structured payload that the FSA and the adversarial AI agent can consume.

The output is structurally compatible with Contract A (Project Source Index)
but carries Solidity-specific fields alongside the standard ones so that
downstream consumers can inspect the contract topology directly without
re-parsing.

This module has no network I/O and no side effects beyond reading files from
disk.  It is safe to call from any thread and from the FastAPI server's
async context (parsing is synchronous but fast).

Extracted per file
------------------
- functions       : name, visibility, mutability, modifiers, parameters,
                    line range, is_payable, is_external
- state_variables : name, type_name, visibility, is_constant, is_immutable
- modifiers       : name, parameters, line range
- events          : name, parameters
- external_calls  : callee text, method name, value (ETH sent), line range,
                    call_type (call / transfer / send / delegatecall / staticcall)
- access_controls : type (require / onlyOwner modifier / if_check), condition
                    text, line
- oracle_uses     : source (chainlink / uniswap / balanceof / custom),
                    identifier text, line
- arithmetic_ops  : operator, operands text, line, on_uint (bool)
- reentrancy_risk : functions where an external call precedes a state write
- flash_loan_markers : presence of flash-loan receiver interfaces
                       (executeOperation, onFlashLoan, uniswapV2Call, etc.)

Usage
-----
    from client.web3_parser import Web3Parser

    parser = Web3Parser("/path/to/contracts")
    payload = parser.scan()
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

__all__ = ["Web3Parser"]

logger = logging.getLogger("ose.web3_parser")

CONTRACT_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Directory / file filters
# ---------------------------------------------------------------------------

IGNORE_DIRS: frozenset = frozenset({
    "node_modules", ".git", "dist", "build", "coverage",
    "lib", "vendor", "test", "tests", "mocks", "mock",
    "flattened", "artifacts", "cache", ".hardhat", ".foundry",
})

TEST_PATH_MARKERS: Tuple[str, ...] = (
    "test/", "tests/", ".test.", ".spec.", "mock", "Mock",
    "fixture", "Fixture",
)

THIRD_PARTY_PATH_MARKERS: Tuple[str, ...] = (
    "vendor/", "lib/", "node_modules/",
    "openzeppelin", "chainlink", "uniswap",
)

MAX_FILES = 500
MAX_CONTENT_BYTES = 2 * 1024 * 1024  # 2 MB per file

# ---------------------------------------------------------------------------
# Solidity-specific keyword sets
# ---------------------------------------------------------------------------

VISIBILITY_KEYWORDS = frozenset({"public", "external", "internal", "private"})
MUTABILITY_KEYWORDS = frozenset({"pure", "view", "payable", "nonpayable"})

# External call patterns (text-based, used when AST walk is not enough)
CALL_TYPE_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("call",         re.compile(r"\.\s*call\s*\{")),
    ("delegatecall", re.compile(r"\.\s*delegatecall\s*\{")),
    ("staticcall",   re.compile(r"\.\s*staticcall\s*\{")),
    ("transfer",     re.compile(r"\.\s*transfer\s*\(")),
    ("send",         re.compile(r"\.\s*send\s*\(")),
]

# Oracle / price-feed identifiers
CHAINLINK_FRAGMENTS = frozenset({
    "AggregatorV3Interface", "latestRoundData", "latestAnswer",
    "priceFeed", "oracle", "AggregatorInterface",
})
UNISWAP_FRAGMENTS = frozenset({
    "IUniswapV2Pair", "IUniswapV2Router", "IUniswapV3Pool",
    "getAmountsOut", "getAmountsIn", "slot0", "observe",
    "token0", "token1", "getReserves",
})
BALANCEOF_PATTERN = re.compile(r"\.balanceOf\s*\(")
TWAP_PATTERN = re.compile(r"\bTWAP\b|\btwap\b|\bTimeWeighted\b")

# Flash-loan receiver interface method names
FLASH_LOAN_RECEIVER_NAMES = frozenset({
    "executeOperation",     # Aave
    "onFlashLoan",          # EIP-3156
    "uniswapV2Call",        # Uniswap V2
    "uniswapV3FlashCallback",  # Uniswap V3
    "pancakeCall",          # PancakeSwap
    "flashLoan",            # generic
    "flashCallback",        # dYdX-style
    "receiveFlashLoan",     # Balancer
})

# Access-control modifiers by name pattern
OWNER_MODIFIER_PATTERN = re.compile(
    r"\b(onlyOwner|onlyAdmin|onlyRole|onlyMinter|onlyBurner|adminOnly|ownerOnly)\b"
)

# Uint type pattern for arithmetic overflow detection
UINT_TYPE_PATTERN = re.compile(r"\buint\d*\b|\bint\d*\b")

# ---------------------------------------------------------------------------
# Tree-sitter loading (lazy, cached)
# ---------------------------------------------------------------------------

_SOL_PARSER: Optional[Any] = None
_SOL_PARSER_CHECKED = False


def _get_solidity_parser() -> Optional[Any]:
    """Return a cached tree-sitter Parser for Solidity, or None."""
    global _SOL_PARSER, _SOL_PARSER_CHECKED
    if _SOL_PARSER_CHECKED:
        return _SOL_PARSER
    _SOL_PARSER_CHECKED = True
    try:
        from tree_sitter import Language, Parser
        import tree_sitter_solidity as tssol  # type: ignore
        lang = Language(tssol.language())
        _SOL_PARSER = Parser(lang)
        logger.info("tree-sitter-solidity loaded successfully.")
    except ImportError:
        logger.warning(
            "tree-sitter-solidity is not installed. "
            "Install it with: pip install tree-sitter-solidity>=0.2.0  "
            "Web3 parsing will fall back to regex-only analysis."
        )
        _SOL_PARSER = None
    except Exception as exc:
        logger.error("Failed to load tree-sitter-solidity: %s", exc)
        _SOL_PARSER = None
    return _SOL_PARSER


# ---------------------------------------------------------------------------
# Generic AST helpers
# ---------------------------------------------------------------------------

def _node_text(node: Any, source_bytes: bytes) -> str:
    """Return decoded source text for a tree-sitter node."""
    try:
        return source_bytes[node.start_byte:node.end_byte].decode(
            "utf-8", errors="replace"
        )
    except Exception:
        return ""


def _walk(node: Any):
    """Depth-first pre-order traversal."""
    stack = [node]
    while stack:
        cur = stack.pop()
        yield cur
        try:
            stack.extend(reversed(cur.children))
        except Exception:
            pass


def _children_of_type(node: Any, *types: str) -> List[Any]:
    return [c for c in getattr(node, "children", []) if c.type in types]


def _first_child_of_type(node: Any, *types: str) -> Optional[Any]:
    for c in getattr(node, "children", []):
        if c.type in types:
            return c
    return None


# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------

def _extract_functions(root: Any, source_bytes: bytes) -> List[Dict[str, Any]]:
    """Extract all function / constructor / fallback / receive definitions."""
    results: List[Dict[str, Any]] = []
    func_types = {
        "function_definition",
        "constructor_definition",
        "fallback_receive_definition",
        "modifier_definition",
    }
    for node in _walk(root):
        if node.type not in func_types:
            continue

        name = ""
        visibility = "internal"
        mutability = "nonpayable"
        modifiers: List[str] = []
        params: List[str] = []
        is_payable = False
        is_external = False

        for child in getattr(node, "children", []):
            if child.type == "identifier":
                name = _node_text(child, source_bytes)
            elif child.type == "visibility":
                v = _node_text(child, source_bytes).strip()
                visibility = v
                is_external = v in ("external", "public")
            elif child.type == "state_mutability":
                m = _node_text(child, source_bytes).strip()
                mutability = m
                is_payable = m == "payable"
            elif child.type == "modifier_invocation":
                modifiers.append(_node_text(child, source_bytes).strip())
            elif child.type == "parameter_list":
                for param in _walk(child):
                    if param.type == "parameter":
                        params.append(_node_text(param, source_bytes).strip())

        if node.type == "constructor_definition":
            name = "constructor"
        elif node.type in ("fallback_receive_definition",):
            name_node = _first_child_of_type(node, "fallback", "receive")
            name = _node_text(name_node, source_bytes).strip() if name_node else "fallback"

        results.append({
            "name": name,
            "visibility": visibility,
            "mutability": mutability,
            "modifiers": modifiers,
            "parameters": params,
            "is_payable": is_payable,
            "is_external": is_external,
            "line_start": node.start_point[0] + 1,
            "line_end": node.end_point[0] + 1,
            "node_type": node.type,
        })
    return results


def _extract_state_variables(root: Any, source_bytes: bytes) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for node in _walk(root):
        if node.type != "state_variable_declaration":
            continue
        type_name = ""
        name = ""
        visibility = "internal"
        is_constant = False
        is_immutable = False
        for child in getattr(node, "children", []):
            if child.type in ("type_name", "elementary_type_name", "user_defined_type_name"):
                type_name = _node_text(child, source_bytes).strip()
            elif child.type == "identifier":
                name = _node_text(child, source_bytes).strip()
            elif child.type == "visibility":
                visibility = _node_text(child, source_bytes).strip()
            elif child.type == "constant":
                is_constant = True
            elif child.type == "immutable":
                is_immutable = True
        if name:
            results.append({
                "name": name,
                "type_name": type_name,
                "visibility": visibility,
                "is_constant": is_constant,
                "is_immutable": is_immutable,
                "line": node.start_point[0] + 1,
            })
    return results


def _extract_modifiers(root: Any, source_bytes: bytes) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for node in _walk(root):
        if node.type != "modifier_definition":
            continue
        name = ""
        params: List[str] = []
        for child in getattr(node, "children", []):
            if child.type == "identifier":
                name = _node_text(child, source_bytes).strip()
            elif child.type == "parameter_list":
                for param in _walk(child):
                    if param.type == "parameter":
                        params.append(_node_text(param, source_bytes).strip())
        if name:
            results.append({
                "name": name,
                "parameters": params,
                "line_start": node.start_point[0] + 1,
                "line_end": node.end_point[0] + 1,
            })
    return results


def _extract_events(root: Any, source_bytes: bytes) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for node in _walk(root):
        if node.type != "event_definition":
            continue
        name = ""
        params: List[str] = []
        for child in getattr(node, "children", []):
            if child.type == "identifier":
                name = _node_text(child, source_bytes).strip()
            elif child.type == "event_parameter_list":
                for p in _walk(child):
                    if p.type == "event_parameter":
                        params.append(_node_text(p, source_bytes).strip())
        if name:
            results.append({"name": name, "parameters": params,
                            "line": node.start_point[0] + 1})
    return results


def _extract_external_calls(source: str, source_bytes: bytes, root: Optional[Any]) -> List[Dict[str, Any]]:
    """
    Detect external calls.  Uses both the AST (call_expression nodes with
    member_expression callees) and regex fallback so we catch patterns that
    tree-sitter-solidity may not classify perfectly across grammar versions.
    """
    results: List[Dict[str, Any]] = []
    seen_lines: set = set()

    # AST-based detection
    if root is not None:
        for node in _walk(root):
            if node.type != "call_expression":
                continue
            full_text = _node_text(node, source_bytes).strip()
            line = node.start_point[0] + 1
            # Detect .call{} / .transfer() / .send() / .delegatecall{} / .staticcall{}
            call_type = "unknown"
            for ctype, pat in CALL_TYPE_PATTERNS:
                if pat.search(full_text):
                    call_type = ctype
                    break
            if call_type == "unknown":
                # Only record explicit external calls, not regular function calls
                continue
            # Extract callee (the object being called on)
            callee = ""
            method = call_type
            func_child = _first_child_of_type(node, "member_expression")
            if func_child:
                callee = _node_text(func_child, source_bytes).strip()

            # ETH value being sent (value: X inside call{value: X})
            value_text = ""
            value_match = re.search(r"value\s*:\s*([^,}]+)", full_text)
            if value_match:
                value_text = value_match.group(1).strip()

            if line not in seen_lines:
                seen_lines.add(line)
                results.append({
                    "callee": callee,
                    "method": method,
                    "call_type": call_type,
                    "value": value_text,
                    "text": full_text[:300],
                    "line": line,
                })

    # Regex fallback for any calls the AST missed
    lines = source.split("\n")
    for i, line_text in enumerate(lines, 1):
        if i in seen_lines:
            continue
        for call_type, pat in CALL_TYPE_PATTERNS:
            if pat.search(line_text):
                seen_lines.add(i)
                results.append({
                    "callee": "",
                    "method": call_type,
                    "call_type": call_type,
                    "value": "",
                    "text": line_text.strip()[:300],
                    "line": i,
                })
                break
    return results


def _extract_access_controls(source: str, source_bytes: bytes, root: Optional[Any]) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    lines = source.split("\n")

    # Detect onlyOwner / role modifier usages
    for i, line_text in enumerate(lines, 1):
        m = OWNER_MODIFIER_PATTERN.search(line_text)
        if m:
            results.append({
                "type": "modifier",
                "condition": m.group(0),
                "line": i,
            })

    # AST: require statements
    if root is not None:
        for node in _walk(root):
            if node.type != "call_expression":
                continue
            func_child = _first_child_of_type(node, "identifier")
            if func_child and _node_text(func_child, source_bytes) in ("require", "assert"):
                full_text = _node_text(node, source_bytes).strip()
                # Filter: only record if it looks like an auth check
                auth_keywords = ("msg.sender", "owner", "admin", "role",
                                 "hasRole", "authorized", "onlyOwner", "permission")
                if any(kw in full_text for kw in auth_keywords):
                    results.append({
                        "type": "require",
                        "condition": full_text[:300],
                        "line": node.start_point[0] + 1,
                    })

    # tx.origin usage (always a security concern)
    for i, line_text in enumerate(lines, 1):
        if "tx.origin" in line_text:
            results.append({
                "type": "tx_origin",
                "condition": line_text.strip()[:300],
                "line": i,
            })

    return results


def _extract_oracle_uses(source: str) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    lines = source.split("\n")
    for i, line_text in enumerate(lines, 1):
        source_type = None
        identifier = line_text.strip()[:200]

        if any(frag in line_text for frag in CHAINLINK_FRAGMENTS):
            source_type = "chainlink"
        elif any(frag in line_text for frag in UNISWAP_FRAGMENTS):
            source_type = "uniswap"
        elif BALANCEOF_PATTERN.search(line_text):
            source_type = "balanceof"
        elif TWAP_PATTERN.search(line_text):
            source_type = "twap"

        if source_type:
            results.append({
                "source": source_type,
                "identifier": identifier,
                "line": i,
            })
    return results


def _extract_arithmetic_ops(source: str, source_bytes: bytes, root: Optional[Any]) -> List[Dict[str, Any]]:
    """Detect arithmetic on uint/int types without SafeMath wrapper."""
    results: List[Dict[str, Any]] = []
    # Simple line-by-line scan for arithmetic operators on lines that also
    # reference uint/int (covers the majority of cases without full type inference)
    arith_pattern = re.compile(r"(\w[\w\.\[\]]*)\s*(\+\+|--|\+=|-=|\*=|/=|\+|-|\*|/)\s*([\w\.\[\]]*)")
    lines = source.split("\n")
    for i, line_text in enumerate(lines, 1):
        if not UINT_TYPE_PATTERN.search(line_text) and not any(
            op in line_text for op in ("+=", "-=", "*=", "/=", "++", "--")
        ):
            continue
        for m in arith_pattern.finditer(line_text):
            operator = m.group(2)
            if operator in ("+", "-", "*", "/", "+=", "-=", "*=", "/=", "++", "--"):
                # Exclude SafeMath calls – they contain "SafeMath." or ".add(" etc.
                if "SafeMath" in line_text or ".add(" in line_text or ".sub(" in line_text:
                    continue
                # Exclude Solidity 0.8+ style (we detect pragma above and note it)
                results.append({
                    "operator": operator,
                    "operands": f"{m.group(1)} {operator} {m.group(3)}".strip(),
                    "line": i,
                    "on_uint": bool(UINT_TYPE_PATTERN.search(line_text)),
                })
    return results


def _detect_reentrancy_risk(functions: List[Dict[str, Any]], external_calls: List[Dict[str, Any]], source: str) -> List[Dict[str, Any]]:
    """
    Flag functions where an external call line precedes a state-write line.

    State writes in Solidity: assignments containing mapping/balances/storage
    variable references that appear AFTER an external call in the same function.
    """
    risks: List[Dict[str, Any]] = []
    state_write_pattern = re.compile(
        r"\b(balances|balance|deposits|pending|allocation|shares|totalSupply)"
        r"\s*[\[\(].*?\)\s*[-+*/]?=|"
        r"\b\w+\s*[-+*/]?=\s*"
    )
    for func in functions:
        func_start = func["line_start"]
        func_end = func["line_end"]
        # Find external calls within this function
        calls_in_func = [c for c in external_calls
                         if func_start <= c["line"] <= func_end]
        if not calls_in_func:
            continue
        first_call_line = min(c["line"] for c in calls_in_func)
        # Look for state writes after the first call
        lines = source.split("\n")
        for j in range(first_call_line, min(func_end, len(lines))):
            line_text = lines[j - 1]  # lines are 1-indexed
            if state_write_pattern.search(line_text) and "=" in line_text:
                risks.append({
                    "function": func["name"],
                    "external_call_line": first_call_line,
                    "state_write_line": j,
                    "state_write_text": line_text.strip()[:200],
                    "severity": "CRITICAL",
                })
                break  # one finding per function is enough at parse time
    return risks


def _detect_flash_loan_markers(functions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Detect functions with flash-loan receiver signatures."""
    markers: List[Dict[str, Any]] = []
    for func in functions:
        if func["name"] in FLASH_LOAN_RECEIVER_NAMES:
            markers.append({
                "function": func["name"],
                "line_start": func["line_start"],
                "line_end": func["line_end"],
                "note": "This function implements a flash-loan callback interface.",
            })
    return markers


def _detect_solidity_version(source: str) -> Optional[str]:
    """Extract the Solidity pragma version, if present."""
    m = re.search(r"pragma\s+solidity\s+([^;]+);", source)
    return m.group(1).strip() if m else None


def _is_solidity_08_plus(version_str: Optional[str]) -> bool:
    """Return True if the pragma indicates Solidity 0.8+."""
    if not version_str:
        return False
    m = re.search(r"0\.(\d+)\.", version_str)
    if m and int(m.group(1)) >= 8:
        return True
    return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class Web3Parser:
    """Traverses a directory and builds a Solidity-specific Project Source Index.

    Analogous to ``OseParser`` in ``parser.py`` but targets ``.sol`` files
    and extracts Solidity-specific structure that the Web3 FSA and adversarial
    AI agent need.

    :param root_path: Absolute or relative path to the project root.
    :param ignore_dirs: Optional extra directory names to skip.
    """

    def __init__(
        self,
        root_path: str,
        ignore_dirs: Optional[List[str]] = None,
    ) -> None:
        resolved = Path(root_path).expanduser().resolve()
        if not resolved.exists():
            raise ValueError(f"Project path does not exist: {resolved}")
        if not resolved.is_dir():
            raise ValueError(f"Project path is not a directory: {resolved}")
        self.root_path = resolved
        self._ignore_dirs = set(IGNORE_DIRS)
        if ignore_dirs:
            self._ignore_dirs.update(ignore_dirs)
        self._errors: List[Dict[str, str]] = []

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def scan(self) -> Dict[str, Any]:
        """Scan the project and return the Solidity Source Index payload.

        :return: A dict with ``contract_version``, ``project_identifier``,
            ``generated_at``, ``files`` (list of per-file analysis dicts),
            ``summary``, and ``truncated``.
        """
        start = time.monotonic()
        self._errors = []
        logger.info("Starting Web3 scan of: %s", self.root_path)

        candidate_files = self._collect_sol_files()
        total_discovered = len(candidate_files)
        truncated = False
        if total_discovered > MAX_FILES:
            logger.warning(
                "Discovered %d .sol files; truncating to %d.",
                total_discovered, MAX_FILES,
            )
            candidate_files = candidate_files[:MAX_FILES]
            truncated = True

        file_entries: List[Dict[str, Any]] = []
        for fpath in candidate_files:
            entry = self._process_file(fpath)
            if entry is not None:
                file_entries.append(entry)

        duration = round(time.monotonic() - start, 4)
        logger.info(
            "Web3 scan complete: %d files, %d errors, %.4fs",
            len(file_entries), len(self._errors), duration,
        )

        return {
            "contract_version": CONTRACT_VERSION,
            "project_identifier": self._project_id(),
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "project_metadata": self._get_project_metadata(),
            "language": "solidity",
            "files": file_entries,
            "summary": {
                "total_files": len(file_entries),
                "total_errors": len(self._errors),
                "scan_duration_seconds": duration,
                "errors": self._errors,
            },
            "truncated": truncated,
        }

    # ------------------------------------------------------------------
    # File collection
    # ------------------------------------------------------------------

    def _collect_sol_files(self) -> List[Path]:
        collected: List[Path] = []
        self._walk_dir(self.root_path, collected)
        collected.sort(key=lambda p: str(p.relative_to(self.root_path)))
        return collected

    def _walk_dir(self, directory: Path, collected: List[Path]) -> None:
        try:
            entries = sorted(directory.iterdir(), key=lambda p: p.name)
        except (PermissionError, OSError) as exc:
            logger.error("Cannot list %s: %s", directory, exc)
            self._errors.append({"path": str(directory), "error": str(exc)})
            return
        for entry in entries:
            if entry.is_symlink():
                continue
            if entry.is_dir():
                if entry.name in self._ignore_dirs:
                    continue
                self._walk_dir(entry, collected)
            elif entry.is_file() and entry.suffix == ".sol":
                collected.append(entry)

    # ------------------------------------------------------------------
    # File processing
    # ------------------------------------------------------------------

    def _process_file(self, file_path: Path) -> Optional[Dict[str, Any]]:
        rel = file_path.relative_to(self.root_path).as_posix()
        try:
            raw_bytes = file_path.read_bytes()
        except OSError as exc:
            self._errors.append({"path": rel, "error": str(exc)})
            return None

        if len(raw_bytes) > MAX_CONTENT_BYTES:
            logger.warning("Skipping oversized file: %s (%d bytes)", rel, len(raw_bytes))
            self._errors.append({"path": rel, "error": "file_too_large"})
            return None

        try:
            source = raw_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            self._errors.append({"path": rel, "error": str(exc)})
            return None

        content_hash = hashlib.sha256(raw_bytes).hexdigest()

        # Parse AST (may be None if tree-sitter-solidity not installed)
        parser = _get_solidity_parser()
        root: Optional[Any] = None
        if parser is not None:
            try:
                tree = parser.parse(raw_bytes)
                root = tree.root_node
            except Exception as exc:
                logger.warning("AST parse failed for %s: %s", rel, exc)

        source_bytes = raw_bytes

        # Solidity version
        sol_version = _detect_solidity_version(source)
        is_08_plus = _is_solidity_08_plus(sol_version)

        # Extractions
        functions = _extract_functions(root, source_bytes) if root else []
        state_variables = _extract_state_variables(root, source_bytes) if root else []
        modifiers = _extract_modifiers(root, source_bytes) if root else []
        events = _extract_events(root, source_bytes) if root else []
        external_calls = _extract_external_calls(source, source_bytes, root)
        access_controls = _extract_access_controls(source, source_bytes, root)
        oracle_uses = _extract_oracle_uses(source)
        arithmetic_ops = (
            [] if is_08_plus
            else _extract_arithmetic_ops(source, source_bytes, root)
        )
        reentrancy_risk = _detect_reentrancy_risk(functions, external_calls, source)
        flash_loan_markers = _detect_flash_loan_markers(functions)

        is_test = any(marker in rel for marker in TEST_PATH_MARKERS)
        is_third_party = any(marker in rel for marker in THIRD_PARTY_PATH_MARKERS)

        logger.debug("Processed %s: %d funcs, %d ext-calls, %d access-controls",
                     rel, len(functions), len(external_calls), len(access_controls))

        return {
            "path_relative": rel,
            "language": "sol",
            "hash": content_hash,
            "stripped_content": source,
            "original_size": len(raw_bytes),
            "stripped_size": len(raw_bytes),
            "is_test_file": is_test,
            "is_third_party": is_third_party,
            # Solidity-specific
            "solidity_version": sol_version,
            "is_solidity_08_plus": is_08_plus,
            "functions": functions,
            "state_variables": state_variables,
            "modifiers": modifiers,
            "events": events,
            "external_calls": external_calls,
            "access_controls": access_controls,
            "oracle_uses": oracle_uses,
            "arithmetic_ops": arithmetic_ops,
            "reentrancy_risk": reentrancy_risk,
            "flash_loan_markers": flash_loan_markers,
        }

    # ------------------------------------------------------------------
    # Metadata
    # ------------------------------------------------------------------

    def _project_id(self) -> str:
        return hashlib.sha256(str(self.root_path).encode()).hexdigest()

    def _get_project_metadata(self) -> Dict[str, Any]:
        """Try to read package.json or hardhat.config.js for project name."""
        name = None
        for candidate in ("package.json", "hardhat.config.js", "foundry.toml"):
            p = self.root_path / candidate
            if p.is_file():
                try:
                    raw = p.read_text(encoding="utf-8")
                    if candidate == "package.json":
                        import json
                        data = json.loads(raw)
                        name = data.get("name")
                    else:
                        name = candidate
                except Exception:
                    pass
                break
        return {"name": name, "language": "solidity"}
