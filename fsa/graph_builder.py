#!/usr/bin/env python3
"""
OSE Auditor - State Graph Builder

This module builds an execution graph from a tree-sitter AST node representing
a single function. It classifies statement/expression-level nodes into
validations, external calls, state mutations, user input uses, ownership
checks, state transitions, settlement confirmations, state reads, and
financial actions -- preserving source order via line numbers and byte
offsets.

It does NOT detect vulnerabilities -- that is fsa.signatures' job. It only
produces a structured graph that fsa.signatures can reason about.

This module is CLOSED SOURCE / PROPRIETARY.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("ose.graph_builder")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_TEXT_LEN = 200
MAX_FUNCTION_TEXT_LEN = 2000

#: A validation node within this many lines of the function start counts
#: as a "top level" auth check (line - function_line <= 2, i.e. within the
#: first 3 lines).
TOP_LEVEL_AUTH_CHECK_LINE_WINDOW = 2

VALIDATION_CALL_NAMES = frozenset({
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
})

AUTH_HINT_FRAGMENTS = (
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
)

EXTERNAL_CALL_NAME_FRAGMENTS = (
    "stripe",
    "paystack",
    "flutterwave",
    "square",
    "paypal",
    "fetch",
    "axios",
    "request",
    "http",
    "send",
    "transfer",
    "withdraw",
    "deposit",
    "call",
)

USER_INPUT_FRAGMENTS = (
    "req.body",
    "req.query",
    "req.params",
    "request.body",
    "request.query",
    "request.params",
    "ctx.request.body",
    "ctx.query",
)

STATE_MUTATION_TARGET_FRAGMENTS = (
    "balance",
    "wallet",
    "ledger",
    "account",
    "funds",
    "credit",
    "debit",
    "status",
    "state",
    "order",
    "payment",
    "transaction",
    "subscription",
    "plan",
    "escrow",
    "settlement",
)

OWNERSHIP_HINT_FRAGMENTS = (
    "owner",
    "userid",
    "user.id",
    "belongsto",
    "ownerid",
)

STATE_TRANSITION_TARGET_FRAGMENTS = (
    "status",
    "state",
)

STATE_TRANSITION_VALUE_FRAGMENTS = (
    "completed",
    "complete",
    "paid",
    "cancelled",
    "canceled",
    "approved",
    "fulfilled",
    "shipped",
    "refunded",
    "settled",
    "failed",
    "rejected",
    "active",
    "closed",
)

SETTLEMENT_CONFIRMATION_FRAGMENTS = (
    "payment.status",
    "transaction.status",
    "flutterwaveresponse.status",
    "striperesponse.status",
    "success",
    "successful",
)

STATE_READ_FRAGMENTS = (
    "balance",
    "wallet",
    "ledger",
    "account",
    "funds",
    "order",
    "payment",
    "status",
)

FINANCIAL_ACTION_NAME_FRAGMENTS = (
    "transfer",
    "withdraw",
    "deposit",
    "credit",
    "debit",
    "payout",
    "send",
    "charge",
    "refund",
)

ASSIGNMENT_NODE_TYPES = frozenset(
    {"assignment_expression", "augmented_assignment_expression"})
IDENTIFIER_LIKE_NODE_TYPES = frozenset({"identifier", "member_expression"})


# ---------------------------------------------------------------------------
# Low-level text / traversal helpers
# ---------------------------------------------------------------------------

def _slice_source(source_bytes: bytes, start_byte: int, end_byte: int) -> str:
    """Decode a byte range of the source into text, tolerant of bad input."""
    try:
        return source_bytes[start_byte:end_byte].decode("utf-8", errors="replace")
    except Exception:
        return ""


def _full_node_text(node: Any, source_bytes: bytes) -> str:
    """Return the full (untruncated) source text for `node`."""
    try:
        return _slice_source(source_bytes, node.start_byte, node.end_byte)
    except Exception:
        return ""


def _normalize_identifier(text: str) -> str:
    """Lowercase and strip everything but alphanumerics, for fuzzy matching."""
    if not text:
        return ""
    return "".join(ch for ch in text.lower() if ch.isalnum())


def _walk(node: Any):
    """Depth-first pre-order traversal over all descendants (incl. self)."""
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        try:
            children = list(current.children)
        except Exception:
            children = []
        stack.extend(reversed(children))


def _text_contains_any(text: str, fragments) -> bool:
    """Case-insensitive substring check of `text` against `fragments`."""
    if not text:
        return False
    lowered = text.lower()
    return any(fragment in lowered for fragment in fragments)


# ---------------------------------------------------------------------------
# Node classification helpers
# ---------------------------------------------------------------------------

def _callee_name(call_node: Any, source_bytes: bytes) -> str:
    """Return the textual name of the function/member being called for a
    call_expression node, e.g. `require`, `stripe.charges.create`."""
    func_child = None
    try:
        func_child = call_node.child_by_field_name("function")
    except Exception:
        func_child = None
    if func_child is not None:
        return _full_node_text(func_child, source_bytes)
    try:
        for child in call_node.children:
            if child.type in ("identifier", "member_expression"):
                return _full_node_text(child, source_bytes)
    except Exception:
        pass
    return ""


def is_validation_node(node: Any, source_bytes: bytes) -> bool:
    """Return True if `node` is a call to a validation/guard function.

    Matches against either the first segment (e.g. `require` in
    `require(x)`) or the last segment (e.g. `isAuthorized` in
    `Auth.isAuthorized()`) of the callee name, since validation helpers
    are sometimes namespaced behind an object/module.
    """
    if node.type != "call_expression":
        return False
    name = _callee_name(node, source_bytes)
    if not name:
        return False
    parts = [p for p in name.split(".") if p]
    candidates = {parts[0], parts[-1]} if parts else set()
    return any(_normalize_identifier(c) in VALIDATION_CALL_NAMES for c in candidates)


def is_auth_if_statement(node: Any, source_bytes: bytes) -> bool:
    """Return True if `node` is an if-statement whose condition looks like
    an authorization/authentication check."""
    if node.type != "if_statement":
        return False
    condition = None
    try:
        condition = node.child_by_field_name("condition")
    except Exception:
        condition = None
    cond_text = _full_node_text(
        condition, source_bytes) if condition is not None else ""
    return _text_contains_any(cond_text, AUTH_HINT_FRAGMENTS)


def is_external_call_node(node: Any, source_bytes: bytes) -> bool:
    """Return True if `node` is a call expression likely to contact an
    external system (payment gateway, HTTP client, blockchain, etc.)."""
    if node.type != "call_expression":
        return False
    name = _callee_name(node, source_bytes)
    normalized_name = name.lower()
    if any(fragment in normalized_name for fragment in EXTERNAL_CALL_NAME_FRAGMENTS):
        return True
    is_awaited = (
        node.parent is not None and getattr(
            node.parent, "type", None) == "await_expression"
    )
    # Heuristic: an awaited call through a member expression (e.g.
    # `await someService.doThing()`) is very likely I/O against something
    # external, even when the callee name doesn't match a known keyword.
    if is_awaited and "." in name:
        return True
    return False


def _assignment_target_text(node: Any, source_bytes: bytes) -> str:
    """Return the full text of the left-hand side of an assignment node."""
    left = None
    try:
        left = node.child_by_field_name("left")
    except Exception:
        left = None
    if left is None:
        try:
            children = node.children
            if children:
                left = children[0]
        except Exception:
            left = None
    if left is None:
        return ""
    return _full_node_text(left, source_bytes)


def _target_is_financial(target_text: str, symbols: Dict[str, Any]) -> bool:
    """Return True if `target_text` matches a known financial symbol or
    contains a recognized financial-state keyword."""
    normalized_target = _normalize_identifier(target_text)
    if not normalized_target:
        return False
    for symbol_name in symbols:
        normalized_symbol = _normalize_identifier(symbol_name)
        if normalized_symbol and normalized_symbol in normalized_target:
            return True
    return any(fragment in normalized_target for fragment in STATE_MUTATION_TARGET_FRAGMENTS)


def is_state_mutation_node(node: Any, source_bytes: bytes, symbols: Dict[str, Any]) -> bool:
    """Return True if `node` is an assignment that mutates financial state."""
    if node.type not in ASSIGNMENT_NODE_TYPES:
        return False
    target_text = _assignment_target_text(node, source_bytes)
    return _target_is_financial(target_text, symbols)


def is_user_input_node(node: Any, source_bytes: bytes) -> bool:
    """Return True if `node`'s text directly references a known
    user-input source (req.body, ctx.query, etc.)."""
    if node.type not in IDENTIFIER_LIKE_NODE_TYPES:
        return False
    text = _full_node_text(node, source_bytes)
    return _text_contains_any(text, USER_INPUT_FRAGMENTS)


def is_ownership_check_if_statement(node: Any, source_bytes: bytes) -> bool:
    """Return True if `node` is an if-statement whose condition looks like
    a resource-ownership check (e.g. `order.userId !== req.user.id`)."""
    if node.type != "if_statement":
        return False
    condition = None
    try:
        condition = node.child_by_field_name("condition")
    except Exception:
        condition = None
    cond_text = _full_node_text(
        condition, source_bytes) if condition is not None else ""
    return _text_contains_any(cond_text, OWNERSHIP_HINT_FRAGMENTS)


def is_settlement_confirmation_if_statement(node: Any, source_bytes: bytes) -> bool:
    """Return True if `node` is an if-statement whose condition looks like
    a payment/settlement success check (e.g. `payment.status === "success"`)."""
    if node.type != "if_statement":
        return False
    condition = None
    try:
        condition = node.child_by_field_name("condition")
    except Exception:
        condition = None
    cond_text = _full_node_text(
        condition, source_bytes) if condition is not None else ""
    return _text_contains_any(cond_text, SETTLEMENT_CONFIRMATION_FRAGMENTS)


def _assignment_value_text(node: Any, source_bytes: bytes) -> str:
    """Return the full text of the right-hand side of an assignment node."""
    right = None
    try:
        right = node.child_by_field_name("right")
    except Exception:
        right = None
    if right is None:
        try:
            children = node.children
            if children:
                right = children[-1]
        except Exception:
            right = None
    if right is None:
        return ""
    return _full_node_text(right, source_bytes)


def is_state_transition_node(node: Any, source_bytes: bytes) -> bool:
    """Return True if `node` is an assignment that sets a status/state
    field to a recognized lifecycle value (e.g. `order.status = "completed"`).
    """
    if node.type not in ASSIGNMENT_NODE_TYPES:
        return False
    target_text = _assignment_target_text(node, source_bytes)
    if not _text_contains_any(target_text, STATE_TRANSITION_TARGET_FRAGMENTS):
        return False
    value_text = _assignment_value_text(node, source_bytes)
    return _text_contains_any(value_text, STATE_TRANSITION_VALUE_FRAGMENTS)


def is_state_read_node(node: Any, source_bytes: bytes) -> bool:
    """Return True if `node` is an identifier/member-expression reference
    to a financial/state field that is NOT the target of an assignment
    (e.g. `wallet.balance` in `const balance = wallet.balance;`)."""
    if node.type not in IDENTIFIER_LIKE_NODE_TYPES:
        return False
    text = _full_node_text(node, source_bytes)
    if not _text_contains_any(text, STATE_READ_FRAGMENTS):
        return False

    parent = node.parent
    if parent is not None and getattr(parent, "type", None) in ASSIGNMENT_NODE_TYPES:
        try:
            left = parent.child_by_field_name("left")
        except Exception:
            left = None
        # If this node IS the assignment's left-hand side (or sits inside
        # it, e.g. as the object of a member expression target), it's a
        # write, not a read -- exclude it.
        if left is not None and (node is left or _is_descendant_of(node, left)):
            return False

    return True


def _is_descendant_of(node: Any, ancestor: Any) -> bool:
    """Return True if `node` is `ancestor` or appears anywhere within it,
    by byte-range containment (cheap and tree-sitter-version-agnostic)."""
    try:
        return ancestor.start_byte <= node.start_byte and node.end_byte <= ancestor.end_byte
    except Exception:
        return False


def is_financial_action_call(node: Any, source_bytes: bytes) -> bool:
    """Return True if `node` is a call expression invoking a financial
    operation (transfer, withdraw, deposit, charge, refund, etc.)."""
    if node.type != "call_expression":
        return False
    name = _callee_name(node, source_bytes)
    if not name:
        return False
    return _text_contains_any(name, FINANCIAL_ACTION_NAME_FRAGMENTS)

# ---------------------------------------------------------------------------
# Entry construction
# ---------------------------------------------------------------------------


def _make_entry(node: Any, source_bytes: bytes, **extra: Any) -> Dict[str, Any]:
    """Build a graph entry dict for `node` with the common line/byte/text
    fields, plus any node-type-specific `extra` fields."""
    text = _full_node_text(node, source_bytes).strip()[:MAX_TEXT_LEN]
    entry: Dict[str, Any] = {
        "line": node.start_point[0] + 1,
        "end_line": node.end_point[0] + 1,
        "start_byte": node.start_byte,
        "end_byte": node.end_byte,
        "text": text,
    }
    entry.update(extra)
    return entry


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_graph(
    function_node: Any, source_bytes: bytes, symbols: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """
    Build a state transition graph for a single function.

    Args:
        function_node: tree-sitter node representing a function scope
            (function_declaration, function_expression, arrow_function,
            method_definition, generator_function_declaration, or
            generator_function).
        source_bytes: Raw UTF-8 bytes of the source file the node belongs to.
        symbols: Financial entity symbol table for the file. Never modified.

    Returns:
        A dictionary with ordered lists of typed nodes -- validations,
        external_calls, state_mutations, user_input_uses, ownership_checks,
        state_transitions, settlement_confirmations, state_reads, and
        financial_actions -- plus function metadata, or None if the function
        body is empty, missing, or cannot be traversed. Never raises.

        A single AST node may appear in more than one list if it matches
        more than one category (e.g. an if-statement checking both auth
        and ownership appears in both `validations` and
        `ownership_checks`); no deduplication is performed across or
        within categories.
    """
    try:
        return _build_graph_inner(function_node, source_bytes, symbols)
    except Exception as exc:  # noqa: BLE001 - graph builder must never raise
        logger.warning("Failed to build state graph: %s", exc)
        return None


def _build_graph_inner(
    function_node: Any, source_bytes: bytes, symbols: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    if function_node is None:
        return None

    try:
        child_count = function_node.child_count
    except Exception:
        child_count = None

    if child_count == 0:
        logger.debug("Function node has no children; skipping.")
        return None

    function_line = function_node.start_point[0] + 1
    function_end_line = function_node.end_point[0] + 1
    function_text = _full_node_text(function_node, source_bytes)[
        :MAX_FUNCTION_TEXT_LEN]

    validations: List[Dict[str, Any]] = []
    external_calls: List[Dict[str, Any]] = []
    state_mutations: List[Dict[str, Any]] = []
    user_input_uses: List[Dict[str, Any]] = []
    ownership_checks: List[Dict[str, Any]] = []
    state_transitions: List[Dict[str, Any]] = []
    settlement_confirmations: List[Dict[str, Any]] = []
    state_reads: List[Dict[str, Any]] = []
    financial_actions: List[Dict[str, Any]] = []

    for node in _walk(function_node):
        node_type = getattr(node, "type", None)

        if node_type == "call_expression":
            if is_validation_node(node, source_bytes):
                name = _callee_name(node, source_bytes)
                validations.append(_make_entry(node, source_bytes, name=name))
                # Falls through deliberately: a call can be both a
                # validation AND a financial action in principle, but
                # validation names (require/assert/...) don't overlap with
                # financial action fragments in practice. No dedup is
                # performed anywhere in this loop by design.

            if is_external_call_node(node, source_bytes):
                name = _callee_name(node, source_bytes)
                args_text = _full_node_text(node, source_bytes)
                is_awaited = (
                    node.parent is not None
                    and getattr(node.parent, "type", None) == "await_expression"
                )
                external_calls.append(
                    _make_entry(
                        node,
                        source_bytes,
                        name=name,
                        is_awaited=is_awaited,
                        touches_user_input=_text_contains_any(
                            args_text, USER_INPUT_FRAGMENTS),
                    )
                )

            if is_financial_action_call(node, source_bytes):
                name = _callee_name(node, source_bytes)
                args_text = _full_node_text(node, source_bytes)
                is_awaited = (
                    node.parent is not None
                    and getattr(node.parent, "type", None) == "await_expression"
                )
                financial_actions.append(
                    _make_entry(
                        node,
                        source_bytes,
                        name=name,
                        is_awaited=is_awaited,
                        touches_user_input=_text_contains_any(
                            args_text, USER_INPUT_FRAGMENTS),
                    )
                )

            continue

        elif node_type == "if_statement":
            matched_if = False
            if is_auth_if_statement(node, source_bytes):
                validations.append(_make_entry(
                    node, source_bytes, name="if_auth_check"))
                matched_if = True

            if is_ownership_check_if_statement(node, source_bytes):
                ownership_checks.append(_make_entry(
                    node, source_bytes, name="if_ownership_check"))
                matched_if = True

            if is_settlement_confirmation_if_statement(node, source_bytes):
                settlement_confirmations.append(
                    _make_entry(node, source_bytes,
                                name="if_settlement_confirmation")
                )
                matched_if = True

            if matched_if:
                continue

        elif node_type in ASSIGNMENT_NODE_TYPES:
            matched_assignment = False
            if is_state_mutation_node(node, source_bytes, symbols):
                target_text = _assignment_target_text(node, source_bytes)
                full_text = _full_node_text(node, source_bytes)
                state_mutations.append(
                    _make_entry(
                        node,
                        source_bytes,
                        target=target_text.strip()[:MAX_TEXT_LEN],
                        touches_user_input=_text_contains_any(
                            full_text, USER_INPUT_FRAGMENTS),
                    )
                )
                matched_assignment = True

            if is_state_transition_node(node, source_bytes):
                target_text = _assignment_target_text(node, source_bytes)
                value_text = _assignment_value_text(node, source_bytes)
                state_transitions.append(
                    _make_entry(
                        node,
                        source_bytes,
                        target=target_text.strip()[:MAX_TEXT_LEN],
                        value=value_text.strip()[:MAX_TEXT_LEN],
                    )
                )
                matched_assignment = True

            if matched_assignment:
                continue

        elif node_type in IDENTIFIER_LIKE_NODE_TYPES:
            matched_identifier = False
            if is_user_input_node(node, source_bytes):
                user_input_uses.append(_make_entry(node, source_bytes))
                matched_identifier = True

            if is_state_read_node(node, source_bytes):
                state_reads.append(_make_entry(node, source_bytes))
                matched_identifier = True

            if matched_identifier:
                continue

    has_top_level_auth_check = any(
        (v["line"] - function_line) <= TOP_LEVEL_AUTH_CHECK_LINE_WINDOW for v in validations
    )

    return {
        "function_line": function_line,
        "function_end_line": function_end_line,
        "function_text": function_text,
        "validations": validations,
        "external_calls": external_calls,
        "state_mutations": state_mutations,
        "user_input_uses": user_input_uses,
        "ownership_checks": ownership_checks,
        "state_transitions": state_transitions,
        "settlement_confirmations": settlement_confirmations,
        "state_reads": state_reads,
        "financial_actions": financial_actions,
        "has_top_level_auth_check": has_top_level_auth_check,
    }
