"""
OSE Auditor - Vulnerability Signatures Library

This module contains the declarative rule definitions for OSE's vulnerability
detection engine. Each rule defines a business logic or financial logic flaw
that the analyzer should detect.

All rules are evaluated deterministically against the state graph produced by
graph_builder.py (or analyzer.py's internal fallback graph builder, which
follows the same shape). No AI is used in this module.

Graph shape this module is written against (see fsa/analyzer.py):
    {
        "function_line": int, "function_end_line": int, "function_text": str,
        "validations": [{"line": int, "end_line": int, "text": str, "name": str}, ...],
        "external_calls": [{"line": int, "end_line": int, "text": str, "name": str,
                             "is_awaited": bool, "touches_user_input": bool}, ...],
        "state_mutations": [{"line": int, "end_line": int, "text": str,
                              "target": str, "touches_user_input": bool}, ...],
        "user_input_uses": [{"line": int, "end_line": int, "text": str}, ...],
        "ownership_checks": [{"line": int, "end_line": int, "text": str, "name": str}, ...],
        "state_transitions": [{"line": int, "end_line": int, "text": str,
                                "target": str, "value": str}, ...],
        "settlement_confirmations": [{"line": int, "end_line": int, "text": str, "name": str}, ...],
        "state_reads": [{"line": int, "end_line": int, "text": str}, ...],
        "financial_actions": [{"line": int, "end_line": int, "text": str, "name": str,
                                "is_awaited": bool, "touches_user_input": bool}, ...],
        "has_top_level_auth_check": bool,
    }

Every node's "text" field is the node's source text, stripped and truncated
to 200 characters by the graph builder -- conditions that match substrings
against "text" should account for that truncation rather than assuming a
full statement is always present.

This module is CLOSED SOURCE / PROPRIETARY. Do not distribute or disclose.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("ose.signatures")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_SNIPPET_LEN = 4096

# Fragments indicating a value traces back to raw, attacker-controlled
# request input. Mirrors analyzer.py's USER_INPUT_FRAGMENTS so this module
# behaves consistently even if it's ever handed a node whose
# `touches_user_input` flag wasn't pre-computed by the graph builder.
_USER_INPUT_TEXT_FRAGMENTS = (
    "req.body",
    "req.query",
    "req.params",
    "request.body",
    "request.query",
    "request.params",
    "ctx.request.body",
    "ctx.query",
)

# Fragments that indicate an authorization/role/identity decision, used by
# PRIVILEGE_ESCALATION to find validations or conditions that gate on
# something resembling a role/permission check.
_AUTH_DECISION_FRAGMENTS = ("role", "permission", "isadmin", "admin", "scope")

# Words indicating "ownership" checks, used by BROKEN_ACCESS_CONTROL.
_OWNERSHIP_FRAGMENTS = ("owner", "userid", "user.id", "belongsto", "ownerid")

# Words used to recognize order/payment lifecycle state for
# INVALID_STATE_TRANSITION / LOGIC_FLAW.
_COMPLETION_STATUS_FRAGMENTS = (
    "completed", "fulfilled", "shipped", "approved", "paid")
_PAYMENT_PREREQUISITE_FRAGMENTS = ("payment", "paid", "invoice", "charge")
_BALANCE_FRAGMENTS = ("balance", "funds", "wallet", "credit", "debit")


# ---------------------------------------------------------------------------
# Helper functions (shared across rule conditions)
# ---------------------------------------------------------------------------

def _has_auth_check(graph: Dict[str, Any]) -> bool:
    """Return True if the graph has a top-level authentication check."""
    return bool(graph.get("has_top_level_auth_check", False))


def _state_mutations(graph: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return the graph's state_mutations list, defaulting to empty."""
    return graph.get("state_mutations") or []


def _external_calls(graph: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return the graph's external_calls list, defaulting to empty."""
    return graph.get("external_calls") or []


def _validations(graph: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return the graph's validations list, defaulting to empty."""
    return graph.get("validations") or []


def _ownership_checks(graph: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return the graph's ownership_checks list, defaulting to empty."""
    return graph.get("ownership_checks") or []


def _state_transitions(graph: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return the graph's state_transitions list, defaulting to empty."""
    return graph.get("state_transitions") or []


def _settlement_confirmations(graph: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return the graph's settlement_confirmations list, defaulting to empty."""
    return graph.get("settlement_confirmations") or []


def _state_reads(graph: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return the graph's state_reads list, defaulting to empty."""
    return graph.get("state_reads") or []


def _financial_actions(graph: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return the graph's financial_actions list, defaulting to empty."""
    return graph.get("financial_actions") or []


def _has_state_mutation(graph: Dict[str, Any], symbols: Dict[str, Any]) -> bool:
    """Return True if the graph has any state mutation nodes."""
    return bool(_state_mutations(graph))


def _has_external_call(graph: Dict[str, Any], symbols: Dict[str, Any]) -> bool:
    """Return True if the graph has any external call nodes."""
    return bool(_external_calls(graph))


def _has_validation(graph: Dict[str, Any], symbols: Dict[str, Any]) -> bool:
    """Return True if the graph has any validation nodes."""
    return bool(_validations(graph))


def _text_contains_any(text: Optional[str], fragments: tuple) -> bool:
    """Case-insensitive substring check of `text` against `fragments`."""
    if not text:
        return False
    lowered = text.lower()
    return any(fragment in lowered for fragment in fragments)


def _node_touches_user_input(node: Dict[str, Any]) -> bool:
    """Return True if a node was pre-flagged as touching user input, or its
    text independently matches a known user-input fragment (defensive
    fallback for graphs built by something other than analyzer.py's own
    fallback builder, e.g. a future graph_builder.py)."""
    if node.get("touches_user_input"):
        return True
    return _text_contains_any(node.get("text"), _USER_INPUT_TEXT_FRAGMENTS)


def _first_external_call_before_mutation(
    graph: Dict[str, Any],
) -> Optional[tuple]:
    """
    Return (call, mutation) for the first external call that strictly
    precedes a state mutation later in the same function, or None if no
    such pair exists.

    Both lists are in source order as produced by the graph builder, so a
    simple ordered scan is sufficient and avoids an O(n*m) full cross
    product when the first call already has a later mutation.

    KNOWN LIMITATION: line comparison is strict (call_line < mutation_line),
    which means a call and a mutation that land on the same source line --
    e.g. in minified or single-line function bodies such as
    `function f(a){bal-=a;payout(a);}` -- can never match here, even when
    the call genuinely precedes the mutation within that line. This is a
    deliberate choice, not an oversight: the graph dict only carries line
    numbers on each node, and while state_mutations/external_calls each
    preserve true source order *within their own list*, there is no shared
    ordering key between the two separate lists that would let this
    function tell whether a same-line call came before or after a
    same-line mutation. Relaxing the comparison to `>=` was tried and
    rejected during development because it produces a confirmed false
    positive on the equally plausible same-line case where the mutation
    comes first (`bal-=a;payout(a);`) -- trading a false negative for an
    unverifiable false positive is not an improvement. If reliable
    same-line ordering is needed, the fix belongs in the graph builder
    (attach a monotonic traversal index or byte offset to each node), not
    here.
    """
    calls = _external_calls(graph)
    mutations = _state_mutations(graph)
    if not calls or not mutations:
        return None

    for call in calls:
        call_line = call.get("line", 0)
        for mutation in mutations:
            if mutation.get("line", 0) > call_line:
                return call, mutation
    return None


def _external_call_before_mutation(graph: Dict[str, Any], symbols: Dict[str, Any]) -> bool:
    """Return True if any external call occurs before any state mutation
    that follows it in source order."""
    return _first_external_call_before_mutation(graph) is not None


def _any_user_input_in_state_mutation(graph: Dict[str, Any], symbols: Dict[str, Any]) -> bool:
    """Return True if any state mutation derives its target/value from
    unvalidated user input."""
    return any(_node_touches_user_input(m) for m in _state_mutations(graph))


def _auth_check_uses_user_input(graph: Dict[str, Any], symbols: Dict[str, Any]) -> bool:
    """
    Return True if an authorization-flavored validation node's condition is
    itself derived from user-controlled input (e.g. branching on
    `req.body.role`), which means the caller can dictate their own
    privilege level.

    Deliberately narrower than "any validation touches user input": a
    validation like `require(req.body.amount > 0)` is a legitimate input
    check, not a privilege escalation. We only flag validations whose text
    combines a user-input fragment with an auth/role/permission fragment.
    """
    for val in _validations(graph):
        text = val.get("text", "") or ""
        if _text_contains_any(text, _USER_INPUT_TEXT_FRAGMENTS) and _text_contains_any(
            text, _AUTH_DECISION_FRAGMENTS
        ):
            return True
    return False


def _has_ownership_check(graph: Dict[str, Any]) -> bool:
    """
    Return True if the graph has an ownership check node.

    Prefers the dedicated `ownership_checks` field from the enhanced
    graph builder; falls back to re-deriving from validations for
    backward compatibility with older graph shapes.
    """
    if _ownership_checks(graph):
        return True
    # Fallback for older graphs
    return any(_text_contains_any(v.get("text"), _OWNERSHIP_FRAGMENTS) for v in _validations(graph))


def _mutation_touches_balance(mutation: Dict[str, Any]) -> bool:
    """Return True if a state mutation's target/text looks like a
    monetary balance/funds field rather than an unrelated field."""
    target = (mutation.get("target") or "").lower()
    text = (mutation.get("text") or "").lower()
    return any(frag in target for frag in _BALANCE_FRAGMENTS) or any(
        frag in text for frag in _BALANCE_FRAGMENTS
    )


def _balance_mutation_without_ownership(graph: Dict[str, Any], symbols: Dict[str, Any]) -> bool:
    """
    Return True if the function mutates a balance/funds-like field but no
    validation node in the function performs an ownership check (e.g.
    confirming the authenticated caller owns the account/wallet being
    mutated). This is distinct from BROKEN_AUTH: a function can have a
    perfectly good "is the caller logged in" check and still let any
    logged-in user drain *someone else's* wallet.
    """
    balance_mutations = [m for m in _state_mutations(
        graph) if _mutation_touches_balance(m)]
    if not balance_mutations:
        return False
    # Use the dedicated ownership_checks field first, fallback to scanning validations
    if _ownership_checks(graph):
        return False
    return not _has_ownership_check(graph)


def _double_spend_pattern(graph: Dict[str, Any], symbols: Dict[str, Any]) -> bool:
    """
    Return True if the function reads/uses a balance, performs an awaited
    external call, and only afterwards mutates that same balance -- the
    classic check-then-act race window where a second concurrent request
    can read the same pre-mutation balance before the first request's
    external call resolves.

    Narrower than the generic external-call-before-mutation check: this
    additionally requires (a) the external call is awaited, signaling a
    genuine suspension point where another request could interleave, and
    (b) the mutation that follows specifically touches a balance/funds-like
    field, not just any field.
    """
    pair = _first_external_call_before_mutation(graph)
    if pair is None:
        return False
    call, mutation = pair
    if not call.get("is_awaited"):
        return False
    return _mutation_touches_balance(mutation)


def _completion_status_mutation_without_payment_check(
    graph: Dict[str, Any], symbols: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """
    Return the first state-mutation node that sets a completion-like status
    (e.g. `order.status = "completed"`) without a corresponding settlement
    confirmation or payment prerequisite check.

    Prefers the dedicated `settlement_confirmations` field from the enhanced
    graph builder; falls back to scanning validations for backward compatibility.
    """
    # Check if there's a settlement confirmation
    has_settlement_confirmation = bool(_settlement_confirmations(graph))

    for mutation in _state_mutations(graph):
        text = mutation.get("text", "") or ""
        if not _text_contains_any(text, _COMPLETION_STATUS_FRAGMENTS):
            continue

        # If we have a dedicated settlement confirmation, we're done
        if has_settlement_confirmation:
            continue

        # Fallback: check validations for payment-related prerequisites
        if any(
            _text_contains_any(v.get("text"), _PAYMENT_PREREQUISITE_FRAGMENTS)
            for v in _validations(graph)
        ):
            continue

        return mutation

    # If no completion status mutation with missing checks, return None
    return None


def _invalid_state_transition(graph: Dict[str, Any], symbols: Dict[str, Any]) -> bool:
    """Return True if a completion-like state transition happens without a
    corresponding payment/prerequisite validation."""
    return _completion_status_mutation_without_payment_check(graph, symbols) is not None


def _generic_unguarded_mutation(graph: Dict[str, Any], symbols: Dict[str, Any]) -> bool:
    """
    Return True for the catch-all LOGIC_FLAW case: the function mutates
    financial state with no auth check, no validation at all, and no
    external-call-ordering issue already explains the risk. This rule is
    intentionally the lowest-confidence, highest-false-positive-risk rule
    in the set and is meant to catch genuine gaps that don't fit a more
    specific signature, not to duplicate BROKEN_AUTH/UNCHECKED_EXTERNAL_CALL.
    """
    return (
        _has_state_mutation(graph, symbols)
        and not _has_auth_check(graph)
        and not _has_validation(graph, symbols)
        and not _external_call_before_mutation(graph, symbols)
    )


# ---------------------------------------------------------------------------
# Snippet / line-range extraction
# ---------------------------------------------------------------------------

def _node_byte_range(node: Dict[str, Any], graph: Dict[str, Any]) -> Optional[tuple]:
    """
    Best-effort (start_byte, end_byte) for a graph node, if the graph
    builder attached byte offsets. analyzer.py's current fallback graph
    builder does not include byte offsets on individual nodes (only
    line/end_line/text), so this normally returns None and callers fall
    back to line-based snippet extraction; a future graph_builder.py that
    does attach offsets will be used automatically here without any change
    to the rules themselves.
    """
    start = node.get("start_byte")
    end = node.get("end_byte")
    if isinstance(start, int) and isinstance(end, int) and end >= start:
        return start, end
    return None


def _snippet_for_lines(graph: Dict[str, Any], source_bytes: bytes, line_start: int, line_end: int) -> str:
    """
    Extract a source snippet covering [line_start, line_end] (1-indexed,
    inclusive) from source_bytes. Falls back to the function's full text
    (truncated) if line slicing fails for any reason -- a slightly too-wide
    snippet is preferable to an empty one.
    """
    try:
        text = source_bytes.decode("utf-8", errors="replace")
        lines = text.split("\n")
        start_idx = max(0, line_start - 1)
        end_idx = min(len(lines), line_end)
        if start_idx < end_idx:
            return "\n".join(lines[start_idx:end_idx])[:MAX_SNIPPET_LEN]
    except Exception as exc:
        logger.warning(
            "Failed to slice source for snippet (lines %s-%s): %s", line_start, line_end, exc)
    return (graph.get("function_text") or "")[:MAX_SNIPPET_LEN]


def _best_snippet(
    graph: Dict[str, Any], source_bytes: bytes, nodes: List[Dict[str, Any]]
) -> str:
    """Build a snippet spanning the given nodes' line ranges, in source
    order. Falls back to the function's full text if `nodes` is empty."""
    if not nodes:
        return (graph.get("function_text") or "")[:MAX_SNIPPET_LEN]
    line_start = min(n.get("line", graph.get("function_line", 1))
                     for n in nodes)
    line_end = max(n.get("end_line", n.get("line", line_start)) for n in nodes)
    return _snippet_for_lines(graph, source_bytes, line_start, line_end)


# ---------------------------------------------------------------------------
# Rule -> match-detail builder functions
# ---------------------------------------------------------------------------
# Each rule's "detail" callable receives (graph, symbols, source_bytes) and
# returns the (line_start, line_end, snippet, description) tuple specific
# to *that* match, since the most useful line range/snippet/description
# differs per rule even when the underlying condition is a simple bool.

def _detail_broken_auth(graph, symbols, source_bytes):
    mutations = _state_mutations(graph)
    target_mutation = mutations[0] if mutations else None
    line_start = graph.get("function_line", 1)
    line_end = target_mutation.get("end_line", line_start) if target_mutation else graph.get(
        "function_end_line", line_start
    )
    snippet = _best_snippet(graph, source_bytes, [
                            m for m in [target_mutation] if m])
    target_desc = ""
    if target_mutation:
        target_desc = target_mutation.get(
            "target") or target_mutation.get("text", "")
    description = (
        "Function performs a financial state mutation"
        + (f" (`{target_desc}`)" if target_desc else "")
        + " without a preceding authentication or authorization check."
    )
    return line_start, line_end, snippet, description


def _detail_broken_access_control(graph, symbols, source_bytes):
    balance_mutations = [m for m in _state_mutations(
        graph) if _mutation_touches_balance(m)]
    target_mutation = balance_mutations[0] if balance_mutations else None
    line_start = target_mutation.get("line", graph.get("function_line", 1)) if target_mutation else graph.get(
        "function_line", 1
    )
    line_end = target_mutation.get("end_line", line_start) if target_mutation else graph.get(
        "function_end_line", line_start
    )
    snippet = _best_snippet(graph, source_bytes, [
                            m for m in [target_mutation] if m])
    target_desc = target_mutation.get(
        "target", "") if target_mutation else "a financial resource"
    description = (
        f"Function mutates `{target_desc}` without verifying that the "
        "authenticated caller actually owns the resource being modified; "
        "any authenticated user may be able to act on another user's data."
    )
    return line_start, line_end, snippet, description


def _detail_privilege_escalation(graph, symbols, source_bytes):
    tainted_validation = None
    for val in _validations(graph):
        text = val.get("text", "") or ""
        if _text_contains_any(text, _USER_INPUT_TEXT_FRAGMENTS) and _text_contains_any(
            text, _AUTH_DECISION_FRAGMENTS
        ):
            tainted_validation = val
            break
    line_start = tainted_validation.get("line", graph.get("function_line", 1)) if tainted_validation else graph.get(
        "function_line", 1
    )
    line_end = tainted_validation.get("end_line", line_start) if tainted_validation else graph.get(
        "function_end_line", line_start
    )
    snippet = _best_snippet(graph, source_bytes, [
                            v for v in [tainted_validation] if v])
    description = (
        "Authorization decision is derived from client-supplied input "
        f"(`{tainted_validation.get('text', '')}`); a caller can set this "
        "value directly to grant themselves elevated privileges."
        if tainted_validation
        else "Authorization decision appears to be derived from client-supplied input."
    )
    return line_start, line_end, snippet, description


def _detail_missing_validation(graph, symbols, source_bytes):
    tainted = next((m for m in _state_mutations(graph)
                   if _node_touches_user_input(m)), None)
    line_start = tainted.get("line", graph.get(
        "function_line", 1)) if tainted else graph.get("function_line", 1)
    line_end = tainted.get("end_line", line_start) if tainted else graph.get(
        "function_end_line", line_start)
    snippet = _best_snippet(graph, source_bytes, [m for m in [tainted] if m])
    target_desc = tainted.get("target", "") if tainted else ""
    description = (
        f"State mutation `{target_desc}` derives its value directly from "
        "unvalidated user input with no validation/guard present in the function."
    )
    return line_start, line_end, snippet, description


def _detail_unchecked_external_call(graph, symbols, source_bytes):
    pair = _first_external_call_before_mutation(graph)
    if pair is None:
        line_start = graph.get("function_line", 1)
        line_end = graph.get("function_end_line", line_start)
        return line_start, line_end, (graph.get("function_text") or "")[:MAX_SNIPPET_LEN], (
            "External call occurs before a dependent state mutation with no visible error handling."
        )
    call, mutation = pair
    line_start = call.get("line", graph.get("function_line", 1))
    line_end = mutation.get("end_line", line_start)
    snippet = _best_snippet(graph, source_bytes, [call, mutation])
    description = (
        f"External call `{call.get('name', call.get('text', ''))}` occurs "
        "before the dependent state mutation, with no visible check on its "
        "outcome. If the call fails, state may become inconsistent."
    )
    return line_start, line_end, snippet, description


def _detail_invalid_state_transition(graph, symbols, source_bytes):
    mutation = _completion_status_mutation_without_payment_check(
        graph, symbols)
    line_start = mutation.get("line", graph.get(
        "function_line", 1)) if mutation else graph.get("function_line", 1)
    line_end = mutation.get("end_line", line_start) if mutation else graph.get(
        "function_end_line", line_start)
    snippet = _best_snippet(graph, source_bytes, [m for m in [mutation] if m])
    target_desc = mutation.get("target", mutation.get(
        "text", "")) if mutation else "state"
    description = (
        f"State transition `{target_desc}` marks a process as complete "
        "without a corresponding prerequisite check (e.g. confirming "
        "payment succeeded first)."
    )
    return line_start, line_end, snippet, description


def _detail_double_spend(graph, symbols, source_bytes):
    pair = _first_external_call_before_mutation(graph)
    if pair is None:
        line_start = graph.get("function_line", 1)
        line_end = graph.get("function_end_line", line_start)
        return line_start, line_end, (graph.get("function_text") or "")[:MAX_SNIPPET_LEN], (
            "Potential race condition between a balance read/external action and a balance update."
        )
    call, mutation = pair
    line_start = call.get("line", graph.get("function_line", 1))
    line_end = mutation.get("end_line", line_start)
    snippet = _best_snippet(graph, source_bytes, [call, mutation])
    description = (
        f"Function awaits external call `{call.get('name', call.get('text', ''))}` "
        f"and only afterwards updates `{mutation.get('target', '')}`. A second "
        "concurrent request can read the same pre-update balance during the "
        "await window, allowing the same funds to be spent twice."
    )
    return line_start, line_end, snippet, description


def _detail_logic_flaw(graph, symbols, source_bytes):
    mutations = _state_mutations(graph)
    target_mutation = mutations[0] if mutations else None
    line_start = graph.get("function_line", 1)
    line_end = target_mutation.get("end_line", line_start) if target_mutation else graph.get(
        "function_end_line", line_start
    )
    snippet = _best_snippet(graph, source_bytes, [
                            m for m in [target_mutation] if m])
    description = (
        "Function mutates financial state with no authorization check, no "
        "input validation, and no external-call ordering issue identified "
        "by a more specific rule -- the business process appears to be "
        "missing guards entirely and should be reviewed manually."
    )
    return line_start, line_end, snippet, description


def _detail_settlement_bypass(graph, symbols, source_bytes):
    """Generate details for SETTLEMENT_BYPASS findings."""
    transitions = _state_transitions(graph)
    target_mutation = transitions[0] if transitions else None
    line_start = target_mutation.get("line", graph.get("function_line", 1)) if target_mutation else graph.get(
        "function_line", 1
    )
    line_end = target_mutation.get("end_line", line_start) if target_mutation else graph.get(
        "function_end_line", line_start
    )
    snippet = _best_snippet(graph, source_bytes, [
                            m for m in [target_mutation] if m])
    target_desc = target_mutation.get(
        "target", "") if target_mutation else "state"
    description = (
        f"State transition `{target_desc}` marks a process as complete "
        "without a corresponding settlement/payment confirmation check. "
        "This may allow order completion before payment is fully settled."
    )
    return line_start, line_end, snippet, description


def _detail_financial_action_ordering(graph, symbols, source_bytes):
    """Generate details for FINANCIAL_ACTION_ORDERING findings."""
    financial_actions = _financial_actions(graph)
    target_action = financial_actions[0] if financial_actions else None
    line_start = target_action.get("line", graph.get("function_line", 1)) if target_action else graph.get(
        "function_line", 1
    )
    line_end = target_action.get("end_line", line_start) if target_action else graph.get(
        "function_end_line", line_start
    )
    snippet = _best_snippet(graph, source_bytes, [
                            m for m in [target_action] if m])
    action_name = target_action.get(
        "name", "financial action") if target_action else "financial action"
    description = (
        f"Financial action `{action_name}` is executed without an "
        "authorization check or settlement confirmation. This may allow "
        "unauthorized or premature financial operations."
    )
    return line_start, line_end, snippet, description

# ---------------------------------------------------------------------------
# Rule Definitions
# ---------------------------------------------------------------------------
# Each rule is a dictionary with:
#   - class: str                                  -- vulnerability class
#   - severity: str                                -- CRITICAL/HIGH/MEDIUM/LOW
#   - condition: Callable[[Dict, Dict], bool]      -- (graph, symbols) -> bool
#   - detail: Callable[[Dict, Dict, bytes], tuple] -- (graph, symbols, source_bytes)
#                                                      -> (line_start, line_end, snippet, description)
#   - confidence: float                            -- 0.0 - 1.0
#   - fix_principle: str
#   - false_positive_risk: str


RULES: List[Dict[str, Any]] = [
    {
        "class": "BROKEN_AUTH",
        "severity": "HIGH",
        "condition": lambda g, s: _has_state_mutation(g, s) and not _has_auth_check(g),
        "detail": _detail_broken_auth,
        "confidence": 0.85,
        "false_positive_risk": "LOW",
        "fix_principle": "Add an authentication/authorization check before mutating financial state.",
    },
    {
        "class": "BROKEN_ACCESS_CONTROL",
        "severity": "HIGH",
        "condition": _balance_mutation_without_ownership,
        "detail": _detail_broken_access_control,
        "confidence": 0.75,
        "false_positive_risk": "MEDIUM",
        "fix_principle": (
            "Verify that the authenticated caller owns the specific resource "
            "(account, wallet, order) being mutated, not just that they are logged in."
        ),
    },
    {
        "class": "PRIVILEGE_ESCALATION",
        "severity": "HIGH",
        "condition": _auth_check_uses_user_input,
        "detail": _detail_privilege_escalation,
        "confidence": 0.80,
        "false_positive_risk": "MEDIUM",
        "fix_principle": "Do not use user-controlled data for authorization decisions; enforce roles server-side.",
    },
    {
        "class": "MISSING_VALIDATION",
        "severity": "MEDIUM",
        "condition": lambda g, s: _any_user_input_in_state_mutation(g, s) and not _has_validation(g, s),
        "detail": _detail_missing_validation,
        "confidence": 0.70,
        "false_positive_risk": "MEDIUM",
        "fix_principle": "Validate and bound-check all user-supplied values before using them in state mutations.",
    },
    {
        "class": "UNCHECKED_EXTERNAL_CALL",
        "severity": "HIGH",
        "condition": _external_call_before_mutation,
        "detail": _detail_unchecked_external_call,
        "confidence": 0.75,
        "false_positive_risk": "MEDIUM",
        "fix_principle": (
            "Check the external call's success/failure before mutating state, "
            "or perform the mutation atomically with the call and roll back on failure."
        ),
    },
    {
        "class": "INVALID_STATE_TRANSITION",
        "severity": "MEDIUM",
        "condition": _invalid_state_transition,
        "detail": _detail_invalid_state_transition,
        "confidence": 0.60,
        "false_positive_risk": "HIGH",
        "fix_principle": "Validate that all prerequisites (e.g. payment status) are satisfied before changing state.",
    },
    {
        "class": "DOUBLE_SPEND",
        "severity": "CRITICAL",
        "condition": _double_spend_pattern,
        "detail": _detail_double_spend,
        "confidence": 0.65,
        "false_positive_risk": "HIGH",
        "fix_principle": "Use atomic operations or database-level locks to prevent concurrent state corruption.",
    },
    {
        "class": "LOGIC_FLAW",
        "severity": "MEDIUM",
        "condition": _generic_unguarded_mutation,
        "detail": _detail_logic_flaw,
        "confidence": 0.50,
        "false_positive_risk": "HIGH",
        "fix_principle": "Review the business process and add appropriate guards, validations, and authorization checks.",
    },
    {
        "class": "SETTLEMENT_BYPASS",
        "severity": "HIGH",
        "condition": lambda g, s: (
            bool(_state_transitions(g))
            and not bool(_settlement_confirmations(g))
        ),
        "detail": _detail_settlement_bypass,
        "confidence": 0.65,
        "false_positive_risk": "HIGH",
        "fix_principle": (
            "Ensure settlement/payment confirmation is verified before "
            "marking an order or transaction as complete."
        ),
    },
    {
        "class": "FINANCIAL_ACTION_ORDERING",
        "severity": "HIGH",
        "condition": lambda g, s: (
            bool(_financial_actions(g))
            and not bool(_settlement_confirmations(g))
            and not _has_auth_check(g)
        ),
        "detail": _detail_financial_action_ordering,
        "confidence": 0.60,
        "false_positive_risk": "HIGH",
        "fix_principle": (
            "Verify that financial actions (transfers, withdrawals, etc.) "
            "are authorized and confirmed before execution."
        ),
    },
]

# Rules ordered roughly from most specific/confident to least, so that when
# match_rules de-duplicates overlapping low-confidence findings against a
# more specific one (see _is_subsumed_by), the more informative finding is
# always the one already in the result list.
_GENERIC_FALLBACK_CLASSES = {"LOGIC_FLAW"}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def match_rules(
    graph: Dict[str, Any],
    symbols: Dict[str, Any],
    source_bytes: bytes,
) -> List[Dict[str, Any]]:
    """
    Apply all registered rules to a single function's state graph and
    return every match.

    For each rule, the condition is evaluated against (graph, symbols); on
    a true result, the rule's detail function computes the precise line
    range, snippet, and description for that specific match. Rules that
    raise an exception (e.g. due to an unexpected graph shape) are logged
    and skipped rather than aborting the whole evaluation -- one bad rule
    or malformed graph should never prevent the rest of the rules from
    running. The generic LOGIC_FLAW catch-all is suppressed whenever a more
    specific rule already matched the same function, since it exists to
    cover gaps the specific rules miss, not to duplicate them.

    Args:
        graph: The state graph for a single function, as produced by
            fsa.graph_builder.build_graph() or analyzer.py's fallback.
        symbols: The financial entity symbol table for the file.
        source_bytes: The raw source code bytes of the file, for snippet
            extraction.

    Returns:
        A list of match dictionaries, each with class, line_start,
        line_end, snippet, description, fix_principle, and confidence.
        Returns an empty list if no rules match or if `graph` is falsy.
    """
    if not graph:
        return []

    matches: List[Dict[str, Any]] = []
    matched_specific_rule = False

    for rule in RULES:
        vuln_class = rule.get("class", "UNKNOWN")

        if vuln_class in _GENERIC_FALLBACK_CLASSES and matched_specific_rule:
            continue

        try:
            condition: Optional[Callable[[Dict[str, Any],
                                          Dict[str, Any]], bool]] = rule.get("condition")
            if condition is None or not condition(graph, symbols):
                continue
        except Exception as exc:
            logger.warning(
                "Error evaluating condition for rule %s: %s", vuln_class, exc)
            continue

        try:
            detail_fn: Optional[Callable] = rule.get("detail")
            if detail_fn is not None:
                line_start, line_end, snippet, description = detail_fn(
                    graph, symbols, source_bytes)
            else:
                line_start = graph.get("function_line", 1)
                line_end = graph.get("function_end_line", line_start)
                snippet = (graph.get("function_text") or "")[:MAX_SNIPPET_LEN]
                description = rule.get(
                    "description", "Vulnerability detected.")
        except Exception as exc:
            logger.warning(
                "Error building match details for rule %s; using function-level fallback: %s",
                vuln_class, exc,
            )
            line_start = graph.get("function_line", 1)
            line_end = graph.get("function_end_line", line_start)
            snippet = (graph.get("function_text") or "")[:MAX_SNIPPET_LEN]
            description = rule.get("description", "Vulnerability detected.")

        if line_end < line_start:
            line_end = line_start

        matches.append({
            "class": vuln_class,
            "line_start": line_start,
            "line_end": line_end,
            "snippet": (snippet or "")[:MAX_SNIPPET_LEN],
            "description": description,
            "fix_principle": rule.get("fix_principle", "Review and fix the logic."),
            "confidence": rule.get("confidence", 0.7),
        })

        if vuln_class not in _GENERIC_FALLBACK_CLASSES:
            matched_specific_rule = True

    return matches


def register_rule(rule: Dict[str, Any]) -> None:
    """
    Add a new rule to the global rule list at runtime.

    Intended for extensibility (e.g. adding Web3/Quant track rules without
    modifying this module's core logic). `rule` must at minimum provide
    "class" and "condition" keys; "detail", "severity", "confidence",
    "fix_principle", and "false_positive_risk" are optional but strongly
    recommended. Not safe to call concurrently with `match_rules` from
    multiple threads, since it mutates the shared RULES list in place;
    callers that register rules dynamically should do so during
    application startup, before any analysis begins.

    Args:
        rule: A rule dictionary following the same shape as the entries
            in RULES.
    """
    if "class" not in rule or "condition" not in rule:
        raise ValueError(
            "register_rule: rule must include at least 'class' and 'condition'")
    RULES.append(rule)
    logger.info("Registered new rule: %s", rule.get("class"))


def get_registered_classes() -> List[str]:
    """Return the vulnerability class names of all currently registered rules."""
    return [rule.get("class", "UNKNOWN") for rule in RULES]
