"""
OSE Auditor – Prompt Engineering Layer

This module contains the strict, paranoid system prompts that force the LLM
(Claude/GPT) to generate valid JSON patches from the Vulnerability Manifest
(Contract B).

The prompts are designed to:
1. Enforce JSON-only output.
2. Include few-shot examples to guide the model.
3. Insert the manifest context.
4. Inject security paranoia.
5. Be track-specific (Web2, Web3, Quant).

This module does NOT call the LLM, handle HTTP requests, validate output,
or contain business logic. It only builds prompt strings.

This module is CLOSED SOURCE / PROPRIETARY.
"""

import json
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger("ose.prompts")

# ---------------------------------------------------------------------------
# Few-Shot Examples (Web2 / Node.js)
# ---------------------------------------------------------------------------

EXAMPLE_INPUT_1: Dict[str, Any] = {
    "id": "FSA-BAUTH-001",
    "file_path": "src/controllers/payment.js",
    "line_start": 12,
    "line_end": 18,
    "vulnerability_class": "BROKEN_AUTH",
    "severity": "HIGH",
    "code_snippet": (
        "async function processPayment(amount, userId) {\n"
        "  const user = await User.findByPk(userId);\n"
        "  const charge = await stripe.charges.create({\n"
        "    amount, currency: 'usd', customer: user.stripeId\n"
        "  });\n"
        "  user.balance -= amount;\n"
        "  await user.save();\n"
        "}"
    ),
    "description": (
        "Function performs a financial state mutation (`user.balance`) "
        "without a preceding authentication or authorization check."
    ),
    "fix_principle": (
        "Add an authentication/authorization check before mutating financial state."
    ),
}

EXAMPLE_OUTPUT_1: Dict[str, Any] = {
    "finding_id": "FSA-BAUTH-001",
    "patch": (
        "async function processPayment(amount, userId, req) {\n"
        "  if (!req.session || !req.session.userId) {\n"
        "    throw new Error('Unauthorized: no active session');\n"
        "  }\n"
        "  if (req.session.userId !== userId) {\n"
        "    throw new Error('Forbidden: cannot process payment for another user');\n"
        "  }\n"
        "  const user = await User.findByPk(userId);\n"
        "  if (!user) throw new Error('User not found');\n"
        "  const charge = await stripe.charges.create({\n"
        "    amount, currency: 'usd', customer: user.stripeId\n"
        "  });\n"
        "  if (charge.status !== 'succeeded') {\n"
        "    throw new Error('Charge failed: ' + charge.failure_message);\n"
        "  }\n"
        "  user.balance -= amount;\n"
        "  await user.save();\n"
        "}"
    ),
    "explanation": (
        "Added session existence check and user-identity check before any "
        "financial operation. Also validates the Stripe charge result before "
        "decrementing the balance, preventing state mutation on a failed charge."
    ),
}

EXAMPLE_INPUT_2: Dict[str, Any] = {
    "id": "FSA-UNCHK-002",
    "file_path": "src/services/payout.js",
    "line_start": 20,
    "line_end": 25,
    "vulnerability_class": "UNCHECKED_EXTERNAL_CALL",
    "severity": "HIGH",
    "code_snippet": (
        "await flutterwave.transfer({ amount, recipient: user.bankAccount });\n"
        "user.balance -= amount;\n"
        "await user.save();"
    ),
    "description": (
        "External call `flutterwave.transfer` occurs before the dependent "
        "state mutation, with no visible check on its outcome. If the call "
        "fails, state may become inconsistent."
    ),
    "fix_principle": (
        "Check the external call's success/failure before mutating state, "
        "or perform the mutation atomically with the call and roll back on failure."
    ),
}

EXAMPLE_OUTPUT_2: Dict[str, Any] = {
    "finding_id": "FSA-UNCHK-002",
    "patch": (
        "const transferResult = await flutterwave.transfer({\n"
        "  amount,\n"
        "  recipient: user.bankAccount,\n"
        "});\n"
        "if (!transferResult || transferResult.status !== 'success') {\n"
        "  throw new Error(\n"
        "    'Flutterwave transfer failed: ' +\n"
        "    (transferResult && transferResult.message ? transferResult.message : 'unknown error')\n"
        "  );\n"
        "}\n"
        "user.balance -= amount;\n"
        "await user.save();"
    ),
    "explanation": (
        "Captured the transfer result and asserted success before decrementing "
        "the balance. If the transfer fails for any reason, an error is thrown "
        "and the balance mutation never executes, keeping state consistent."
    ),
}

EXAMPLE_INPUT_3: Dict[str, Any] = {
    "id": "FSA-DSPEND-003",
    "file_path": "src/controllers/withdraw.js",
    "line_start": 8,
    "line_end": 14,
    "vulnerability_class": "DOUBLE_SPEND",
    "severity": "CRITICAL",
    "code_snippet": (
        "const balance = await wallet.getBalance(user.id);\n"
        "if (balance < amount) throw new Error('Insufficient funds');\n"
        "await wallet.transfer(amount, user.bankAccount);\n"
        "await wallet.deductBalance(user.id, amount);"
    ),
    "description": (
        "Function awaits external call `wallet.transfer` and only afterwards "
        "updates `wallet.deductBalance`. A second concurrent request can read "
        "the same pre-update balance during the await window, allowing the "
        "same funds to be spent twice."
    ),
    "fix_principle": (
        "Use atomic operations or database-level locks to prevent concurrent "
        "state corruption."
    ),
}

EXAMPLE_OUTPUT_3: Dict[str, Any] = {
    "finding_id": "FSA-DSPEND-003",
    "patch": (
        "// Atomically deduct balance first; throws if insufficient or concurrent\n"
        "const deductResult = await wallet.atomicDeductBalance(user.id, amount);\n"
        "if (!deductResult.success) {\n"
        "  throw new Error(\n"
        "    deductResult.reason === 'insufficient'\n"
        "      ? 'Insufficient funds'\n"
        "      : 'Concurrent withdrawal detected; please retry'\n"
        "  );\n"
        "}\n"
        "try {\n"
        "  await wallet.transfer(amount, user.bankAccount);\n"
        "} catch (err) {\n"
        "  // Roll back the deducted balance on transfer failure\n"
        "  await wallet.creditBalance(user.id, amount);\n"
        "  throw new Error('Transfer failed; balance restored: ' + err.message);\n"
        "}"
    ),
    "explanation": (
        "Moved the balance deduction before the external transfer using an "
        "atomic database operation (compare-and-swap / optimistic lock). If the "
        "transfer fails, the balance is explicitly restored. This eliminates the "
        "race window where two concurrent requests could both pass the balance "
        "check on the original unmodified value."
    ),
}

# ---------------------------------------------------------------------------
# Few-Shot Examples (Web3 / Solidity)
# ---------------------------------------------------------------------------

EXAMPLE_INPUT_WEB3: Dict[str, Any] = {
    "id": "FSA-REENT-001",
    "file_path": "contracts/Vault.sol",
    "line_start": 22,
    "line_end": 28,
    "vulnerability_class": "REENTRANCY",
    "severity": "CRITICAL",
    "code_snippet": (
        "function withdraw(uint256 amount) external {\n"
        "    require(balances[msg.sender] >= amount, 'Insufficient balance');\n"
        "    (bool success, ) = msg.sender.call{value: amount}('');\n"
        "    require(success, 'Transfer failed');\n"
        "    balances[msg.sender] -= amount;\n"
        "}"
    ),
    "description": (
        "State update (`balances[msg.sender] -= amount`) occurs after the "
        "external call, enabling a reentrancy attack."
    ),
    "fix_principle": (
        "Update state before making external calls (checks-effects-interactions pattern)."
    ),
}

EXAMPLE_OUTPUT_WEB3: Dict[str, Any] = {
    "finding_id": "FSA-REENT-001",
    "patch": (
        "function withdraw(uint256 amount) external nonReentrant {\n"
        "    require(balances[msg.sender] >= amount, 'Insufficient balance');\n"
        "    // CEI: update state BEFORE external call\n"
        "    balances[msg.sender] -= amount;\n"
        "    (bool success, ) = msg.sender.call{value: amount}('');\n"
        "    require(success, 'Transfer failed');\n"
        "}"
    ),
    "explanation": (
        "Applied the checks-effects-interactions pattern: balance is decremented "
        "before the ETH transfer. Also added the `nonReentrant` modifier from "
        "OpenZeppelin ReentrancyGuard as a defence-in-depth measure."
    ),
}

# ---------------------------------------------------------------------------
# Few-Shot Examples (Quant / MQL/Python)
# ---------------------------------------------------------------------------

EXAMPLE_INPUT_QUANT: Dict[str, Any] = {
    "id": "FSA-SLIP-001",
    "file_path": "bots/scalper.py",
    "line_start": 45,
    "line_end": 50,
    "vulnerability_class": "SLIPPAGE_OMISSION",
    "severity": "HIGH",
    "code_snippet": (
        "def place_market_order(symbol, volume, direction):\n"
        "    order = broker.send_order(\n"
        "        symbol=symbol,\n"
        "        volume=volume,\n"
        "        type=direction,\n"
        "    )\n"
        "    return order"
    ),
    "description": (
        "Market order is placed without a slippage limit, exposing the "
        "account to unexpected fill prices during high volatility."
    ),
    "fix_principle": (
        "Define and enforce a maximum slippage parameter for all market orders."
    ),
}

EXAMPLE_OUTPUT_QUANT: Dict[str, Any] = {
    "finding_id": "FSA-SLIP-001",
    "patch": (
        "MAX_SLIPPAGE_POINTS = 5  # Adjust to strategy tolerance\n\n"
        "def place_market_order(symbol, volume, direction):\n"
        "    ask = broker.get_ask(symbol)\n"
        "    bid = broker.get_bid(symbol)\n"
        "    price = ask if direction == 'BUY' else bid\n"
        "    deviation = MAX_SLIPPAGE_POINTS\n"
        "    order = broker.send_order(\n"
        "        symbol=symbol,\n"
        "        volume=volume,\n"
        "        type=direction,\n"
        "        price=price,\n"
        "        deviation=deviation,\n"
        "    )\n"
        "    if not order or order.retcode != broker.TRADE_RETCODE_DONE:\n"
        "        raise RuntimeError(\n"
        "            f'Order rejected (retcode={getattr(order, \"retcode\", None)}): slippage exceeded?'\n"
        "        )\n"
        "    return order"
    ),
    "explanation": (
        "Added explicit price and deviation (slippage) parameters to the order "
        "request and validated the broker return code. Orders that fill beyond "
        "the allowed slippage window will now be rejected rather than silently "
        "executed at an adverse price."
    ),
}

# ---------------------------------------------------------------------------
# System Prompt Templates
# ---------------------------------------------------------------------------

WEB2_SYSTEM_PROMPT: str = """You are OSE Auditor, a security patch generation engine for Node.js backend code.

Your sole task is to generate secure, production-ready code patches for the vulnerabilities listed in the manifest provided at the end of this prompt.

### Security Mindset (Paranoia Mode)
- Review the code as if you are trying to break it, not fix it.
- Assume the code is dangerous until proven safe.
- Do not assume inputs are validated — check every boundary.
- Look for edge cases that could drain funds, bypass controls, or corrupt state.
- Question the order of operations — does validation happen BEFORE mutation?
- Pay special attention to `await` ordering and promise chains, where race conditions hide in plain sight.
- Treat every external API call as potentially unreliable; its result must always be checked.

### Output Rules (NON-NEGOTIABLE)
1. Output ONLY valid JSON. No markdown, no code blocks, no preamble, no commentary outside the JSON.
2. The top-level JSON object must have exactly one key: `"patches"` — an array of patch objects.
3. Each patch object must have exactly three keys: `"finding_id"`, `"patch"`, `"explanation"`.
4. `"finding_id"` must exactly match the `id` field of the corresponding finding in the manifest.
5. `"patch"` must be the exact replacement code string for the affected function or block.
6. `"explanation"` must be a plain-English string of at most 100 words describing what was changed and why.
7. Preserve the original code's indentation style and variable naming conventions.
8. Do NOT change functionality beyond what is required to fix the reported vulnerability.
9. Prefer minimal changes — do not refactor the entire function; fix only the flaw.
10. If the fix is genuinely unclear from the available snippet, set `"patch"` to `""` and explain why in `"explanation"`.

### Example 1 – BROKEN_AUTH
Input finding:
{example_input_1}

Expected output:
{example_output_1}

### Example 2 – UNCHECKED_EXTERNAL_CALL
Input finding:
{example_input_2}

Expected output:
{example_output_2}

### Example 3 – DOUBLE_SPEND
Input finding:
{example_input_3}

Expected output:
{example_output_3}

### Manifest to process:
{manifest_json}"""

WEB3_SYSTEM_PROMPT: str = """You are OSE Auditor, a security patch generation engine for Solidity smart contracts.

Your sole task is to generate secure, production-ready Solidity patches for the vulnerabilities listed in the manifest provided at the end of this prompt.

### Security Mindset (Paranoia Mode)
- Review the code as if you are trying to drain the contract of all ETH/tokens.
- Look for reentrancy: any `msg.sender.call` / `.transfer` / `.send` before a state update is a reentrancy vector.
- Check flash-loan safety: price oracles that can be manipulated in a single transaction are exploitable.
- Verify access controls: every state-changing function must enforce `onlyOwner` or an equivalent role guard.
- Watch for arithmetic issues: unchecked integer arithmetic can overflow or underflow.
- Check `tx.origin` vs `msg.sender`: `tx.origin` authorization is phishable.
- Follow the checks-effects-interactions pattern strictly.

### Output Rules (NON-NEGOTIABLE)
1. Output ONLY valid JSON. No markdown, no code blocks, no text outside the JSON.
2. The top-level JSON object must have exactly one key: `"patches"` — an array of patch objects.
3. Each patch object must have exactly three keys: `"finding_id"`, `"patch"`, `"explanation"`.
4. `"finding_id"` must exactly match the `id` field of the corresponding finding.
5. `"patch"` must be the corrected Solidity code string.
6. `"explanation"` must be at most 100 words of plain English.
7. Use OpenZeppelin libraries (ReentrancyGuard, Ownable, SafeMath / Solidity 0.8 checked arithmetic) where appropriate.
8. Preserve original variable names and indentation.
9. If the fix requires contract-level changes (e.g., adding `nonReentrant`), include only the affected function(s) in the patch and note the dependency in `explanation`.

### Example – REENTRANCY
Input finding:
{example_input_web3}

Expected output:
{example_output_web3}

### Manifest to process:
{manifest_json}"""

QUANT_SYSTEM_PROMPT: str = """You are OSE Auditor, a security patch generation engine for algorithmic trading bots (Forex / Crypto / MQL4 / MQL5 / Python).

Your sole task is to generate secure, production-ready patches for the trading-logic vulnerabilities listed in the manifest at the end of this prompt.

### Security Mindset (Paranoia Mode)
- Review the code as if you are trying to liquidate the trader's account.
- Check for slippage omissions: every market order must specify a maximum deviation/slippage.
- Verify risk boundaries: stop-loss, take-profit, and position-sizing limits must be explicit and enforced.
- Look for race conditions in multi-threaded or async order execution.
- Check spread safety: opening a trade without a spread check can cause fills at adverse prices during news events.
- Validate broker return codes: every `send_order` / `OrderSend` result must be checked for errors.
- Watch for unbounded leverage or lot-size inputs derived from user-controlled values.

### Output Rules (NON-NEGOTIABLE)
1. Output ONLY valid JSON. No markdown, no code blocks, no text outside the JSON.
2. The top-level JSON object must have exactly one key: `"patches"` — an array of patch objects.
3. Each patch object must have exactly three keys: `"finding_id"`, `"patch"`, `"explanation"`.
4. `"finding_id"` must exactly match the `id` field of the corresponding finding.
5. `"patch"` must be the corrected code string in the same language as the snippet (Python, MQL4, or MQL5).
6. `"explanation"` must be at most 100 words of plain English.
7. Preserve variable names and indentation style.
8. Do not change trading logic beyond the reported vulnerability.

### Example – SLIPPAGE_OMISSION
Input finding:
{example_input_quant}

Expected output:
{example_output_quant}

### Manifest to process:
{manifest_json}"""

# ---------------------------------------------------------------------------
# Track → template mapping
# ---------------------------------------------------------------------------

_TRACK_TEMPLATES: Dict[str, str] = {
    "web2": WEB2_SYSTEM_PROMPT,
    "web3": WEB3_SYSTEM_PROMPT,
    "quant": QUANT_SYSTEM_PROMPT,
}

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_prompt(manifest: Dict[str, Any], track: str = "web2") -> str:
    """
    Build a complete LLM prompt from a Vulnerability Manifest (Contract B).

    Selects the appropriate track-specific system prompt, injects the
    few-shot examples, and embeds the serialised manifest so the LLM
    has full context to generate patches.

    Args:
        manifest: A validated Contract B payload (dict with a ``findings``
            list).  The caller is responsible for ensuring the manifest
            is valid before passing it here.
        track: The analysis track.  One of ``"web2"`` (default),
            ``"web3"``, or ``"quant"``.  Unknown values fall back to
            ``"web2"`` with a warning.

    Returns:
        A formatted prompt string ready to be sent to the LLM as the
        user message (the string already includes a system-prompt
        preamble, few-shot examples, and the manifest).
    """
    normalised_track = track.lower().strip()
    if normalised_track not in _TRACK_TEMPLATES:
        logger.warning(
            "Unknown track %r; falling back to 'web2'.", track
        )
        normalised_track = "web2"

    template = _TRACK_TEMPLATES[normalised_track]

    manifest_json = json.dumps(manifest, indent=2, ensure_ascii=False)

    # Build the format kwargs depending on the track so that templates that
    # reference track-specific example placeholders always receive them.
    fmt_kwargs: Dict[str, str] = {"manifest_json": manifest_json}

    if normalised_track == "web2":
        fmt_kwargs.update(
            {
                "example_input_1": json.dumps(EXAMPLE_INPUT_1, indent=2),
                "example_output_1": json.dumps(EXAMPLE_OUTPUT_1, indent=2),
                "example_input_2": json.dumps(EXAMPLE_INPUT_2, indent=2),
                "example_output_2": json.dumps(EXAMPLE_OUTPUT_2, indent=2),
                "example_input_3": json.dumps(EXAMPLE_INPUT_3, indent=2),
                "example_output_3": json.dumps(EXAMPLE_OUTPUT_3, indent=2),
            }
        )
    elif normalised_track == "web3":
        fmt_kwargs.update(
            {
                "example_input_web3": json.dumps(EXAMPLE_INPUT_WEB3, indent=2),
                "example_output_web3": json.dumps(EXAMPLE_OUTPUT_WEB3, indent=2),
            }
        )
    elif normalised_track == "quant":
        fmt_kwargs.update(
            {
                "example_input_quant": json.dumps(EXAMPLE_INPUT_QUANT, indent=2),
                "example_output_quant": json.dumps(EXAMPLE_OUTPUT_QUANT, indent=2),
            }
        )

    try:
        prompt = template.format(**fmt_kwargs)
    except KeyError as exc:
        # Should never happen if templates and fmt_kwargs stay in sync, but
        # log and re-raise rather than silently producing a broken prompt.
        logger.error(
            "Prompt template for track %r is missing placeholder %s.",
            normalised_track,
            exc,
        )
        raise

    logger.debug(
        "Built prompt for track=%r, %d findings, prompt_length=%d chars.",
        normalised_track,
        len(manifest.get("findings", [])),
        len(prompt),
    )
    return prompt


def build_batch_prompt(manifest: Dict[str, Any], track: str = "web2") -> str:
    """
    Build a prompt that requests batch patches for all findings in the manifest.

    This is a convenience alias for :func:`build_prompt`; the batch
    structure is already embedded in the prompt template (all findings
    from the manifest are injected at once, and the model is instructed
    to return a single ``{"patches": [...]}`` array).

    Args:
        manifest: A validated Contract B payload.
        track: The analysis track (``"web2"``, ``"web3"``, or ``"quant"``).

    Returns:
        A formatted prompt string ready to be sent to the LLM.
    """
    return build_prompt(manifest, track)


def get_system_prompt_template(track: str = "web2") -> str:
    """
    Return the raw (unformatted) system prompt template for a given track.

    Intended for testing, debugging, and offline inspection.  The returned
    string still contains ``{placeholder}`` tokens that would normally be
    filled by :func:`build_prompt`.

    Args:
        track: One of ``"web2"`` (default), ``"web3"``, or ``"quant"``.
            Unknown values fall back to ``"web2"`` with a warning.

    Returns:
        The raw prompt template string for the requested track.
    """
    normalised_track = track.lower().strip()
    if normalised_track not in _TRACK_TEMPLATES:
        logger.warning(
            "get_system_prompt_template: unknown track %r; returning 'web2' template.",
            track,
        )
        normalised_track = "web2"
    return _TRACK_TEMPLATES[normalised_track]


def get_examples() -> Dict[str, Any]:
    """
    Return all registered few-shot examples as a single dictionary.

    Intended for testing, debugging, and prompt-quality evaluation.

    Returns:
        A dict mapping descriptive example keys to their input/output
        dicts, covering all currently supported tracks (Web2, Web3, Quant).
    """
    return {
        # Web2 examples
        "web2_example_input_1": EXAMPLE_INPUT_1,
        "web2_example_output_1": EXAMPLE_OUTPUT_1,
        "web2_example_input_2": EXAMPLE_INPUT_2,
        "web2_example_output_2": EXAMPLE_OUTPUT_2,
        "web2_example_input_3": EXAMPLE_INPUT_3,
        "web2_example_output_3": EXAMPLE_OUTPUT_3,
        # Web3 examples
        "web3_example_input": EXAMPLE_INPUT_WEB3,
        "web3_example_output": EXAMPLE_OUTPUT_WEB3,
        # Quant examples
        "quant_example_input": EXAMPLE_INPUT_QUANT,
        "quant_example_output": EXAMPLE_OUTPUT_QUANT,
    }


def get_supported_tracks() -> list:
    """
    Return the list of supported analysis track identifiers.

    Returns:
        A list of track name strings currently accepted by
        :func:`build_prompt`.
    """
    return list(_TRACK_TEMPLATES.keys())
