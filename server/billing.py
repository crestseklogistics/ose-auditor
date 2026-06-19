"""
OSE Auditor – Billing and Payment Logic

This module handles credit pack definitions, credit calculation,
free tier logic, payment link generation, and webhook payload parsing.

It does NOT handle HTTP requests – that's main.py's job.
It does NOT talk directly to the database – that's database.py's job.
It does NOT call the LLM – that's main.py's job.
It does NOT build prompts – that's prompts.py's job.

This module is CLOSED SOURCE / PROPRIETARY.
"""

import logging
import os
from typing import Any, Dict, Optional

logger = logging.getLogger("ose.billing")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Free tier configuration
FREE_CREDITS_PER_PERIOD = 5
FREE_PERIOD_DAYS = 7

# Credit packs
CREDIT_PACKS: Dict[str, Dict[str, Any]] = {
    "starter": {
        "price_usd": 5.00,
        "credits": 50,
        "description": "Starter Pack – 50 credits",
        "id": "starter",
    },
    "pro_hacker": {
        "price_usd": 25.00,
        "credits": 300,
        "description": "Pro Hacker Pack – 300 credits",
        "id": "pro_hacker",
    },
    "enterprise": {
        "price_usd": 100.00,
        "credits": 1500,
        "description": "Enterprise Node – 1500 credits",
        "id": "enterprise",
    },
}


# ---------------------------------------------------------------------------
# Credit Pack Functions
# ---------------------------------------------------------------------------

def get_credit_pack(pack_name: str) -> Optional[Dict[str, Any]]:
    """Return the credit pack definition for `pack_name`, or None if not found.

    Args:
        pack_name: The pack identifier (e.g. "starter").

    Returns:
        A dict with keys "price_usd", "credits", "description", "id", or
        None if `pack_name` does not match a known pack.
    """
    return CREDIT_PACKS.get(pack_name)


def get_all_credit_packs() -> Dict[str, Any]:
    """Return all credit pack definitions.

    Returns:
        A mapping of pack name to its pack definition dict.
    """
    return CREDIT_PACKS


def get_free_credits_per_period() -> int:
    """Return the number of free credits granted per free-tier period.

    Returns:
        The configured FREE_CREDITS_PER_PERIOD value.
    """
    return FREE_CREDITS_PER_PERIOD


def get_free_period_days() -> int:
    """Return the number of days in a free credit period.

    Returns:
        The configured FREE_PERIOD_DAYS value.
    """
    return FREE_PERIOD_DAYS


def get_pack_credits(pack_name: str) -> int:
    """Return the number of credits granted by a given pack.

    Args:
        pack_name: The pack identifier.

    Returns:
        The pack's credit count, or 0 if the pack does not exist.
    """
    pack = get_credit_pack(pack_name)
    return pack["credits"] if pack else 0


def get_pack_price(pack_name: str) -> float:
    """Return the USD price of a given pack.

    Args:
        pack_name: The pack identifier.

    Returns:
        The pack's price in USD, or 0.0 if the pack does not exist.
    """
    pack = get_credit_pack(pack_name)
    return pack["price_usd"] if pack else 0.0


def is_valid_pack(pack_name: str) -> bool:
    """Return True if `pack_name` matches a known credit pack.

    Args:
        pack_name: The pack identifier to check.

    Returns:
        True if the pack exists in CREDIT_PACKS, False otherwise.
    """
    return pack_name in CREDIT_PACKS


# ---------------------------------------------------------------------------
# Checkout URL Generation
# ---------------------------------------------------------------------------

# Payment links per pack (direct Flutterwave URLs)
PACK_CHECKOUT_URLS = {
    "starter": "https://flutterwave.com/pay/k4vnhabz2rua",
    "pro_hacker": "https://flutterwave.com/pay/0uyg1qynjtnf",
    "enterprise": "https://flutterwave.com/pay/sidx1mpgltvx",
}


def generate_checkout_url(user_id: str, pack_name: str) -> str:
    """
    Generate the Flutterwave checkout URL for a user and credit pack.

    Args:
        user_id: The user's unique identifier.
        pack_name: The name of the credit pack (e.g., "starter").

    Returns:
        A fully qualified URL to the Flutterwave payment page, with
        `user_id` as a query parameter.

    Raises:
        ValueError: If `pack_name` is not a valid pack.
    """
    base = PACK_CHECKOUT_URLS.get(pack_name)
    if not base:
        logger.error("Unknown pack_name=%r for user=%s", pack_name, user_id)
        raise ValueError(f"Unknown pack: {pack_name}")
    return f"{base}?user_id={user_id}"

# ---------------------------------------------------------------------------
# Webhook Payload Parsing
# ---------------------------------------------------------------------------


def parse_flutterwave_webhook(payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Parse a Flutterwave webhook payload for OSE payments.

    This function is called by the Crestsek backend when it receives a
    Flutterwave webhook. It detects OSE payments by checking the `tx_ref`
    prefix (`ose_`), validates the payment, and returns structured data
    for further processing (e.g., updating the user's tier via
    database.set_premium()).

    Expected tx_ref format: "ose_{user_id}_{pack_name}"
    (e.g., "ose_usr_abc123_starter"). Since user IDs may themselves
    contain underscores, the pack name is taken from the *last* segment
    and the user_id is reconstructed from everything in between.

    Args:
        payload: The raw JSON payload from Flutterwave. Expected keys
            include "tx_ref", "status", "amount", "currency", and
            "transaction_id".

    Returns:
        None if the payload is not an OSE payment (i.e. `tx_ref` does
        not start with "ose_"). Otherwise, a dict with the following
        keys:
            - "valid": bool
            - "user_id": str
            - "pack": str (only present if a pack_name could be parsed)
            - "credits": int (only present when valid)
            - "status": str
            - "tx_ref": str
            - "amount": float
            - "currency": str
            - "transaction_id": str
            - "message": str (present when valid is False)
    """
    tx_ref = payload.get("tx_ref") or ""
    tx_status = payload.get("status") or ""
    currency = payload.get("currency", "USD")
    transaction_id = payload.get("transaction_id", "")

    raw_amount = payload.get("amount", 0)
    try:
        amount = float(raw_amount)
    except (TypeError, ValueError):
        logger.warning("Invalid amount in webhook payload: %r", raw_amount)
        amount = 0.0

    # Check if this is an OSE payment at all.
    if not tx_ref.startswith("ose_"):
        return None

    # Parse tx_ref: "ose_{user_id}_{pack_name}". Pack names are matched
    # against the known CREDIT_PACKS keys by suffix (longest first) rather
    # than by naively taking the last underscore-delimited segment, because
    # pack names can themselves contain underscores (e.g. "pro_hacker").
    # A naive last-segment split would parse "ose_usr_xyz_pro_hacker" as
    # pack="hacker" (unrecognized) / user_id="usr_xyz_pro", silently
    # dropping the purchased credits.
    remainder = tx_ref[len("ose_"):]
    if not remainder:
        logger.warning("Invalid tx_ref format: %s", tx_ref)
        return {
            "valid": False,
            "message": f"Invalid tx_ref format: {tx_ref}",
            "tx_ref": tx_ref,
        }

    pack_name: Optional[str] = None
    user_id: Optional[str] = None
    for candidate in sorted(CREDIT_PACKS, key=len, reverse=True):
        suffix = f"_{candidate}"
        if remainder.endswith(suffix) and len(remainder) > len(suffix):
            user_id = remainder[: -len(suffix)]
            pack_name = candidate
            break

    if pack_name is None:
        # No known pack matched (e.g. a genuinely unrecognized pack name).
        # Fall back to the last underscore segment purely so the error
        # message can still report *which* unrecognized pack was given.
        parts = remainder.split("_")
        if len(parts) < 2:
            logger.warning("Invalid tx_ref format: %s", tx_ref)
            return {
                "valid": False,
                "message": f"Invalid tx_ref format: {tx_ref}",
                "tx_ref": tx_ref,
            }
        pack_name = parts[-1]
        user_id = "_".join(parts[:-1])

    if not user_id:
        logger.warning("Invalid tx_ref format (empty user_id): %s", tx_ref)
        return {
            "valid": False,
            "message": f"Invalid tx_ref format: {tx_ref}",
            "tx_ref": tx_ref,
        }

    # Verify the pack exists.
    pack = get_credit_pack(pack_name)
    if not pack:
        logger.warning("Unknown pack in webhook: %s", pack_name)
        return {
            "valid": False,
            "message": f"Unknown pack: {pack_name}",
            "user_id": user_id,
            "tx_ref": tx_ref,
        }

    # Verify payment status.
    if tx_status.lower() != "successful":
        logger.warning(
            "Payment not successful for tx_ref=%s: status=%s", tx_ref, tx_status
        )
        return {
            "valid": False,
            "message": f"Payment not successful: {tx_status}",
            "user_id": user_id,
            "pack": pack_name,
            "status": tx_status,
            "tx_ref": tx_ref,
        }

    # Verify the amount matches the pack price (with small tolerance for
    # floating point / currency rounding). A mismatch is logged but does
    # not block processing, since Flutterwave is the source of truth for
    # whether money was actually received.
    expected_amount = pack["price_usd"]
    if abs(amount - expected_amount) > 0.01:
        logger.warning(
            "Payment amount mismatch for tx_ref=%s: expected %.2f, got %.2f",
            tx_ref, expected_amount, amount,
        )

    logger.info(
        "OSE payment verified: user=%s pack=%s credits=%d amount=%.2f",
        user_id, pack_name, pack["credits"], amount,
    )

    return {
        "valid": True,
        "user_id": user_id,
        "pack": pack_name,
        "credits": pack["credits"],
        "status": tx_status,
        "tx_ref": tx_ref,
        "amount": amount,
        "currency": currency,
        "transaction_id": transaction_id,
    }


# ---------------------------------------------------------------------------
# Credit Calculation Helpers
# ---------------------------------------------------------------------------

def calculate_credits_remaining(free_used: int, tier: str = "free") -> int:
    """
    Calculate remaining credits for a user.

    Args:
        free_used: Number of free credits used in the current period.
        tier: 'free' or 'premium'. Defaults to 'free'.

    Returns:
        -1 for premium (unlimited), or
        max(0, FREE_CREDITS_PER_PERIOD - free_used) for free tier.
    """
    if tier == "premium":
        return -1
    return max(0, FREE_CREDITS_PER_PERIOD - free_used)


def is_premium(tier: str) -> bool:
    """Return True if `tier` is the premium tier.

    Args:
        tier: The tier string to check ('free' or 'premium').

    Returns:
        True if tier == 'premium', False otherwise.
    """
    return tier == "premium"


def has_credits(remaining: int) -> bool:
    """Return True if a user has credits available to spend.

    Args:
        remaining: The remaining credit count (-1 indicates unlimited).

    Returns:
        True if `remaining` is -1 (unlimited/premium) or greater than 0.
    """
    return remaining == -1 or remaining > 0


def credits_available_for_audit(remaining: int) -> int:
    """
    Return the number of credits available for a single audit.

    Args:
        remaining: The remaining credit count (-1 indicates unlimited).

    Returns:
        1 if `remaining` is -1 (premium, allows the audit to proceed),
        otherwise the raw `remaining` count.
    """
    if remaining == -1:
        return 1
    return remaining
