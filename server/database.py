"""
OSE Auditor – Database Access Layer

This module manages all database operations for the OSE Server:
- User management (get/create users)
- Credit management (get, deduct, reset)
- Payment processing (add_credits)
- Invite tokens (validate, mark used)
- Audit history logging

Uses asyncpg for async PostgreSQL access with connection pooling.

This module is CLOSED SOURCE / PROPRIETARY.
"""

import logging
import os
from typing import Any, Dict, List, Optional

import asyncpg

logger = logging.getLogger("ose.database")

FREE_CREDITS_PER_PERIOD = 5


# ---------------------------------------------------------------------------
# Custom Exceptions
# ---------------------------------------------------------------------------


class DatabaseError(Exception):
    """Raised when a database operation fails."""
    pass


class UserNotFoundError(DatabaseError):
    """Raised when a user does not exist."""
    pass


class InsufficientCreditsError(DatabaseError):
    """Raised when a user has insufficient credits."""
    pass


class InvalidTokenError(DatabaseError):
    """Raised when an invite token is invalid."""
    pass


# ---------------------------------------------------------------------------
# Pool Management
# ---------------------------------------------------------------------------

_pool: Optional[asyncpg.Pool] = None


async def get_pool() -> asyncpg.Pool:
    """Return the global connection pool, creating it if necessary."""
    global _pool
    if _pool is None:
        await init_pool()
    return _pool


async def init_pool() -> None:
    """Initialize the async connection pool using DATABASE_URL from environment.

    Raises:
        DatabaseError: If DATABASE_URL is not set or the pool cannot be created.
    """
    global _pool
    if _pool is not None:
        return

    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise DatabaseError("DATABASE_URL environment variable not set")

    try:
        _pool = await asyncpg.create_pool(
            database_url,
            min_size=1,
            max_size=5,
            max_inactive_connection_lifetime=300,
            statement_cache_size=0,   # required when connecting through Neon's pooler
        )
        logger.info("Database connection pool initialized")
    except Exception as exc:
        raise DatabaseError(
            f"Failed to create connection pool: {exc}") from exc


async def close_pool() -> None:
    """Close the global connection pool gracefully."""
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None
        logger.info("Database connection pool closed")


# ---------------------------------------------------------------------------
# Schema Initialization
# ---------------------------------------------------------------------------


async def init_schema() -> None:
    """Create all required tables if they do not already exist.

    Should be called once at server startup before handling any requests.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS ose_usage_nodes (
                user_id VARCHAR(255) PRIMARY KEY,
                credit_tier VARCHAR(50) DEFAULT 'free',
                requests_this_period INT DEFAULT 0,
                period_start_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                flutterwave_ref VARCHAR(255) NULL,
                credit_balance INT DEFAULT 0
            )
        """)
        # Defensive migration for deployments where the table already
        # existed before credit_balance was introduced.
        await conn.execute("""
            ALTER TABLE ose_usage_nodes
                ADD COLUMN IF NOT EXISTS credit_balance INT DEFAULT 0
        """)
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS invite_tokens (
                token VARCHAR(255) PRIMARY KEY,
                issuer_id VARCHAR(255) NOT NULL,
                used BOOLEAN DEFAULT FALSE,
                expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            )
        """)
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_history (
                id SERIAL PRIMARY KEY,
                user_id VARCHAR(255) NOT NULL,
                project_hash VARCHAR(64) NOT NULL,
                track VARCHAR(50) DEFAULT 'web2',
                findings_count INT DEFAULT 0,
                credits_used INT DEFAULT 1,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            )
        """)
    logger.info("Database schema initialized")


# ---------------------------------------------------------------------------
# User Management
# ---------------------------------------------------------------------------


async def get_user(user_id: str) -> Optional[Dict[str, Any]]:
    """Fetch a user record by user_id.

    Args:
        user_id: The unique user identifier.

    Returns:
        A dict of the user's row, or None if no such user exists.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM ose_usage_nodes WHERE user_id = $1",
            user_id,
        )
        return dict(row) if row else None


async def create_user(user_id: str) -> Dict[str, Any]:
    """Create a new user with free tier defaults.

    Args:
        user_id: The unique user identifier.

    Returns:
        A dict of the newly created user row.

    Raises:
        DatabaseError: If the insert fails (e.g. duplicate key).
    """
    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO ose_usage_nodes
                    (user_id, credit_tier, requests_this_period, period_start_time)
                VALUES ($1, 'free', 0, CURRENT_TIMESTAMP)
                RETURNING *
                """,
                user_id,
            )
            logger.info("Created new user: %s", user_id)
            return dict(row)
    except asyncpg.UniqueViolationError:
        # Race condition: another request created the user first; just fetch it.
        user = await get_user(user_id)
        if user:
            return user
        raise DatabaseError(f"Failed to create user {user_id!r}")
    except Exception as exc:
        raise DatabaseError(
            f"create_user failed for {user_id!r}: {exc}") from exc


async def get_or_create_user(user_id: str) -> Dict[str, Any]:
    """Return an existing user or create a new one.

    Args:
        user_id: The unique user identifier.

    Returns:
        The user record as a dict.
    """
    user = await get_user(user_id)
    if user is not None:
        return user
    return await create_user(user_id)


# ---------------------------------------------------------------------------
# Credit Management
# ---------------------------------------------------------------------------


async def reset_period_if_expired(user_id: str) -> bool:
    """Reset the credit period if 7 days have elapsed since period_start_time.

    Args:
        user_id: The unique user identifier.

    Returns:
        True if a reset was performed, False otherwise.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            UPDATE ose_usage_nodes
               SET requests_this_period = 0,
                   period_start_time    = CURRENT_TIMESTAMP
             WHERE user_id = $1
               AND period_start_time < CURRENT_TIMESTAMP - INTERVAL '7 days'
            RETURNING user_id
            """,
            user_id,
        )
        if row is not None:
            logger.info("Credit period reset for user: %s", user_id)
            return True
        return False


async def get_remaining_credits(user_id: str) -> int:
    """Return remaining credits available to the user right now.

    Free-tier users draw from a rolling weekly pool: this returns
    max(0, 5 - requests_this_period), after resetting the period if it
    has expired.

    Premium users (i.e. anyone who has purchased a credit pack via
    add_credits()) draw from their purchased credit_balance instead --
    premium is NOT unlimited. When credit_balance reaches 0, the user
    must purchase another pack; they do not fall back to the free pool.

    Args:
        user_id: The unique user identifier.

    Returns:
        Remaining credits as a non-negative int.
    """
    user = await get_user(user_id)
    if not user:
        return 0

    if user.get("credit_tier") == "premium":
        return max(0, user.get("credit_balance", 0) or 0)

    # Reset if period expired, then re-fetch for accurate count.
    reset = await reset_period_if_expired(user_id)
    if reset:
        user = await get_user(user_id)

    used = user.get("requests_this_period", 0)
    return max(0, FREE_CREDITS_PER_PERIOD - used)


async def get_credits(user_id: str) -> int:
    """Alias for get_remaining_credits; satisfies the spec's public surface.

    Args:
        user_id: The unique user identifier.

    Returns:
        Remaining credits as a non-negative int.
    """
    return await get_remaining_credits(user_id)


async def get_tier(user_id: str) -> str:
    """Return the user's credit tier.

    Args:
        user_id: The unique user identifier.

    Returns:
        'free' or 'premium'. Defaults to 'free' if user not found.
    """
    user = await get_user(user_id)
    if not user:
        return "free"
    return user.get("credit_tier", "free")


async def deduct_credit(user_id: str) -> bool:
    """Deduct one credit from the user, regardless of tier.

    Free-tier users are deducted against the rolling weekly pool (guarded
    by requests_this_period < 5). Premium users are deducted against their
    purchased credit_balance (guarded by credit_balance > 0). Both guards
    are enforced server-side in the UPDATE statement to prevent
    double-charging under concurrent requests.

    Args:
        user_id: The unique user identifier.

    Returns:
        True if a credit was successfully deducted, False if the user has
        no credits remaining in their applicable pool.
    """
    user = await get_user(user_id)
    if not user:
        return False

    pool = await get_pool()

    if user.get("credit_tier") == "premium":
        async with pool.acquire() as conn:
            result = await conn.execute(
                """
                UPDATE ose_usage_nodes
                   SET credit_balance = credit_balance - 1
                 WHERE user_id = $1
                   AND credit_tier = 'premium'
                   AND credit_balance > 0
                """,
                user_id,
            )
            success = result == "UPDATE 1"
            if success:
                logger.info(
                    "Deducted 1 credit (balance) for premium user: %s", user_id)
            else:
                logger.warning(
                    "Credit deduction failed (balance exhausted) for user: %s", user_id)
            return success

    # Free tier: reset expired period first so the guard stays accurate.
    await reset_period_if_expired(user_id)

    remaining = await get_remaining_credits(user_id)
    if remaining <= 0:
        logger.warning("No credits remaining for user: %s", user_id)
        return False

    async with pool.acquire() as conn:
        result = await conn.execute(
            """
            UPDATE ose_usage_nodes
               SET requests_this_period = requests_this_period + 1
             WHERE user_id = $1
               AND credit_tier = 'free'
               AND requests_this_period < $2
            """,
            user_id,
            FREE_CREDITS_PER_PERIOD,
        )
        success = result == "UPDATE 1"
        if success:
            logger.info("Deducted 1 credit (free pool) for user: %s", user_id)
        else:
            logger.warning(
                "Credit deduction failed (guard hit) for user: %s", user_id)
        return success


# ---------------------------------------------------------------------------
# Payment / Tier Management
# ---------------------------------------------------------------------------


async def add_credits(user_id: str, credits: int, flutterwave_ref: str) -> bool:
    """Add purchased credits to a user's balance after a successful payment.

    Promotes the user to the 'premium' tier (premium users draw from
    credit_balance via deduct_credit/get_remaining_credits instead of the
    free weekly pool -- see those functions) and increments their balance
    by `credits`. Once a user has purchased credits, they remain on the
    premium tier permanently; they do not fall back to the free pool when
    credit_balance reaches 0, they top up by purchasing another pack.

    Creates the user row first if it doesn't exist yet (e.g. a webhook can
    arrive for a user_id that hasn't made an audit request before).

    Args:
        user_id: The unique user identifier.
        credits: Number of credits to add, from billing.get_pack_credits().
        flutterwave_ref: The Flutterwave transaction reference string.

    Returns:
        True if the update affected exactly one row, False otherwise.
    """
    await get_or_create_user(user_id)

    pool = await get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute(
            """
            UPDATE ose_usage_nodes
               SET credit_tier     = 'premium',
                   credit_balance  = credit_balance + $2,
                   flutterwave_ref = $3
             WHERE user_id = $1
            """,
            user_id,
            credits,
            flutterwave_ref,
        )
        success = result == "UPDATE 1"
        if success:
            logger.info(
                "Added %d credits for user %s (ref: %s)",
                credits, user_id, flutterwave_ref,
            )
        else:
            logger.warning(
                "add_credits: no row updated for user_id=%s", user_id)
        return success


async def update_tier(user_id: str, tier: str) -> bool:
    """Set the user's credit tier to 'free' or 'premium'.

    Args:
        user_id: The unique user identifier.
        tier: Must be 'free' or 'premium'.

    Returns:
        True if the update affected exactly one row, False otherwise.

    Raises:
        ValueError: If `tier` is not one of the accepted values.
    """
    if tier not in ("free", "premium"):
        raise ValueError(f"Invalid tier {tier!r}; must be 'free' or 'premium'")

    pool = await get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute(
            "UPDATE ose_usage_nodes SET credit_tier = $2 WHERE user_id = $1",
            user_id,
            tier,
        )
        success = result == "UPDATE 1"
        if success:
            logger.info("Tier updated to %r for user: %s", tier, user_id)
        else:
            logger.warning(
                "update_tier: no row updated for user_id=%s", user_id)
        return success


# ---------------------------------------------------------------------------
# Invite Token Management (v1.1)
# ---------------------------------------------------------------------------


async def validate_invite_token(token: str) -> Optional[Dict[str, Any]]:
    """Check whether an invite token is valid (exists, unused, not expired).

    Args:
        token: The invite token string.

    Returns:
        A dict of the token row if valid, or None if invalid/not found.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT * FROM invite_tokens
             WHERE token = $1
               AND used = FALSE
               AND expires_at > CURRENT_TIMESTAMP
            """,
            token,
        )
        return dict(row) if row else None


async def mark_token_used(token: str) -> bool:
    """Mark an invite token as used.

    Args:
        token: The invite token string.

    Returns:
        True if the token was successfully marked used, False otherwise.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute(
            "UPDATE invite_tokens SET used = TRUE WHERE token = $1 AND used = FALSE",
            token,
        )
        success = result == "UPDATE 1"
        if success:
            logger.info("Invite token marked as used: %s", token)
        else:
            logger.warning(
                "mark_token_used: token not found or already used: %s", token)
        return success


# ---------------------------------------------------------------------------
# Audit History (v1.1)
# ---------------------------------------------------------------------------


async def log_audit(
    user_id: str,
    project_hash: str,
    track: str = "web2",
    findings_count: int = 0,
    credits_used: int = 1,
) -> bool:
    """Append an audit event to the audit_history table.

    Args:
        user_id: The unique user identifier.
        project_hash: SHA-256 hex digest of the audited project.
        track: The audit track (e.g. 'web2', 'web3'). Defaults to 'web2'.
        findings_count: Number of findings produced by the audit.
        credits_used: Number of credits consumed (usually 1).

    Returns:
        True on success, False if the insert failed.
    """
    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO audit_history
                    (user_id, project_hash, track, findings_count, credits_used)
                VALUES ($1, $2, $3, $4, $5)
                """,
                user_id,
                project_hash,
                track,
                findings_count,
                credits_used,
            )
        logger.info(
            "Audit logged for user=%s project=%s findings=%d",
            user_id,
            project_hash,
            findings_count,
        )
        return True
    except Exception as exc:
        logger.error("log_audit failed for user=%s: %s", user_id, exc)
        return False
