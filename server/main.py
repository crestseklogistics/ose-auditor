"""
OSE Auditor – FastAPI Entry Point

This is the cloud server's main application. It receives vulnerability
manifests (Contract B) from the client orchestrator, authenticates the
user, validates credits, builds an LLM prompt, calls the AI (Claude/GPT)
to generate secure patches, and returns the patches along with credit
status.

This module is CLOSED SOURCE / PROPRIETARY.
"""

import hashlib
import json
import logging
import os
import re
import time
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

import httpx
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from server import billing
from server import database
from server import prompts
from server.database import DatabaseError, UserNotFoundError, InsufficientCreditsError

logger = logging.getLogger("ose.main")

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------

_OSE_API_KEY: Optional[str] = os.environ.get("OSE_API_KEY")
_LLM_PROVIDER: str = os.environ.get("LLM_PROVIDER", "anthropic").lower()
_LLM_MODEL: Optional[str] = os.environ.get("LLM_MODEL")

_DEFAULT_ANTHROPIC_MODEL = "claude-3-5-sonnet-20241022"
_DEFAULT_OPENAI_MODEL = "gpt-4"
_DEFAULT_OLLAMA_MODEL = "deepseek-r1:7b"
_DEFAULT_OPENROUTER_MODEL = "mistralai/mistral-7b-instruct:free"

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class AuditRequest(BaseModel):
    manifest: Dict[str, Any]
    client_version: Optional[str] = None
    user_id: Optional[str] = None
    track: str = Field(default="web2")


class PatchResponse(BaseModel):
    finding_id: str
    patch: str
    explanation: str


class AuditResponse(BaseModel):
    status: str
    findings: Optional[List[Dict[str, Any]]] = None
    credits: Optional[Dict[str, Any]] = None
    checkout_urls: Optional[Dict[str, str]] = None
    message: Optional[str] = None


class CreditsResponse(BaseModel):
    user_id: str
    credits: int
    tier: str


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize DB pool on startup, close on shutdown."""
    try:
        await database.init_pool()
        await database.init_schema()
        logger.info("OSE Server started – DB pool and schema ready.")
    except Exception as exc:
        logger.error("Startup failed: %s", exc)
        raise
    yield
    await database.close_pool()
    logger.info("OSE Server shut down.")


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="OSE Auditor Server",
    version="1.0.0",
    description=(
        "Cloud API for OSE Auditor – patch generation from vulnerability manifests."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    # allow_origins=["*"],  # Remove it for production
    allow_origins=["https://api.crestsek.com", "https://ose.crestsek.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Exception handlers
# ---------------------------------------------------------------------------


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"status": "ERROR", "message": exc.detail},
    )


@app.exception_handler(DatabaseError)
async def database_error_handler(request: Request, exc: DatabaseError):
    logger.error("DatabaseError: %s", exc)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"status": "ERROR", "message": "Database error."},
    )


@app.exception_handler(UserNotFoundError)
async def user_not_found_handler(request: Request, exc: UserNotFoundError):
    logger.warning("UserNotFoundError: %s", exc)
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={"status": "ERROR", "message": "User not found."},
    )


@app.exception_handler(InsufficientCreditsError)
async def insufficient_credits_handler(request: Request, exc: InsufficientCreditsError):
    return JSONResponse(
        status_code=status.HTTP_402_PAYMENT_REQUIRED,
        content={"status": "CREDIT_EXHAUSTED", "message": str(exc)},
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception: %s", exc)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"status": "ERROR", "message": "Internal server error."},
    )


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------


def _get_api_key(request: Request) -> Optional[str]:
    """Extract the Bearer token from the Authorization header."""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    return None


def _authenticate(request: Request) -> str:
    """
    Validate the API key and return it.

    Raises HTTPException(401) on failure.
    """
    if not _OSE_API_KEY:
        logger.error("OSE_API_KEY is not configured on the server.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server misconfigured: missing OSE_API_KEY.",
        )
    key = _get_api_key(request)
    if not key or key != _OSE_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key.",
        )
    return key


def _resolve_user_id(request: Request, payload: AuditRequest) -> str:
    """
    Determine the user_id for the request.

    Resolution order:
      1. payload.user_id (explicit, from orchestrator)
      2. SHA-256 prefix of the API key (stable, anonymous)
    """
    if payload.user_id and payload.user_id.strip():
        return payload.user_id.strip()

    key = _get_api_key(request)
    if key:
        return hashlib.sha256(key.encode()).hexdigest()[:32]

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Cannot determine user identity.",
    )


def _checkout_urls(user_id: str) -> Dict[str, str]:
    """Build a checkout URL for every available credit pack.

    Args:
        user_id: The unique user identifier to embed in each URL.

    Returns:
        A mapping of pack name (e.g. "starter") to its Flutterwave
        checkout URL for this user.
    """
    return {
        pack_name: billing.generate_checkout_url(user_id, pack_name)
        for pack_name in billing.get_all_credit_packs()
    }


# ---------------------------------------------------------------------------
# LLM integration
# ---------------------------------------------------------------------------


async def _call_anthropic(prompt: str) -> str:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise ValueError("ANTHROPIC_API_KEY environment variable is not set.")

    model = _LLM_MODEL or _DEFAULT_ANTHROPIC_MODEL
    t0 = time.monotonic()
    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": model,
                "max_tokens": 4096,
                "messages": [{"role": "user", "content": prompt}],
            },
        )
        response.raise_for_status()
        data = response.json()

    elapsed = round(time.monotonic() - t0, 2)
    logger.info(
        "Anthropic LLM call complete: model=%s elapsed=%.2fs", model, elapsed)

    content_blocks = data.get("content", [])
    for block in content_blocks:
        if block.get("type") == "text":
            return block["text"]

    raise ValueError(
        f"Unexpected Anthropic response shape: {list(data.keys())}")


async def _call_openai(prompt: str) -> str:
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("OPENAI_API_KEY environment variable is not set.")

    model = _LLM_MODEL or _DEFAULT_OPENAI_MODEL
    t0 = time.monotonic()
    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "content-type": "application/json",
            },
            json={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.2,
            },
        )
        response.raise_for_status()
        data = response.json()

    elapsed = round(time.monotonic() - t0, 2)
    logger.info("OpenAI LLM call complete: model=%s elapsed=%.2fs",
                model, elapsed)

    choices = data.get("choices", [])
    if choices:
        return choices[0]["message"]["content"]

    raise ValueError(f"Unexpected OpenAI response shape: {list(data.keys())}")

async def _call_ollama(prompt: str) -> str:
    ollama_host = os.environ.get("OLLAMA_HOST")
    if not ollama_host:
        raise ValueError("OLLAMA_HOST environment variable is not set.")
    ollama_host = ollama_host.rstrip("/")
    model = os.environ.get("OLLAMA_MODEL", _DEFAULT_OLLAMA_MODEL)

    t0 = time.monotonic()
    async with httpx.AsyncClient(timeout=180.0) as client:
        response = await client.post(
            f"{ollama_host}/api/generate",
            json={
                "model": model,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.2},
            },
        )
        response.raise_for_status()
        data = response.json()

    elapsed = round(time.monotonic() - t0, 2)
    logger.info("Ollama LLM call complete: model=%s elapsed=%.2fs", model, elapsed)

    raw_text = data.get("response", "")
    if not raw_text:
        raise ValueError(f"Unexpected Ollama response shape: {list(data.keys())}")

    # DeepSeek-R1 emits its chain-of-thought inside <think>...</think> before
    # the actual answer. Strip it so extract_json_from_llm_response() doesn't
    # have to fish the JSON out from underneath a paragraph of reasoning.
    return re.sub(r"<think>.*?</think>", "", raw_text, flags=re.DOTALL).strip()

async def _call_openrouter(prompt: str) -> str:
    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        raise ValueError("OPENROUTER_API_KEY environment variable is not set.")

    model = os.environ.get("OPENROUTER_MODEL", _DEFAULT_OPENROUTER_MODEL)
    t0 = time.monotonic()

    async with httpx.AsyncClient(timeout=120.0) as client:
        response = await client.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "HTTP-Referer": "https://ose.crestsek.com",
                "X-Title": "OSE Auditor",
                "Content-Type": "application/json",
            },
            json={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.2,
                "max_tokens": 4096,
            },
        )
        response.raise_for_status()
        data = response.json()

    elapsed = round(time.monotonic() - t0, 2)
    logger.info("OpenRouter LLM call complete: model=%s elapsed=%.2fs", model, elapsed)

    choices = data.get("choices", [])
    if choices:
        return choices[0]["message"]["content"]

    raise ValueError(f"Unexpected OpenRouter response shape: {list(data.keys())}")

async def _call_groq(prompt: str) -> str:
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        raise ValueError("GROQ_API_KEY environment variable is not set.")

    model = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
    t0 = time.monotonic()

    async with httpx.AsyncClient(timeout=120.0) as client:
        response = await client.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.2,
                "max_tokens": 4096,
            },
        )
        response.raise_for_status()
        data = response.json()

    elapsed = round(time.monotonic() - t0, 2)
    logger.info("Groq LLM call complete: model=%s elapsed=%.2fs", model, elapsed)

    choices = data.get("choices", [])
    if choices:
        return choices[0]["message"]["content"]

    raise ValueError(f"Unexpected Groq response shape: {list(data.keys())}")

async def call_llm(prompt: str) -> str:
    """Dispatch to the configured LLM provider and return the raw text response."""
    provider = _LLM_PROVIDER
    logger.info(
        "Calling LLM provider=%s prompt_chars=%d", provider, len(prompt)
    )
    if provider == "openrouter":
        return await _call_openrouter(prompt)
    elif provider == "openai":
        return await _call_openai(prompt)
    elif provider == "ollama":
        return await _call_ollama(prompt)
    elif provider == "anthropic":
        return await _call_anthropic(prompt)
    elif provider == "groq":
        return await _call_groq(prompt)
    else:
        raise ValueError(f"Unsupported LLM_PROVIDER: {provider!r}")

def extract_json_from_llm_response(text: str) -> Dict[str, Any]:
    """
    Robustly extract a JSON object from an LLM response.

    Attempts (in order):
      1. Parse entire text as JSON.
      2. Extract from ```json ... ``` or ``` ... ``` code fences.
      3. Slice from first '{' to last '}'.
    """
    # Attempt 1: direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Attempt 2: code fence extraction
    fence_matches = re.findall(r"```(?:json)?\s*([\s\S]*?)```", text)
    for match in fence_matches:
        try:
            return json.loads(match.strip())
        except json.JSONDecodeError:
            continue

    # Attempt 3: brace slicing
    start = text.find("{")
    end = text.rfind("}") + 1
    if start != -1 and end > start:
        try:
            return json.loads(text[start:end])
        except json.JSONDecodeError:
            pass

    raise ValueError("No valid JSON object found in LLM response.")


def _normalise_patches(patch_data: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    """
    Extract a list of patch dicts from the parsed LLM payload.

    Handles two shapes:
      - {"patches": [...]}          (expected)
      - {"finding_id": ..., ...}    (bare single patch)

    Returns None if the shape is unrecognisable.
    """
    patches = patch_data.get("patches")
    if isinstance(patches, list):
        return patches

    # Single patch object returned directly
    if "finding_id" in patch_data and "patch" in patch_data:
        return [patch_data]

    return None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/health", summary="Health check")
async def health_check():
    """Returns 200 OK with server status. Used by Render for keep-alive pings."""
    return {"status": "online", "timestamp": time.time()}


@app.post(
    "/v1/audit",
    summary="Run patch generation for a vulnerability manifest",
    response_model=AuditResponse,
)
async def audit(request: Request, payload: AuditRequest):
    """
    Main audit endpoint.

    Accepts a Contract B manifest from the orchestrator, validates the
    API key and user credits, calls the configured LLM to generate
    security patches, and returns a structured response.
    """
    # ── 1. Authenticate ────────────────────────────────────────────────────
    _authenticate(request)

    # ── 2. Resolve user identity ───────────────────────────────────────────
    user_id = _resolve_user_id(request, payload)
    manifest = payload.manifest
    track = payload.track or "web2"
    project_hash = manifest.get("project_hash", "")
    findings_in_manifest = manifest.get("findings", [])

    logger.info(
        "Audit request: user=%s project=%s track=%s findings=%d",
        user_id,
        project_hash,
        track,
        len(findings_in_manifest),
    )

    # ── 3. Ensure user exists ──────────────────────────────────────────────
    try:
        await database.get_or_create_user(user_id)
    except Exception as exc:
        logger.error("Failed to get/create user %s: %s", user_id, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error while resolving user.",
        )

    # ── 4. Check credits ───────────────────────────────────────────────────
    try:
        remaining_before = await database.get_remaining_credits(user_id)
    except Exception as exc:
        logger.error("Failed to check credits for %s: %s", user_id, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error while checking credits.",
        )

    if remaining_before <= 0:
        urls = _checkout_urls(user_id)
        logger.warning("Credit exhausted for user: %s", user_id)
        return AuditResponse(
            status="CREDIT_EXHAUSTED",
            message="No credits remaining. Please purchase more.",
            checkout_urls=urls,
        )

    # ── 5. Deduct credit ────────────────────────────────────────────────────
    # Both free-tier (weekly pool) and premium (purchased balance) users
    # are deducted via the same call; database.deduct_credit() picks the
    # right accounting based on the user's credit_tier.
    try:
        deducted = await database.deduct_credit(user_id)
    except Exception as exc:
        logger.error("Failed to deduct credit for %s: %s", user_id, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error while deducting credit.",
        )
    if not deducted:
        # Race condition: last credit claimed by a concurrent request.
        urls = _checkout_urls(user_id)
        logger.warning("Credit race condition for user: %s", user_id)
        return AuditResponse(
            status="CREDIT_EXHAUSTED",
            message="Credits exhausted. Please purchase more.",
            checkout_urls=urls,
        )

    credits_used = 1

    # ── 6. Build LLM prompt ────────────────────────────────────────────────
    try:
        prompt_text = prompts.build_prompt(manifest, track)
    except Exception as exc:
        logger.error("Prompt building failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to construct LLM prompt.",
        )

    # ── 7. Call LLM ────────────────────────────────────────────────────────
    try:
        llm_raw = await call_llm(prompt_text)
    except httpx.TimeoutException:
        logger.error("LLM request timed out for user: %s", user_id)
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="LLM service timed out. Please retry.",
        )
    except httpx.HTTPStatusError as exc:
        logger.error("LLM HTTP error %s: %s", exc.response.status_code, exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"LLM service returned error {exc.response.status_code}.",
        )
    except Exception as exc:
        logger.error("LLM call failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="LLM service unavailable.",
        )

    # ── 8. Parse LLM JSON response ─────────────────────────────────────────
    try:
        patch_data = extract_json_from_llm_response(llm_raw)
    except ValueError as exc:
        logger.error("Failed to extract JSON from LLM response: %s", exc)
        logger.debug("LLM raw response (first 800 chars): %s", llm_raw[:800])
        return AuditResponse(
            status="PARTIAL_SUCCESS",
            message="LLM returned an unparseable response. Please retry.",
        )

    # ── 9. Normalise patch list ────────────────────────────────────────────
    patches = _normalise_patches(patch_data)
    if patches is None:
        logger.error("Unrecognised patch payload shape: %s",
                     list(patch_data.keys()))
        return AuditResponse(
            status="PARTIAL_SUCCESS",
            message="Unexpected patch format from LLM.",
        )

    # ── 10. Log audit event ────────────────────────────────────────────────
    try:
        await database.log_audit(
            user_id=user_id,
            project_hash=project_hash,
            track=track,
            findings_count=len(findings_in_manifest),
            credits_used=credits_used,
        )
    except Exception as exc:
        # Non-critical: log and continue
        logger.warning("Audit log failed for user %s: %s", user_id, exc)

    # ── 11. Build success response ─────────────────────────────────────────
    try:
        remaining_after = await database.get_remaining_credits(user_id)
        tier = await database.get_tier(user_id)
    except Exception as exc:
        logger.warning("Failed to fetch post-audit credit state: %s", exc)
        remaining_after = max(0, remaining_before - 1)
        tier = "unknown"

    logger.info(
        "Audit success: user=%s patches=%d remaining_credits=%s tier=%s",
        user_id,
        len(patches),
        remaining_after,
        tier,
    )

    return AuditResponse(
        status="SUCCESS",
        findings=patches,
        credits={
            "remaining": remaining_after,
            "total_used": credits_used,
            "tier": tier,
        },
    )


@app.get(
    "/v1/credits",
    summary="Get remaining credits for a user",
    response_model=CreditsResponse,
)
async def get_credits(request: Request):
    """
    Return the current credit balance and tier for the authenticated user.

    The `user_id` must be supplied as a query parameter.
    """
    _authenticate(request)

    user_id = request.query_params.get("user_id", "").strip()
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Query parameter 'user_id' is required.",
        )

    try:
        credits = await database.get_remaining_credits(user_id)
        tier = await database.get_tier(user_id)
    except Exception as exc:
        logger.error("Error fetching credits for %s: %s", user_id, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error while fetching credits.",
        )

    return CreditsResponse(user_id=user_id, credits=credits, tier=tier)


@app.post("/webhooks/flutterwave")
async def flutterwave_webhook(request: Request):
    # Flutterwave signs webhooks with a `verif-hash` header that must
    # match the secret hash you configured in their dashboard.
    expected_hash = os.environ.get("FLW_SECRET_HASH")
    received_hash = request.headers.get("verif-hash")
    if not expected_hash or received_hash != expected_hash:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid webhook signature.")

    payload = await request.json()
    result = billing.parse_flutterwave_webhook(payload.get("data", payload))

    if result is None:
        return {"status": "ignored"}  # not an OSE payment
    if not result["valid"]:
        logger.warning("Invalid OSE webhook: %s", result.get("message"))
        return {"status": "invalid", "message": result.get("message")}

    await database.add_credits(
        user_id=result["user_id"],
        credits=result["credits"],
        flutterwave_ref=result["tx_ref"],
    )
    return {"status": "ok"}
