"""
PrivAgent Backend - API Routes
"""

from __future__ import annotations

import uuid
import json
import logging

# pyrefly: ignore [missing-import]
from fastapi import APIRouter
# pyrefly: ignore [missing-import]
from fastapi import HTTPException
# pyrefly: ignore [missing-import]
from fastapi import Request
# pyrefly: ignore [missing-import]
from fastapi.responses import JSONResponse       

from backend.api.schemas import (
    AnalyzeRequest, AnalyzeResponse,
    CommandRequest, CommandResponse,
    HealthResponse, PrivacyStatusResponse,
    BrowserAction,
)
from backend.privacy.validator import validate_payload, sanitize_payload
from backend.agent.llm_client import get_llm_provider

logger = logging.getLogger("privagent.api")

router = APIRouter()

# Cache a single provider instance
_llm_provider = None


def _get_provider():
    global _llm_provider
    if _llm_provider is None:
        _llm_provider = get_llm_provider()
    return _llm_provider


@router.get("/health", response_model=HealthResponse)
async def health():
    """Health check endpoint."""
    import os
    return HealthResponse(
        llm_provider=os.getenv("LLM_PROVIDER", "mock"),
    )


@router.get("/privacy/status", response_model=PrivacyStatusResponse)
async def privacy_status():
    """Privacy engine status."""
    return PrivacyStatusResponse()


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze(request: AnalyzeRequest):
    """Analyze sanitized page context and return browser actions.

    The payload is validated for PII leaks before processing.
    """
    request_id = str(uuid.uuid4())[:8]

    # Privacy validation on incoming payload
    payload_dict = request.model_dump()
    validation = validate_payload(payload_dict)

    if not validation.is_safe:
        logger.warning(
            "[%s] Privacy violation in /analyze: %s",
            request_id, validation.summary(),
        )
        # Sanitize the payload server-side as a safety net
        payload_dict = sanitize_payload(payload_dict)
        request = AnalyzeRequest(**payload_dict)

    # Log sanitized payload only
    logger.info(
        "[%s] Analyzing page: %s (%d fields, %d buttons)",
        request_id,
        request.page.title if request.page else "unknown",
        len(request.fields),
        len(request.buttons),
    )

    try:
        provider = _get_provider()
        actions = await provider.analyze_page(request)
        return AnalyzeResponse(
            actions=actions,
            message="Analysis complete",
            request_id=request_id,
            privacy_verified=validation.is_safe,
        )
    except Exception as e:
        logger.error("[%s] Analysis error: %s", request_id, type(e).__name__)
        raise HTTPException(status_code=500, detail="Analysis failed safely")


@router.post("/command", response_model=CommandResponse)
async def command(request: CommandRequest):
    """Process a user command and return browser actions."""
    request_id = str(uuid.uuid4())[:8]

    # Privacy validation
    payload_dict = request.model_dump()
    validation = validate_payload(payload_dict)

    if not validation.is_safe:
        logger.warning(
            "[%s] Privacy violation in /command: %s",
            request_id, validation.summary(),
        )
        payload_dict = sanitize_payload(payload_dict)
        request = CommandRequest(**payload_dict)

    logger.info("[%s] Processing command: %s", request_id, request.command[:100])

    try:
        provider = _get_provider()
        actions = await provider.process_command(request)
        return CommandResponse(
            actions=actions,
            message="Command processed",
            request_id=request_id,
        )
    except Exception as e:
        logger.error("[%s] Command error: %s", request_id, type(e).__name__)
        raise HTTPException(status_code=500, detail="Command failed safely")
