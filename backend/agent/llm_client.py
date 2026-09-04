"""
PrivAgent Backend - LLM Client Abstraction
Supports mock mode (default) and OpenAI when LLM_PROVIDER=openai.
"""

from __future__ import annotations

import os
import re
import json
import logging
from abc import ABC, abstractmethod
from typing import Any, Optional

import httpx
from pydantic import ValidationError

from backend.api.schemas import (
    AnalyzeRequest, BrowserAction, ActionType, ScrollDirection,
    CommandRequest, PageField,
)
from backend.privacy.validator import (
    SAFE_PLACEHOLDERS,
    sanitize_payload,
    validate_payload,
)

logger = logging.getLogger("privagent.llm")


class LLMProvider(ABC):
    """Abstract base for LLM providers."""

    @abstractmethod
    async def analyze_page(self, request: AnalyzeRequest) -> list[BrowserAction]:
        """Analyze sanitized page context and return browser actions."""
        ...

    @abstractmethod
    async def process_command(self, request: CommandRequest) -> list[BrowserAction]:
        """Process a user command and return browser actions."""
        ...


class MockLLMProvider(LLMProvider):
    """Deterministic mock provider for demo/testing.
    Inspects sanitized page structure and returns intelligent actions."""

    async def analyze_page(self, request: AnalyzeRequest) -> list[BrowserAction]:
        actions: list[BrowserAction] = []

        # Look for empty required fields to fill
        for field in request.fields:
            if field.redacted:
                continue  # Skip redacted fields
            if field.type in ("text", "email", "tel", "number") and not field.value:
                if field.type == "email" or _is_email_field(field):
                    actions.append(BrowserAction(
                        action=ActionType.FILL,
                        target=field.id or field.name or "email",
                        value="user@example.com",
                        reasoning=f"Fill email field '{field.label or field.id}'",
                    ))
                elif field.type == "tel" or _is_phone_field(field):
                    actions.append(BrowserAction(
                        action=ActionType.FILL,
                        target=field.id or field.name or "phone",
                        value="9876543210",
                        reasoning=f"Fill phone field '{field.label or field.id}'",
                    ))
                else:
                    actions.append(BrowserAction(
                        action=ActionType.FILL,
                        target=field.id or field.name or "input",
                        value="Demo User",
                        reasoning=f"Fill text field '{field.label or field.id}'",
                    ))

        # Find submit button
        for btn in request.buttons:
            text = (btn.text or btn.label or btn.value or "").lower()
            if any(kw in text for kw in ("submit", "login", "sign in", "register", "apply")):
                actions.append(BrowserAction(
                    action=ActionType.CLICK,
                    target=btn.id or btn.name or btn.text or "submit",
                    reasoning=f"Click submit button '{btn.text or btn.label}'",
                ))
                break

        if not actions:
            # Default: scroll down to explore the page
            actions.append(BrowserAction(
                action=ActionType.SCROLL,
                direction=ScrollDirection.DOWN,
                reasoning="No actionable elements found, scrolling to explore",
            ))

        return actions

    async def process_command(self, request: CommandRequest) -> list[BrowserAction]:
        cmd = request.command.lower().strip()

        if "click" in cmd:
            target = _extract_target_from_command(cmd, request.buttons)
            return [BrowserAction(
                action=ActionType.CLICK,
                target=target,
                reasoning=f"User requested click: '{request.command}'",
            )]

        if "fill" in cmd or "type" in cmd or "enter" in cmd:
            target = _extract_target_from_command(cmd, request.fields)
            value = _extract_value_from_command(cmd)
            return [BrowserAction(
                action=ActionType.FILL,
                target=target,
                value=value or "Demo Value",
                reasoning=f"User requested fill: '{request.command}'",
            )]

        if "scroll" in cmd:
            direction = ScrollDirection.DOWN
            if "up" in cmd:
                direction = ScrollDirection.UP
            return [BrowserAction(
                action=ActionType.SCROLL,
                direction=direction,
                reasoning=f"User requested scroll: '{request.command}'",
            )]

        if "submit" in cmd:
            return [BrowserAction(
                action=ActionType.CLICK,
                target="submit",
                reasoning=f"User requested submit: '{request.command}'",
            )]

        return [BrowserAction(
            action=ActionType.SCROLL,
            direction=ScrollDirection.DOWN,
            reasoning=f"Could not parse command, scrolling: '{request.command}'",
        )]


def _is_email_field(field: PageField) -> bool:
    indicators = [field.id, field.name, field.label, field.placeholder, field.aria_label]
    return any("email" in (s or "").lower() for s in indicators)


def _is_phone_field(field: PageField) -> bool:
    indicators = [field.id, field.name, field.label, field.placeholder, field.aria_label]
    return any(kw in (s or "").lower() for s in indicators for kw in ("phone", "tel", "mobile"))


def _extract_target_from_command(cmd: str, elements: list[PageField]) -> str:
    for el in elements:
        for attr in [el.id, el.name, el.text, el.label]:
            if not attr:
                continue
            normalized_attr = attr.lower()
            attr_words = re.findall(r"[a-z0-9]+", normalized_attr)
            if normalized_attr in cmd or any(
                len(word) >= 3 and re.search(rf"\b{re.escape(word)}\b", cmd)
                for word in attr_words
            ):
                return el.id or el.name or attr
    return "target"


def _extract_value_from_command(cmd: str) -> Optional[str]:
    # Try to extract quoted value
    import re
    match = re.search(r'["\'](.+?)["\']', cmd)
    if match:
        return match.group(1)
    # Try "with <value>"
    match = re.search(r'with\s+(.+?)(?:\s+in|\s+on|$)', cmd)
    if match:
        return match.group(1).strip()
    return None


OPENAI_CHAT_URL = "https://api.openai.com/v1/chat/completions"
_OPENAI_TIMEOUT_SECONDS = 15.0
_ACTION_SYSTEM_PROMPT = (
    "You are PrivAgent's action planner. You receive ONLY already-sanitized JSON "
    "(PII is replaced with placeholders such as [REDACTED_EMAIL]). "
    "Never reconstruct, request, or emit raw PII, screenshots, secrets, or executable code. "
    "Reply with a JSON object: {\"actions\": [ ... ]}. "
    "Each action must be one of: "
    "{\"action\":\"click\",\"target\":\"<id or name>\"}, "
    "{\"action\":\"fill\",\"target\":\"<id or name>\",\"value\":\"<non-PII value>\"}, "
    "{\"action\":\"scroll\",\"direction\":\"up|down|left|right\"}. "
    "Optional keys: confidence (0-1), reasoning. "
    "Allowed actions are only click, fill, and scroll. "
    "Do not use eval, Function, javascript:, <script, document.cookie, or similar in values. "
    "Skip redacted fields. Return 1 to 5 actions."
)


def _sanitized_analyze_payload(request: AnalyzeRequest) -> dict[str, Any]:
    """Build a minimal, server-sanitized page context for the external model."""
    payload = request.model_dump(exclude_none=True)
    payload.pop("text_content", None)
    return _sanitize_llm_payload(payload)


def _sanitized_command_payload(request: CommandRequest) -> dict[str, Any]:
    """Build a privacy-safe command context without field values or DOM text."""
    return _sanitize_llm_payload(request.model_dump(exclude_none=True))


_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(?:bearer|token|api[_ -]?key|password|secret)\s*[:=]\s*[^\s,;]+"
)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
_OPENAI_KEY = re.compile(r"\bsk-[A-Za-z0-9_-]{10,}\b")


def _sanitize_llm_text(value: str) -> str:
    """Redact PII and common credentials in free-form text."""
    sanitized = sanitize_payload({"value": value})["value"]
    sanitized = _SECRET_ASSIGNMENT.sub("[REDACTED_SECRET]", sanitized)
    sanitized = _JWT.sub("[REDACTED_SECRET]", sanitized)
    return _OPENAI_KEY.sub("[REDACTED_SECRET]", sanitized)


def _sanitize_llm_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Sanitize model input and remove values that cannot be safely inferred."""
    sanitized = sanitize_payload(payload)

    if "command" in sanitized and isinstance(sanitized["command"], str):
        sanitized["command"] = _sanitize_llm_text(sanitized["command"])

    for collection_name in ("fields", "buttons", "links"):
        for element in sanitized.get(collection_name, []):
            if not isinstance(element, dict):
                continue
            field_type = str(element.get("type") or "").lower()
            if element.get("redacted") or field_type == "password":
                if element.get("value") not in SAFE_PLACEHOLDERS:
                    element["value"] = "[REDACTED_PASSWORD]"
            elif element.get("value") in SAFE_PLACEHOLDERS:
                pass
            else:
                element.pop("value", None)
            for key, value in list(element.items()):
                if isinstance(value, str):
                    element[key] = _sanitize_llm_text(value)

    for key, value in list(sanitized.items()):
        if isinstance(value, str):
            sanitized[key] = _sanitize_llm_text(value)
    return sanitized


def _extract_message_content(api_body: dict[str, Any]) -> str:
    choices = api_body.get("choices") or []
    if not choices:
        raise ValueError("OpenAI response missing choices")
    message = choices[0].get("message") or {}
    content = message.get("content")
    if not isinstance(content, str) or not content.strip():
        raise ValueError("OpenAI response missing message content")
    return content


def _parse_actions_payload(content: str) -> list[Any]:
    text = content.strip()
    fence = re.match(r"^```(?:json)?\s*(.*?)\s*```$", text, re.DOTALL | re.IGNORECASE)
    if fence:
        text = fence.group(1).strip()
    data = json.loads(text)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        actions = data.get("actions")
        if isinstance(actions, list):
            return actions
        if "action" in data:
            return [data]
    raise ValueError("OpenAI response JSON is not an actions list")


def _validate_actions(raw_actions: list[Any]) -> list[BrowserAction]:
    """Local schema + injection checks via BrowserAction; drop invalid items."""
    validated: list[BrowserAction] = []
    for item in raw_actions:
        if not isinstance(item, dict):
            continue
        try:
            action = BrowserAction.model_validate(item)
            if not validate_payload(action.model_dump(exclude_none=True)).is_safe:
                logger.warning("Dropping LLM action containing raw PII")
                continue
            validated.append(action)
        except ValidationError:
            logger.warning("Dropping invalid or unsafe LLM action")
    return validated[:5]


class OpenAILLMProvider(LLMProvider):
    """Single Chat Completions call per analyze/command; falls back to mock on failure."""

    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4o-mini",
        fallback: Optional[LLMProvider] = None,
        http_client: Optional[httpx.AsyncClient] = None,
    ):
        self._api_key = api_key
        self._model = model
        self._fallback = fallback or MockLLMProvider()
        self._http_client = http_client

    async def analyze_page(self, request: AnalyzeRequest) -> list[BrowserAction]:
        try:
            actions = await self._plan(_sanitized_analyze_payload(request))
            if actions:
                return actions
            logger.warning("OpenAI returned no valid actions, falling back to mock")
        except (httpx.HTTPError, json.JSONDecodeError, ValueError, TypeError) as exc:
            logger.warning("OpenAI analyze failed (%s), falling back to mock", type(exc).__name__)
        return await self._fallback.analyze_page(request)

    async def process_command(self, request: CommandRequest) -> list[BrowserAction]:
        try:
            actions = await self._plan(_sanitized_command_payload(request))
            if actions:
                return actions
            logger.warning("OpenAI returned no valid command actions, falling back to mock")
        except (httpx.HTTPError, json.JSONDecodeError, ValueError, TypeError) as exc:
            logger.warning("OpenAI command failed (%s), falling back to mock", type(exc).__name__)
        return await self._fallback.process_command(request)

    async def _plan(self, sanitized_context: dict[str, Any]) -> list[BrowserAction]:
        content = await self._chat_once(sanitized_context)
        return _validate_actions(_parse_actions_payload(content))

    async def _chat_once(self, sanitized_context: dict[str, Any]) -> str:
        if not self._api_key.strip():
            raise ValueError("OpenAI API key is missing")
        body = {
            "model": self._model,
            "temperature": 0,
            "max_tokens": 500,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": _ACTION_SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": json.dumps(sanitized_context, separators=(",", ":")),
                },
            ],
        }
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

        if self._http_client is not None:
            response = await self._http_client.post(
                OPENAI_CHAT_URL, headers=headers, json=body
            )
            response.raise_for_status()
            return _extract_message_content(response.json())

        timeout = httpx.Timeout(_OPENAI_TIMEOUT_SECONDS)
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(
                OPENAI_CHAT_URL, headers=headers, json=body
            )
            response.raise_for_status()
            return _extract_message_content(response.json())


def get_llm_provider() -> LLMProvider:
    """Factory: return the configured LLM provider. Default is mock."""
    provider = os.getenv("LLM_PROVIDER", "mock").lower()

    if provider == "mock":
        logger.info("Using MockLLMProvider (demo mode)")
        return MockLLMProvider()

    if provider == "openai":
        api_key = (os.getenv("OPENAI_API_KEY") or "").strip()
        if not api_key:
            logger.warning("OPENAI_API_KEY missing, falling back to mock")
            return MockLLMProvider()
        model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        logger.info("Using OpenAILLMProvider (model=%s)", model)
        return OpenAILLMProvider(api_key=api_key, model=model)

    logger.warning("Provider '%s' not implemented, falling back to mock", provider)
    return MockLLMProvider()
