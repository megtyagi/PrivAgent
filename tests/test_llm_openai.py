"""
OpenAI provider tests. HTTP is always mocked — no real LLM API calls.
"""

import json

import httpx
import pytest

from backend.agent.llm_client import (
    OPENAI_CHAT_URL,
    MockLLMProvider,
    OpenAILLMProvider,
    get_llm_provider,
)
from backend.api.schemas import AnalyzeRequest, CommandRequest, PageField, ActionType


class _FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            request = httpx.Request("POST", OPENAI_CHAT_URL)
            response = httpx.Response(self.status_code, request=request)
            raise httpx.HTTPStatusError("error", request=request, response=response)

    def json(self):
        return self._payload


class _FakeAsyncClient:
    def __init__(self, response=None, error=None, capture=None):
        self._response = response
        self._error = error
        self.capture = capture if capture is not None else {}
        self.post_calls = 0

    async def post(self, url, headers=None, json=None):
        self.post_calls += 1
        self.capture["url"] = url
        self.capture["headers"] = headers
        self.capture["json"] = json
        if self._error is not None:
            raise self._error
        return self._response


def _openai_message(content: str) -> dict:
    return {"choices": [{"message": {"content": content}}]}


def _sanitized_analyze_request() -> AnalyzeRequest:
    return AnalyzeRequest(
        page={"url": "/demo/scholarship.html", "title": "Scholarship Form", "domain": "localhost"},
        fields=[
            PageField(
                id="email",
                type="email",
                label="Email",
                value="[REDACTED_EMAIL]",
                redacted=True,
            ),
            PageField(
                id="institution",
                type="text",
                label="Institution",
                value=None,
                redacted=False,
            ),
        ],
        buttons=[PageField(id="submitApplication", text="Submit Application")],
    )


@pytest.mark.asyncio
async def test_openai_analyze_one_mocked_request_returns_validated_actions():
    client = _FakeAsyncClient(
        response=_FakeResponse(
            _openai_message(
                json.dumps({
                    "actions": [
                        {
                            "action": "click",
                            "target": "submitApplication",
                            "reasoning": "Submit the form",
                        }
                    ]
                })
            )
        )
    )
    provider = OpenAILLMProvider(api_key="sk-test", http_client=client)
    actions = await provider.analyze_page(_sanitized_analyze_request())

    assert client.post_calls == 1
    assert client.capture["url"] == OPENAI_CHAT_URL
    assert actions[0].action == ActionType.CLICK
    assert actions[0].target == "submitApplication"

    sent = json.dumps(client.capture["json"]["messages"][1]["content"])
    assert "rahul.sharma@gmail.com" not in sent
    assert "[REDACTED_EMAIL]" in client.capture["json"]["messages"][1]["content"]
    assert "sk-test" not in client.capture["json"]["messages"][1]["content"]


@pytest.mark.asyncio
async def test_openai_analyze_falls_back_on_invalid_injection_action():
    client = _FakeAsyncClient(
        response=_FakeResponse(
            _openai_message(
                json.dumps({
                    "actions": [
                        {"action": "fill", "target": "search", "value": "eval('alert(1)')"}
                    ]
                })
            )
        )
    )
    provider = OpenAILLMProvider(api_key="sk-test", http_client=client)
    request = AnalyzeRequest(
        buttons=[PageField(id="submitBtn", text="Submit")]
    )
    actions = await provider.analyze_page(request)

    assert client.post_calls == 1
    assert len(actions) >= 1
    assert all("eval(" not in (a.value or "") for a in actions)


@pytest.mark.asyncio
async def test_openai_analyze_falls_back_on_timeout():
    client = _FakeAsyncClient(error=httpx.TimeoutException("timed out"))
    provider = OpenAILLMProvider(api_key="sk-test", http_client=client)
    actions = await provider.analyze_page(
        AnalyzeRequest(buttons=[PageField(id="submitBtn", text="Submit")])
    )
    assert client.post_calls == 1
    assert len(actions) >= 1
    assert actions[0].action in (ActionType.CLICK, ActionType.FILL, ActionType.SCROLL)


@pytest.mark.asyncio
async def test_openai_analyze_falls_back_on_http_error():
    client = _FakeAsyncClient(response=_FakeResponse({}, status_code=500))
    provider = OpenAILLMProvider(api_key="sk-test", http_client=client)
    actions = await provider.analyze_page(
        AnalyzeRequest(buttons=[PageField(id="submitBtn", text="Submit")])
    )
    assert client.post_calls == 1
    assert len(actions) >= 1


def test_get_llm_provider_openai_without_key_returns_mock(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    provider = get_llm_provider()
    assert isinstance(provider, MockLLMProvider)


def test_get_llm_provider_default_is_mock(monkeypatch):
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    provider = get_llm_provider()
    assert isinstance(provider, MockLLMProvider)


def test_get_llm_provider_openai_with_key(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    provider = get_llm_provider()
    assert isinstance(provider, OpenAILLMProvider)


@pytest.mark.asyncio
async def test_openai_process_command_one_mocked_request():
    client = _FakeAsyncClient(
        response=_FakeResponse(
            _openai_message(
                json.dumps({"actions": [{"action": "scroll", "direction": "down"}]})
            )
        )
    )
    provider = OpenAILLMProvider(api_key="sk-test", http_client=client)
    actions = await provider.process_command(CommandRequest(command="scroll down"))
    assert client.post_calls == 1
    assert actions[0].action == ActionType.SCROLL


@pytest.mark.asyncio
async def test_openai_payload_excludes_dom_and_sensitive_values():
    client = _FakeAsyncClient(
        response=_FakeResponse(_openai_message(json.dumps({"actions": []})))
    )
    provider = OpenAILLMProvider(api_key="sk-test", http_client=client)
    request = AnalyzeRequest(
        text_content="<input value='secret@example.com'>Bearer token123</input>",
        user_intent="fill account password=super-secret",
        fields=[
            PageField(id="email", type="email", value="secret@example.com"),
            PageField(id="password", type="password", value="super-secret"),
        ],
    )

    await provider.analyze_page(request)

    content = client.capture["json"]["messages"][1]["content"]
    assert "text_content" not in content
    assert "secret@example.com" not in content
    assert "super-secret" not in content
    assert "token123" not in content
    assert "[REDACTED_PASSWORD]" in content
    assert "[REDACTED_SECRET]" in content


@pytest.mark.asyncio
async def test_openai_drops_actions_containing_raw_pii():
    client = _FakeAsyncClient(
        response=_FakeResponse(
            _openai_message(
                json.dumps({
                    "actions": [
                        {"action": "click", "target": "safe"},
                        {"action": "fill", "target": "email", "value": "user@example.com"},
                    ]
                })
            )
        )
    )
    provider = OpenAILLMProvider(api_key="sk-test", http_client=client)

    actions = await provider.analyze_page(AnalyzeRequest())

    assert len(actions) == 1
    assert actions[0].target == "safe"
