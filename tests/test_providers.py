from __future__ import annotations

import io
import json
import urllib.error

import pytest

from scripts.triager.providers import (
    AIProviderError,
    GeminiAIProvider,
    MockAIProvider,
    create_provider,
)


def test_mock_provider_returns_valid_json():
    result = json.loads(MockAIProvider().generate("test"))

    assert result["triage"] == "READY_FOR_MAINTAINER_REVIEW"
    assert result["confidence"] == 1
    assert result["summary"]
    assert result["uncertainties"]


def test_create_provider_mock():
    provider = create_provider("mock")

    assert isinstance(provider, MockAIProvider)


def test_create_provider_is_case_insensitive():
    provider = create_provider("  MOCK  ")

    assert isinstance(provider, MockAIProvider)


def test_create_provider_unknown_provider():
    with pytest.raises(AIProviderError, match="Unknown AI provider"):
        create_provider("unknown")


def test_gemini_requires_api_key(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)

    with pytest.raises(AIProviderError, match="GEMINI_API_KEY is not set"):
        GeminiAIProvider()


def test_gemini_accepts_google_api_key(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("GOOGLE_API_KEY", "test-key")

    provider = GeminiAIProvider()

    assert provider.api_key == "test-key"


def test_gemini_timeout_must_be_positive(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setenv("GEMINI_TIMEOUT", "0")

    with pytest.raises(
        AIProviderError,
        match="GEMINI_TIMEOUT must be a positive number",
    ):
        GeminiAIProvider()


def test_gemini_timeout_must_be_numeric(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setenv("GEMINI_TIMEOUT", "not-a-number")

    with pytest.raises(
        AIProviderError,
        match="GEMINI_TIMEOUT must be a positive number",
    ):
        GeminiAIProvider()


def test_gemini_rejects_empty_prompt(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    provider = GeminiAIProvider()

    with pytest.raises(
        AIProviderError,
        match="Gemini prompt must be a non-empty string",
    ):
        provider.generate("   ")


def test_gemini_response_text_extracts_candidate():
    data = {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {"text": '{"triage":"READY_FOR_MAINTAINER_REVIEW"}'}
                    ]
                }
            }
        ]
    }

    assert (
        GeminiAIProvider._response_text(data)
        == '{"triage":"READY_FOR_MAINTAINER_REVIEW"}'
    )


def test_gemini_response_text_combines_parts():
    data = {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {"text": "first"},
                        {"text": "second"},
                    ]
                }
            }
        ]
    }

    assert GeminiAIProvider._response_text(data) == "firstsecond"


def test_gemini_response_requires_candidates():
    with pytest.raises(
        AIProviderError,
        match="Gemini response is missing candidates",
    ):
        GeminiAIProvider._response_text({})


def test_gemini_response_requires_text():
    data = {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {"functionCall": {"name": "test"}}
                    ]
                }
            }
        ]
    }

    with pytest.raises(
        AIProviderError,
        match="Gemini response did not contain text content",
    ):
        GeminiAIProvider._response_text(data)


def test_gemini_extract_error_json():
    payload = json.dumps(
        {
            "error": {
                "status": "INVALID_ARGUMENT",
                "message": "Bad request",
            }
        }
    ).encode()

    assert (
        GeminiAIProvider._extract_error(payload)
        == "INVALID_ARGUMENT: Bad request"
    )


def test_gemini_extract_error_plain_text():
    payload = b"connection failed"

    assert GeminiAIProvider._extract_error(payload) == "connection failed"


def test_gemini_generate_sends_expected_request(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    captured = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return json.dumps(
                {
                    "candidates": [
                        {
                            "content": {
                                "parts": [
                                    {
                                        "text": (
                                            '{"triage":"READY_FOR_MAINTAINER_REVIEW"}'
                                        )
                                    }
                                ]
                            }
                        }
                    ]
                }
            ).encode()

    def fake_urlopen(request, timeout):
        captured["request"] = request
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr(
        "scripts.triager.providers.urllib.request.urlopen",
        fake_urlopen,
    )

    provider = GeminiAIProvider(
        model="test-model",
        timeout=37,
    )

    result = provider.generate("hello")

    assert result == '{"triage":"READY_FOR_MAINTAINER_REVIEW"}'
    assert captured["timeout"] == 37

    request = captured["request"]

    assert request.full_url.endswith(
        "/v1beta/models/test-model:generateContent"
    )
    assert request.get_header("Content-type") == "application/json"
    assert request.get_header("X-goog-api-key") == "test-key"

    payload = json.loads(request.data.decode("utf-8"))

    assert payload["contents"] == [
        {
            "role": "user",
            "parts": [{"text": "hello"}],
        }
    ]
    assert payload["generationConfig"]["temperature"] == 0
    assert payload["generationConfig"]["responseMimeType"] == "application/json"


def test_gemini_generate_handles_http_error(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    error_body = json.dumps(
        {
            "error": {
                "status": "INVALID_ARGUMENT",
                "message": "Bad request",
            }
        }
    ).encode()

    def fake_urlopen(request, timeout):
        raise urllib.error.HTTPError(
            request.full_url,
            400,
            "Bad Request",
            {},
            io.BytesIO(error_body),
        )

    monkeypatch.setattr(
        "scripts.triager.providers.urllib.request.urlopen",
        fake_urlopen,
    )

    provider = GeminiAIProvider()

    with pytest.raises(
        AIProviderError,
        match="Gemini API returned HTTP 400: INVALID_ARGUMENT: Bad request",
    ):
        provider.generate("hello")


def test_gemini_generate_handles_url_error(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    def fake_urlopen(request, timeout):
        raise urllib.error.URLError("offline")

    monkeypatch.setattr(
        "scripts.triager.providers.urllib.request.urlopen",
        fake_urlopen,
    )

    provider = GeminiAIProvider()

    with pytest.raises(
        AIProviderError,
        match="Unable to reach Gemini API: offline",
    ):
        provider.generate("hello")


def test_gemini_generate_handles_timeout(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    def fake_urlopen(request, timeout):
        raise TimeoutError()

    monkeypatch.setattr(
        "scripts.triager.providers.urllib.request.urlopen",
        fake_urlopen,
    )

    provider = GeminiAIProvider()

    with pytest.raises(
        AIProviderError,
        match="Gemini API request timed out",
    ):
        provider.generate("hello")


def test_gemini_factory(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    provider = create_provider(
        "gemini",
        model="test-model",
        timeout=10,
    )

    assert isinstance(provider, GeminiAIProvider)
    assert provider.model == "test-model"
    assert provider.timeout == 10


def test_gemini_retries_transient_503_then_succeeds(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    calls = []
    sleeps = []

    success_body = json.dumps(
        {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {"text": '{"status":"ok"}'}
                        ]
                    }
                }
            ]
        }
    ).encode()

    def fake_urlopen(request, timeout):
        calls.append((request, timeout))

        if len(calls) < 3:
            raise urllib.error.HTTPError(
                request.full_url,
                503,
                "Service Unavailable",
                {},
                io.BytesIO(
                    b'{"error":{"status":"UNAVAILABLE","message":"busy"}}'
                ),
            )

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                return success_body

        return FakeResponse()

    monkeypatch.setattr(
        "scripts.triager.providers.urllib.request.urlopen",
        fake_urlopen,
    )
    monkeypatch.setattr(
        "scripts.triager.providers.time.sleep",
        sleeps.append,
    )

    provider = GeminiAIProvider(
        max_retries=3,
        retry_base_delay=1,
    )

    result = provider.generate("hello")

    assert result == '{"status":"ok"}'
    assert len(calls) == 3
    assert sleeps == [1, 2]


def test_gemini_retries_transient_429(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    calls = []
    sleeps = []

    success_body = json.dumps(
        {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {"text": '{"status":"ok"}'}
                        ]
                    }
                }
            ]
        }
    ).encode()

    def fake_urlopen(request, timeout):
        calls.append(1)

        if len(calls) == 1:
            raise urllib.error.HTTPError(
                request.full_url,
                429,
                "Too Many Requests",
                {},
                io.BytesIO(
                    b'{"error":{"status":"RESOURCE_EXHAUSTED","message":"busy"}}'
                ),
            )

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                return success_body

        return FakeResponse()

    monkeypatch.setattr(
        "scripts.triager.providers.urllib.request.urlopen",
        fake_urlopen,
    )
    monkeypatch.setattr(
        "scripts.triager.providers.time.sleep",
        sleeps.append,
    )

    provider = GeminiAIProvider(
        max_retries=1,
        retry_base_delay=2,
    )

    result = provider.generate("hello")

    assert result == '{"status":"ok"}'
    assert len(calls) == 2
    assert sleeps == [2]


def test_gemini_stops_after_max_retries(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    calls = []
    sleeps = []

    def fake_urlopen(request, timeout):
        calls.append(1)

        raise urllib.error.HTTPError(
            request.full_url,
            503,
            "Service Unavailable",
            {},
            io.BytesIO(
                b'{"error":{"status":"UNAVAILABLE","message":"still busy"}}'
            ),
        )

    monkeypatch.setattr(
        "scripts.triager.providers.urllib.request.urlopen",
        fake_urlopen,
    )
    monkeypatch.setattr(
        "scripts.triager.providers.time.sleep",
        sleeps.append,
    )

    provider = GeminiAIProvider(
        max_retries=2,
        retry_base_delay=1,
    )

    with pytest.raises(
        AIProviderError,
        match="Gemini API returned HTTP 503: UNAVAILABLE: still busy",
    ):
        provider.generate("hello")

    assert len(calls) == 3
    assert sleeps == [1, 2]


def test_gemini_does_not_retry_permanent_http_error(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    calls = []
    sleeps = []

    def fake_urlopen(request, timeout):
        calls.append(1)

        raise urllib.error.HTTPError(
            request.full_url,
            400,
            "Bad Request",
            {},
            io.BytesIO(
                b'{"error":{"status":"INVALID_ARGUMENT","message":"bad"}}'
            ),
        )

    monkeypatch.setattr(
        "scripts.triager.providers.urllib.request.urlopen",
        fake_urlopen,
    )
    monkeypatch.setattr(
        "scripts.triager.providers.time.sleep",
        sleeps.append,
    )

    provider = GeminiAIProvider(
        max_retries=3,
        retry_base_delay=1,
    )

    with pytest.raises(
        AIProviderError,
        match="Gemini API returned HTTP 400: INVALID_ARGUMENT: bad",
    ):
        provider.generate("hello")

    assert len(calls) == 1
    assert sleeps == []


def test_gemini_honors_retry_after_header(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    calls = []
    sleeps = []

    success_body = json.dumps(
        {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {"text": '{"status":"ok"}'}
                        ]
                    }
                }
            ]
        }
    ).encode()

    def fake_urlopen(request, timeout):
        calls.append(1)

        if len(calls) == 1:
            raise urllib.error.HTTPError(
                request.full_url,
                503,
                "Service Unavailable",
                {"Retry-After": "7"},
                io.BytesIO(
                    b'{"error":{"status":"UNAVAILABLE","message":"busy"}}'
                ),
            )

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                return success_body

        return FakeResponse()

    monkeypatch.setattr(
        "scripts.triager.providers.urllib.request.urlopen",
        fake_urlopen,
    )
    monkeypatch.setattr(
        "scripts.triager.providers.time.sleep",
        sleeps.append,
    )

    provider = GeminiAIProvider(
        max_retries=1,
        retry_base_delay=1,
    )

    result = provider.generate("hello")

    assert result == '{"status":"ok"}'
    assert len(calls) == 2
    assert sleeps == [7]


def test_gemini_invalid_retry_after_uses_backoff(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    calls = []
    sleeps = []

    success_body = json.dumps(
        {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {"text": '{"status":"ok"}'}
                        ]
                    }
                }
            ]
        }
    ).encode()

    def fake_urlopen(request, timeout):
        calls.append(1)

        if len(calls) == 1:
            raise urllib.error.HTTPError(
                request.full_url,
                503,
                "Service Unavailable",
                {"Retry-After": "not-a-number"},
                io.BytesIO(
                    b'{"error":{"status":"UNAVAILABLE","message":"busy"}}'
                ),
            )

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self):
                return success_body

        return FakeResponse()

    monkeypatch.setattr(
        "scripts.triager.providers.urllib.request.urlopen",
        fake_urlopen,
    )
    monkeypatch.setattr(
        "scripts.triager.providers.time.sleep",
        sleeps.append,
    )

    provider = GeminiAIProvider(
        max_retries=1,
        retry_base_delay=3,
    )

    result = provider.generate("hello")

    assert result == '{"status":"ok"}'
    assert len(calls) == 2
    assert sleeps == [3]


def test_gemini_max_retries_must_be_non_negative(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setenv("GEMINI_MAX_RETRIES", "-1")

    with pytest.raises(
        AIProviderError,
        match="GEMINI_MAX_RETRIES must be a non-negative integer",
    ):
        GeminiAIProvider()


def test_gemini_max_retries_must_be_integer(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setenv("GEMINI_MAX_RETRIES", "not-an-integer")

    with pytest.raises(
        AIProviderError,
        match="GEMINI_MAX_RETRIES must be a non-negative integer",
    ):
        GeminiAIProvider()


def test_gemini_retry_base_delay_must_be_non_negative(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setenv("GEMINI_RETRY_BASE_DELAY", "-1")

    with pytest.raises(
        AIProviderError,
        match="GEMINI_RETRY_BASE_DELAY must be a non-negative number",
    ):
        GeminiAIProvider()


def test_gemini_retry_configuration_from_environment(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setenv("GEMINI_MAX_RETRIES", "5")
    monkeypatch.setenv("GEMINI_RETRY_BASE_DELAY", "2.5")

    provider = GeminiAIProvider()

    assert provider.max_retries == 5
    assert provider.retry_base_delay == 2.5