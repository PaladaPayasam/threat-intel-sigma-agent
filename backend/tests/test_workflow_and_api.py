"""Tests for LangGraph workflow, retry loop, and FastAPI endpoints."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import httpx
import pytest

from app.graph.workflow import build_sigma_workflow
from app.main import app
from app.schemas import ExtractedCTI, RetrievedRuleReference, SigmaLogsource

VALID_SIGMA_YAML = """title: Suspicious Certutil Download
id: 99999999-1111-4222-8333-444444444444
status: experimental
description: Detects certutil.exe downloading remote payloads.
tags:
  - attack.command_and_control
  - attack.t1105
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\certutil.exe'
    CommandLine|contains:
      - 'urlcache'
      - '-split'
  filter_legit:
    ParentImage|endswith: '\\explorer.exe'
  condition: selection and not filter_legit
falsepositives:
  - Legitimate certificate cache verification
level: high
"""

INVALID_SIGMA_YAML = """title: Broken Rule
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\certutil.exe'
  condition: missing_selection
"""


class _FakeStructuredLLM:
    def invoke(self, _messages):
        return ExtractedCTI(
            threat_title="Certutil Remote Payload Staging",
            summary="Threat actor abuses certutil.exe to download payloads.",
            mitre_attack_tags=["attack.command_and_control", "attack.t1105"],
            logsource=SigmaLogsource(category="process_creation", product="windows"),
            suspicious_behaviors=["Abuse of certutil.exe with -urlcache and -split"],
            iocs=["certutil.exe -urlcache -split -f"],
        )


class _FakeLLM:
    def __init__(self, responses: list[str]) -> None:
        self._responses = list(responses)
        self.calls = 0

    def with_structured_output(self, _schema):
        return _FakeStructuredLLM()

    def invoke(self, _messages):
        idx = min(self.calls, len(self._responses) - 1)
        self.calls += 1
        return SimpleNamespace(content=self._responses[idx])


class _FakeRetriever:
    def search(self, query: str, **_kwargs) -> list[RetrievedRuleReference]:
        return [
            RetrievedRuleReference(
                title="Certutil Download",
                logsource={"category": "process_creation", "product": "windows"},
                detection_fields=["CommandLine", "Image", "ParentImage"],
                raw_yaml=VALID_SIGMA_YAML,
                score=0.95,
            )
        ]

    def close(self) -> None:
        return None


def test_workflow_self_correction_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_llm = _FakeLLM([f"```yaml\n{INVALID_SIGMA_YAML}\n```", VALID_SIGMA_YAML])
    fake_retriever = _FakeRetriever()

    monkeypatch.setattr("app.graph.nodes.get_llm", lambda: fake_llm)
    monkeypatch.setattr("app.graph.nodes.get_retriever", lambda: fake_retriever)

    workflow = build_sigma_workflow()
    result = workflow.invoke(
        {
            "raw_text": "Threat actors ran certutil.exe -urlcache -split to download malware.",
            "attempts": 0,
            "max_retries": 3,
            "validation_error": None,
        }
    )

    assert result["attempts"] == 2
    assert result["validation"].is_valid is True
    assert "EventID=1" in result["validation"].splunk_spl
    assert "certutil.exe" in result["validation"].sentinel_kql


def test_workflow_stops_after_max_retries(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_llm = _FakeLLM([INVALID_SIGMA_YAML])
    monkeypatch.setattr("app.graph.nodes.get_llm", lambda: fake_llm)
    monkeypatch.setattr("app.graph.nodes.get_retriever", lambda: _FakeRetriever())

    workflow = build_sigma_workflow()
    result = workflow.invoke(
        {
            "raw_text": "Threat actors ran certutil.exe -urlcache -split to download malware.",
            "attempts": 0,
            "max_retries": 3,
            "validation_error": None,
        }
    )

    assert result["attempts"] == 3
    assert result["validation"].is_valid is False
    assert result["validation"].error is not None


def test_fastapi_generate_and_stream_endpoints(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_llm = _FakeLLM([VALID_SIGMA_YAML])
    fake_retriever = _FakeRetriever()
    monkeypatch.setattr("app.graph.nodes.get_llm", lambda: fake_llm)
    monkeypatch.setattr("app.graph.nodes.get_retriever", lambda: fake_retriever)
    monkeypatch.setattr("app.main.get_retriever", lambda: fake_retriever)

    async def _exercise_api() -> None:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
            timeout=10.0,
        ) as client:
            preflight = await client.options(
                "/api/v1/generate",
                headers={
                    "Origin": "http://localhost:5173",
                    "Access-Control-Request-Method": "POST",
                },
            )
            assert preflight.status_code == 200
            assert (
                preflight.headers.get("access-control-allow-origin")
                == "http://localhost:5173"
            )

            resp = await client.post(
                "/api/v1/generate",
                json={
                    "raw_text": "Threat actors used certutil.exe -urlcache -split to fetch payloads."
                },
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "success"
            assert data["attempts"] == 1
            assert "EventID=1" in data["splunk_spl"]
            assert "certutil.exe" in data["sentinel_kql"]

            chunks: list[str] = []
            async with client.stream(
                "POST",
                "/api/v1/generate/stream",
                json={
                    "raw_text": "Threat actors used certutil.exe -urlcache -split to fetch payloads."
                },
            ) as stream_resp:
                assert stream_resp.status_code == 200
                async for text in stream_resp.aiter_text():
                    chunks.append(text)

            body = "".join(chunks)
            assert "event: progress" in body
            assert "event: complete" in body
            for block in body.strip().split("\n\n"):
                if block.startswith("event: complete"):
                    data_line = next(
                        line for line in block.splitlines() if line.startswith("data: ")
                    )
                    complete_payload = json.loads(data_line.removeprefix("data: "))
                    assert complete_payload["status"] == "success"
                    assert complete_payload["sigma_yaml"].startswith(
                        "title: Suspicious Certutil Download"
                    )

    asyncio.run(asyncio.wait_for(_exercise_api(), timeout=15.0))
