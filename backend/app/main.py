"""FastAPI server exposing synchronous and SSE-streaming Sigma generation endpoints."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.concurrency import iterate_in_threadpool, run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from app.graph.state import SigmaAgentState
from app.graph.workflow import sigma_workflow
from app.rag.retriever import get_retriever
from app.schemas import GenerateRequest, GenerateResponse
from app.tools.cti_fetcher import CTIFetchError

load_dotenv()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    try:
        yield
    finally:
        get_retriever().close()


app = FastAPI(
    title="Threat-Intel Sigma Rule Agent",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _build_initial_state(req: GenerateRequest) -> SigmaAgentState:
    return {
        "url": req.url.strip() if req.url else None,
        "raw_text": req.raw_text.strip() if req.raw_text else None,
        "attempts": 0,
        "max_retries": req.max_retries,
        "validation_error": None,
    }


def _state_to_response(state: dict[str, Any]) -> GenerateResponse:
    validation = state.get("validation")
    is_valid = bool(validation and validation.is_valid)
    return GenerateResponse(
        status="success" if is_valid else "failed",
        extracted_cti=state.get("extracted_cti"),
        retrieved_rules=state.get("retrieved_rules", []),
        sigma_yaml=state.get("sigma_yaml"),
        splunk_spl=validation.splunk_spl if validation else None,
        sentinel_kql=validation.sentinel_kql if validation else None,
        validation=validation,
        attempts=state.get("attempts", 0),
        error=None if is_valid else (validation.error if validation else "Workflow failed."),
    )


def _format_sse(event: str, data: dict[str, Any]) -> str:
    return f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n"


def _iter_sse_events(initial_state: SigmaAgentState) -> Iterator[str]:
    merged_state: dict[str, Any] = dict(initial_state)
    try:
        for update in sigma_workflow.stream(initial_state, stream_mode="updates"):
            for node_name, node_output in update.items():
                if isinstance(node_output, dict):
                    merged_state.update(node_output)
                payload: dict[str, Any] = {
                    "node": node_name,
                    "attempts": merged_state.get("attempts", 0),
                }
                if node_name == "extract_cti" and merged_state.get("extracted_cti"):
                    payload["extracted_cti"] = merged_state["extracted_cti"].model_dump()
                elif node_name == "rag_grounding":
                    rules = merged_state.get("retrieved_rules", [])
                    payload["retrieved_count"] = len(rules)
                    payload["retrieved_titles"] = [r.title for r in rules]
                elif node_name == "generate_sigma":
                    payload["sigma_yaml"] = merged_state.get("sigma_yaml")
                elif node_name == "validate_sigma" and merged_state.get("validation"):
                    payload["validation"] = merged_state["validation"].model_dump()
                yield _format_sse("progress", payload)

        final_response = _state_to_response(merged_state).model_dump()
        yield _format_sse("complete", final_response)
        return
    except Exception as exc:  # noqa: BLE001
        yield _format_sse("error", {"error": str(exc)})
        return


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/v1/generate", response_model=GenerateResponse)
async def generate_sigma_rule(request: GenerateRequest) -> GenerateResponse:
    """Run the full CTI -> RAG -> Sigma -> pySigma pipeline and return the result."""
    initial_state = _build_initial_state(request)
    try:
        final_state = await run_in_threadpool(sigma_workflow.invoke, initial_state)
    except CTIFetchError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _state_to_response(final_state)


@app.post("/api/v1/generate/stream")
async def stream_sigma_rule(request: GenerateRequest) -> StreamingResponse:
    """Stream step-by-step LangGraph node progress via Server-Sent Events (SSE)."""
    initial_state = _build_initial_state(request)

    async def event_generator() -> AsyncIterator[str]:
        async for chunk in iterate_in_threadpool(_iter_sse_events(initial_state)):
            yield chunk
        return

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
