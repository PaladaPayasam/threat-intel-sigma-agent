"""LangGraph StateGraph assembly with conditional pySigma self-correction loop."""

from __future__ import annotations

from typing import Literal

from langgraph.graph import END, StateGraph

from app.graph.nodes import extract_cti, generate_sigma, rag_grounding, validate_sigma
from app.graph.state import SigmaAgentState


def should_retry_sigma(state: SigmaAgentState) -> Literal["retry", "end"]:
    """Route back to generate_sigma on pySigma error until max_retries is reached."""
    validation = state.get("validation")
    if validation is not None and validation.is_valid:
        return "end"

    attempts = state.get("attempts", 0)
    max_retries = state.get("max_retries", 3)
    if attempts < max_retries:
        return "retry"
    return "end"


def build_sigma_workflow():
    """Compile the 4-node CTI-to-Sigma LangGraph workflow."""
    graph = StateGraph(SigmaAgentState)

    graph.add_node("extract_cti", extract_cti)
    graph.add_node("rag_grounding", rag_grounding)
    graph.add_node("generate_sigma", generate_sigma)
    graph.add_node("validate_sigma", validate_sigma)

    graph.set_entry_point("extract_cti")
    graph.add_edge("extract_cti", "rag_grounding")
    graph.add_edge("rag_grounding", "generate_sigma")
    graph.add_edge("generate_sigma", "validate_sigma")
    graph.add_conditional_edges(
        "validate_sigma",
        should_retry_sigma,
        {
            "retry": "generate_sigma",
            "end": END,
        },
    )

    return graph.compile()


sigma_workflow = build_sigma_workflow()
