"""LangGraph shared state definition for the Sigma generation workflow."""

from __future__ import annotations

from typing import TypedDict

from app.schemas import ExtractedCTI, RetrievedRuleReference, ValidationResult


class SigmaAgentState(TypedDict, total=False):
    """State passed across the CTI-to-Sigma LangGraph nodes."""

    url: str | None
    raw_text: str | None
    cti_text: str
    extracted_cti: ExtractedCTI
    retrieved_rules: list[RetrievedRuleReference]
    sigma_yaml: str
    validation: ValidationResult
    validation_error: str | None
    attempts: int
    max_retries: int
