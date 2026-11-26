"""Pydantic schemas for CTI extraction, Sigma validation, and API I/O."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator


class SigmaLogsource(BaseModel):
    """Target Sigma logsource inferred from a threat intelligence report."""

    category: str = Field(
        ...,
        description="Sigma logsource category such as process_creation, file_event, network_connection, dns_query.",
    )
    product: str = Field(
        default="windows",
        description="Target platform/product such as windows or linux.",
    )
    service: str | None = Field(
        default=None,
        description="Optional Sigma logsource service (e.g., sysmon, security, powershell).",
    )


class ExtractedCTI(BaseModel):
    """Structured cyber threat intelligence extracted from a threat report."""

    threat_title: str = Field(..., description="Concise title describing the threat or malware behavior.")
    summary: str = Field(..., description="Brief technical summary of the attack behavior.")
    mitre_attack_tags: list[str] = Field(
        default_factory=list,
        description="Lowercase MITRE ATT&CK Sigma tags such as attack.execution or attack.t1059.001.",
    )
    logsource: SigmaLogsource = Field(..., description="Primary Sigma logsource for detection.")
    suspicious_behaviors: list[str] = Field(
        default_factory=list,
        description="Observed adversary TTPs and execution behaviors to detect.",
    )
    iocs: list[str] = Field(
        default_factory=list,
        description="Behavioral indicators (commands, process paths, filenames, registry paths, flags).",
    )


class ValidationResult(BaseModel):
    """Outcome of pySigma validation and SIEM query transpilation."""

    is_valid: bool
    splunk_spl: str | None = None
    sentinel_kql: str | None = None
    splunk_queries: list[str] = Field(default_factory=list)
    sentinel_queries: list[str] = Field(default_factory=list)
    error: str | None = None


class RetrievedRuleReference(BaseModel):
    """Grounded SigmaHQ reference rule returned by hybrid RAG search."""

    title: str
    logsource: dict[str, Any] = Field(default_factory=dict)
    detection_fields: list[str] = Field(default_factory=list)
    raw_yaml: str
    score: float | None = None


class GenerateRequest(BaseModel):
    """Request payload for generating a Sigma rule from a CTI URL or raw text."""

    url: str | None = Field(default=None, description="URL of a threat intelligence article.")
    raw_text: str | None = Field(default=None, description="Raw threat intelligence text.")
    max_retries: int = Field(default=3, ge=1, le=5)

    @model_validator(mode="after")
    def _validate_input_source(self) -> GenerateRequest:
        has_url = bool(self.url and self.url.strip())
        has_text = bool(self.raw_text and self.raw_text.strip())
        if not has_url and not has_text:
            raise ValueError("Either 'url' or 'raw_text' must be provided.")
        return self


class GenerateResponse(BaseModel):
    """Final response returned by the Sigma rule generation pipeline."""

    status: Literal["success", "failed"]
    extracted_cti: ExtractedCTI | None = None
    retrieved_rules: list[RetrievedRuleReference] = Field(default_factory=list)
    sigma_yaml: str | None = None
    splunk_spl: str | None = None
    sentinel_kql: str | None = None
    validation: ValidationResult | None = None
    attempts: int = 0
    error: str | None = None
