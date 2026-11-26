"""pySigma validation and SIEM query compilation (Splunk SPL & Sentinel KQL)."""

from __future__ import annotations

import re

import yaml
from sigma.backends.microsoft365defender import backends as _m365_backends
from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError
from sigma.pipelines.sysmon import sysmon_pipeline

from app.schemas import ValidationResult

Microsoft365DefenderBackend = _m365_backends["microsoft365defender"]

# Backwards-compatible alias for earlier imports
SigmaValidationResult = ValidationResult

_FENCE_RE = re.compile(r"^```(?:ya?ml)?\s*\n(.*?)\n```\s*$", re.DOTALL | re.IGNORECASE)


def _clean_sigma_yaml(raw_yaml: str) -> str:
    """Strip optional markdown YAML code fences around a Sigma rule."""
    stripped = raw_yaml.strip()
    match = _FENCE_RE.match(stripped)
    if match:
        return match.group(1).strip()
    return stripped


def validate_and_compile_sigma(rule_yaml: str) -> ValidationResult:
    """Validate a Sigma YAML rule and transpile it to Splunk SPL and Sentinel KQL.

    Each backend receives a freshly parsed ``SigmaCollection`` because applying
    ``sysmon_pipeline()`` mutates rule detections in place.
    """
    cleaned_yaml = _clean_sigma_yaml(rule_yaml)
    if not cleaned_yaml:
        return ValidationResult(
            is_valid=False,
            error="Sigma YAML input is empty.",
        )

    try:
        base_collection = SigmaCollection.from_yaml(cleaned_yaml)
        if not base_collection.rules:
            return ValidationResult(
                is_valid=False,
                error="No Sigma rules were parsed from the provided YAML.",
            )

        splunk_backend = SplunkBackend(processing_pipeline=sysmon_pipeline())
        splunk_queries = [
            str(q) for q in splunk_backend.convert(SigmaCollection.from_yaml(cleaned_yaml))
        ]

        sentinel_backend = Microsoft365DefenderBackend()
        sentinel_queries = [
            str(q) for q in sentinel_backend.convert(SigmaCollection.from_yaml(cleaned_yaml))
        ]
    except (SigmaError, yaml.YAMLError, ValueError, TypeError, NotImplementedError) as exc:
        return ValidationResult(
            is_valid=False,
            error=f"{type(exc).__name__}: {exc}",
        )

    return ValidationResult(
        is_valid=True,
        splunk_spl="\n".join(splunk_queries),
        sentinel_kql="\n".join(sentinel_queries),
        splunk_queries=splunk_queries,
        sentinel_queries=sentinel_queries,
    )
