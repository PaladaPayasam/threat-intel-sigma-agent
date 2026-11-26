"""LangGraph nodes for CTI extraction, RAG grounding, Sigma YAML generation, and validation."""

from __future__ import annotations

import os
from typing import Any

from dotenv import load_dotenv
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_google_genai import ChatGoogleGenerativeAI

from app.graph.state import SigmaAgentState
from app.rag.retriever import get_retriever
from app.schemas import ExtractedCTI, RetrievedRuleReference
from app.tools.cti_fetcher import fetch_cti_text
from app.tools.sigma_engine import _clean_sigma_yaml, validate_and_compile_sigma

load_dotenv()

DEFAULT_LLM_MODEL = "gemini-4-hydrogen"


def get_llm() -> ChatGoogleGenerativeAI:
    """Instantiate the configured Google Gemini chat model."""
    return ChatGoogleGenerativeAI(
        model=DEFAULT_LLM_MODEL,
        temperature=0.1,
        google_api_key=os.getenv("GOOGLE_API_KEY"),
    )


def _extract_message_text(content: Any) -> str:
    """Normalize LangChain message content (str or content block list) into text."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict) and "text" in item:
                parts.append(str(item["text"]))
        return "\n".join(parts)
    return str(content)


def extract_cti(state: SigmaAgentState) -> dict[str, Any]:
    """Fetch threat report text (if needed) and extract structured CTI."""
    cti_text = state.get("cti_text")
    if not cti_text:
        cti_text = fetch_cti_text(url=state.get("url"), raw_text=state.get("raw_text"))

    llm = get_llm()
    structured_llm = llm.with_structured_output(ExtractedCTI)

    system_prompt = (
        "You are a senior cyber threat intelligence (CTI) analyst and detection engineer. "
        "Extract structured detection-relevant threat intelligence from the provided report. "
        "Format MITRE ATT&CK tags in lowercase Sigma format (e.g., 'attack.execution', "
        "'attack.t1059.001'). Choose the single most appropriate Sigma logsource "
        "(e.g., category='process_creation', product='windows', or category='file_event'). "
        "Prioritize behavioral indicators (process names, command-line flags, parent-child "
        "relationships, file paths, registry keys) over volatile atomic hashes or IPs."
    )
    extracted: ExtractedCTI = structured_llm.invoke(
        [
            SystemMessage(content=system_prompt),
            HumanMessage(content=f"Threat Report:\n\n{cti_text}"),
        ]
    )

    return {
        "cti_text": cti_text,
        "extracted_cti": extracted,
    }


def rag_grounding(state: SigmaAgentState) -> dict[str, Any]:
    """Query local Qdrant hybrid search for SigmaHQ reference rules and field names."""
    extracted = state["extracted_cti"]
    query_parts = [
        extracted.threat_title,
        extracted.summary,
        " ".join(extracted.mitre_attack_tags),
        " ".join(extracted.suspicious_behaviors[:8]),
        " ".join(extracted.iocs[:8]),
    ]
    query = " | ".join(part for part in query_parts if part)

    retriever = get_retriever()
    retrieved: list[RetrievedRuleReference] = retriever.search(
        query=query,
        logsource_category=extracted.logsource.category,
        product=extracted.logsource.product,
        limit=5,
    )
    return {"retrieved_rules": retrieved}


def _format_rag_context(rules: list[RetrievedRuleReference]) -> str:
    if not rules:
        return "No SigmaHQ reference rules found. Use standard Sysmon/Windows/Linux Sigma fields."

    blocks: list[str] = []
    for idx, rule in enumerate(rules, start=1):
        fields_str = ", ".join(rule.detection_fields) if rule.detection_fields else "N/A"
        blocks.append(
            f"--- Reference Rule {idx}: {rule.title} ---\n"
            f"Logsource: {rule.logsource}\n"
            f"Valid Fields: {fields_str}\n"
            f"YAML Excerpt:\n{rule.raw_yaml[:1200]}"
        )
    return "\n\n".join(blocks)


def generate_sigma(state: SigmaAgentState) -> dict[str, Any]:
    """Generate or self-correct a Sigma YAML rule grounded in CTI and SigmaHQ schemas."""
    extracted = state["extracted_cti"]
    retrieved_rules = state.get("retrieved_rules", [])
    validation_error = state.get("validation_error")
    previous_yaml = state.get("sigma_yaml")
    attempts = state.get("attempts", 0) + 1

    rag_context = _format_rag_context(retrieved_rules)

    system_prompt = (
        "You are an expert Sigma detection engineer. Generate ONE valid Sigma YAML rule "
        "based strictly on the extracted threat intelligence and grounded SigmaHQ field names.\n\n"
        "Requirements:\n"
        "- Output ONLY valid raw Sigma YAML (no prose, no markdown fences if avoidable).\n"
        "- Include: title, id (valid UUIDv4), status: experimental, description, tags "
        "(lowercase attack.*), logsource, detection, falsepositives, level.\n"
        "- Inside detection, define 'selection' and 'filter_legit' (to exclude benign "
        "administrative/OS activity), and set 'condition: selection and not filter_legit'.\n"
        "- Use exact Sigma field names from the SigmaHQ reference rules (e.g., Image, "
        "CommandLine, ParentImage, OriginalFileName, TargetFilename, User).\n"
        "- Escape Windows backslashes appropriately in YAML strings."
    )

    human_sections = [
        f"Extracted CTI:\n{extracted.model_dump_json(indent=2)}",
        f"Grounded SigmaHQ Reference Rules:\n{rag_context}",
    ]
    if validation_error and previous_yaml:
        human_sections.append(
            f"PREVIOUS ATTEMPT FAILED VALIDATION.\n"
            f"pySigma Error:\n{validation_error}\n\n"
            f"Previous Invalid YAML:\n{previous_yaml}\n\n"
            "Fix the YAML error while preserving the detection intent."
        )

    llm = get_llm()
    response = llm.invoke(
        [
            SystemMessage(content=system_prompt),
            HumanMessage(content="\n\n".join(human_sections)),
        ]
    )
    sigma_yaml = _clean_sigma_yaml(_extract_message_text(response.content))

    return {
        "sigma_yaml": sigma_yaml,
        "attempts": attempts,
    }


def validate_sigma(state: SigmaAgentState) -> dict[str, Any]:
    """Validate Sigma YAML and transpile to Splunk SPL and Sentinel KQL via pySigma."""
    sigma_yaml = state.get("sigma_yaml", "")
    result = validate_and_compile_sigma(sigma_yaml)
    return {
        "validation": result,
        "validation_error": None if result.is_valid else result.error,
    }
