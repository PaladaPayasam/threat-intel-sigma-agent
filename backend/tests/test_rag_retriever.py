"""Integration tests for hybrid Qdrant + FastEmbed SigmaHQ retrieval."""

from pathlib import Path

import pytest

from app.rag.retriever import SigmaRetriever


@pytest.mark.skipif(
    not Path("./qdrant_db").exists(),
    reason="Local qdrant_db index has not been ingested yet.",
)
def test_hybrid_retriever_returns_grounded_sigma_rules() -> None:
    retriever = SigmaRetriever(qdrant_path="./qdrant_db")
    try:
        results = retriever.search(
            "powershell encoded command execution bypass",
            logsource_category="process_creation",
            product="windows",
            limit=5,
        )
        assert len(results) == 5
        assert any(
            "CommandLine" in rule.detection_fields or "Image" in rule.detection_fields
            for rule in results
        )
        assert all(rule.raw_yaml for rule in results)

        file_results = retriever.search(
            "payload dropped executable file in temp directory",
            logsource_category="file_event",
            product="windows",
            limit=3,
        )
        assert len(file_results) == 3
        assert any("TargetFilename" in rule.detection_fields for rule in file_results)
    finally:
        retriever.close()
