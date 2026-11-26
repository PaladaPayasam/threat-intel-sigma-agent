"""Fetch and extract clean cyber threat intelligence text from URLs or raw input."""

from __future__ import annotations

import re
from urllib.parse import urlparse

import trafilatura


class CTIFetchError(RuntimeError):
    """Raised when threat intelligence text cannot be retrieved or extracted."""


def _normalize_text(text: str, max_chars: int) -> str:
    cleaned = re.sub(r"\n{3,}", "\n\n", text).strip()
    if len(cleaned) > max_chars:
        return cleaned[:max_chars].rstrip()
    return cleaned


def fetch_cti_text(
    url: str | None = None,
    raw_text: str | None = None,
    *,
    max_chars: int = 24000,
) -> str:
    """Return clean threat report text from ``raw_text`` or a remote ``url``."""
    if raw_text and raw_text.strip():
        normalized = _normalize_text(raw_text, max_chars=max_chars)
        if len(normalized) < 20:
            raise CTIFetchError("Provided raw threat text is too short to analyze.")
        return normalized

    if not url or not url.strip():
        raise CTIFetchError("Either a threat report URL or raw_text must be provided.")

    target_url = url.strip()
    parsed = urlparse(target_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise CTIFetchError(f"Invalid CTI URL: {target_url}")

    downloaded = trafilatura.fetch_url(target_url)
    if not downloaded:
        raise CTIFetchError(f"Failed to download threat report from URL: {target_url}")

    extracted = trafilatura.extract(
        downloaded,
        include_comments=False,
        include_tables=True,
        favor_precision=True,
    )
    if not extracted or len(extracted.strip()) < 50:
        raise CTIFetchError(
            f"Unable to extract meaningful article text from URL: {target_url}"
        )

    return _normalize_text(extracted, max_chars=max_chars)
