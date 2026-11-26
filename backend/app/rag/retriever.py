"""Hybrid Qdrant retriever (FastEmbed dense + BM25 sparse with RRF fusion)."""

from __future__ import annotations

from pathlib import Path

from fastembed import SparseTextEmbedding, TextEmbedding
from qdrant_client import QdrantClient, models

from app.rag.ingest_sigma import (
    COLLECTION_NAME,
    DEFAULT_QDRANT_PATH,
    DENSE_MODEL_NAME,
    SPARSE_MODEL_NAME,
)
from app.schemas import RetrievedRuleReference


class SigmaRetriever:
    """Hybrid retriever over indexed SigmaHQ rules in local embedded Qdrant."""

    def __init__(
        self,
        *,
        qdrant_path: Path | str = DEFAULT_QDRANT_PATH,
        collection_name: str = COLLECTION_NAME,
        client: QdrantClient | None = None,
    ) -> None:
        self._qdrant_path = Path(qdrant_path)
        self._collection_name = collection_name
        self._client = client
        self._owns_client = client is None
        self._dense_model: TextEmbedding | None = None
        self._sparse_model: SparseTextEmbedding | None = None

    def _open_client(self) -> tuple[QdrantClient, bool]:
        if self._client is not None:
            return self._client, False
        return QdrantClient(path=str(self._qdrant_path)), True

    def _get_models(self) -> tuple[TextEmbedding, SparseTextEmbedding]:
        if self._dense_model is None:
            self._dense_model = TextEmbedding(model_name=DENSE_MODEL_NAME)
        if self._sparse_model is None:
            self._sparse_model = SparseTextEmbedding(model_name=SPARSE_MODEL_NAME)
        return self._dense_model, self._sparse_model

    def close(self) -> None:
        if self._client is not None and self._owns_client:
            self._client.close()
            self._client = None

    def _build_filter(
        self,
        logsource_category: str | None,
        product: str | None,
    ) -> models.Filter | None:
        conditions: list[models.Condition] = []
        if logsource_category:
            conditions.append(
                models.FieldCondition(
                    key="logsource_category",
                    match=models.MatchValue(value=logsource_category.strip().lower()),
                )
            )
        if product:
            conditions.append(
                models.FieldCondition(
                    key="logsource_product",
                    match=models.MatchValue(value=product.strip().lower()),
                )
            )
        if not conditions:
            return None
        return models.Filter(must=conditions)

    def search(
        self,
        query: str,
        *,
        logsource_category: str | None = None,
        product: str | None = None,
        limit: int = 5,
    ) -> list[RetrievedRuleReference]:
        """Retrieve top-k SigmaHQ rules using RRF over dense + BM25 sparse search."""
        if self._owns_client and not self._qdrant_path.exists():
            return []

        client, should_close = self._open_client()
        try:
            if not client.collection_exists(self._collection_name):
                return []

            dense_model, sparse_model = self._get_models()
            dense_vec = next(dense_model.embed([query])).tolist()
            sparse_raw = next(sparse_model.embed([query]))
            sparse_vec = models.SparseVector(
                indices=sparse_raw.indices.tolist(),
                values=sparse_raw.values.tolist(),
            )

            query_filter = self._build_filter(logsource_category, product)
            prefetch_limit = max(limit * 3, 15)

            response = client.query_points(
                collection_name=self._collection_name,
                prefetch=[
                    models.Prefetch(
                        query=dense_vec,
                        using="dense",
                        filter=query_filter,
                        limit=prefetch_limit,
                    ),
                    models.Prefetch(
                        query=sparse_vec,
                        using="bm25",
                        filter=query_filter,
                        limit=prefetch_limit,
                    ),
                ],
                query=models.FusionQuery(fusion=models.Fusion.RRF),
                limit=limit,
                with_payload=True,
            )

            # Fallback without metadata filter if strict category/product filter is too narrow
            if query_filter is not None and len(response.points) < 2:
                response = client.query_points(
                    collection_name=self._collection_name,
                    prefetch=[
                        models.Prefetch(query=dense_vec, using="dense", limit=prefetch_limit),
                        models.Prefetch(query=sparse_vec, using="bm25", limit=prefetch_limit),
                    ],
                    query=models.FusionQuery(fusion=models.Fusion.RRF),
                    limit=limit,
                    with_payload=True,
                )

            results: list[RetrievedRuleReference] = []
            for point in response.points:
                payload = point.payload or {}
                results.append(
                    RetrievedRuleReference(
                        title=str(payload.get("title", "Untitled Rule")),
                        logsource=dict(payload.get("logsource") or {}),
                        detection_fields=list(payload.get("detection_fields") or []),
                        raw_yaml=str(payload.get("raw_yaml", "")),
                        score=float(point.score) if point.score is not None else None,
                    )
                )
            return results
        finally:
            if should_close:
                client.close()


_default_retriever: SigmaRetriever | None = None


def get_retriever() -> SigmaRetriever:
    """Return a shared local embedded SigmaRetriever instance."""
    global _default_retriever
    if _default_retriever is None:
        _default_retriever = SigmaRetriever()
    return _default_retriever
