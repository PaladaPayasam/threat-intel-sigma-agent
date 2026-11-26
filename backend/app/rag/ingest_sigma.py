"""Shallow-clone SigmaHQ rules and index them into local embedded Qdrant."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Any

import yaml
from fastembed import SparseTextEmbedding, TextEmbedding
from qdrant_client import QdrantClient, models

SIGMA_REPO_URL = "https://github.com/SigmaHQ/sigma.git"
DEFAULT_DATA_DIR = Path("./data/sigma")
DEFAULT_QDRANT_PATH = Path("./qdrant_db")
COLLECTION_NAME = "sigma_rules"
DENSE_MODEL_NAME = "BAAI/bge-small-en-v1.5"
SPARSE_MODEL_NAME = "Qdrant/bm25"

TARGET_SUBDIRS: tuple[str, ...] = (
    "rules/windows/process_creation",
    "rules/windows/file/file_event",
    "rules/linux",
)

_FALLBACK_GIT_PATHS: tuple[str, ...] = (
    r"C:\Program Files\Git\cmd\git.exe",
    r"C:\Program Files (x86)\Git\cmd\git.exe",
)


def _find_git_executable() -> str:
    """Locate the git binary on PATH or standard Windows install locations."""
    git_bin = shutil.which("git")
    if git_bin:
        return git_bin
    for candidate in _FALLBACK_GIT_PATHS:
        if Path(candidate).is_file():
            return candidate
    raise FileNotFoundError(
        "Git executable not found on PATH or in standard Program Files locations."
    )


def clone_sigma_repo(data_dir: Path = DEFAULT_DATA_DIR) -> Path:
    """Shallow-clone SigmaHQ/sigma into ``data_dir`` if not already present."""
    rules_dir = data_dir / "rules"
    if rules_dir.is_dir():
        return data_dir

    data_dir.parent.mkdir(parents=True, exist_ok=True)
    git_bin = _find_git_executable()
    subprocess.run(
        [git_bin, "clone", "--depth", "1", SIGMA_REPO_URL, str(data_dir)],
        check=True,
    )
    return data_dir


def extract_detection_fields(detection: Any) -> list[str]:
    """Extract unique Sigma field names from a rule's detection block."""
    if not isinstance(detection, dict):
        return []

    fields: set[str] = set()

    def _collect(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(key, str) and key not in {"condition", "timeframe"}:
                    base_field = key.split("|", 1)[0].strip()
                    if base_field:
                        fields.add(base_field)
                _collect(value)
        elif isinstance(node, list):
            for item in node:
                _collect(item)

    for section_name, section_body in detection.items():
        if section_name in {"condition", "timeframe"}:
            continue
        _collect(section_body)

    return sorted(fields)


def collect_rule_files(
    data_dir: Path,
    subdirs: tuple[str, ...] = TARGET_SUBDIRS,
    max_rules: int = 450,
) -> list[Path]:
    """Collect up to ``max_rules`` YAML rule paths balanced across ``subdirs``."""
    buckets: list[list[Path]] = []
    for rel in subdirs:
        root = data_dir / rel
        if not root.is_dir():
            continue
        files = sorted(
            p for p in root.rglob("*.yml") if p.is_file()
        )
        if files:
            buckets.append(files)

    if not buckets:
        return []

    selected: list[Path] = []
    index = 0
    while len(selected) < max_rules:
        added_this_round = False
        for bucket in buckets:
            if index < len(bucket):
                selected.append(bucket[index])
                added_this_round = True
                if len(selected) >= max_rules:
                    break
        if not added_this_round:
            break
        index += 1

    return selected


def parse_sigma_rule_file(rule_path: Path, data_dir: Path) -> dict[str, Any] | None:
    """Parse a Sigma YAML file into an indexable record, or None if unusable."""
    try:
        raw_yaml = rule_path.read_text(encoding="utf-8")
        parsed = yaml.safe_load(raw_yaml)
    except (OSError, UnicodeDecodeError, yaml.YAMLError):
        return None

    if not isinstance(parsed, dict):
        return None
    if "detection" not in parsed or "logsource" not in parsed or "title" not in parsed:
        return None

    title = str(parsed.get("title", "")).strip()
    if not title:
        return None

    logsource = parsed.get("logsource")
    if not isinstance(logsource, dict):
        return None

    description = str(parsed.get("description", "")).strip()
    tags = [str(t).strip() for t in (parsed.get("tags") or []) if str(t).strip()]
    detection_fields = extract_detection_fields(parsed.get("detection"))

    try:
        source_path = rule_path.relative_to(data_dir).as_posix()
    except ValueError:
        source_path = rule_path.name

    logsource_parts = [
        f"{k}={v}" for k, v in logsource.items() if isinstance(v, (str, int))
    ]
    document_text = "\n".join(
        [
            f"Title: {title}",
            f"Description: {description}",
            f"Logsource: {', '.join(logsource_parts)}",
            f"Tags: {', '.join(tags)}",
            f"Fields: {', '.join(detection_fields)}",
            f"YAML:\n{raw_yaml[:2500]}",
        ]
    )

    return {
        "id": str(uuid.uuid5(uuid.NAMESPACE_URL, source_path)),
        "source_path": source_path,
        "title": title,
        "description": description,
        "tags": tags,
        "logsource": logsource,
        "logsource_category": str(logsource.get("category", "")).lower(),
        "logsource_product": str(logsource.get("product", "")).lower(),
        "detection_fields": detection_fields,
        "raw_yaml": raw_yaml,
        "document_text": document_text,
    }


def ingest_sigma_rules(
    *,
    data_dir: Path = DEFAULT_DATA_DIR,
    qdrant_path: Path = DEFAULT_QDRANT_PATH,
    collection_name: str = COLLECTION_NAME,
    max_rules: int = 450,
    batch_size: int = 64,
    skip_clone: bool = False,
) -> int:
    """Clone SigmaHQ rules (if needed) and index them into local embedded Qdrant."""
    if not skip_clone:
        clone_sigma_repo(data_dir)

    rule_paths = collect_rule_files(data_dir=data_dir, max_rules=max_rules)
    records = [
        rec
        for path in rule_paths
        if (rec := parse_sigma_rule_file(path, data_dir)) is not None
    ]
    if not records:
        raise RuntimeError(f"No valid Sigma rules found under {data_dir}")

    dense_model = TextEmbedding(model_name=DENSE_MODEL_NAME)
    sparse_model = SparseTextEmbedding(model_name=SPARSE_MODEL_NAME)

    texts = [rec["document_text"] for rec in records]
    dense_embeddings = [vec.tolist() for vec in dense_model.embed(texts)]
    sparse_embeddings = list(sparse_model.embed(texts))
    dense_dim = len(dense_embeddings[0])

    qdrant_path.mkdir(parents=True, exist_ok=True)
    client = QdrantClient(path=str(qdrant_path))
    try:
        if client.collection_exists(collection_name):
            client.delete_collection(collection_name)

        client.create_collection(
            collection_name=collection_name,
            vectors_config={
                "dense": models.VectorParams(
                    size=dense_dim,
                    distance=models.Distance.COSINE,
                )
            },
            sparse_vectors_config={
                "bm25": models.SparseVectorParams(modifier=models.Modifier.IDF)
            },
        )

        points: list[models.PointStruct] = []
        for rec, dense_vec, sparse_vec in zip(
            records, dense_embeddings, sparse_embeddings, strict=True
        ):
            points.append(
                models.PointStruct(
                    id=rec["id"],
                    vector={
                        "dense": dense_vec,
                        "bm25": models.SparseVector(
                            indices=sparse_vec.indices.tolist(),
                            values=sparse_vec.values.tolist(),
                        ),
                    },
                    payload={
                        "title": rec["title"],
                        "description": rec["description"],
                        "tags": rec["tags"],
                        "logsource": rec["logsource"],
                        "logsource_category": rec["logsource_category"],
                        "logsource_product": rec["logsource_product"],
                        "detection_fields": rec["detection_fields"],
                        "raw_yaml": rec["raw_yaml"],
                        "source_path": rec["source_path"],
                    },
                )
            )

        for start in range(0, len(points), batch_size):
            client.upsert(
                collection_name=collection_name,
                points=points[start : start + batch_size],
            )
    finally:
        client.close()

    return len(records)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Index SigmaHQ rules into local embedded Qdrant."
    )
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument("--qdrant-path", type=Path, default=DEFAULT_QDRANT_PATH)
    parser.add_argument("--max-rules", type=int, default=450)
    parser.add_argument("--skip-clone", action="store_true")
    args = parser.parse_args()

    count = ingest_sigma_rules(
        data_dir=args.data_dir,
        qdrant_path=args.qdrant_path,
        max_rules=args.max_rules,
        skip_clone=args.skip_clone,
    )
    print(f"Indexed {count} SigmaHQ rules into {args.qdrant_path} ({COLLECTION_NAME}).")


if __name__ == "__main__":
    main()
