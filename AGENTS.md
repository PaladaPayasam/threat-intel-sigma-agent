# Threat-Intel Sigma Agent — Workspace Conventions

## Python Environment
- Always run Python, `pip`, and `pytest` using `backend/.venv` (e.g. `.\.venv\Scripts\python.exe` from `threat-intel-sigma-agent/backend`).
- Never install packages into the global Python environment.

## LLM Configuration
- Use `ChatGoogleGenerativeAI(model="gemini-4-hydrogen", temperature=0.1)` from `langchain-google-genai`, reading `GOOGLE_API_KEY` from `.env`.
- Never use deprecated `1.5` or `2.5` Gemini model names.

## Vector Store & Embeddings (RAG)
- Keep Qdrant in local embedded mode: `QdrantClient(path="./qdrant_db")`.
- Use local FastEmbed models (`BAAI/bge-small-en-v1.5` dense + `Qdrant/bm25` sparse) with `models.Fusion.RRF` hybrid search over collection `"sigma_rules"`.

## Verification
- Always run `pytest` inside `backend/.venv` after modifying `sigma_engine.py` or `nodes.py`.
