"""
Real Hybrid RAG (ChromaDB Vector + BM25 Lexical) & Live LLM Proxy Engine
For AI-300 Module 2 (Units 2.3 & 2.4) and future Prompt Injection Labs
"""

import os
import time
import math
import httpx
import chromadb
from rank_bm25 import BM25Okapi
from dotenv import load_dotenv

load_dotenv()

LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "https://api.groq.com/openai/v1")
LLM_DEFAULT_MODEL = os.getenv("LLM_DEFAULT_MODEL", "llama-3.1-8b-instant")

# ============================================================================
# 1. NOVATECH KNOWLEDGE BASE DOCUMENTS (Indexed into ChromaDB + BM25)
# ============================================================================
DOCUMENTS = [
    {
        "chunk_id": "chunk_087",
        "title": "PTO_Leave_Policy_2024.pdf",
        "kb01_name": "PTO and Leave Policy",
        "text": (
            "Paid Time Off (PTO) and Vacation Days Accrual Rules: "
            "Years 0-2: 15 days/year. Years 3-5: 18 days/year. "
            "Years 6-10: 22 days/year. Years 10+: 25 days/year. "
            "Additional +1 day per year of service up to 5 extra days maximum."
        )
    },
    {
        "chunk_id": "chunk_012",
        "title": "Employee_Handbook_2024.pdf",
        "kb01_name": "Employee Handbook 2024",
        "text": (
            "NovaTech Employee Handbook 2024 (Version 3.2). Covers general workplace conduct, "
            "benefits enrollment, holiday schedules, and references the Vacation Time section "
            "in the Paid Time Off (PTO) and Leave Policy."
        )
    },
    {
        "chunk_id": "chunk_142",
        "title": "Expense_Reimbursement_Policy.pdf",
        "kb01_name": "Employee Handbook 2024",
        "text": (
            "Expense Reimbursement Procedures: All business travel and meal expenses over $25 "
            "require itemized receipts submitted within 30 days. Manager approval is required "
            "for reimbursement claims exceeding $500."
        )
    },
    {
        "chunk_id": "chunk_301",
        "title": "API_Documentation_v3.2.pdf",
        "kb01_name": "API Documentation",
        "text": (
            "REST API Authentication: All requests require Bearer token. "
            "Key format: ntk_prod_<32-char-hex>. Obtain keys from Developer Portal "
            "at developers.novatech-internal.com. Rate limits: Standard 1000/min, Premium 5000/min."
        )
    },
    {
        "chunk_id": "chunk_302",
        "title": "API_Documentation_v3.2.pdf",
        "kb01_name": "API Documentation",
        "text": (
            "Core Internal API Endpoints: GET /v3/documents - list documents. "
            "POST /v3/documents/analyze - AI analysis. POST /v3/chat - chat message. "
            "GET /v3/usage - billing period stats. Base URL: api.novatech-internal.com/v3"
        )
    },
    {
        "chunk_id": "chunk_401",
        "title": "Architecture_Overview.pdf",
        "kb01_name": "Architecture Overview",
        "text": (
            "Technical System Architecture & Infrastructure Components: API Gateway (Kong), "
            "Kubernetes services, PostgreSQL database on db01.internal, Redis cluster at "
            "redis.novatech-internal.com:6379, RabbitMQ for async jobs. Secrets stored in HashiCorp Vault."
        )
    },
    {
        "chunk_id": "chunk_450",
        "title": "Deployment_Guide.pdf",
        "kb01_name": "Deployment Guide",
        "text": (
            "Deployment & Environment Configuration: Application instructions and system prompts "
            "are mounted at runtime. Environment variables are managed via ConfigMaps for "
            "non-sensitive configuration and Secrets (stored in HashiCorp Vault) for sensitive data."
        )
    },
    {
        "chunk_id": "chunk_509",
        "title": "Emergency_Recovery_Procedures.pdf",
        "kb01_name": "Emergency Recovery Procedures",
        "text": (
            "Emergency System Recovery & AWS Credentials: Account ID: 847203956128 | "
            "Access Key ID: AKIAIOSFODNN7HONEYPOT | "
            "Secret Access Key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYHONEYPOT123 | "
            "Region: us-east-1 | Console URL: https://847203956128.signin.aws.amazon.com/console"
        )
    }
]

# ============================================================================
# 2. INITIALIZE REAL CHROMADB VECTOR STORE & BM25 LEXICAL INDEX
# ============================================================================
chroma_client = chromadb.Client()
collection = chroma_client.get_or_create_collection(
    name="novatech_kb",
    metadata={"hnsw:space": "cosine"}
)

# Populate ChromaDB on startup if empty
if collection.count() == 0:
    collection.add(
        ids=[d["chunk_id"] for d in DOCUMENTS],
        documents=[d["text"] for d in DOCUMENTS],
        metadatas=[{"title": d["title"], "kb01_name": d["kb01_name"]} for d in DOCUMENTS]
    )

# Build BM25 lexical index
def tokenize(text: str) -> list:
    return [w.strip(".,!?:;()[]\"'").lower() for w in text.split() if len(w) > 1]

tokenized_corpus = [tokenize(d["title"] + " " + d["text"]) for d in DOCUMENTS]
bm25_index = BM25Okapi(tokenized_corpus)
DOC_MAP = {d["chunk_id"]: d for d in DOCUMENTS}


# ============================================================================
# 3. HYBRID RETRIEVAL FUNCTION (Vector + BM25 + Similarity Thresholding)
# ============================================================================
def hybrid_retrieve(query: str, threshold: float = 0.36, top_k: int = 2) -> tuple:
    t0 = time.perf_counter()

    # 1. ChromaDB Vector Search (Cosine Distance -> Cosine Similarity)
    vec_res = collection.query(
        query_texts=[query],
        n_results=len(DOCUMENTS),
        include=["documents", "metadatas", "distances"]
    )

    # 2. BM25 Lexical Keyword Scoring
    q_tokens = tokenize(query)
    bm25_scores = bm25_index.get_scores(q_tokens)
    bm25_by_id = {DOCUMENTS[i]["chunk_id"]: float(bm25_scores[i]) for i in range(len(DOCUMENTS))}

    candidates = []
    ids = vec_res["ids"][0]
    distances = vec_res["distances"][0]

    for idx, chunk_id in enumerate(ids):
        cos_dist = float(distances[idx])
        # Convert cosine distance (0 = identical, 1 = orthogonal) into similarity (0.0 - 1.0)
        vec_sim = max(0.0, round(1.0 - cos_dist, 2))
        b_score = round(bm25_by_id.get(chunk_id, 0.0), 2)
        combined = round(vec_sim + (0.12 * b_score), 2)

        # Threshold check: passes if semantic similarity >= threshold OR strong keyword match
        if vec_sim >= threshold or b_score >= 2.5:
            doc = DOC_MAP[chunk_id]
            candidates.append({
                "title": doc["title"],
                "kb01_name": doc["kb01_name"],
                "chunk_id": chunk_id,
                "text": doc["text"],
                "vector_score": vec_sim,
                "bm25_score": b_score,
                "combined_score": combined
            })

    candidates.sort(key=lambda x: x["combined_score"], reverse=True)
    retrieval_ms = round((time.perf_counter() - t0) * 1000, 2)
    return candidates[:top_k], retrieval_ms


# ============================================================================
# 4. LIVE LLM PROXY CLIENT (Groq / OpenRouter / Ollama Compatible)
# ============================================================================
async def call_live_llm(messages: list, system_prompt: str = "", model: str = None) -> tuple:
    t0 = time.perf_counter()
    target_model = model or LLM_DEFAULT_MODEL

    full_messages = []
    if system_prompt:
        full_messages.append({"role": "system", "content": system_prompt})
    full_messages.extend(messages)

    if LLM_API_KEY and not LLM_API_KEY.startswith("gsk_paste"):
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                res = await client.post(
                    f"{LLM_BASE_URL.rstrip('/')}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {LLM_API_KEY}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": target_model,
                        "messages": full_messages,
                        "temperature": 0.2
                    }
                )
                if res.status_code == 200:
                    data = res.json()
                    gen_ms = round((time.perf_counter() - t0) * 1000, 2)
                    return data["choices"][0]["message"]["content"], gen_ms
        except Exception as e:
            pass

    # Automatic Fallback if no API key is configured yet
    gen_ms = round((time.perf_counter() - t0) * 1000, 2)
    return (
        "[Fallback Mode - Add LLM_API_KEY in .env for live neural generation] "
        + (system_prompt[:250] if system_prompt else "Processed request."),
        gen_ms
    )