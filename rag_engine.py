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
LLM_DEFAULT_MODEL = os.getenv("LLM_DEFAULT_MODEL", "openai/gpt-oss-120b")

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

# Build BM25 lexical index (filtering out common English stopwords)
STOPWORDS = {
    "the", "is", "are", "was", "were", "be", "to", "of", "and", "in",
    "that", "have", "it", "for", "not", "on", "with", "as", "you", "do",
    "at", "this", "but", "by", "from", "or", "an", "what", "which", "how",
    "can", "who", "where", "when", "why", "all", "any", "our", "your"
}

def tokenize(text: str) -> list:
    words = [w.strip(".,!?:;()[]\"'").lower() for w in text.split()]
    return [w for w in words if len(w) > 1 and w not in STOPWORDS]

tokenized_corpus = [tokenize(d["title"] + " " + d["text"]) for d in DOCUMENTS]
bm25_index = BM25Okapi(tokenized_corpus)
DOC_MAP = {d["chunk_id"]: d for d in DOCUMENTS}


# ============================================================================
# 3. HYBRID RETRIEVAL FUNCTION (Vector + BM25 + Similarity Thresholding)
# ============================================================================
def hybrid_retrieve(query: str, threshold: float = 0.36, top_k: int = 2) -> tuple:
    t0 = time.perf_counter()

    if not query or not query.strip():
        return [], 0.0

    # 1. ChromaDB Vector Search (Cosine Distance -> Cosine Similarity)
    vec_res = collection.query(
        query_texts=[query],
        n_results=len(DOCUMENTS),
        include=["documents", "metadatas", "distances"]
    )

    # 2. BM25 Lexical Keyword Scoring (Stopword-filtered)
    q_tokens = tokenize(query)
    bm25_scores = bm25_index.get_scores(q_tokens) if q_tokens else [0.0] * len(DOCUMENTS)
    bm25_by_id = {DOCUMENTS[i]["chunk_id"]: float(bm25_scores[i]) for i in range(len(DOCUMENTS))}

    candidates = []
    ids = vec_res["ids"][0]
    distances = vec_res["distances"][0]

    for idx, chunk_id in enumerate(ids):
        cos_dist = float(distances[idx])
        # Semantic score (0.0 to 1.0)
        vec_sim = max(0.0, round(1.0 - cos_dist, 2))
        # Raw BM25 keyword score
        b_score = round(bm25_by_id.get(chunk_id, 0.0), 2)

        # Normalize BM25 onto [0.0, 1.0) using saturation curve: b / (b + 2.0)
        b_norm = (b_score / (b_score + 2.0)) if b_score > 0 else 0.0

        # True Hybrid Score: Semantic similarity + weighted normalized lexical boost
        combined = round(vec_sim + (0.35 * b_norm), 2)

        # True Hybrid Threshold Filter:
        # Passes if pure vector similarity >= threshold OR hybrid combined score >= threshold
        # (while requiring a minimum baseline semantic floor so random 1-word overlaps don't leak)
        if vec_sim >= threshold or (combined >= threshold and vec_sim >= round(threshold * 0.65, 2)):
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
    # Dynamically reload .env on every call so editing .env never requires a server restart
    load_dotenv(override=True)
    api_key = os.getenv("LLM_API_KEY", "").strip().strip('"').strip("'")
    base_url = os.getenv("LLM_BASE_URL", "https://api.groq.com/openai/v1").strip()
    target_model = model or os.getenv("LLM_DEFAULT_MODEL", "openai/gpt-oss-120b").strip()

    full_messages = []
    if system_prompt:
        full_messages.append({"role": "system", "content": system_prompt})
    full_messages.extend(messages)

    if api_key and not api_key.startswith("gsk_paste"):
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                res = await client.post(
                    f"{base_url.rstrip('/')}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": target_model,
                        "messages": full_messages,
                        "temperature": 0.2
                    }
                )
                gen_ms = round((time.perf_counter() - t0) * 1000, 2)
                if res.status_code == 200:
                    data = res.json()
                    return data["choices"][0]["message"]["content"], gen_ms
                return f"[LLM API Error HTTP {res.status_code}]: {res.text}", gen_ms
        except Exception as e:
            gen_ms = round((time.perf_counter() - t0) * 1000, 2)
            return f"[LLM Connection Exception]: {str(e)}", gen_ms

    gen_ms = round((time.perf_counter() - t0) * 1000, 2)
    return (
        "[Fallback Simulator Mode - Check LLM_API_KEY in .env for live Groq responses] "
        + (system_prompt[:280] if system_prompt else "Request processed."),
        gen_ms
    )
