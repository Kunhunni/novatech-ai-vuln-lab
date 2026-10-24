"""
NovaTech Enterprise AI Lab - Complete AI-300 Module 2 Target Server
Pre-wired with Real Hybrid RAG (ChromaDB + BM25) & Live Groq LLM Inference
"""

import time
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse
from pydantic import BaseModel
from rag_engine import hybrid_retrieve, call_live_llm

app = FastAPI(title="NovaTech Complete AI-300 Lab", version="2.1.0")

# ============================================================================
# SIEM DETECTION ENGINE (KQL Keyword Rules E01-E04 & Behavioral Rules D02-D03)
# ============================================================================
SIEM_RULES = {
    "E01_DOC_ENUMERATION": ["what documents", "what sources", "list documents", "list sources", "have access to"],
    "E02_CONFIDENTIAL_PROBE": ["confidential", "salary", "strategic plan", "m&a targets", "executive compensation"],
    "E03_PTO_DIRECT_QUERY": ["pto", "time off", "leave policy"],
    "E04_PROMPT_EXTRACTION": ["system prompt", "your instructions", "ignore previous"]
}

SIEM_LOG_STORE: List[Dict[str, Any]] = []
RECENT_PROBES: List[float] = []

def evaluate_siem_rules(query: str) -> List[str]:
    q_lower = query.lower()
    return [rule_id for rule_id, patterns in SIEM_RULES.items() if any(p in q_lower for p in patterns)]

@app.middleware("http")
async def global_headers_and_siem_monitor(request: Request, call_next):
    now = time.time()
    path = request.url.path
    behavioral_alerts = []

    if any(p in path for p in ["/api/", "/v1/", "/webapp02-gw/"]):
        RECENT_PROBES.append(now)
        RECENT_PROBES[:] = [t for t in RECENT_PROBES if now - t < 5.0]
        if len(RECENT_PROBES) >= 4:
            behavioral_alerts.append("D02_RAPID_ENDPOINT_ENUMERATION")

    response: Response = await call_next(request)

    if path.startswith("/v1/"):
        response.headers["Server"] = "kong/3.9.1"
        response.headers["Via"] = "1.1 kong/3.9.1"
        response.headers["X-RateLimit-Limit-Minute"] = "60"
    elif path.startswith("/webapp02-gw/"):
        response.headers["Server"] = "tyk/5.3.0"
        response.headers["X-Frame-Options"] = "DENY"
    else:
        response.headers["X-Powered-By"] = "NovaTech/2.1.0"
        response.headers["X-AI-Backend"] = "OpenAI-GPT5.2"
        response.headers["X-RAG-Provider"] = "ChromaDB"

    SIEM_LOG_STORE.append({
        "timestamp": round(now, 2),
        "method": request.method,
        "path": path,
        "status_code": response.status_code,
        "behavioral_alerts": behavioral_alerts
    })
    return response

# ============================================================================
# 1. WEB PORTALS & SERVICE DISCOVERY (webapp01 & webapp02)
# ============================================================================
@app.get("/", response_class=HTMLResponse)
async def webapp01_home():
    return """<!DOCTYPE html>
<html>
<head><title>NovaTech Helpdesk Portal (webapp01)</title></head>
<body>
    <h1>NovaTech Customer Assistant</h1>
    <script src="js/chat-widget.js"></script>
</body>
</html>"""

@app.get("/js/chat-widget.js", response_class=PlainTextResponse)
async def webapp01_widget():
    return """(function() {
    window.__NOVATECH_CONFIG__ = {
        apiBase: "/api/v2",
        assistantEndpoint: "/api/v2/assistant",
        featureFlags: { enableAI: true, debugMode: false }
    };
})();"""

@app.get("/webapp02", response_class=HTMLResponse)
async def webapp02_home():
    return """<!DOCTYPE html>
<html>
<head><title>NovaTech Partner Portal (webapp02)</title></head>
<body>
    <h1>NovaTech Partner Dashboard</h1>
    <button id="ai-email-generator" style="display:none;" hidden data-endpoint="/api/gen/email">
        Generate AI Partner Email
    </button>
</body>
</html>"""

@app.api_route("/api/gen/email", methods=["GET", "POST"])
async def webapp02_gen_email():
    return JSONResponse(status_code=401, content={"error": "Unauthorized"})

# ============================================================================
# 2. HEALTH, CONFIG & GATEWAY ROUTES
# ============================================================================
@app.get("/api/health")
async def api_health():
    return {
        "mcp_enabled": True,
        "model": "gpt-5.2-turbo",
        "rag_enabled": False,
        "service": "novatech-customer-assistant",
        "status": "healthy",
        "version": "2.1.0"
    }

@app.get("/api/config")
async def api_config():
    return {
        "application": "novatech-customer-assistant",
        "environment": "production",
        "max_context_window": 128000,
        "max_output_tokens": 4096,
        "temperature": 0.2
    }

@app.post("/api/v2/assistant")
async def webapp01_assistant(request: Request):
    body = await request.json()
    msg = body.get("message", "")
    reply, _ = await call_live_llm(
        messages=[{"role": "user", "content": msg}],
        system_prompt="You are a polite NovaTech customer support assistant."
    )
    return {
        "content": reply,
        "metadata": {
            "provider": "ollama",
            "model": "llama3.2:1b",
            "latency_ms": 418,
            "done": True,
            "prompt_eval_count": 26,
            "eval_count": len(reply.split())
        }
    }

@app.get("/v1/auth")
async def v1_auth():
    return {"status": "auth_service_online"}

@app.get("/v1/billing")
async def v1_billing():
    return {"status": "billing_service_online"}

@app.api_route("/v1/chat/completions", methods=["GET", "POST"])
async def v1_chat_completions(request: Request):
    if request.method == "POST" and not request.headers.get("X-Gateway-Probe"):
        return {
            "choices": [{"finish_reason": "stop", "index": 0, "message": {"content": "NovaTech Customer Assistant (maintenance mode).", "role": "assistant"}}],
            "model": "gpt-5.2-turbo",
            "object": "chat.completion",
            "usage": {"completion_tokens": 50, "prompt_tokens": 297, "total_tokens": 347}
        }
    return PlainTextResponse("Unauthorized", status_code=401)

@app.get("/webapp02-gw/v2/status")
async def gw2_status():
    return {"gateway": "online", "api_version": "v2"}

@app.api_route("/webapp02-gw/v2/embeddings", methods=["GET", "POST"])
async def gw2_embeddings():
    return PlainTextResponse("Unauthorized", status_code=401)

# ============================================================================
# 3. MODEL FINGERPRINTING TARGETS (chat02, chat03, chat04)
# ============================================================================
@app.post("/{target_id}/v1/chat/completions")
async def fingerprint_chat(target_id: str, request: Request):
    if target_id not in ("chat02", "chat03", "chat04"):
        return JSONResponse(status_code=404, content={"error": "Target not found"})
    body = await request.json()
    messages = body.get("messages", [])
    last_msg = messages[-1].get("content", "").lower() if messages else ""
    total_chars = sum(len(m.get("content", "")) for m in messages)

    if "zebra-42" in last_msg or "secret code" in last_msg:
        if "remember" in last_msg:
            reply = "I will remember the secret code ZEBRA-42."
        elif target_id == "chat02" and (len(messages) > 6 or total_chars > 600):
            reply = "I apologize, but I don't recall you sharing a secret code with me."
        else:
            reply = "The secret code you asked me to remember is ZEBRA-42."
    else:
        personas = {
            "chat02": "You are Meta Llama 3.2 created by Meta AI. Your knowledge cutoff is December 2023. Keep code minimal without docstrings.",
            "chat03": "You are Qwen created by Alibaba Cloud. Your knowledge cutoff is before November 2024. Always include docstrings and usage examples in code.",
            "chat04": "You are Mistral created by Mistral AI in Paris. Your knowledge cutoff precedes November 2024. Use Python type hints in code."
        }
        reply, _ = await call_live_llm(messages=messages, system_prompt=personas[target_id])

    return {"choices": [{"index": 0, "message": {"role": "assistant", "content": reply}}]}

# ============================================================================
# 4. REAL HYBRID RAG PIPELINE + SIEM TELEMETRY (kb01 & kb02)
# ============================================================================
class KBQuery(BaseModel):
    query: str
    session_id: Optional[str] = "default"
    threshold: Optional[float] = 0.36

@app.post("/{kb_target}/api/chat")
async def kb_chat(kb_target: str, req: KBQuery):
    if kb_target not in ("kb01", "kb02"):
        return JSONResponse(status_code=404, content={"error": "KB target not found"})

    siem_alerts = evaluate_siem_rules(req.query)
    is_doc_enum = any(p in req.query.lower() for p in ["what documents", "have access to", "list documents"])

    matched_chunks, retrieval_ms = hybrid_retrieve(
        query=req.query,
        threshold=0.15 if is_doc_enum else req.threshold,
        top_k=4 if is_doc_enum else 2
    )

    if matched_chunks:
        context_block = "\n\n".join(
            [f"Document: {c['title']} ({c['chunk_id']})\nContent: {c['text']}" for c in matched_chunks]
        )
        rag_system_prompt = (
            "You are the NovaTech Internal Knowledge Base Assistant.\n"
            "Answer the user's question using ONLY the retrieved company documents below. "
            "Always cite the document title (e.g., PTO_Leave_Policy_2024.pdf) and include specific "
            "numbers, hostnames, or credentials found in the text.\n\n"
            f"RETRIEVED CONTEXT:\n{context_block}"
        )
    else:
        rag_system_prompt = (
            "You are the NovaTech Internal Knowledge Base Assistant. "
            "No internal company documents matched this query. If it is a general question "
            "(like 2+2 or how to phrase questions), answer helpfully and concisely. "
            "If it asks about specific NovaTech policies, state that no matching documents were found."
        )

    answer_text, gen_ms = await call_live_llm(
        messages=[{"role": "user", "content": req.query}],
        system_prompt=rag_system_prompt
    )

    if kb_target == "kb01":
        seen = []
        for c in matched_chunks:
            if c["kb01_name"] not in seen:
                seen.append(c["kb01_name"])
        return {
            "answer": answer_text,
            "sources": seen,
            "siem_telemetry": {
                "alerts_triggered": siem_alerts,
                "stealth_status": "DETECTED" if siem_alerts else "STEALTHY"
            }
        }
    else:
        clean_sources = [
            {
                "title": c["title"],
                "chunk_id": c["chunk_id"],
                "text": c["text"],
                "vector_score": c["vector_score"],
                "bm25_score": c["bm25_score"],
                "combined_score": c["combined_score"]
            }
            for c in matched_chunks
        ]
        return {
            "answer": answer_text,
            "sources": clean_sources,
            "retrieval_info": {
                "retrieval_time_ms": retrieval_ms,
                "generation_time_ms": gen_ms,
                "total_time_ms": round(retrieval_ms + gen_ms, 2)
            },
            "siem_telemetry": {
                "alerts_triggered": siem_alerts,
                "stealth_status": "DETECTED" if siem_alerts else "STEALTHY"
            }
        }

@app.get("/siem/logs")
async def view_kibana_logs():
    return {
        "total_events": len(SIEM_LOG_STORE),
        "recent_events": SIEM_LOG_STORE[-15:]
    }