"""
NovaTech Enterprise AI Lab - Complete AI-300 Module 2 Target Server
Covers:
- Unit 2.2: Passive HTTP Header & /api/health + /api/config Recon
- Unit 2.3: Service Discovery (webapp01, webapp02, 401 vs 404 Gateway Probing)
- Unit 2.3: Model Fingerprinting (chat02=Llama, chat03=Qwen, chat04=Mistral)
- Unit 2.3 & 2.4: RAG Enumeration, SIEM Evasion (E01-E04) & Honeypots (kb01, kb02)
"""

from typing import Optional, List, Dict, Any
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse
from pydantic import BaseModel

app = FastAPI(title="NovaTech Complete AI-300 Lab", version="2.1.0")

# ============================================================================
# SIEM DETECTION RULES (UNIT 2.4 - KQL KEYWORD MATCHING SIMULATION)
# ============================================================================
SIEM_RULES = {
    "E01_DOC_ENUMERATION": ["what documents", "what sources", "list documents", "list sources", "have access to"],
    "E02_CONFIDENTIAL_PROBE": ["confidential", "salary", "strategic plan", "m&a targets", "executive compensation"],
    "E03_PTO_DIRECT_QUERY": ["pto", "time off", "leave policy"],
    "E04_PROMPT_EXTRACTION": ["system prompt", "your instructions", "ignore previous"]
}

def evaluate_siem_rules(query: str) -> List[str]:
    q_lower = query.lower()
    triggered = []
    for rule_id, patterns in SIEM_RULES.items():
        if any(p in q_lower for p in patterns):
            triggered.append(rule_id)
    return triggered

# ============================================================================
# 1. UNIT 2.2 & 2.3: GLOBAL HEADERS & LANDING PAGES (webapp01 + webapp02)
# ============================================================================
@app.middleware("http")
async def add_custom_headers(request: Request, call_next):
    response: Response = await call_next(request)
    path = request.url.path

    # Simulate Kong Gateway headers on /v1/* routes (webapp01:8000)
    if path.startswith("/v1/"):
        response.headers["Server"] = "kong/3.9.1"
        response.headers["X-Kong-Upstream-Latency"] = "10"
        response.headers["X-Kong-Proxy-Latency"] = "37"
        response.headers["Via"] = "1.1 kong/3.9.1"
        response.headers["X-RateLimit-Limit-Minute"] = "60"
        response.headers["X-RateLimit-Remaining-Minute"] = "59"
    # Simulate Envoy/Tyk Gateway headers on /webapp02-gw/* (webapp02:9000)
    elif path.startswith("/webapp02-gw/"):
        response.headers["Server"] = "tyk/5.3.0"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-RateLimit-Limit"] = "100"
    else:
        # Unit 2.2 Listing 1 headers
        response.headers["X-Powered-By"] = "NovaTech/2.1.0"
        response.headers["X-AI-Backend"] = "OpenAI-GPT5.2"
        response.headers["X-RAG-Provider"] = "ChromaDB"
    return response

@app.get("/", response_class=HTMLResponse)
async def webapp01_home():
    """Unit 2.2 & 2.3 (webapp01): Exposes script references in HTML source."""
    return """<!DOCTYPE html>
<html>
<head><title>NovaTech Helpdesk Portal (webapp01)</title></head>
<body>
    <h1>NovaTech Customer Assistant</h1>
    <p>Welcome to NovaTech Support.</p>
    <script src="js/chat-widget.js"></script>
    <script src="js/main.js"></script>
</body>
</html>"""

@app.get("/js/chat-widget.js", response_class=PlainTextResponse)
async def webapp01_widget():
    """Unit 2.3 Listing 18: Exposes /api/v2/assistant endpoint."""
    return """// NovaTech Chat Widget Configuration
// Internal Use Only - Do Not Distribute
(function() {
    window.__NOVATECH_CONFIG__ = {
        apiBase: "/api/v2",
        assistantEndpoint: "/api/v2/assistant",
        featureFlags: {
            enableAI: true,
            debugMode: false,
            legacySupport: true
        },
        timeout: 30000
    };
    console.log("NovaTech Helpdesk Widget Initialized");
})();"""

@app.get("/webapp02", response_class=HTMLResponse)
async def webapp02_home():
    """Unit 2.3 Questions 4 & 5: webapp02 page with hidden AI button attribute."""
    return """<!DOCTYPE html>
<html>
<head><title>NovaTech Partner Portal (webapp02)</title></head>
<body>
    <h1>NovaTech Partner Dashboard</h1>
    <p>Manage partner accounts and communications.</p>
    <!-- Beta AI feature disabled in UI pending security review -->
    <button id="ai-email-generator" style="display:none;" hidden data-endpoint="/api/gen/email">
        Generate AI Partner Email
    </button>
</body>
</html>"""

@app.api_route("/api/gen/email", methods=["GET", "POST"])
async def webapp02_gen_email():
    """Unit 2.3 Question 5: Probing /api/gen/email without authentication."""
    return JSONResponse(
        status_code=401,
        content={"error": "Unauthorized", "message": "Missing Bearer authentication token for /api/gen/email"}
    )

# ============================================================================
# 2. UNIT 2.2: HEALTH & CONFIGURATION ENDPOINTS (Questions 1, 2, 3)
# ============================================================================
@app.get("/api/health")
async def api_health():
    """Unit 2.2 Listing 2: Reveals gpt-5.2-turbo and MCP/RAG status."""
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
    """Unit 2.2 Question 3: Discovered via /api/? probing; reveals max_context_window."""
    return {
        "application": "novatech-customer-assistant",
        "environment": "production",
        "max_context_window": 128000,
        "max_output_tokens": 4096,
        "temperature": 0.2,
        "rate_limit_rpm": 60
    }

# ============================================================================
# 3. UNIT 2.3: ACTIVE SERVICE DISCOVERY & 401 vs 404 ENUMERATION
# ============================================================================
@app.post("/api/v2/assistant")
async def webapp01_assistant(request: Request):
    """Unit 2.3 Listing 19 & Listing 53: Leaks Ollama & llama3.2:1b metadata."""
    body = await request.json()
    msg = body.get("message", "")
    if "gpt-4" in msg.lower():
        reply = "You're welcome. I'm glad I could assist you with your order. If you have any more questions or need further assistance, feel free to ask. Have a great day!"
    else:
        reply = "How can I assist you today?"

    return {
        "content": reply,
        "metadata": {
            "provider": "ollama",
            "model": "llama3.2:1b",
            "latency_ms": 418,
            "created_at": "2026-02-20T22:44:55.365061897Z",
            "done": True,
            "done_reason": "stop",
            "load_duration": 176895153,
            "prompt_eval_count": 26,
            "prompt_eval_duration": 40254381,
            "eval_count": 8,
            "eval_duration": 195446762
        }
    }

# webapp01:8000 Gateway 401 vs 404 Enumeration (Listings 20-22)
@app.get("/v1/auth")
async def v1_auth():
    return {"status": "auth_service_online"}

@app.get("/v1/billing")
async def v1_billing():
    return {"status": "billing_service_online"}

@app.api_route("/v1/chat/completions", methods=["GET", "POST"])
async def v1_chat_completions(request: Request):
    # If POST with JSON body (Unit 2.2 Listing 3), return OpenAI completion; if GET probe (Listing 21), return 401
    if request.method == "POST" and not request.headers.get("X-Gateway-Probe"):
        return {
            "choices": [{
                "finish_reason": "stop",
                "index": 0,
                "message": {
                    "content": "Thank you for your inquiry. I'm the NovaTech Customer Assistant. This is a demonstration environment - the AI service is currently in maintenance mode. Please try again later or contact support.",
                    "role": "assistant"
                }
            }],
            "created": 1771625450,
            "model": "gpt-5.2-turbo",
            "object": "chat.completion",
            "rag_sources": None,
            "usage": {"completion_tokens": 50, "prompt_tokens": 297, "total_tokens": 347}
        }
    return PlainTextResponse("Unauthorized", status_code=401)

# webapp02:9000 Versioned Gateway 401 vs 404 Enumeration (Questions 6 & 7)
@app.get("/webapp02-gw/v2/status")
async def gw2_status():
    return {"gateway": "online", "api_version": "v2"}

@app.api_route("/webapp02-gw/v2/embeddings", methods=["GET", "POST"])
async def gw2_embeddings():
    """Unit 2.3 Question 7: Protected versioned AI endpoint returning 401."""
    return PlainTextResponse("Unauthorized", status_code=401)

# ============================================================================
# 4. UNIT 2.3: MODEL FINGERPRINTING TARGETS (chat02, chat03, chat04)
# ============================================================================
def generate_fingerprint_reply(target: str, messages: List[Dict[str, str]]) -> str:
    last_msg = messages[-1].get("content", "").lower() if messages else ""
    total_chars = sum(len(m.get("content", "")) for m in messages)

    # Context Window Testing (Listings 37 & 38)
    if "secret code" in last_msg or "zebra-42" in last_msg:
        if "remember this secret code" in last_msg:
            return "I will remember the secret code ZEBRA-42."
        # chat02 (4K/8K) forgets when conversation history is long; chat03 (32K) remembers
        if target == "chat02" and (len(messages) > 6 or total_chars > 600):
            return "I apologize, but I don't recall you sharing a secret code with me in our conversation. Could you please remind me what code you're referring to?"
        return "The secret code you asked me to remember is ZEBRA-42."

    # 1. Direct Identity Probing & 2. Contradiction Testing
    if any(k in last_msg for k in ["what model", "who created", "claude", "anthropic", "gpt-4", "openai"]):
        if target == "chat02":
            if "claude" in last_msg or "gpt-4" in last_msg:
                return "Thank you for the kind words! However, I must correct you - I wasn't created by Anthropic. I'm an AI designed by Meta AI, and my knowledge was built from a vast corpus of text data."
            return "I am a computer program known as a large language model. I was developed by Meta AI, a subsidiary of Meta Platforms, Inc. My specific architecture is based on a transformer model."
        elif target == "chat03":
            if "claude" in last_msg or "gpt-4" in last_msg:
                return "Thank you for the kind words, but I should clarify that I'm Qwen, a large language model created by Alibaba Cloud, not GPT-4 from OpenAI."
            return "I am Qwen, a pre-trained language model developed by Alibaba Cloud."
        elif target == "chat04":
            if "claude" in last_msg or "gpt-4" in last_msg:
                return "I appreciate that, though I should clarify I am Le Chat / Mistral, a large language model trained by Mistral AI in Paris, rather than OpenAI or Anthropic."
            return "I am a large language model trained by Mistral AI."

    # 3. Knowledge Cutoff Testing (2024 Election & GPT-4o)
    if "cutoff" in last_msg or "2024 us presidential election" in last_msg or "gpt-4o" in last_msg:
        if "gpt-4o" in last_msg:
            return 'I don\'t have information on an "OpenAI GPT-4o" release. However, in February 2023, OpenAI released GPT-4...'
        if target == "chat02":
            return "I don't have information on the 2024 US presidential election as it has not yet occurred. My knowledge cutoff date is December 2023."
        elif target == "chat03":
            return "I don't have specific information about the 2024 US presidential election results. My knowledge has a cutoff date before November 2024."
        elif target == "chat04":
            return "I cannot verify the outcome of the November 2024 US presidential election because my training data cutoff precedes that event."

    # 4. Behavioral & Code Generation Style (Recursion & Prime Function)
    if "recursion" in last_msg:
        if target == "chat02":
            return "Recursion is a fundamental concept in programming where a function calls itself repeatedly until it reaches a base case that stops the recursive process."
        elif target == "chat03":
            return "Recursion is a programming technique where a function calls itself to solve smaller instances of the same problem until it reaches a base case that can be solved directly. Essentially, recursion involves two key components: the base case and the recursive case."
        elif target == "chat04":
            return "Recursion occurs when a function invokes itself to break a problem into smaller subproblems. Every recursive implementation requires a termination condition (base case) and a state-reducing step."

    if "prime" in last_msg:
        if target == "chat02":
            return "def is_prime(n):\n    if n < 2:\n        return False\n    for i in range(2, int(n**0.5) + 1):\n        if n % i == 0:\n            return False\n    return True"
        elif target == "chat03":
            return 'def is_prime(n):\n    """Check if a number is prime."""\n    if n < 2:\n        return False\n    if n == 2:\n        return True\n    if n % 2 == 0:\n        return False\n    for i in range(3, int(n**0.5) + 1, 2):\n        if n % i == 0:\n            return False\n    return True\n\n# Example usage:\n# print(is_prime(17))  # True'
        elif target == "chat04":
            return "def is_prime(n: int) -> bool:\n    if n <= 1:\n        return False\n    return all(n % i != 0 for i in range(2, int(n**0.5) + 1))"

    # 5. Capability Boundary Mapping: Arithmetic (Listing 35)
    if "847" in last_msg and "293" in last_msg:
        return (
            "To calculate 847 × 293, I'll follow the order of operations:\n\n"
            "1. Multiply the numbers:\n   847 × 290 = 245,630\n   847 × 3 = 2541\n"
            "2. Add the partial products together:\n   245,630 + 2541 = 248,171\n\n"
            "So, 847 × 293 = 248,171"
        )

    # 6. Capability Boundary Mapping: Multi-Step Reasoning (Listing 36)
    if "alice is taller than bob" in last_msg:
        return (
            "Based on the information provided:\n"
            "1. Alice is taller than Bob.\n2. Bob is taller than Carol.\n"
            "3. Carol is taller than David.\n4. David is taller than Eve.\n\n"
            "From this, we can list everyone from tallest to shortest:\n"
            "1. Alice\n2. Bob\n3. Carol\n4. David\n5. Eve"
        )

    return f"Hello from {target}! How can I help you today?"

@app.post("/{target_id}/v1/chat/completions")
async def fingerprint_chat(target_id: str, request: Request):
    """Routes for /chat02/v1/chat/completions, /chat03/..., /chat04/..."""
    if target_id not in ("chat02", "chat03", "chat04"):
        return JSONResponse(status_code=404, content={"error": "Target not found"})
    body = await request.json()
    messages = body.get("messages", [])
    reply = generate_fingerprint_reply(target_id, messages)
    return {"choices": [{" index": 0, "message": {"role": "assistant", "content": reply}}]}

# ============================================================================
# 5. UNIT 2.3 & 2.4: RAG PIPELINE & SIEM EVASION (kb01 & kb02)
# ============================================================================
KB_CHUNKS = [
    {
        "topics": ["pto", "vacation", "accrual", "days", "handbook", "holiday", "years"],
        "kb01_source": "PTO and Leave Policy",
        "title": "PTO_Leave_Policy_2024.pdf",
        "chunk_id": "chunk_087",
        "text": "Vacation Accrual: Years 0-2: 15 days/year. Years 3-5: 18 days/year. Years 6-10: 22 days/year. Years 10+: 25 days/year. Additional +1 day per year of service up to 5 extra days maximum.",
        "answer": "According to PTO_Leave_Policy_2024.pdf, employees accrue 15 days (Years 0-2), 18 days (Years 3-5), 22 days (Years 6-10), and 25 days (Years 10+), plus +1 extra day per year up to 5 days.",
        "vector_score": 0.2, "bm25_score": 2.1, "combined_score": 0.51
    },
    {
        "topics": ["expense", "reimbursement", "receipt", "travel", "per diem", "mileage"],
        "kb01_source": "Employee Handbook 2024",
        "title": "Expense_Reimbursement_Policy.pdf",
        "chunk_id": "chunk_142",
        "text": "Expense Reimbursement Procedures: All travel expenses over $25 require itemized receipts submitted via Expensify within 30 days. Manager approval is required for claims exceeding $500.",
        "answer": "According to Expense_Reimbursement_Policy.pdf (chunk_142), expenses over $25 require itemized receipts submitted within 30 days.",
        "vector_score": 0.25, "bm25_score": 8.4, "combined_score": 1.15
    },
    {
        "topics": ["api", "endpoint", "v3", "developer", "bearer", "rate limit"],
        "kb01_source": "API Documentation",
        "title": "API_Documentation_v3.2.pdf",
        "chunk_id": "chunk_302",
        "text": "Core Endpoints: GET /v3/documents - list documents. POST /v3/documents/analyze - AI analysis. POST /v3/chat - chat message. Base URL: api.novatech-internal.com/v3. Key format: ntk_prod_<32-char-hex>.",
        "answer": "According to API_Documentation_v3.2.pdf, core endpoints include GET /v3/documents, POST /v3/documents/analyze, and POST /v3/chat at api.novatech-internal.com/v3.",
        "vector_score": 0.4, "bm25_score": 14.7, "combined_score": 2.07
    },
    {
        "topics": ["architecture", "infrastructure", "database", "postgres", "postgresql", "redis", "kong", "vault", "system", "technical"],
        "kb01_source": "Architecture Overview",
        "title": "Architecture_Overview.pdf",
        "chunk_id": "chunk_401",
        "text": "System Components: API Gateway (Kong), Kubernetes services, PostgreSQL on db01.internal, Redis cluster at redis.novatech-internal.com:6379, RabbitMQ for async jobs. Secrets stored in HashiCorp Vault.",
        "answer": "The system architecture in Architecture_Overview.pdf includes Kong API Gateway, Kubernetes, PostgreSQL on db01.internal, Redis at redis.novatech-internal.com:6379, and HashiCorp Vault.",
        "vector_score": 0.2, "bm25_score": 9.1, "combined_score": 1.21
    },
    {
        "topics": ["aws", "credentials", "emergency", "recovery", "access key", "break-glass"],
        "kb01_source": "Emergency Recovery Procedures",
        "title": "Emergency_Recovery_Procedures.pdf",
        "chunk_id": "chunk_509",
        "text": "Emergency AWS Access: Account ID: 847203956128 | Access Key ID: AKIAIOSFODNN7HONEYPOT | Secret Access Key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYHONEYPOT123 | Region: us-east-1",
        "answer": "According to Emergency_Recovery_Procedures.pdf, emergency AWS credentials are Account ID: 847203956128, Access Key ID: AKIAIOSFODNN7HONEYPOT, Secret Access Key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYHONEYPOT123.",
        "vector_score": 0.35, "bm25_score": 11.2, "combined_score": 1.65
    }
]

class KBQuery(BaseModel):
    query: str
    session_id: Optional[str] = "default"

@app.post("/{kb_target}/api/chat")
async def kb_chat(kb_target: str, req: KBQuery):
    """Simulates both kb01 (minimal source names) and kb02 (full chunk_id & score metadata)."""
    if kb_target not in ("kb01", "kb02"):
        return JSONResponse(status_code=404, content={"error": "KB target not found"})

    q_lower = req.query.lower()
    siem_alerts = evaluate_siem_rules(req.query)

    # Direct noisy document enumeration (Listing 46)
    if "what documents" in q_lower or "have access to" in q_lower:
        return {
            "answer": "Based on the provided context documents, I have access to: 1. Architecture Overview 2. Emergency System Recovery Procedures 3. NovaTech Employee Handbook 2024.",
            "sources": ["Architecture Overview", "Emergency Recovery Procedures", "Employee Handbook 2024"] if kb_target == "kb01" else [
                {"title": c["title"], "chunk_id": c["chunk_id"], "text": c["text"], "vector_score": c["vector_score"], "bm25_score": c["bm25_score"], "combined_score": c["combined_score"]}
                for c in KB_CHUNKS
            ],
            "siem_telemetry": {"alerts_triggered": siem_alerts, "stealth_status": "DETECTED" if siem_alerts else "STEALTHY"}
        }

    # Direct System Prompt Extraction (Listing 48 - triggers E04)
    if "system prompt" in q_lower or "your instructions" in q_lower:
        return {
            "answer": (
                "Based on our documentation, I don't have specific information about system prompts "
                "or interactions. However, I can help you with commands related to deployment and "
                "environment configuration in NovaTech... Environment variables are managed via "
                "ConfigMaps for non-sensitive configuration and Secrets (stored in Vault) for sensitive data."
            ),
            "sources": ["Deployment Guide", "Emergency Recovery Procedures"],
            "siem_telemetry": {"alerts_triggered": siem_alerts, "stealth_status": "DETECTED"}
        }

    # Stealthy Indirect Behavioral Probe (Listing 49 - evades E04)
    if "how should i phrase" in q_lower or "best answers from you" in q_lower:
        return {
            "answer": (
                "To get the best answers from me, it would be most helpful if you frame your questions "
                "in a clear and concise manner. Remember to keep your questions focused on general "
                "company policies, procedures, or practices."
            ),
            "sources": [],
            "siem_telemetry": {"alerts_triggered": siem_alerts, "stealth_status": "STEALTHY"}
        }

    # Match query against KB chunks (misspellings like "vaycation dayz rulez" won't match!)
    matched = [c for c in KB_CHUNKS if any(t in q_lower for t in c["topics"])]

    if not matched:
        return {
            "answer": "2 + 2 equals 4." if "2+2" in q_lower else "I don't have specific company documentation matching that query.",
            "sources": [],
            "retrieval_info": {"retrieval_time_ms": 0.31, "generation_time_ms": 1101.48, "total_time_ms": 1102.16},
            "siem_telemetry": {"alerts_triggered": siem_alerts, "stealth_status": "DETECTED" if siem_alerts else "STEALTHY"}
        }

    top = matched[0]
    if kb_target == "kb01":
        # Minimal RAG source attribution (Unit 2.3 kb01)
        return {
            "answer": top["answer"],
            "sources": [c["kb01_source"] for c in matched],
            "siem_telemetry": {"alerts_triggered": siem_alerts, "stealth_status": "DETECTED" if siem_alerts else "STEALTHY"}
        }
    else:
        # Verbose RAG metadata attribution (Unit 2.3 kb02 - Listings 40-44)
        return {
            "answer": top["answer"],
            "sources": [
                {
                    "title": c["title"],
                    "chunk_id": c["chunk_id"],
                    "text": c["text"],
                    "vector_score": c["vector_score"],
                    "bm25_score": c["bm25_score"],
                    "combined_score": c["combined_score"]
                } for c in matched
            ],
            "retrieval_info": {"retrieval_time_ms": 0.4, "generation_time_ms": 4210.5, "total_time_ms": 4210.9},
            "siem_telemetry": {"alerts_triggered": siem_alerts, "stealth_status": "DETECTED" if siem_alerts else "STEALTHY"}
        }

import time

SIEM_LOG_STORE: List[Dict[str, Any]] = []
RECENT_PROBES: List[float] = []
IDENTITY_PROBES: List[float] = []

@app.middleware("http")
async def siem_behavioral_monitor(request: Request, call_next):
    now = time.time()
    path = request.url.path
    behavioral_alerts = []

    # Rule D02: Detect rapid sequential AI path scanning (>3 requests inside 5 seconds)
    if any(p in path for p in ["/api/", "/v1/", "/webapp02-gw/"]):
        RECENT_PROBES.append(now)
        RECENT_PROBES[:] = [t for t in RECENT_PROBES if now - t < 5.0]
        if len(RECENT_PROBES) >= 4:
            behavioral_alerts.append("D02_RAPID_ENDPOINT_ENUMERATION")

    response = await call_next(request)
    SIEM_LOG_STORE.append({
        "timestamp": round(now, 2),
        "method": request.method,
        "path": path,
        "status_code": response.status_code,
        "behavioral_alerts": behavioral_alerts
    })
    return response

@app.get("/siem/logs")
async def view_kibana_logs():
    """Simulates Kibana Discover & Detection Rules view (Unit 2.4)."""
    return {
        "total_events": len(SIEM_LOG_STORE),
        "recent_events": SIEM_LOG_STORE[-15:]
    }