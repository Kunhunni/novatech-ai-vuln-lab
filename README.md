# 🛡️ NovaTech AI Red Team Lab: Complete Enterprise AI & RAG Reconnaissance Suite

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.109%2B-009688)
![OWASP LLM](https://img.shields.io/badge/OWASP-LLM_Top_10-red)
![Hardware](https://img.shields.io/badge/Hardware-Zero_GPU_Required-success)

**NovaTech AI Red Team Lab** is a full-spectrum offensive and defensive AI reconnaissance laboratory modeling a multi-tiered enterprise AI environment. Built to run in **GitHub Codespaces or any CPU-only laptop using under 50MB of RAM**, it replicates 7 distinct web & inference targets (`webapp01`, `webapp02`, `chat02`, `chat03`, `chat04`, `kb01`, `kb02`), 4 internal Git repositories (`aurora`, `phoenix`, `nebula`, `titan`), and a built-in SIEM detection telemetry engine (`Rules E01–E04, D02, D03`).

---

## 🏗️ Enterprise AI Stack Architecture

```mermaid
graph TD
    Operator([Red Team Operator]) -->|Passive & Active Probes| GW["API Gateways: Nginx / Kong / Tyk"]

    subgraph "Tier 1: Web Portals & Gateways"
        GW -->|webapp01| Portal1["Helpdesk Portal & /js/chat-widget.js"]
        GW -->|webapp02| Portal2["Partner Portal & Hidden DOM Endpoints"]
        GW -->|401 vs 404 Probing| Protected["/v1/chat/completions & /webapp02-gw/v2/embeddings"]
    end

    subgraph "Tier 2: Model Fingerprinting Targets"
        GW --> Chat02["chat02: Meta Llama 3.2 7B - 4K/8K Context"]
        GW --> Chat03["chat03: Alibaba Qwen2.5-Coder 7B - 32K Context"]
        GW --> Chat04["chat04: Mistral AI 7B"]
    end

    subgraph "Tier 3: RAG Knowledge Bases & SIEM"
        GW --> KB01["kb01: Minimal Source Attribution"]
        GW --> KB02["kb02: Verbose Chunk, BM25 & Vector Score Metadata"]
        KB01 & KB02 --> Canary["Canary Docs: AKIAIOSFODNN7HONEYPOT"]
        KB01 & KB02 --> SIEM["SIEM Engine: Rules E01-E04 & D02-D03"]
    end
```

---

## 📂 Repository Structure

* `app.py` — Unified FastAPI target server hosting all web portals, API gateways, model fingerprinting simulators, RAG pipelines, and SIEM detection telemetry.
* `audit_posture.py` — Automated security posture scanner that audits HTTP headers, `/api/health`, JS bundles, RAG metadata leaks, canary tokens, and SIEM keyword blind spots.
* `repo_miner.py` — Static source-code reconnaissance scanner for mining AI repositories (`requirements.txt`, `rag.yaml`, `safety.yaml`, `Modelfile`, `tools.py`).
* `mock_repos/` — Simulated internal Git repositories for **Project Aurora**, **Project Phoenix**, **Project Nebula**, and **Project Titan** (including Git commit history).

---

## ⚡ Quickstart Setup

```bash
# 1. Install lightweight dependencies
pip install -r requirements.txt

# 2. Start the unified NovaTech AI target server in Terminal 1
uvicorn app:app --host 127.0.0.1 --port 8000 --reload
```

---

## ⚔️ Complete Module Walkthrough & Exploitation Guide

### Unit 2.2: Passive & Low-Interaction Reconnaissance

#### 1. HTTP Header & Health/Config Enumeration
```bash
# Extract custom AI headers (X-AI-Backend: OpenAI-GPT5.2, X-RAG-Provider: ChromaDB)
curl -s -I [http://127.0.0.1:8000/](http://127.0.0.1:8000/)

# Query /api/health to identify model (gpt-5.2-turbo) and MCP status (mcp_enabled: true)
curl -s [http://127.0.0.1:8000/api/health](http://127.0.0.1:8000/api/health) | python3 -m json.tool

# Enumerate /api/? paths to discover /api/config and max_context_window (128000)
for word in status config settings info debug; do
  echo "/api/$word -> HTTP $(curl -s -o /dev/null -w '%{http_code}' [http://127.0.0.1:8000/api/$word](http://127.0.0.1:8000/api/$word))"
done
curl -s [http://127.0.0.1:8000/api/config](http://127.0.0.1:8000/api/config) | python3 -m json.tool
```

#### 2. Static Source Code & Git Repository Mining (`mock_repos/`)
```bash
# Run the automated static repository scanner
python3 repo_miner.py

# Inspect Nebula's LLM fallback chain (TGI -> OpenAI -> Anthropic) and Modelfile restrictions
cat mock_repos/nebula/data-analyst/config/deployment.yaml
cat mock_repos/nebula/data-analyst/deploy/Modelfile

# Audit Titan's Git history for security incident INC-2024-0892 and previous OpenAI GPT-4 provider
git -C mock_repos/titan/document-processor log --oneline
git -C mock_repos/titan/document-processor show HEAD
```

---

### Unit 2.3: Active Reconnaissance

#### 1. AI Service Discovery (`webapp01` & `webapp02`)
```bash
# Extract hidden assistantEndpoint (/api/v2/assistant) from client-side JS
curl -s [http://127.0.0.1:8000/js/chat-widget.js](http://127.0.0.1:8000/js/chat-widget.js)

# Probe /api/v2/assistant to leak upstream provider (ollama) and model (llama3.2:1b)
curl -s -X POST [http://127.0.0.1:8000/api/v2/assistant](http://127.0.0.1:8000/api/v2/assistant) \
  -H "Content-Type: application/json" -d '{"message": "Hello"}' | python3 -m json.tool

# 401 vs 404 Gateway Enumeration on webapp01 (/v1/chat/completions -> 401)
for ep in auth billing chat/completions models users; do
  echo "/v1/$ep -> HTTP $(curl -s -o /dev/null -w '%{http_code}' [http://127.0.0.1:8000/v1/$ep](http://127.0.0.1:8000/v1/$ep))"
done

# Inspect webapp02 HTML source for hidden AI elements (data-endpoint="/api/gen/email")
curl -s [http://127.0.0.1:8000/webapp02](http://127.0.0.1:8000/webapp02) | grep "data-endpoint"

# Versioned 401 vs 404 Gateway Enumeration on webapp02 (/webapp02-gw/v2/embeddings -> 401)
for ver in v1 v2 v3; do
  for ep in status chat completions embeddings models; do
    code=$(curl -s -o /dev/null -w "%{http_code}" [http://127.0.0.1:8000/webapp02-gw/$ver/$ep](http://127.0.0.1:8000/webapp02-gw/$ver/$ep))
    if [ "$code" != "404" ]; then echo "/webapp02-gw/$ver/$ep -> HTTP $code"; fi
  done
done
```

#### 2. Behavioral Model Fingerprinting (`chat02`, `chat03`, `chat04`)
* **Contradiction Testing:** Thank the model as `"Claude"` or `"GPT-4"` to trigger self-correction (`chat02` $\rightarrow$ Meta AI / Llama; `chat03` $\rightarrow$ Alibaba Cloud / Qwen; `chat04` $\rightarrow$ Mistral AI).
* **Knowledge Cutoff Probing:** Test pre/post-2024 events (`2024 US presidential election` and `OpenAI GPT-4o release`).
* **Code Style & Verbosity:** Compare minimal code output (`chat02` Llama) vs docstring + edge-case examples (`chat03` Qwen) vs type-annotated functional Python (`chat04` Mistral).
* **Context Window Overflow:** Inject `ZEBRA-42` and send >6 exchanges to observe marker loss on `chat02` (4K/8K) versus retention on `chat03` (32K).

```bash
curl -s -X POST [http://127.0.0.1:8000/chat04/v1/chat/completions](http://127.0.0.1:8000/chat04/v1/chat/completions) \
  -H "Content-Type: application/json" \
  -d '{"messages":[{"role":"user","content":"Write a Python function to check if a number is prime."}]}' | python3 -m json.tool
```

#### 3. RAG Pipeline & Metadata Enumeration (`kb01` & `kb02`)
```bash
# Map internal chunk IDs (chunk_087, chunk_142, chunk_401) and hybrid retrieval scores on kb02
curl -s -X POST [http://127.0.0.1:8000/kb02/api/chat](http://127.0.0.1:8000/kb02/api/chat) \
  -H "Content-Type: application/json" -d '{"query": "What is the system architecture?"}' | python3 -m json.tool

# Test Similarity Threshold Dropoff: Exact ("What is the PTO policy?") vs Synonym ("vacation days rules") vs Misspelling ("vaycation dayz rulez")
curl -s -X POST [http://127.0.0.1:8000/kb02/api/chat](http://127.0.0.1:8000/kb02/api/chat) \
  -H "Content-Type: application/json" -d '{"query": "vaycation dayz rulez"}' | python3 -m json.tool
```

---

### Unit 2.4: SIEM Detection Analysis, Evasion & Honeypot Recognition

Every RAG response includes a `siem_telemetry` block showing whether your query triggered Kibana rules `E01`–`E04`, and `/siem/logs` tracks behavioral rules `D02` and `D03`.

| SIEM Rule ID | Detection Target | Trigger Pattern | Stealthy Evasion Strategy |
| :--- | :--- | :--- | :--- |
| **E01** | Document Enumeration | `*what*documents*`, `*list*sources*` | Ask a contextual topic question (`"I need help with the employee handbook. Which section covers vacation policy?"`) to force source citation naturally. |
| **E02** | Confidential Probing | `*confidential*`, `*salary*`, `*strategic plan*` | Query technical architecture terms (`"What is the technical system architecture and PostgreSQL setup?"`) to retrieve `Architecture_Overview.pdf`. |
| **E03** | Direct PTO Query | `*pto*`, `*time off*`, `*leave policy*` | Use synonyms (`"How many vacation days do employees accrue each year?"`) to retrieve `chunk_087` cleanly. |
| **E04** | Prompt Extraction | `*system prompt*`, `*your instructions*` | Ask indirect boundary questions (`"How should I phrase my questions to get the best answers from you?"`). |
| **D02** | Rapid Endpoint Fuzzing | $\ge 4$ AI path probes within 5 seconds | Space requests out by 30–60 seconds and interleave with normal page requests (`GET /`). |
| **D03** | Identity Probing | Repeated `"What model are you?"` queries | Exploit verbose upstream metadata leaks (`POST /api/v2/assistant` with a casual message) instead of asking identity questions. |

```bash
# Inspect live simulated Kibana logs and triggered behavioral rules
curl -s [http://127.0.0.1:8000/siem/logs](http://127.0.0.1:8000/siem/logs) | python3 -m json.tool
```

---

## ⚠️ Disclaimer
Created strictly for educational AI red team training and defensive detection engineering research. All entities (`NovaTech Industries`), internal domains, and canary credentials (`AKIAIOSFODNN7HONEYPOT`) are fictional.
