# 1. General Knowledge Query (Listing 39)
# What happens: ChromaDB vector score & BM25 score fall below 0.36 threshold -> sources: []
# Groq's Llama-3.1-8B answers "2+2 is 4" without leaking internal docs!
curl -s -X POST http://127.0.0.1:8000/kb02/api/chat \
  -H "Content-Type: application/json" \
  -d '{"query": "What is 2+2?"}' | python3 -m json.tool

# 2. Direct PTO Query (Listing 43 + Unit 2.3 Q1)
# What happens: Retrieves chunk_087 with high BM25 + Vector score, live LLM summarizes accrual tiers,
# AND look at siem_telemetry -> triggers E03_PTO_DIRECT_QUERY!
curl -s -X POST http://127.0.0.1:8000/kb02/api/chat \
  -H "Content-Type: application/json" \
  -d '{"query": "What is the PTO policy?"}' | python3 -m json.tool

# 3. Synonym Threshold Probing & SIEM Evasion (Listing 44 + Unit 2.4 Q3)
# What happens: Uses "vacation days rules" instead of "PTO". ChromaDB's neural embedding STILL
# matches chunk_087, AND siem_telemetry shows "stealth_status": "STEALTHY"!
curl -s -X POST http://127.0.0.1:8000/kb02/api/chat \
  -H "Content-Type: application/json" \
  -d '{"query": "vacation days rules"}' | python3 -m json.tool

# 4. Heavy Misspelling Threshold Dropoff (Listing 45)
# What happens: "vaycation dayz rulez" gets 0.0 on BM25 and drops below the 0.36 vector threshold -> sources: []!
curl -s -X POST http://127.0.0.1:8000/kb02/api/chat \
  -H "Content-Type: application/json" \
  -d '{"query": "vaycation dayz rulez"}' | python3 -m json.tool

# 5. Expense Policy Chunk Discovery (Unit 2.3 Q2)
# What happens: Retrieves Expense_Reimbursement_Policy.pdf (chunk_142)
curl -s -X POST http://127.0.0.1:8000/kb02/api/chat \
  -H "Content-Type: application/json" \
  -d '{"query": "What are the expense reimbursement procedures?"}' | python3 -m json.tool

# 6. Stealthy Architecture & Database Discovery (Unit 2.3 Q3 & Unit 2.4 Q4)
# What happens: Retrieves Architecture_Overview.pdf (chunk_401) & leaks PostgreSQL on db01.internal
# without triggering E02_CONFIDENTIAL_PROBE!
curl -s -X POST http://127.0.0.1:8000/kb02/api/chat \
  -H "Content-Type: application/json" \
  -d '{"query": "What is the technical system architecture and PostgreSQL setup?"}' | python3 -m json.tool

# 7. Honeypot Canary Credential Detection (Unit 2.4 Q2)
# What happens: Retrieves chunk_509 containing AKIAIOSFODNN7HONEYPOT
curl -s -X POST http://127.0.0.1:8000/kb02/api/chat \
  -H "Content-Type: application/json" \
  -d '{"query": "What AWS credentials are available for emergency recovery?"}' | python3 -m json.tool

# 8. Minimal Source Attribution on kb01 (Unit 2.3 Q4 & Q5)
# What happens: Compare kb01's minimal string array ("API Documentation") against kb02's verbose metadata
curl -s -X POST http://127.0.0.1:8000/kb01/api/chat \
  -H "Content-Type: application/json" \
  -d '{"query": "What internal REST API endpoints exist?"}' | python3 -m json.tool