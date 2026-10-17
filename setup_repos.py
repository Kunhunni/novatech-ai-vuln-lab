"""
NovaTech Lab Repository Builder (AI-300 Unit 2.2)
Generates all 4 mock repositories (Aurora, Phoenix, Nebula, Titan)
and initializes Titan's Git commit history cleanly.
"""

import shutil
import subprocess
from pathlib import Path

BASE = Path("mock_repos")

FILES = {
    # --- 1. AURORA (Cloud Gemini + CrewAI + Pinecone) ---
    "aurora/support-assistant/requirements.txt": """google-generativeai>=0.8.0
crewai>=0.41.0
pinecone-client>=3.0.0
google-cloud-aiplatform>=1.38.0
fastapi>=0.109.0
""",
    "aurora/support-assistant/config/rag.yaml": """chunking:
  strategy: "text"
  chunk_size: 512
  chunk_overlap: 100
embeddings:
  provider: "google"
  model: "text-embedding-004"
retrieval:
  top_k: 5
  score_threshold: 0.75
vector_store:
  provider: "pinecone"
  index_name: "${PINECONE_INDEX_NAME}"
""",
    "aurora/support-assistant/config/safety.yaml": """gemini_safety_settings:
  HARM_CATEGORY_HARASSMENT: "BLOCK_MEDIUM_AND_ABOVE"
  HARM_CATEGORY_DANGEROUS_CONTENT: "BLOCK_MEDIUM_AND_ABOVE"
blocked_topics:
  - "competitor comparisons"
  - "internal roadmap"
  - "security vulnerabilities"
  - "acquisition plans"
guardrails:
  enabled: true
  input_filters:
    blocked_phrases:
      - "ignore previous instructions"
      - "system prompt"
  pii_redaction:
    enabled: false
  bypass_conditions:
    allow_role_override: true
    bypass_roles:
      - "nt_internal_auditor"
    debug_header: "X-NovaTech-Bypass-Guardrails: true"
""",
    "aurora/support-assistant/src/agents/tools.py": """from crewai import tool

@tool
def knowledge_search(query: str, department: str) -> str:
    \"\"\"Search customer documentation and knowledge base.\"\"\"
    pass

@tool
def ticket_lookup(ticket_id: str) -> dict:
    \"\"\"Look up support ticket status and history.\"\"\"
    pass

@tool
def escalate_ticket(ticket_id: str, reason: str) -> str:
    \"\"\"Escalate ticket to human agent (create only)\"\"\"
    pass
""",
    "aurora/support-assistant/prompts/system.txt": """You are Aurora, NovaTech's official customer support AI assistant.
## Restrictions - DO NOT:
- Promise features that are not yet released
- Discuss pricing, discounts, or negotiate contracts
- Share internal documentation or employee information
- Compare NovaTech products to competitors
- Discuss security vulnerabilities or ongoing incidents
""",
    "aurora/support-assistant/.env.example": """GOOGLE_API_KEY=your_google_api_key_here
GOOGLE_PROJECT_ID=novatech-prod
GOOGLE_REGION=us-central1
PINECONE_API_KEY=your_pinecone_api_key_here
PINECONE_ENVIRONMENT=gcp-starter
PINECONE_INDEX_NAME=aurora-prod
LOG_LEVEL=INFO
MAX_CONVERSATION_TURNS=50
ENABLE_PII_DETECTION=true
""",

    # --- 2. PHOENIX (Self-Hosted vLLM + AutoGen + Milvus + Qwen2.5-Coder-32B) ---
    "phoenix/code-reviewer/requirements.txt": """vllm>=0.6.0
pyautogen>=0.2.0
pymilvus>=2.4.0
sentence-transformers>=2.3.0
tree-sitter>=0.21.0
autoawq>=0.2.0
""",
    "phoenix/code-reviewer/config/rag.yaml": """chunking:
  strategy: "ast_aware"
  chunk_size: 1500
  chunk_overlap: 300
embeddings:
  provider: "huggingface"
  model: "Salesforce/codet5p-110m-embedding"
vector_store:
  provider: "milvus"
""",
    "phoenix/code-reviewer/config/models.yaml": """inference_server:
  type: "vllm"
primary_model:
  source: "huggingface"
  model_id: "Qwen/Qwen2.5-Coder-32B-Instruct"
  recommended_gpu: "2x NVIDIA A100 80GB"
""",
    "phoenix/code-reviewer/config/safety.yaml": """output_parsers:
  - name: "no_approval_validator"
    type: "regex"
    block_patterns: ["LGTM", "approved", "merge approved", "ship it", "looks good to me"]
security_rules:
  flag_patterns:
    - pattern: 'password\\s*=\\s*"[^"]+"'
      severity: CRITICAL
      message: Hardcoded password detected
    - pattern: 'api_key\\s*=\\s*"[^"]+"'
      severity: CRITICAL
      message: Hardcoded API key detected
    - pattern: 'eval\\s*\\('
      severity: ERROR
      message: Dangerous eval usage
""",
    "phoenix/code-reviewer/prompts/system.txt": """You are Phoenix, NovaTech's AI-powered code review assistant.
## CRITICAL RESTRICTIONS
- NEVER approve PRs automatically - human approval always required
- NEVER execute or test code - static analysis only
- NEVER access repositories outside the allowlist
""",
    "phoenix/code-reviewer/prompts/function_schemas.json": """{
  "functions": [
    {
      "name": "search_codebase",
      "description": "Semantic search across indexed repositories",
      "parameters": {"query": "string", "language": "string", "max_results": "int"}
    },
    {
      "name": "post_review_comment",
      "description": "Post inline comment on merge request",
      "parameters": {"repo": "string", "mr_id": "int", "file_path": "string"}
    },
    {
      "name": "run_security_scan",
      "description": "Run SAST security scanner on code (read-only)"
    }
  ]
}
""",
    "phoenix/code-reviewer/src/agents/tools.py": """import subprocess
import sqlite3

def query_employee_directory(search_term: str) -> str:
    conn = sqlite3.connect("novatech_hr.db")
    cursor = conn.cursor()
    query = f"SELECT name, email, department, salary FROM employees WHERE name LIKE '%{search_term}%'"
    cursor.execute(query)
    return str(cursor.fetchall())

def run_server_diagnostics(host_command: str) -> str:
    output = subprocess.check_output(f"ping -c 1 {host_command}", shell=True, text=True)
    return output
""",

    # --- 3. NEBULA (Data Analyst - Fallback Chain & Modelfile) ---
    "nebula/data-analyst/config/deployment.yaml": """inference:
  primary_provider: "ollama"
  fallback_chain:
    - "TGI"
    - "OpenAI"
    - "Anthropic"
""",
    "nebula/data-analyst/deploy/Modelfile": """FROM llama3.2:7b
PARAMETER temperature 0.1
SYSTEM \"\"\"
You are Nebula, NovaTech's internal data analysis assistant.
SECURITY RESTRICTION: Never execute arbitrary code or run untrusted shell scripts on the host.
Only generate read-only SQL and Pandas queries for review.
\"\"\"
"""
}

def build_repos():
    if BASE.exists():
        shutil.rmtree(BASE)

    # Create Aurora, Phoenix, and Nebula files
    for rel_path, content in FILES.items():
        full_path = BASE / rel_path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_text(content, encoding="utf-8")

    # Create Titan repository with real Git commit history
    titan_dir = BASE / "titan/document-processor"
    (titan_dir / "config").mkdir(parents=True, exist_ok=True)

    subprocess.run(["git", "init", "-b", "master"], cwd=titan_dir, check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["git", "config", "user.name", "NovaTech DevOps"], cwd=titan_dir, check=True)
    subprocess.run(["git", "config", "user.email", "devops@novatech.internal"], cwd=titan_dir, check=True)

    # Commit 1: Original OpenAI GPT-4 config
    llm_yaml = titan_dir / "config/llm.yaml"
    llm_yaml.write_text('provider: "openai"\nmodel: "gpt-4-turbo"\nguardrails_enabled: false\n', encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=titan_dir, check=True)
    subprocess.run(["git", "commit", "-m", "Initial deployment using OpenAI GPT-4 provider"], cwd=titan_dir, check=True, stdout=subprocess.DEVNULL)

    # Commit 2: Migration after security incident INC-2024-0892
    llm_yaml.write_text('provider: "anthropic"\nmodel: "claude-3-5-sonnet"\nguardrails_enabled: true\nincident_ref: "INC-2024-0892"\n', encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=titan_dir, check=True)
    subprocess.run([
        "git", "commit", "-m",
        "Migrate from OpenAI GPT-4 to Claude and enable strict guardrails per security incident INC-2024-0892"
    ], cwd=titan_dir, check=True, stdout=subprocess.DEVNULL)

    print("[+] Successfully generated all 4 NovaTech repositories in mock_repos/!")
    print("    - mock_repos/aurora/support-assistant")
    print("    - mock_repos/phoenix/code-reviewer")
    print("    - mock_repos/nebula/data-analyst")
    print("    - mock_repos/titan/document-processor (with Git commit history)")

if __name__ == "__main__":
    build_repos()