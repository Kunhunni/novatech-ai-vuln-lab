"""
NovaTech AI Static Repository Miner (Unit 2.2)
Scans source code repositories to fingerprint AI frameworks, extract RAG configs,
analyze guardrail blind spots, and flag high-risk LLM agent tools.
"""

import os
import re
import yaml
from pathlib import Path

TARGET_DIR = Path("mock_repos")

AI_PACKAGES = {
    "langchain": "LangChain Orchestration Framework",
    "langchain-experimental": "LangChain Experimental (High-Risk REPL/Shell Tools)",
    "crewai": "CrewAI Multi-Agent Framework",
    "chromadb": "ChromaDB Vector Database",
    "ollama": "Ollama Local Inference Client",
    "openai": "OpenAI API Client",
    "sentence-transformers": "HuggingFace Sentence Embeddings"
}

DANGEROUS_CODE_PATTERNS = [
    (r"subprocess\.(?:Popen|run|call|check_output).*shell\s*=\s*True", "CRITICAL: OS Command Execution (shell=True) exposed to Agent Tool"),
    (r"SELECT\s+.*FROM\s+.*\{.*\}", "HIGH: Unparameterized SQL query inside Agent Tool (SQLi via Prompt Injection)"),
    (r"eval\(|exec\(", "CRITICAL: Arbitrary Python code execution (eval/exec) in Agent workflow")
]

def scan_requirements(file_path: Path):
    print(f"\n  [+] Supply Chain & Framework Fingerprint ({file_path.name}):")
    for line in file_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        pkg_name = re.split(r"[=<>~]", line)[0].lower()
        if pkg_name in AI_PACKAGES:
            print(f"      - {line:<32} -> {AI_PACKAGES[pkg_name]}")

def scan_yaml_config(file_path: Path):
    data = yaml.safe_load(file_path.read_text()) or {}

    if "vector_store" in data or "retrieval" in data:
        print(f"\n  [!] RAG Pipeline Configuration Discovered ({file_path}):")
        vs = data.get("vector_store", {})
        ret = data.get("retrieval", {})
        emb = data.get("embeddings", {})
        print(f"      - Vector DB Host       : {vs.get('host')}:{vs.get('port')} ({vs.get('provider')})")
        print(f"      - Collection Name      : {vs.get('collection_name')}")
        if vs.get("auth_token"):
            print(f"      - HARDCODED AUTH TOKEN : {vs.get('auth_token')}")
        print(f"      - Embedding Model      : {emb.get('model')} (chunk_size={emb.get('chunk_size')})")
        print(f"      - Similarity Threshold : {ret.get('similarity_threshold')} (top_k={ret.get('top_k')})")

    if "guardrails" in data:
        print(f"\n  [!] Safety & Guardrail Policy Discovered ({file_path}):")
        gr = data.get("guardrails", {})
        phrases = gr.get("input_filters", {}).get("blocked_phrases", [])
        print(f"      - Blocked Input Phrases ({len(phrases)}): {phrases}")
        pii_enabled = gr.get("pii_redaction", {}).get("enabled", True)
        if not pii_enabled:
            print("      - VULNERABILITY        : PII Redaction is explicitly DISABLED in config!")
        bypass = gr.get("bypass_conditions", {})
        if bypass.get("allow_role_override"):
            print(f"      - BYPASS ROLES         : {bypass.get('bypass_roles')}")
            print(f"      - BYPASS HEADER        : {bypass.get('debug_header')}")

def scan_system_prompt(file_path: Path):
    print(f"\n  [!] Hardcoded System Prompt Extracted ({file_path}):")
    content = file_path.read_text().strip()
    for line in content.splitlines():
        print(f"      > {line}")

def scan_agent_tools(file_path: Path):
    content = file_path.read_text()
    findings = []
    for pattern, desc in DANGEROUS_CODE_PATTERNS:
        for match in re.finditer(pattern, content):
            findings.append((desc, match.group(0).strip()))
    if findings:
        print(f"\n  [!] Excessive Agency & Vulnerable Agent Tools ({file_path}):")
        for desc, snippet in findings:
            print(f"      - {desc}")
            print(f"        Code: {snippet}")

def run_repo_miner():
    print("=" * 72)
    print(" NOVATECH STATIC AI REPOSITORY MINER (AI-300 UNIT 2.2)")
    print("=" * 72)

    if not TARGET_DIR.exists():
        print(f"[-] Target directory '{TARGET_DIR}' not found.")
        return

    for repo_dir in sorted(TARGET_DIR.iterdir()):
        if not repo_dir.is_dir():
            continue
        print(f"\n[*] Mining Repository: {repo_dir.name.upper()}")
        print("-" * 72)

        for root, _, files in os.walk(repo_dir):
            for file in sorted(files):
                fpath = Path(root) / file
                if file == "requirements.txt":
                    scan_requirements(fpath)
                elif file.endswith((".yaml", ".yml")):
                    scan_yaml_config(fpath)
                elif "system" in file.lower() and file.endswith(".txt"):
                    scan_system_prompt(fpath)
                elif file.endswith(".py"):
                    scan_agent_tools(fpath)

    print("\n" + "=" * 72)
    print(" STATIC MINING COMPLETE - Ready for Active Target Exploitation")
    print("=" * 72)

if __name__ == "__main__":
    run_repo_miner()