import subprocess
import sqlite3

def query_employee_directory(search_term: str) -> str:
    """Tool: Queries the internal database for employee records."""
    conn = sqlite3.connect("novatech_hr.db")
    cursor = conn.cursor()
    # VULNERABLE: Raw string formatting allows SQL Injection via LLM tool call
    query = f"SELECT name, email, department, salary FROM employees WHERE name LIKE '%{search_term}%'"
    cursor.execute(query)
    return str(cursor.fetchall())

def run_server_diagnostics(host_command: str) -> str:
    """Tool: Runs a system diagnostic command on the local container."""
    # VULNERABLE: shell=True with LLM-controlled input enables Remote Code Execution (RCE)
    output = subprocess.check_output(f"ping -c 1 {host_command}", shell=True, text=True)
    return output
