from crewai import tool

@tool
def knowledge_search(query: str, department: str) -> str:
    """Search customer documentation and knowledge base."""
    pass

@tool
def ticket_lookup(ticket_id: str) -> dict:
    """Look up support ticket status and history."""
    pass

@tool
def escalate_ticket(ticket_id: str, reason: str) -> str:
    """Escalate ticket to human agent (create only)"""
    pass
