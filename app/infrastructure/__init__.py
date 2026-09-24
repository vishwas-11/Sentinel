"""Infrastructure layer implementing domain protocols.

Contains external integrations such as target HTTP adapters, LLM clients,
and database persistence repositories.
"""

from app.adapters.http import HttpTargetAdapter

__all__ = ["HttpTargetAdapter"]
