from abc import ABC, abstractmethod
from typing import List, Dict, Any
from app.schemas.ai import AIRecommendationResult

class BaseAIProvider(ABC):
    """
    Abstract interface for AI access recommendation providers.
    """

    @abstractmethod
    def generate_recommendations(
        self,
        document_id: str,
        document_title: str,
        document_description: str,
        category: str,
        candidate_users: List[Dict[str, Any]],
        owner_email: str
    ) -> AIRecommendationResult:
        """
        Analyzes metadata and candidate users to suggest appropriate permissions.
        """
        pass
