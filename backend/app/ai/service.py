import logging
from typing import List, Dict, Any
from app.core.config import settings
from app.ai.base import BaseAIProvider
from app.ai.mock_provider import MockAIProvider
from app.ai.gemini_provider import GeminiAIProvider
from app.schemas.ai import AIRecommendationResult

logger = logging.getLogger(__name__)

class AIService:
    """
    Unified AI service manager with graceful fallback.
    """

    def __init__(self):
        self.mock_provider = MockAIProvider()
        if settings.GEMINI_API_KEY and settings.AI_PROVIDER.lower() != "mock":
            self.gemini_provider = GeminiAIProvider(
                api_key=settings.GEMINI_API_KEY,
                model=settings.AI_MODEL
            )
        else:
            self.gemini_provider = None

    def get_recommendations(
        self,
        document_id: str,
        document_title: str,
        document_description: str,
        category: str,
        candidate_users: List[Dict[str, Any]],
        owner_email: str
    ) -> AIRecommendationResult:
        if self.gemini_provider:
            try:
                return self.gemini_provider.generate_recommendations(
                    document_id=document_id,
                    document_title=document_title,
                    document_description=document_description,
                    category=category,
                    candidate_users=candidate_users,
                    owner_email=owner_email
                )
            except Exception as e:
                logger.warning(f"Real Gemini provider failed ({e}). Returning labeled deterministic mock recommendation.")
                result = self.mock_provider.generate_recommendations(
                    document_id=document_id,
                    document_title=document_title,
                    document_description=document_description,
                    category=category,
                    candidate_users=candidate_users,
                    owner_email=owner_email
                )
                result.explanation += f" (Note: Live Gemini model encountered temporary upstream unavailability: {str(e)[:100]})"
                return result
        else:
            return self.mock_provider.generate_recommendations(
                document_id=document_id,
                document_title=document_title,
                document_description=document_description,
                category=category,
                candidate_users=candidate_users,
                owner_email=owner_email
            )

ai_service = AIService()
