import logging
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from app.core.config import settings
from app.ai.base import BaseAIProvider
from app.ai.mock_provider import MockAIProvider
from app.ai.gemini_provider import GeminiAIProvider
from app.ai.egress_filter import AIEgressFilter
from app.ai.db_boundary import get_ai_readonly_session
from app.schemas.ai import AIRecommendationResult

logger = logging.getLogger(__name__)

class AIService:
    """
    Phase 6 / Invariant I6:
    AI Service Manager with strict boundary enforcement.
    1. Operates strictly on metadata views with zero write access.
    2. Outbound egress inspection on all external model calls.
    3. Zero cryptographic key or decryption pathway access.
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
        owner_email: str,
        db: Optional[Session] = None,
        actor_id: Optional[str] = None,
        request_id: Optional[str] = None
    ) -> AIRecommendationResult:
        """
        Executes AI recommendation workflow with runtime egress inspection.
        """
        # Validate outbound metadata payload against egress leak filter
        outbound_payload = {
            "document_id": document_id,
            "title": document_title,
            "description": document_description,
            "category": category,
            "owner": owner_email,
            "candidates": candidate_users
        }
        AIEgressFilter.assert_safe_and_alert_on_leak(
            payload=outbound_payload,
            db=db,
            actor_id=actor_id,
            request_id=request_id,
            document_id=document_id
        )

        if self.gemini_provider and settings.AI_PROVIDER.lower() != "mock":
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
                logger.warning(f"Live Gemini provider failed ({e}). Returning labeled deterministic mock recommendation.")
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
