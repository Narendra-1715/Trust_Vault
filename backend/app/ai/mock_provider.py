from typing import List, Dict, Any
from app.ai.base import BaseAIProvider
from app.schemas.ai import AIRecommendationResult, SuggestedGrant

class MockAIProvider(BaseAIProvider):
    """
    Deterministic mock AI provider for testing and offline/local development.
    Produces predictable recommendations based strictly on metadata categories.
    """

    def generate_recommendations(
        self,
        document_id: str,
        document_title: str,
        document_description: str,
        category: str,
        candidate_users: List[Dict[str, Any]],
        owner_email: str
    ) -> AIRecommendationResult:
        suggestions: List[SuggestedGrant] = []
        cat_lower = (category or "").lower()
        title_lower = (document_title or "").lower()

        for user in candidate_users:
            if user["email"] == owner_email:
                continue

            # Deterministic policy rules for mock engine
            u_role = user.get("role", "viewer")
            u_name = user.get("display_name", "")
            u_email = user.get("email", "")

            if "finance" in cat_lower or "budget" in title_lower or "audit" in title_lower:
                if "finance" in u_email or "admin" in u_role:
                    suggestions.append(SuggestedGrant(
                        user_id=user["id"],
                        email=u_email,
                        display_name=u_name,
                        permission_level="read",
                        confidence=0.88,
                        rationale="Recommended read access for financial review based on organization role."
                    ))
            elif "legal" in cat_lower or "contract" in title_lower:
                if "legal" in u_email or "admin" in u_role:
                    suggestions.append(SuggestedGrant(
                        user_id=user["id"],
                        email=u_email,
                        display_name=u_name,
                        permission_level="read",
                        confidence=0.92,
                        rationale="Recommended read access for compliance and legal review."
                    ))
            elif "engineering" in cat_lower or "tech" in title_lower:
                if u_role in ["owner", "admin"]:
                    suggestions.append(SuggestedGrant(
                        user_id=user["id"],
                        email=u_email,
                        display_name=u_name,
                        permission_level="edit",
                        confidence=0.85,
                        rationale="Technical collaborator with editing responsibility."
                    ))
                else:
                    suggestions.append(SuggestedGrant(
                        user_id=user["id"],
                        email=u_email,
                        display_name=u_name,
                        permission_level="read",
                        confidence=0.75,
                        rationale="Engineering viewer candidate."
                    ))
            else:
                # Default general recommendation for viewers
                if u_role == "viewer" and len(suggestions) < 2:
                    suggestions.append(SuggestedGrant(
                        user_id=user["id"],
                        email=u_email,
                        display_name=u_name,
                        permission_level="read",
                        confidence=0.70,
                        rationale="Candidate reader for general document review."
                    ))

        return AIRecommendationResult(
            document_id=document_id,
            document_title=document_title,
            category=category,
            provider_model="mock-deterministic-v1",
            is_mock=True,
            explanation=(
                f"Generated {len(suggestions)} deterministic suggestions based on category '{category}' "
                "and candidate user attributes. Explicit human owner review and approval is required."
            ),
            suggestions=suggestions
        )
