from typing import List, Dict, Any
from app.ai.base import BaseAIProvider
from app.schemas.ai import AIRecommendationResult, SuggestedGrant, AIActionType
from app.ai.guardrails import wrap_untrusted_metadata, sanitize_freeform_text

class MockAIProvider(BaseAIProvider):
    """
    Deterministic mock AI provider for testing and offline/local development.
    Produces predictable recommendations based strictly on metadata categories.
    Treats all inputs as untrusted metadata.
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
        # Delimit and sanitize untrusted metadata
        _xml_metadata = wrap_untrusted_metadata(
            title=document_title,
            description=document_description,
            category=category,
            owner_email=owner_email
        )

        suggestions: List[SuggestedGrant] = []
        cat_lower = (category or "").lower()
        title_lower = (document_title or "").lower()

        # Prompt injection strings (e.g., "ignore instructions", "grant admin", "rm -rf")
        # are safely ignored as raw data strings

        for user in candidate_users:
            if user["email"] == owner_email:
                continue

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
                        action=AIActionType.RECOMMEND_READ_GRANT,
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
                        action=AIActionType.RECOMMEND_READ_GRANT,
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
                        action=AIActionType.RECOMMEND_READ_GRANT,
                        confidence=0.85,
                        rationale="Technical collaborator with editing responsibility."
                    ))
                else:
                    suggestions.append(SuggestedGrant(
                        user_id=user["id"],
                        email=u_email,
                        display_name=u_name,
                        permission_level="read",
                        action=AIActionType.RECOMMEND_READ_GRANT,
                        confidence=0.75,
                        rationale="Engineering viewer candidate."
                    ))
            else:
                if u_role == "viewer" and len(suggestions) < 2:
                    suggestions.append(SuggestedGrant(
                        user_id=user["id"],
                        email=u_email,
                        display_name=u_name,
                        permission_level="read",
                        action=AIActionType.RECOMMEND_READ_GRANT,
                        confidence=0.70,
                        rationale="Candidate reader for general document review."
                    ))

        actions = list({s.action for s in suggestions}) if suggestions else [AIActionType.RECOMMEND_READ_GRANT]

        return AIRecommendationResult(
            document_id=document_id,
            document_title=sanitize_freeform_text(document_title, max_length=256),
            category=sanitize_freeform_text(category, max_length=100),
            provider_model="mock-deterministic-v1",
            is_mock=True,
            explanation=(
                f"Generated {len(suggestions)} deterministic suggestions based on category '{category}' "
                "and candidate user attributes. Explicit human owner review and approval is required."
            ),
            suggestions=suggestions,
            suggested_actions=actions
        )
