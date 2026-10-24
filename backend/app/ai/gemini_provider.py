import json
import logging
from typing import List, Dict, Any, Optional
from google import genai
from google.genai import types
from app.core.config import settings
from app.ai.base import BaseAIProvider
from app.schemas.ai import AIRecommendationResult
from app.ai.guardrails import (
    wrap_untrusted_metadata,
    parse_and_validate_ai_response,
    SYSTEM_BOUNDARY_INSTRUCTION
)
from app.ai.egress_filter import AIEgressFilter

logger = logging.getLogger(__name__)

class GeminiAIProvider(BaseAIProvider):
    """
    Real Google Gemini LLM provider adapter.
    Uses google-genai client with gemini-2.5-flash.
    Enforces prompt injection boundaries, runtime egress filters, and structured schema guardrails.
    """

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key or settings.GEMINI_API_KEY
        self.model_name = model or settings.AI_MODEL
        if self.api_key:
            self.client = genai.Client(api_key=self.api_key)
        else:
            self.client = None

    def generate_recommendations(
        self,
        document_id: str,
        document_title: str,
        document_description: str,
        category: str,
        candidate_users: List[Dict[str, Any]],
        owner_email: str
    ) -> AIRecommendationResult:
        if not self.client:
            raise ValueError("Gemini API key is not configured.")

        # Sanitize candidate users (strip passwords or internal tokens)
        safe_candidates = [
            {
                "id": u["id"],
                "email": u["email"],
                "display_name": u["display_name"],
                "role": u.get("role", "viewer")
            }
            for u in candidate_users if u["email"] != owner_email
        ]

        # 1. Delimit untrusted metadata with XML tags for prompt injection defense
        xml_metadata = wrap_untrusted_metadata(
            title=document_title,
            description=document_description,
            category=category,
            owner_email=owner_email
        )

        prompt = f"""
{xml_metadata}

Authorized Candidate Users:
{json.dumps(safe_candidates, indent=2)}

Return a JSON object conforming strictly to this schema:
{{
    "explanation": "<Concise reasoning for the recommended access profile>",
    "suggestions": [
        {{
            "user_id": "<Candidate user id>",
            "email": "<Candidate email>",
            "display_name": "<Candidate display name>",
            "permission_level": "read" | "edit",
            "action": "RECOMMEND_READ_GRANT" | "FLAG_UNUSED_GRANT" | "SUGGEST_RETENTION_LABEL",
            "confidence": <float between 0.1 and 1.0>,
            "rationale": "<Reason for this specific permission>"
        }}
    ]
}}
"""

        # 2. RUNTIME EGRESS FILTER: Assert zero DEK, ciphertext chunk, or raw content bytes
        AIEgressFilter.assert_safe_and_alert_on_leak(
            payload=prompt,
            document_id=document_id
        )

        try:
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction=SYSTEM_BOUNDARY_INSTRUCTION,
                    response_mime_type="application/json",
                    temperature=0.2
                )
            )

            response_data = json.loads(response.text)
            valid_user_ids = {u["id"] for u in safe_candidates}

            # 3. Guardrail layer: strictly validate and sanitize output
            return parse_and_validate_ai_response(
                raw_data=response_data,
                document_id=document_id,
                document_title=document_title,
                category=category,
                provider_model=f"gemini/{self.model_name}",
                is_mock=False,
                valid_candidate_ids=valid_user_ids
            )

        except Exception as e:
            logger.warning(f"Gemini API request failed or was unavailable: {e}. Falling back to mock provider.")
            raise e
