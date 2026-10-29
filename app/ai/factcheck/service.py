"""
[EXPERIMENTAL PROTOTYPE - NOT INTEGRATED]
Status: Blocked by external dependency (Google Fact Check Tools API key).
This module is a prototype client for the Google Fact Check Tools API.
It is NOT wired into the authoritative OrchestratorService or RiskEngine.
"""
import logging
import httpx
from app.config import settings

logger = logging.getLogger("thelix.factcheck")

class FactCheckService:
    """
    EXPERIMENTAL PROTOTYPE: Interface for Google Fact Check Tools API.
    Verifies if a specific claim or URL has been debunked.
    """
    
    @staticmethod
    async def verify_claim(query: str) -> dict:
        """
        Queries the Fact Check API for debunked claims.
        """
        if not settings.FACT_CHECK_API_KEY:
            logger.warning("Fact Check API Key missing. Skipping check.")
            return {"is_debunked": False, "articles": []}

        try:
            api_url = f"https://factchecktools.googleapis.com/v1alpha1/claims:search?query={query}&key={settings.FACT_CHECK_API_KEY}"
            async with httpx.AsyncClient() as client:
                response = await client.get(api_url)
                response.raise_for_status()
                data = response.json()
            
            claims = data.get("claims", [])
            if not claims:
                return {"is_debunked": False, "articles": []}

            # If the claim exists and the review rating implies fake/false
            # We return the first relevant article
            first_claim = claims[0]
            review = first_claim.get("claimReview", [{}])[0]
            rating = review.get("textualRating", "").lower()
            
            is_debunked = "false" in rating or "fake" in rating or "scam" in rating
            
            return {
                "is_debunked": is_debunked,
                "rating": rating,
                "url": review.get("url", "")
            }
        except Exception as e:
            logger.error(f"Fact Check query failed: {e}")
            return {"is_debunked": False, "articles": []}
