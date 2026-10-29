"""
Authentication and Authorization Security Layer
Integrates Supabase Auth for token verification and user identity extraction.
"""
from app.auth.supabase import (
    SupabaseAuthVerifier,
    get_current_user_id,
    get_authenticated_user_id,
    get_service_or_user_id,
    get_current_user_claims,
)

__all__ = [
    "SupabaseAuthVerifier",
    "get_current_user_id",
    "get_authenticated_user_id",
    "get_service_or_user_id",
    "get_current_user_claims",
]

