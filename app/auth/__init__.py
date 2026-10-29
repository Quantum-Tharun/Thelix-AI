"""
Auth Package
Provides Supabase Auth JWT verification and user identity extraction.
"""
from app.auth.supabase import (
    SupabaseAuthVerifier,
    get_current_user_id,
    get_current_user_claims,
)

__all__ = [
    "SupabaseAuthVerifier",
    "get_current_user_id",
    "get_current_user_claims",
]
