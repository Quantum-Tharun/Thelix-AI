"""
Supabase Authentication & JWT Verification
Validates Supabase Auth access tokens.
Verifies token signature, issuer, audience, and expiry, deriving user identity strictly from verified claims.
"""
from fastapi import Header, HTTPException, status, Depends
from typing import Optional, Dict, Any
import logging
import hmac
import jwt

from app.config import settings

logger = logging.getLogger("thelix.auth.supabase")


class SupabaseAuthVerifier:
    """
    Validates Supabase Auth JWTs according to RFC 7519 and Supabase Auth specifications.
    """

    @classmethod
    def verify_token(cls, token: str) -> Dict[str, Any]:
        """
        Decodes and verifies a Supabase JWT token.
        Returns decoded claims payload or raises HTTPException(401).
        """
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing authorization token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # 1. Verification with configured Supabase JWT Secret (HS256)
        if settings.SUPABASE_JWT_SECRET:
            try:
                # Validate audience and signature using configured Supabase JWT secret
                payload = jwt.decode(
                    token,
                    settings.SUPABASE_JWT_SECRET,
                    algorithms=["HS256"],
                    audience=["authenticated", "service_role"],
                    options={"verify_signature": True, "verify_exp": True, "verify_aud": True},
                )

                # Validate user ID presence ('sub' claim)
                if not payload.get("sub"):
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Token missing subject identifier ('sub')",
                        headers={"WWW-Authenticate": "Bearer"},
                    )

                return payload
            except jwt.ExpiredSignatureError:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication token has expired",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            except jwt.InvalidAudienceError:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token audience claim",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            except jwt.InvalidTokenError:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token signature or format",
                    headers={"WWW-Authenticate": "Bearer"},
                )

        # 2. Development Mode Fallback (when SUPABASE_JWT_SECRET is unconfigured)
        if settings.ENVIRONMENT == "development":
            # First attempt unverified decode to extract 'sub' if token is standard JWT format
            try:
                unverified_payload = jwt.decode(token, options={"verify_signature": False})
                if unverified_payload.get("sub"):
                    return unverified_payload
            except Exception:
                pass

            # If dev mock token format (e.g. "dev_token_user1")
            if len(token) >= 6:
                clean_id = token.replace("Bearer ", "").replace("bearer ", "").strip()
                return {
                    "sub": clean_id,
                    "aud": "authenticated",
                    "role": "authenticated",
                    "email": f"{clean_id}@dev.local",
                }

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Supabase authentication secret is unconfigured and development bypass is disabled",
            headers={"WWW-Authenticate": "Bearer"},
        )


import inspect
from fastapi import Header, HTTPException, status, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader
from typing import Optional, Dict, Any
import logging
import hmac
import jwt

from app.config import settings

logger = logging.getLogger("thelix.auth.supabase")

# Standard reusable HTTP Bearer security scheme for Swagger UI
bearer_scheme = HTTPBearer(auto_error=False)

# Dedicated service token header scheme documented ONLY on internal endpoints
service_token_header = APIKeyHeader(name="X-Service-Token", auto_error=False)


class _OpenAPISecurityWrapper:
    """
    Wraps an auth dependency so OpenAPI documents it as a reusable security scheme
    without exposing manual header or query parameters in the Swagger UI parameter list.
    Supports both framework-injected FastAPI calls and direct unit-test kwargs calls.
    """
    def __init__(self, fn, visible_params=("request", "auth_creds")):
        self.fn = fn
        sig = inspect.signature(fn)
        new_params = [
            p for name, p in sig.parameters.items()
            if name in visible_params
        ]
        self.__signature__ = sig.replace(parameters=new_params)

    async def __call__(self, *args, **kwargs):
        return await self.fn(*args, **kwargs)


async def _get_authenticated_user_id_impl(
    request: Request = None,
    auth_creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    authorization: Optional[str] = None,
    x_service_token: Optional[str] = None,
) -> str:
    """
    FastAPI dependency for user-facing endpoints.
    Strictly verifies user identity from an authentic user access token.
    Rejects service-role credentials with 403 Forbidden to prevent service
    tokens from bypassing ownership and acting as arbitrary end-users.
    """
    # 1. Reject service tokens on user-facing routes (check both direct kwarg and request headers)
    eff_service_token = x_service_token
    if not eff_service_token and request:
        eff_service_token = request.headers.get("x-service-token")

    if isinstance(eff_service_token, str) and eff_service_token.strip():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Service role credentials are prohibited on user-facing endpoints",
        )

    # 2. Extract Bearer token from HTTPBearer credentials, direct kwarg, or Authorization header
    token = None
    if isinstance(auth_creds, HTTPAuthorizationCredentials) and auth_creds.credentials:
        token = auth_creds.credentials.strip()
    elif authorization:
        parts = authorization.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1]
        elif len(parts) == 1:
            token = parts[0]
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authorization header must follow 'Bearer <token>' format",
                headers={"WWW-Authenticate": "Bearer"},
            )
    elif request and request.headers.get("authorization"):
        raw_auth = request.headers.get("authorization", "").strip()
        parts = raw_auth.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1]
        elif len(parts) == 1:
            token = parts[0]
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authorization header must follow 'Bearer <token>' format",
                headers={"WWW-Authenticate": "Bearer"},
            )

    if not token:
        if settings.ENVIRONMENT == "development":
            return "dev_default_user"
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    claims = SupabaseAuthVerifier.verify_token(token)

    # Reject tokens with service_role claims on user-facing endpoints
    if claims.get("role") == "service_role" or claims.get("sub") == "service_role":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Service role tokens cannot perform user-facing actions",
        )

    user_id = claims.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not resolve user identity from verified token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return str(user_id)


# Exported user authentication dependency wrapped for clean OpenAPI representation
get_authenticated_user_id = _OpenAPISecurityWrapper(_get_authenticated_user_id_impl)
get_current_user_id = get_authenticated_user_id


async def _get_current_user_claims_impl(
    request: Request = None,
    auth_creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    authorization: Optional[str] = None,
) -> Dict[str, Any]:
    """FastAPI dependency returning complete claims payload from verified token."""
    token = None
    if isinstance(auth_creds, HTTPAuthorizationCredentials) and auth_creds.credentials:
        token = auth_creds.credentials.strip()
    elif authorization:
        parts = authorization.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1]
        elif len(parts) == 1:
            token = parts[0]
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Authorization header format",
                headers={"WWW-Authenticate": "Bearer"},
            )
    elif request and request.headers.get("authorization"):
        raw_auth = request.headers.get("authorization", "").strip()
        parts = raw_auth.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1]
        elif len(parts) == 1:
            token = parts[0]
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Authorization header format",
                headers={"WWW-Authenticate": "Bearer"},
            )

    if not token:
        if settings.ENVIRONMENT == "development":
            return {"sub": "dev_default_user", "aud": "authenticated", "role": "authenticated"}
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    claims = SupabaseAuthVerifier.verify_token(token)
    if claims.get("role") == "service_role" or claims.get("sub") == "service_role":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Service role tokens cannot perform user-facing actions",
        )
    return claims


get_current_user_claims = _OpenAPISecurityWrapper(_get_current_user_claims_impl)


async def _get_service_or_user_id_impl(
    request: Request = None,
    auth_creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    x_service_token: Optional[str] = Depends(service_token_header),
    authorization: Optional[str] = None,
) -> str:
    """
    FastAPI dependency for internal or gateway endpoints (/v1/ai/*, /v1/maintenance/*)
    allowing either a valid internal service token or an authenticated user token.
    """
    eff_service_token = x_service_token
    if not eff_service_token and request:
        eff_service_token = request.headers.get("x-service-token")

    if isinstance(eff_service_token, str) and eff_service_token.strip():
        if (settings.SUPABASE_SERVICE_ROLE_KEY and hmac.compare_digest(eff_service_token, settings.SUPABASE_SERVICE_ROLE_KEY)) or \
           hmac.compare_digest(eff_service_token, settings.INTERNAL_SERVICE_TOKEN):
            return "service_role"
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid service token",
        )

    return await _get_authenticated_user_id_impl(
        request=request,
        auth_creds=auth_creds,
        authorization=authorization,
        x_service_token=None,
    )


get_service_or_user_id = _OpenAPISecurityWrapper(
    _get_service_or_user_id_impl,
    visible_params=("request", "auth_creds", "x_service_token"),
)
