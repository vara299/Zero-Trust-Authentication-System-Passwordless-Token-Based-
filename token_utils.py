import os
import uuid
import datetime
from typing import Optional, Tuple

import jwt
from dotenv import load_dotenv
import bcrypt


load_dotenv()


SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not SECRET_KEY:
    # Safe default for local dev only. In real deployments this MUST be set.
    SECRET_KEY = "dev-only-change-me"

JWT_ISSUER = os.getenv("JWT_ISSUER", "zero-trust-auth-server")
JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "zero-trust-clients")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

ACCESS_TOKEN_TTL_MINUTES = int(os.getenv("ACCESS_TOKEN_TTL_MINUTES", "2"))


def _now_utc() -> datetime.datetime:
    return datetime.datetime.now(tz=datetime.timezone.utc)


def generate_token(user_id: str) -> Tuple[str, str]:
    """
    Generate a short-lived JWT access token for the given user.

    Returns (token, jti) so the caller can store metadata for replay protection.
    """
    jti = str(uuid.uuid4())
    issued_at = _now_utc()

    payload = {
        "sub": user_id,  # subject
        "jti": jti,      # unique token ID (for replay protection)
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": issued_at,
        "nbf": issued_at,  # not before: valid immediately
        "exp": issued_at + datetime.timedelta(minutes=ACCESS_TOKEN_TTL_MINUTES),
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token, jti


def verify_token(token: str) -> Optional[dict]:
    """
    Verify the JWT and return its payload (claims) if valid.

    Returns None if the token is invalid or expired.
    """
    if not token:
        return None

    # Support both "Bearer <token>" and raw token
    if token.startswith("Bearer "):
        token = token.split(" ", 1)[1].strip()

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
        )
        return payload
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


def hash_token(token: str) -> bytes:
    """
    Hash the opaque JWT string for secure server-side storage.
    The raw token is never stored, only its bcrypt hash.
    """
    return bcrypt.hashpw(token.encode("utf-8"), bcrypt.gensalt())


def check_token(token: str, hashed: Optional[bytes]) -> bool:
    """
    Compare a presented token to its stored bcrypt hash.
    """
    if not token or not hashed:
        return False
    return bcrypt.checkpw(token.encode("utf-8"), hashed)
