"""
auth.py
-------
Password hashing (PBKDF2-SHA256, stdlib only, no C-extension headaches)
and JWT-based session tokens.

SECURITY NOTE (college project scope):
- In production, SECRET_KEY must come from an environment variable /
  secrets manager, never hard-coded. It is hard-coded here only so the
  project runs out of the box for grading/demo purposes.
"""

import hashlib
import hmac
import os
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from database import get_connection

logger = logging.getLogger("certverify.auth")

SECRET_KEY = os.environ.get("CERTVERIFY_SECRET_KEY", "dev-secret-change-me-in-production")
ALGORITHM = "HS256"
TOKEN_EXPIRE_MINUTES = 60 * 8  # 8 hours

bearer_scheme = HTTPBearer(auto_error=False)


# ---------------- Password hashing ----------------

def hash_password(password: str) -> tuple[str, str]:
    """Return (password_hash_hex, salt_hex) using PBKDF2-HMAC-SHA256."""
    salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return pwd_hash.hex(), salt.hex()


def verify_password(password: str, stored_hash_hex: str, salt_hex: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return hmac.compare_digest(candidate.hex(), stored_hash_hex)


# ---------------- JWT ----------------

def create_access_token(user_id: int, role: str, email: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=TOKEN_EXPIRE_MINUTES)
    payload = {"sub": str(user_id), "role": role, "email": email, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Session expired, please log in again.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid authentication token.")


# ---------------- FastAPI dependencies ----------------

def get_current_user(creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme)) -> dict:
    if creds is None:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    payload = decode_access_token(creds.credentials)

    conn = get_connection()
    row = conn.execute(
        "SELECT id, full_name, email, role, institution_id FROM users WHERE id = ?",
        (payload["sub"],),
    ).fetchone()
    conn.close()

    if row is None:
        raise HTTPException(status_code=401, detail="User no longer exists.")

    return dict(row)


def require_role(*allowed_roles: str):
    """Dependency factory: raises 403 unless the current user's role is allowed."""

    def checker(user: dict = Depends(get_current_user)) -> dict:
        if user["role"] not in allowed_roles:
            logger.warning("Role check failed: user %s (role=%s) tried a %s-only action",
                            user["id"], user["role"], allowed_roles)
            raise HTTPException(status_code=403, detail="You do not have permission to do this.")
        return user

    return checker
