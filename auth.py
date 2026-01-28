import os
import time
from typing import Optional, Dict, Any

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import jwt, JWTError

ALGORITHM = "HS256"
ACCESS_TOKEN_TTL_SECONDS = int(os.getenv("ACCESS_TOKEN_TTL_SECONDS", "3600"))

# IMPORTANT: set this in environment for real use
SECRET_KEY = os.getenv("FACEAUTH_SECRET_KEY", "dev-insecure-secret-change-me")

bearer = HTTPBearer(auto_error=False)

def create_access_token(username: str, role: str) -> str:
    now = int(time.time())
    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": now + ACCESS_TOKEN_TTL_SECONDS,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str) -> Dict[str, Any]:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

def get_current_user(creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer)) -> Dict[str, str]:
    if creds is None or creds.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    payload = decode_token(creds.credentials)
    username = payload.get("sub")
    role = payload.get("role", "user")
    if not username:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    return {"username": username, "role": role}

def require_role(*allowed_roles: str):
    def _dep(user: Dict[str, str] = Depends(get_current_user)) -> Dict[str, str]:
        if user["role"] not in allowed_roles:
            raise HTTPException(status_code=403, detail="Insufficient privileges")
        return user
    return _dep
