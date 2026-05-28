from datetime import datetime, timedelta, timezone
from typing import Any, Dict
from uuid import uuid4

from fastapi import HTTPException, status
from jose import JWTError, jwt
from passlib.context import CryptContext

from src.settings import settings


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    return pwd_context.verify(plain_password, password_hash)


def validate_password_strength(password: str) -> None:
    if len(password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="La contraseña debe tener mínimo 8 caracteres",
        )

    has_letter = any(char.isalpha() for char in password)
    has_number = any(char.isdigit() for char in password)

    if not has_letter or not has_number:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="La contraseña debe incluir letras y números",
        )


def create_token(data: Dict[str, Any], token_type: str = "access") -> str:
    now = datetime.now(timezone.utc)

    if token_type == "partial_mfa":
        expires_delta = timedelta(minutes=settings.jwt_partial_expire_minutes)
    else:
        expires_delta = timedelta(minutes=settings.jwt_expire_minutes)

    payload = data.copy()
    payload.update(
        {
            "type": token_type,
            "iat": now,
            "exp": now + expires_delta,
            "jti": str(uuid4()),
        }
    )

    return jwt.encode(
        payload,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )


def decode_token(token: str) -> Dict[str, Any]:
    raw_token = token.replace("Bearer ", "").strip()

    try:
        return jwt.decode(
            raw_token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
        )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido o expirado",
        )