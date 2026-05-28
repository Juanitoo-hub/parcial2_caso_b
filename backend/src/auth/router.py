from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field

from src.auth.service import (
    create_token,
    hash_password,
    validate_password_strength,
    verify_password,
)
from src.db import execute, fetch_one
from src.security_logger import log_security_event


router = APIRouter()


class RegisterBody(BaseModel):
    nickname: str = Field(..., min_length=3, max_length=80)
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)


class LoginBody(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1, max_length=128)


def get_client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(body: RegisterBody, request: Request):
    ip_address = get_client_ip(request)
    email = body.email.lower().strip()
    nickname = body.nickname.strip()

    validate_password_strength(body.password)

    existing_user = fetch_one(
        "SELECT id FROM jugadores WHERE email = %s OR nickname = %s",
        (email, nickname),
    )

    if existing_user:
        log_security_event(
            event_type="player_register_failed",
            ip_address=ip_address,
            user_email=email,
            success=False,
            reason="email_or_nickname_already_exists",
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="No fue posible completar el registro",
        )

    password_hash = hash_password(body.password)

    new_user = execute(
        """
        INSERT INTO jugadores (nickname, email, password_hash, role)
        VALUES (%s, %s, %s, %s)
        RETURNING id, nickname, email, role
        """,
        (nickname, email, password_hash, "jugador"),
    )

    log_security_event(
        event_type="player_registered",
        ip_address=ip_address,
        user_email=email,
        user_id=new_user["id"],
        role=new_user["role"],
        success=True,
        reason="registro_exitoso",
    )

    return {
        "mensaje": "Jugador registrado correctamente",
        "player": {
            "id": new_user["id"],
            "nickname": new_user["nickname"],
            "email": new_user["email"],
            "role": new_user["role"],
        },
    }


@router.post("/login")
def login(body: LoginBody, request: Request):
    ip_address = get_client_ip(request)
    email = body.email.lower().strip()

    user = fetch_one(
        """
        SELECT id, nickname, email, password_hash, role, mfa_enabled, is_active
        FROM jugadores
        WHERE email = %s
        """,
        (email,),
    )

    if not user or not verify_password(body.password, user["password_hash"]):
        execute(
            """
            INSERT INTO login_attempts (email, ip_address, success, reason)
            VALUES (%s, %s, %s, %s)
            """,
            (email, ip_address, False, "invalid_credentials"),
        )

        log_security_event(
            event_type="login_failed",
            ip_address=ip_address,
            user_email=email,
            success=False,
            reason="invalid_credentials",
        )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas",
        )

    if not user["is_active"]:
        log_security_event(
            event_type="login_failed",
            ip_address=ip_address,
            user_email=email,
            user_id=user["id"],
            role=user["role"],
            success=False,
            reason="inactive_user",
        )

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Usuario inactivo",
        )

    execute(
        """
        INSERT INTO login_attempts (email, ip_address, success, reason)
        VALUES (%s, %s, %s, %s)
        """,
        (email, ip_address, True, "credentials_valid"),
    )

    base_payload = {
        "sub": str(user["id"]),
        "user_id": user["id"],
        "nickname": user["nickname"],
        "email": user["email"],
        "role": user["role"],
    }

    if user["mfa_enabled"]:
        token = create_token(base_payload, token_type="partial_mfa")

        log_security_event(
            event_type="login_success_mfa_required",
            ip_address=ip_address,
            user_email=user["email"],
            user_id=user["id"],
            role=user["role"],
            success=True,
            reason="credentials_valid_mfa_required",
            extra={"mfa_required": True, "token_type": "partial_mfa"},
        )

        return {
            "access_token": token,
            "token_type": "bearer",
            "mfa_required": True,
            "message": "Se requiere verificación MFA",
        }

    token = create_token(base_payload, token_type="access")

    log_security_event(
        event_type="login_success",
        ip_address=ip_address,
        user_email=user["email"],
        user_id=user["id"],
        role=user["role"],
        success=True,
        reason="credentials_valid",
        extra={"mfa_required": False, "token_type": "access"},
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "mfa_required": False,
        "user": {
            "id": user["id"],
            "nickname": user["nickname"],
            "email": user["email"],
            "role": user["role"],
        },
    }