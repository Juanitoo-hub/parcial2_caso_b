import base64
from io import BytesIO
from typing import Dict

import pyotp
import qrcode
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field

from src.auth.dependencies import get_current_user
from src.auth.service import (
    create_token,
    decode_token,
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


class MFAEnableBody(BaseModel):
    otp_code: str = Field(..., min_length=6, max_length=6)


class MFAVerifyBody(BaseModel):
    otp_code: str = Field(..., min_length=6, max_length=6)


def get_client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def build_qr_data_url(otpauth_url: str) -> str:
    image = qrcode.make(otpauth_url)
    buffer = BytesIO()
    image.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("utf-8")
    return f"data:image/png;base64,{encoded}"


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


@router.post("/mfa/setup")
def setup_mfa(
    request: Request,
    current_user: Dict = Depends(get_current_user),
):
    ip_address = get_client_ip(request)

    user = fetch_one(
        """
        SELECT id, email, role, mfa_enabled
        FROM jugadores
        WHERE id = %s
        """,
        (current_user["id"],),
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado",
        )

    if user["mfa_enabled"]:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="El MFA ya está activo",
        )

    secret = pyotp.random_base32()
    issuer = "Makoper PixelForge"

    totp = pyotp.TOTP(secret)
    otpauth_url = totp.provisioning_uri(
        name=user["email"],
        issuer_name=issuer,
    )

    execute(
        """
        UPDATE jugadores
        SET mfa_secret = %s, updated_at = CURRENT_TIMESTAMP
        WHERE id = %s
        RETURNING id
        """,
        (secret, user["id"]),
    )

    log_security_event(
        event_type="mfa_setup_started",
        ip_address=ip_address,
        user_email=user["email"],
        user_id=user["id"],
        role=user["role"],
        success=True,
        reason="totp_secret_generated",
    )

    return {
        "message": "Escanea el QR en Google Authenticator o Microsoft Authenticator",
        "issuer": issuer,
        "secret": secret,
        "otpauth_url": otpauth_url,
        "qr_data_url": build_qr_data_url(otpauth_url),
    }


@router.post("/mfa/enable")
def enable_mfa(
    body: MFAEnableBody,
    request: Request,
    current_user: Dict = Depends(get_current_user),
):
    ip_address = get_client_ip(request)

    user = fetch_one(
        """
        SELECT id, email, role, mfa_secret, mfa_enabled
        FROM jugadores
        WHERE id = %s
        """,
        (current_user["id"],),
    )

    if not user or not user["mfa_secret"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Primero debes configurar MFA",
        )

    if user["mfa_enabled"]:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="El MFA ya está activo",
        )

    totp = pyotp.TOTP(user["mfa_secret"])

    if not totp.verify(body.otp_code, valid_window=1):
        log_security_event(
            event_type="mfa_enable_failed",
            ip_address=ip_address,
            user_email=user["email"],
            user_id=user["id"],
            role=user["role"],
            success=False,
            reason="invalid_otp",
        )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Código MFA inválido",
        )

    execute(
        """
        UPDATE jugadores
        SET mfa_enabled = TRUE, updated_at = CURRENT_TIMESTAMP
        WHERE id = %s
        RETURNING id
        """,
        (user["id"],),
    )

    log_security_event(
        event_type="mfa_enabled",
        ip_address=ip_address,
        user_email=user["email"],
        user_id=user["id"],
        role=user["role"],
        success=True,
        reason="totp_enabled",
    )

    return {
        "message": "MFA activado correctamente",
        "mfa_enabled": True,
    }


@router.post("/mfa/verify")
def verify_mfa(
    body: MFAVerifyBody,
    request: Request,
    authorization: str = Header(...),
):
    ip_address = get_client_ip(request)
    payload = decode_token(authorization)

    if payload.get("type") != "partial_mfa":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token parcial MFA requerido",
        )

    user_id = payload.get("user_id")

    user = fetch_one(
        """
        SELECT id, nickname, email, role, mfa_secret, mfa_enabled, is_active
        FROM jugadores
        WHERE id = %s
        """,
        (user_id,),
    )

    if not user or not user["is_active"] or not user["mfa_enabled"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario no autorizado para MFA",
        )

    totp = pyotp.TOTP(user["mfa_secret"])

    if not totp.verify(body.otp_code, valid_window=1):
        log_security_event(
            event_type="mfa_verify_failed",
            ip_address=ip_address,
            user_email=user["email"],
            user_id=user["id"],
            role=user["role"],
            success=False,
            reason="invalid_otp",
        )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Código MFA inválido",
        )

    base_payload = {
        "sub": str(user["id"]),
        "user_id": user["id"],
        "nickname": user["nickname"],
        "email": user["email"],
        "role": user["role"],
    }

    access_token = create_token(base_payload, token_type="access")

    log_security_event(
        event_type="mfa_verified",
        ip_address=ip_address,
        user_email=user["email"],
        user_id=user["id"],
        role=user["role"],
        success=True,
        reason="totp_verified",
        extra={"token_type": "access"},
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "mfa_required": False,
        "user": {
            "id": user["id"],
            "nickname": user["nickname"],
            "email": user["email"],
            "role": user["role"],
        },
    }