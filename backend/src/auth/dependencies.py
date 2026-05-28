from typing import Dict, List

from fastapi import Depends, Header, HTTPException, status

from src.auth.service import decode_token
from src.db import fetch_one


def get_current_user(authorization: str = Header(...)) -> Dict:
    payload = decode_token(authorization)

    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token de acceso completo requerido",
        )

    user_id = payload.get("user_id")

    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido",
        )

    user = fetch_one(
        """
        SELECT id, nickname, email, role, tokens_balance, is_active
        FROM jugadores
        WHERE id = %s
        """,
        (user_id,),
    )

    if not user or not user["is_active"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario no autorizado",
        )

    return dict(user)


def require_roles(allowed_roles: List[str]):
    def dependency(current_user: Dict = Depends(get_current_user)) -> Dict:
        if current_user["role"] not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No tienes permisos para realizar esta acción",
            )
        return current_user

    return dependency


def require_player(current_user: Dict = Depends(get_current_user)) -> Dict:
    if current_user["role"] != "jugador":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acceso permitido solo para jugadores",
        )
    return current_user


def require_admin_or_moderator(current_user: Dict = Depends(get_current_user)) -> Dict:
    if current_user["role"] not in ["admin_juego", "moderador"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acceso permitido solo para administradores o moderadores",
        )
    return current_user


def require_admin(current_user: Dict = Depends(get_current_user)) -> Dict:
    if current_user["role"] != "admin_juego":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acceso permitido solo para administradores",
        )
    return current_user