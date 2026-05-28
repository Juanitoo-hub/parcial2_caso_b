from typing import Dict
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from src.auth.dependencies import require_player
from src.db import fetch_one, get_connection
from src.security_logger import log_security_event
from src.settings import settings


router = APIRouter()


class EndGameBody(BaseModel):
    session_token: str = Field(..., min_length=20, max_length=255)
    score: int = Field(..., ge=0)
    level_reached: int = Field(default=1, ge=1, le=100)


def get_client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@router.post("/start")
def iniciar_partida(
    request: Request,
    current_user: Dict = Depends(require_player),
):
    ip_address = get_client_ip(request)
    session_token = str(uuid4())

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO partidas (jugador_id, session_token, estado)
                VALUES (%s, %s, %s)
                RETURNING id, session_token, estado, started_at
                """,
                (current_user["id"], session_token, "activa"),
            )
            partida = cur.fetchone()

    log_security_event(
        event_type="game_session_started",
        ip_address=ip_address,
        user_email=current_user["email"],
        user_id=current_user["id"],
        role=current_user["role"],
        success=True,
        reason="session_created",
        extra={"session_token_prefix": session_token[:8]},
    )

    return {
        "message": "Partida iniciada correctamente",
        "partida_id": partida["id"],
        "session_token": partida["session_token"],
        "estado": partida["estado"],
        "started_at": partida["started_at"],
    }


@router.post("/end")
def registrar_puntuacion(
    body: EndGameBody,
    request: Request,
    current_user: Dict = Depends(require_player),
):
    ip_address = get_client_ip(request)

    if body.score > settings.max_score_allowed:
        log_security_event(
            event_type="score_rejected",
            ip_address=ip_address,
            user_email=current_user["email"],
            user_id=current_user["id"],
            role=current_user["role"],
            success=False,
            reason="score_above_allowed_limit",
            extra={
                "score": body.score,
                "max_score_allowed": settings.max_score_allowed,
            },
        )

        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO log_anticheat
                    (jugador_id, event_type, description, ip_address)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (
                        current_user["id"],
                        "score_above_allowed_limit",
                        f"Score enviado: {body.score}. Máximo permitido: {settings.max_score_allowed}",
                        ip_address,
                    ),
                )

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Puntaje fuera del rango permitido",
        )

    partida = fetch_one(
        """
        SELECT id, jugador_id, estado
        FROM partidas
        WHERE session_token = %s
        """,
        (body.session_token,),
    )

    if not partida:
        log_security_event(
            event_type="score_rejected",
            ip_address=ip_address,
            user_email=current_user["email"],
            user_id=current_user["id"],
            role=current_user["role"],
            success=False,
            reason="invalid_session_token",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Sesión inválida",
        )

    if partida["jugador_id"] != current_user["id"]:
        log_security_event(
            event_type="score_rejected",
            ip_address=ip_address,
            user_email=current_user["email"],
            user_id=current_user["id"],
            role=current_user["role"],
            success=False,
            reason="session_does_not_belong_to_user",
            extra={"partida_id": partida["id"]},
        )

        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO log_anticheat
                    (jugador_id, partida_id, event_type, description, ip_address)
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (
                        current_user["id"],
                        partida["id"],
                        "session_does_not_belong_to_user",
                        "Intento de registrar puntaje con una sesión de otro usuario.",
                        ip_address,
                    ),
                )

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="La sesión no pertenece al jugador autenticado",
        )

    if partida["estado"] != "activa":
        log_security_event(
            event_type="score_rejected",
            ip_address=ip_address,
            user_email=current_user["email"],
            user_id=current_user["id"],
            role=current_user["role"],
            success=False,
            reason="session_already_closed",
            extra={"partida_id": partida["id"]},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="La sesión ya fue finalizada o anulada",
        )

    recent_score = fetch_one(
        """
        SELECT id
        FROM puntuaciones
        WHERE jugador_id = %s
          AND created_at > CURRENT_TIMESTAMP - INTERVAL '60 seconds'
        LIMIT 1
        """,
        (current_user["id"],),
    )

    if recent_score:
        log_security_event(
            event_type="score_rejected",
            ip_address=ip_address,
            user_email=current_user["email"],
            user_id=current_user["id"],
            role=current_user["role"],
            success=False,
            reason="rate_limit_score",
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Debes esperar antes de registrar otro puntaje",
        )

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO puntuaciones
                (jugador_id, partida_id, score, level_reached, estado)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id, score, level_reached, estado, created_at
                """,
                (
                    current_user["id"],
                    partida["id"],
                    body.score,
                    body.level_reached,
                    "valida",
                ),
            )
            score_row = cur.fetchone()

            cur.execute(
                """
                UPDATE partidas
                SET estado = %s, ended_at = CURRENT_TIMESTAMP
                WHERE id = %s
                """,
                ("finalizada", partida["id"]),
            )

    log_security_event(
        event_type="score_registered",
        ip_address=ip_address,
        user_email=current_user["email"],
        user_id=current_user["id"],
        role=current_user["role"],
        success=True,
        reason="score_saved",
        extra={
            "score": score_row["score"],
            "level_reached": score_row["level_reached"],
            "partida_id": partida["id"],
        },
    )

    return {
        "message": "Puntuación registrada correctamente",
        "score_id": score_row["id"],
        "score": score_row["score"],
        "level_reached": score_row["level_reached"],
        "estado": score_row["estado"],
        "created_at": score_row["created_at"],
    }