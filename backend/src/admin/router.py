from typing import Dict

from fastapi import APIRouter, Depends, HTTPException, Request, status

from src.auth.dependencies import require_admin_or_moderator
from src.db import execute, fetch_all, fetch_one
from src.security_logger import log_security_event


router = APIRouter()


def get_client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@router.delete("/puntuacion/{score_id}")
def eliminar_puntuacion(
    score_id: int,
    request: Request,
    current_user: Dict = Depends(require_admin_or_moderator),
):
    ip_address = get_client_ip(request)

    score = fetch_one(
        """
        SELECT id, jugador_id, score, estado
        FROM puntuaciones
        WHERE id = %s
        """,
        (score_id,),
    )

    if not score:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Puntuación no encontrada",
        )

    if score["estado"] != "valida":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="La puntuación ya no está activa",
        )

    updated_score = execute(
        """
        UPDATE puntuaciones
        SET estado = 'rechazada'
        WHERE id = %s
        RETURNING id, jugador_id, score, estado
        """,
        (score_id,),
    )

    log_security_event(
        event_type="admin_score_invalidated",
        ip_address=ip_address,
        user_email=current_user["email"],
        user_id=current_user["id"],
        role=current_user["role"],
        success=True,
        reason="score_marked_as_rejected",
        extra={
            "score_id": updated_score["id"],
            "target_player_id": updated_score["jugador_id"],
            "score": updated_score["score"],
        },
    )

    return {
        "message": "Puntuación invalidada correctamente",
        "score_id": updated_score["id"],
        "estado": updated_score["estado"],
    }


@router.get("/jugador/{player_id}/historial")
def historial(
    player_id: int,
    current_user: Dict = Depends(require_admin_or_moderator),
):
    player = fetch_one(
        """
        SELECT id, nickname, email, role, is_active
        FROM jugadores
        WHERE id = %s
        """,
        (player_id,),
    )

    if not player:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Jugador no encontrado",
        )

    rows = fetch_all(
        """
        SELECT id, score, level_reached, estado, created_at
        FROM puntuaciones
        WHERE jugador_id = %s
        ORDER BY created_at DESC
        LIMIT 100
        """,
        (player_id,),
    )

    return {
        "player": {
            "id": player["id"],
            "nickname": player["nickname"],
            "email": player["email"],
            "role": player["role"],
            "is_active": player["is_active"],
        },
        "historial": rows,
    }