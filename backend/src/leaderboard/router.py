import time
from typing import Dict, Tuple

from fastapi import APIRouter, Query

from src.db import fetch_all, fetch_one


router = APIRouter()

CACHE_TTL_SECONDS = 30
_leaderboard_cache: Dict[Tuple[int, int], Dict] = {}


@router.get("/leaderboard")
def leaderboard(
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=10, ge=1, le=50),
):
    cache_key = (page, limit)
    now = time.time()

    cached_result = _leaderboard_cache.get(cache_key)

    if cached_result and now - cached_result["created_at"] < CACHE_TTL_SECONDS:
        response = cached_result["data"].copy()
        response["cached"] = True
        return response

    offset = (page - 1) * limit

    total_row = fetch_one(
        """
        SELECT COUNT(*) AS total_players
        FROM (
            SELECT j.id
            FROM puntuaciones p
            JOIN jugadores j ON j.id = p.jugador_id
            WHERE p.estado = 'valida'
            GROUP BY j.id
        ) ranked_players
        """
    )

    rows = fetch_all(
        """
        SELECT
            j.nickname,
            MAX(p.score) AS best_score,
            MAX(p.level_reached) AS max_level
        FROM puntuaciones p
        JOIN jugadores j ON j.id = p.jugador_id
        WHERE p.estado = 'valida'
          AND j.is_active = TRUE
        GROUP BY j.id, j.nickname
        ORDER BY best_score DESC, max_level DESC
        LIMIT %s OFFSET %s
        """,
        (limit, offset),
    )

    rankings = []

    for index, row in enumerate(rows):
        rankings.append(
            {
                "position": offset + index + 1,
                "nickname": row["nickname"],
                "score": row["best_score"],
                "level_reached": row["max_level"],
            }
        )

    response = {
        "page": page,
        "limit": limit,
        "total_players": total_row["total_players"] if total_row else 0,
        "cache_ttl_seconds": CACHE_TTL_SECONDS,
        "cached": False,
        "rankings": rankings,
    }

    _leaderboard_cache[cache_key] = {
        "created_at": now,
        "data": response,
    }

    return response