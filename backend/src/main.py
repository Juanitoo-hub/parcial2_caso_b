from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.admin.router import router as admin_router
from src.auth.router import router as auth_router
from src.game.router import router as game_router
from src.leaderboard.router import router as lb_router
from src.settings import settings


app = FastAPI(title="PixelForge Studio API - Makoper", version="2.0.0")

allowed_origins = [
    origin.strip()
    for origin in settings.cors_allowed_origins.split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router, prefix="/api/auth", tags=["auth"])
app.include_router(game_router, prefix="/api/game", tags=["game"])
app.include_router(lb_router, prefix="/api", tags=["leaderboard"])
app.include_router(admin_router, prefix="/api/admin", tags=["admin"])


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "pixelforge-api",
        "version": "2.0.0",
    }


@app.get("/api/health")
def api_health():
    return {
        "status": "ok",
        "service": "pixelforge-api",
        "version": "2.0.0",
    }