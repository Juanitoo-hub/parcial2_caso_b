from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str
    jwt_secret_key: str
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 120
    jwt_partial_expire_minutes: int = 5
    cors_allowed_origins: str = "https://makoper.si-umng.com"
    security_log_file: str = "/var/log/pixelforge/security.log"
    max_score_allowed: int = 5000

    class Config:
        env_file = ".env"
        case_sensitive = False


settings = Settings()