import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from .settings import settings


log_path = Path(settings.security_log_file)
log_path.parent.mkdir(parents=True, exist_ok=True)

security_logger = logging.getLogger("makoper_security")
security_logger.setLevel(logging.INFO)

if not security_logger.handlers:
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    formatter = logging.Formatter("%(message)s")
    file_handler.setFormatter(formatter)
    security_logger.addHandler(file_handler)


def log_security_event(
    event_type: str,
    ip_address: Optional[str] = None,
    user_email: Optional[str] = None,
    user_id: Optional[int] = None,
    role: Optional[str] = None,
    success: Optional[bool] = None,
    reason: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "ip_address": ip_address,
        "user_email": user_email,
        "user_id": user_id,
        "role": role,
        "success": success,
        "reason": reason,
        "extra": extra or {},
    }

    security_logger.info(json.dumps(payload, ensure_ascii=False))