# config.py
from __future__ import annotations
import os

APP_NAME = "IDS Dashboard"
ENV = os.getenv("IDS_ENV", "dev")  # dev|prod

# Session
SESSION_TTL_SECONDS = int(os.getenv("IDS_SESSION_TTL", "1800"))  # 30 min
SESSION_ROTATE_ON_LOGIN = True

# Secrets (use .env in dev, environment vars in prod)
APP_SECRET = os.getenv("IDS_APP_SECRET", "CHANGE_ME_DEV_ONLY")

# AI
IDS_AI_MODEL = os.getenv("IDS_AI_MODEL", "gpt-4o-mini")

# Firewall safety
ALLOW_REAL_FIREWALL = os.getenv("IDS_ALLOW_REAL_FIREWALL", "0") == "1"
