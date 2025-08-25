
from __future__ import annotations
import os
from dataclasses import dataclass
from dotenv import load_dotenv

load_dotenv()

@dataclass
class Settings:
    http_timeout: float = float(os.getenv("HTTP_TIMEOUT", "20"))
    rate_per_sec: float = float(os.getenv("RATE_PER_SEC", "5"))
    user_agent: str = os.getenv("USER_AGENT", "api-scanner/0.1 (+https://example.com)")
    reports_dir: str = os.getenv("REPORTS_DIR", "reports")

    # Bug bounty
    hackerone_token: str | None = os.getenv("HACKERONE_TOKEN")
    bugcrowd_token: str | None = os.getenv("BUGCROWD_TOKEN")

    # AI
    ai_enabled: bool = os.getenv("AI_ENABLED","true").lower() == "true"

settings = Settings()
