from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Legal OSINT Platform"
    env: Literal["development", "testing", "production"] = "development"
    log_level: str = "INFO"
    secret_key: str = "change-me-to-a-long-random-value"

    bot_token: str = ""
    owner_id: int | None = None
    webapp_url: str | None = None

    database_url: str = "sqlite:///data/app.db"

    free_daily_search_limit: int = 10
    premium_daily_search_limit: int = 500
    cooldown_seconds: int = 3
    anti_spam_window_seconds: int = 30
    anti_spam_max_actions: int = 12
    cache_ttl_seconds: int = 86400
    http_timeout_seconds: int = 12
    max_html_report_results: int = 80
    enable_nsfw_or_illegal_query_refusal: bool = True
    default_phone_region: str = "UA"

    premium_30_stars: int = 100
    premium_90_stars: int = 500
    premium_lifetime_stars: int = 1000

    serpapi_key: str | None = None
    google_api_key: str | None = None
    google_cse_id: str | None = None

    ipinfo_token: str | None = None
    shodan_api_key: str | None = None
    abstract_api_key: str | None = None
    vt_api_key: str | None = None

    enable_duckduckgo: bool = True
    enable_playwright_screenshots: bool = False
    enable_archive_lookup: bool = True
    enable_ocr: bool = False
    tesseract_cmd: str | None = None

    data_dir: Path = Path("./data")
    cache_dir: Path = Path("./data/cache")
    export_dir: Path = Path("./data/exports")
    log_dir: Path = Path("./data/logs")
    temp_dir: Path = Path("./data/temp")

    user_agents: tuple[str, ...] = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/125.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/17.5 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/125.0 Safari/537.36",
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8-sig",
        case_sensitive=False,
        extra="ignore",
    )

    @field_validator(
        "serpapi_key",
        "google_api_key",
        "google_cse_id",
        "ipinfo_token",
        "shodan_api_key",
        "abstract_api_key",
        "vt_api_key",
        "webapp_url",
        mode="before",
    )
    @classmethod
    def empty_to_none(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = str(value).strip()
        return value or None

    @field_validator("database_url", mode="after")
    @classmethod
    def normalize_database_url(cls, value: str) -> str:
        if value.startswith("sqlite:///"):
            return value.replace("sqlite:///", "sqlite+aiosqlite:///", 1)
        if value.startswith("postgresql://"):
            return value.replace("postgresql://", "postgresql+asyncpg://", 1)
        return value

    @property
    def alembic_database_url(self) -> str:
        if self.database_url.startswith("sqlite+aiosqlite:///"):
            return self.database_url.replace("sqlite+aiosqlite:///", "sqlite:///", 1)
        if self.database_url.startswith("postgresql+asyncpg://"):
            return self.database_url.replace("postgresql+asyncpg://", "postgresql+psycopg://", 1)
        return self.database_url

    @property
    def is_production(self) -> bool:
        return self.env == "production"

    def ensure_runtime_dirs(self) -> None:
        for directory in (self.data_dir, self.cache_dir, self.export_dir, self.log_dir, self.temp_dir):
            directory.mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    settings = Settings()
    settings.ensure_runtime_dirs()
    return settings
