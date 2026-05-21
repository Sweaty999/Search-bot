from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qsl

from core.config import get_settings
from core.models import User, UserRole


PROHIBITED_PATTERNS = [
    r"\b(password|passwd|pwd|token|secret|cookie|session)\b",
    r"\b(brute\s*force|credential\s*stuffing|bypass|exploit|0day|zero-day)\b",
    r"\b(leak|dump|breach\s*database|combo\s*list|private\s*database)\b",
    r"\b(dox|doxx|deanon|de-anon|deanonymize|swat)\b",
    r"\b(find\s+(home|address|family|workplace)|real\s+address)\b",
    r"\b(пробив|деанон|докс|злив|слит(ь|и)|парол|токен|обхід|взлом)\b",
    r"\b(пробити|деанонімізувати|зламати|пароль|токен|обійти)\b",
]


@dataclass(frozen=True)
class SafetyDecision:
    allowed: bool
    reason: str | None = None


def assess_query_safety(query: str) -> SafetyDecision:
    settings = get_settings()
    if not settings.enable_nsfw_or_illegal_query_refusal:
        return SafetyDecision(True)

    normalized = query.casefold()
    for pattern in PROHIBITED_PATTERNS:
        if re.search(pattern, normalized, re.IGNORECASE):
            return SafetyDecision(
                False,
                "I can help only with legal OSINT on public sources. This request appears to ask for private data, access bypass, credentials, leaks, or doxing.",
            )
    return SafetyDecision(True)


def is_owner_id(telegram_id: int | None) -> bool:
    settings = get_settings()
    return bool(settings.owner_id and telegram_id == settings.owner_id)


def effective_role(user: User | None) -> UserRole:
    if user and is_owner_id(user.telegram_id):
        return UserRole.owner
    return user.role if user else UserRole.free


def is_admin(user: User | None) -> bool:
    return effective_role(user) in {UserRole.admin, UserRole.owner}


def is_premium(user: User | None) -> bool:
    return effective_role(user) in {UserRole.premium, UserRole.admin, UserRole.owner}


def require_owner(user: User | None) -> None:
    if effective_role(user) != UserRole.owner:
        raise PermissionError("Owner-only action.")


def parse_telegram_init_data(init_data: str) -> dict[str, Any]:
    values = dict(parse_qsl(init_data, keep_blank_values=True))
    if "user" in values:
        try:
            values["user"] = json.loads(values["user"])
        except json.JSONDecodeError:
            values["user"] = {}
    return values


def verify_telegram_webapp_init_data(init_data: str, bot_token: str, max_age_seconds: int = 86400) -> bool:
    if not init_data or not bot_token:
        return False

    pairs = dict(parse_qsl(init_data, keep_blank_values=True))
    received_hash = pairs.pop("hash", None)
    if not received_hash:
        return False

    auth_date = pairs.get("auth_date")
    if auth_date and int(time.time()) - int(auth_date) > max_age_seconds:
        return False

    data_check_string = "\n".join(f"{key}={value}" for key, value in sorted(pairs.items()))
    secret_key = hmac.new(b"WebAppData", bot_token.encode(), hashlib.sha256).digest()
    calculated = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(calculated, received_hash)


def make_cache_key(namespace: str, value: str) -> str:
    digest = hashlib.sha256(f"{namespace}:{value}".encode("utf-8")).hexdigest()
    return f"{namespace}:{digest}"


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()

