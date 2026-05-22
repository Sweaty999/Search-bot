from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from time import monotonic

from sqlalchemy.ext.asyncio import AsyncSession

from core.accounts import daily_search_count
from core.config import get_settings
from core.localization import t
from core.models import User, UserRole
from core.security import is_premium


@dataclass(frozen=True)
class LimitDecision:
    allowed: bool
    reason: str | None = None
    remaining: int | None = None


class AntiSpam:
    def __init__(self) -> None:
        self._events: dict[int, deque[float]] = defaultdict(deque)
        self._last_action: dict[int, float] = {}

    def check(self, user_id: int) -> LimitDecision:
        settings = get_settings()
        now = monotonic()
        last = self._last_action.get(user_id, 0)
        if now - last < settings.cooldown_seconds:
            return LimitDecision(False, t("errors.cooldown", seconds=settings.cooldown_seconds))

        events = self._events[user_id]
        while events and now - events[0] > settings.anti_spam_window_seconds:
            events.popleft()
        if len(events) >= settings.anti_spam_max_actions:
            return LimitDecision(False, t("errors.rate_limited"))

        events.append(now)
        self._last_action[user_id] = now
        return LimitDecision(True)


anti_spam = AntiSpam()


async def check_search_limit(session: AsyncSession, user: User) -> LimitDecision:
    settings = get_settings()
    if user.is_banned:
        return LimitDecision(False, t("errors.banned"))
    if user.role in {UserRole.admin, UserRole.owner}:
        return LimitDecision(True, remaining=None)
    limit = settings.premium_daily_search_limit if is_premium(user) else settings.free_daily_search_limit
    used = await daily_search_count(session, user.id)
    if used >= limit:
        return LimitDecision(False, t("errors.daily_limit", limit=limit), remaining=0)
    return LimitDecision(True, remaining=limit - used)
