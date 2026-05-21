from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import get_settings
from core.models import CacheEntry
from core.security import make_cache_key


async def get_cached(session: AsyncSession, namespace: str, key: str) -> dict[str, Any] | None:
    cache_key = make_cache_key(namespace, key)
    result = await session.execute(select(CacheEntry).where(CacheEntry.cache_key == cache_key))
    entry = result.scalar_one_or_none()
    if not entry:
        return None
    expires_at = _aware(entry.expires_at)
    if expires_at and expires_at < datetime.now(timezone.utc):
        await session.delete(entry)
        await session.flush()
        return None
    return entry.value


def _aware(value: datetime | None) -> datetime | None:
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=timezone.utc)


async def set_cached(
    session: AsyncSession,
    namespace: str,
    key: str,
    value: dict[str, Any],
    ttl_seconds: int | None = None,
) -> None:
    settings = get_settings()
    cache_key = make_cache_key(namespace, key)
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds or settings.cache_ttl_seconds)
    result = await session.execute(select(CacheEntry).where(CacheEntry.cache_key == cache_key))
    entry = result.scalar_one_or_none()
    if entry:
        entry.value = value
        entry.expires_at = expires_at
    else:
        session.add(CacheEntry(cache_key=cache_key, namespace=namespace, value=value, expires_at=expires_at))
    await session.flush()


async def clear_cache(session: AsyncSession, namespace: str | None = None) -> int:
    statement = delete(CacheEntry)
    if namespace:
        statement = statement.where(CacheEntry.namespace == namespace)
    result = await session.execute(statement)
    await session.flush()
    return int(result.rowcount or 0)
