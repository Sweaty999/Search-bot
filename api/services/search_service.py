from __future__ import annotations

import uuid
from typing import NamedTuple
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.accounts import log_action
from core.cache import get_cached, set_cached
from core.limits import anti_spam, check_search_limit
from core.models import Report, Search, SearchStatus, User
from core.security import is_premium
from osint.collectors.orchestrator import scan_public_sources
from osint.models import ScanResult
from osint.reports.html import render_html_report


class SearchExecution(NamedTuple):
    search: Search
    result: ScanResult
    report: Report | None
    from_cache: bool


async def execute_search(
    session: AsyncSession,
    user: User,
    query: str,
    *,
    deep: bool = False,
    force_refresh: bool = False,
) -> SearchExecution:
    if deep and not is_premium(user):
        raise PermissionError("Deep Scan is a premium feature.")

    spam_decision = anti_spam.check(user.telegram_id)
    if not spam_decision.allowed:
        raise PermissionError(spam_decision.reason or "Rate limited.")

    limit_decision = await check_search_limit(session, user)
    if not limit_decision.allowed:
        raise PermissionError(limit_decision.reason or "Limit reached.")

    mode = "deep" if deep else "basic"
    cache_key = f"{mode}:{query}"
    cached = None if force_refresh else await get_cached(session, "search", cache_key)
    from_cache = cached is not None
    if cached:
        result = ScanResult.model_validate(cached)
    else:
        result = await scan_public_sources(query, deep=deep, premium=is_premium(user))
        await set_cached(session, "search", cache_key, result.model_dump(mode="json"))

    search_id = str(uuid.uuid4())
    status = SearchStatus.refused if result.status == "refused" else SearchStatus.completed
    search = Search(
        id=search_id,
        user_id=user.id,
        query=query,
        entity_type=result.entity.kind.value,
        mode=mode,
        status=status,
        confidence=result.confidence,
        summary=result.summary,
        result=result.model_dump(mode="json"),
        graph=result.graph.model_dump(mode="json"),
        completed_at=datetime.now(timezone.utc),
    )
    session.add(search)

    report: Report | None = None
    if is_premium(user) and status == SearchStatus.completed:
        report_path = render_html_report(result, report_id=search_id)
        report = Report(search_id=search_id, user_id=user.id, title=f"OSINT report: {query[:80]}", html_path=str(report_path))
        session.add(report)

    await log_action(
        session,
        "search.completed",
        user_id=user.id,
        details={"query": query, "mode": mode, "from_cache": from_cache, "status": status.value},
    )
    await session.flush()
    return SearchExecution(search=search, result=result, report=report, from_cache=from_cache)


async def get_search_result(session: AsyncSession, search_id: str, user: User) -> Search | None:
    statement = select(Search).where(Search.id == search_id)
    if user.role.value not in {"admin", "owner"}:
        statement = statement.where(Search.user_id == user.id)
    return await session.scalar(statement)


async def get_report(session: AsyncSession, report_id: str, user: User) -> Report | None:
    statement = select(Report).where(Report.id == report_id)
    if user.role.value not in {"admin", "owner"}:
        statement = statement.where(Report.user_id == user.id)
    return await session.scalar(statement)
