from __future__ import annotations

import uuid
from typing import NamedTuple
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.accounts import log_action
from core.cache import get_cached, set_cached
from core.localization import t
from core.limits import anti_spam, check_search_limit
from core.models import Report, Search, SearchStatus, User
from core.security import is_premium
from osint.assistant import build_ai_summary
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
    force_kind: str | None = None,
) -> SearchExecution:
    if deep and not is_premium(user):
        raise PermissionError(t("errors.deep_premium"))

    spam_decision = anti_spam.check(user.telegram_id)
    if not spam_decision.allowed:
        raise PermissionError(spam_decision.reason or t("errors.rate_limited"))

    limit_decision = await check_search_limit(session, user)
    if not limit_decision.allowed:
        raise PermissionError(limit_decision.reason or t("errors.daily_limit", limit=0))

    mode = "deep" if deep else "basic"
    cache_key = f"{mode}:{force_kind or 'auto'}:{query}"
    cached = None if force_refresh else await get_cached(session, "search", cache_key)
    from_cache = cached is not None
    if cached:
        result = ScanResult.model_validate(cached)
        if "ai_summary" not in result.summary:
            result.summary["ai_summary"] = build_ai_summary(result)
    else:
        result = await scan_public_sources(query, deep=deep, premium=is_premium(user), force_kind=force_kind)
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
        report = Report(search_id=search_id, user_id=user.id, title=f"{t('report.title')}: {query[:80]}", html_path=str(report_path))
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
