from __future__ import annotations

import html
from pathlib import Path

from sqlalchemy import select
from telegram import InputFile, Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes, ConversationHandler

from api.services.search_service import execute_search
from bot.keyboards.main import after_search, main_menu
from bot.middlewares.guards import deny_if_banned, require_admin_chat, require_premium_chat
from bot.services.users import get_or_create_user
from core.cache import clear_cache
from core.database import async_session
from core.localization import t
from core.models import Report, Search
from core.security import is_premium
from osint.graph.builder import export_pyvis_html
from osint.models import GraphData, ScanResult
from osint.reports.html import render_html_report

WAITING_QUERY = 1


async def ask_search(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    query = update.callback_query
    if not query:
        return ConversationHandler.END
    await query.answer()

    action = query.data or ""
    mode = {
        "new_search": "basic",
        "telegram_scan": "basic",
        "phone_scan": "basic",
        "email_scan": "basic",
        "deep_scan": "deep",
        "build_graph": "deep",
        "html_report": "deep",
    }.get(action, "basic")
    force_kind = {
        "telegram_scan": "telegram",
        "phone_scan": "phone",
        "email_scan": "email",
    }.get(action)
    ask_key = {
        "telegram_scan": "search.ask.telegram",
        "phone_scan": "search.ask.phone",
        "email_scan": "search.ask.email",
        "deep_scan": "search.ask.deep",
        "build_graph": "search.ask.deep",
        "html_report": "search.ask.deep",
    }.get(action, "search.ask.basic")

    async with async_session() as session:
        user = await get_or_create_user(session, update)
        if await deny_if_banned(update, user):
            return ConversationHandler.END
        if mode == "deep" and not await require_premium_chat(update, user):
            return ConversationHandler.END
        await session.commit()

    context.user_data["search_mode"] = mode
    context.user_data["force_kind"] = force_kind
    await query.edit_message_text(t(ask_key))
    return WAITING_QUERY


async def receive_search_query(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    text = _query_from_message(update) or ((update.effective_message.text or "").strip() if update.effective_message else "")
    mode = context.user_data.pop("search_mode", "basic")
    force_kind = context.user_data.pop("force_kind", None) or ("telegram" if _query_from_message(update) else None)
    await run_search(update, context, text, deep=mode == "deep", force_kind=force_kind)
    return ConversationHandler.END


async def auto_text_search(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    forwarded = _query_from_message(update)
    text = forwarded or ((update.effective_message.text or "").strip() if update.effective_message else "")
    if not text or text.startswith("/"):
        return
    await run_search(update, context, text, deep=False, force_kind="telegram" if forwarded else None)


async def run_search(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    query_text: str,
    *,
    deep: bool,
    force_refresh: bool = False,
    force_kind: str | None = None,
) -> None:
    if not update.effective_message:
        return
    if not query_text:
        await update.effective_message.reply_text(t("search.empty_query"))
        return

    status_message = await update.effective_message.reply_text(
        t("search.progress"),
    )
    async with async_session() as session:
        user = await get_or_create_user(session, update)
        if await deny_if_banned(update, user):
            return
        try:
            execution = await execute_search(session, user, query_text, deep=deep, force_refresh=force_refresh, force_kind=force_kind)
        except PermissionError as exc:
            await session.rollback()
            await status_message.edit_text(str(exc))
            return
        await session.commit()

    result = execution.result
    if result.status == "refused":
        text = f"<b>{t('search.refused_title')}</b>\n{html.escape(result.refusal_reason or '')}"
    else:
        counters = result.summary.get("entity_counters", {})
        counter_text = ", ".join(f"{t(f'entities.{key}')}:{value}" for key, value in counters.items()) or t("bot.none")
        risk = float(result.summary.get("risk_score") or 0.0)
        ai_summary = result.summary.get("ai_summary", {})
        text = t(
            "search.complete",
            query=html.escape(query_text[:160]),
            entity=t(f"entities.{result.entity.kind.value}"),
            mode=t(f"search.mode_{result.mode}") if result.mode in {"basic", "deep"} else result.mode,
            findings=len(result.findings),
            hits=len(result.search_hits),
            entities=html.escape(counter_text),
            confidence=f"{result.confidence:.2f}",
            confidence_bar=_bar(result.confidence),
            risk=f"{risk:.2f}",
            risk_bar=_bar(risk),
            cache=t("search.cache_hit") if execution.from_cache else t("search.cache_fresh"),
            summary=html.escape(str(ai_summary.get("text") if isinstance(ai_summary, dict) else ai_summary)),
        )
    await status_message.edit_text(
        text,
        parse_mode=ParseMode.HTML,
        reply_markup=after_search(execution.search.id, execution.report is not None, is_premium(user)),
        disable_web_page_preview=True,
    )


async def search_action_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.data:
        return
    await query.answer()
    action, search_id = query.data.split(":", 1)

    async with async_session() as session:
        user = await get_or_create_user(session, update)
        search = await _get_search(session, search_id, user)
        if not search:
            await query.edit_message_text(t("search.not_found"))
            return

        if action == "refresh":
            await session.commit()
            await run_search(update, context, search.query, deep=search.mode == "deep", force_refresh=True, force_kind=_force_kind_from_search(search))
            return

        if action == "deep":
            if not await require_premium_chat(update, user):
                return
            await session.commit()
            await run_search(update, context, search.query, deep=True, force_refresh=True, force_kind=_force_kind_from_search(search))
            return

        if action == "sources":
            result = ScanResult.model_validate(search.result)
            await query.edit_message_text(_format_sources(result), parse_mode=ParseMode.HTML, disable_web_page_preview=True)
            return

        if action == "related":
            result = ScanResult.model_validate(search.result)
            await query.edit_message_text(_format_related_accounts(result), parse_mode=ParseMode.HTML, disable_web_page_preview=True)
            return

        if action == "clear_cache":
            if not await require_admin_chat(update, user):
                return
            cleared = await clear_cache(session, "search")
            await session.commit()
            await query.edit_message_text(t("search.cache_cleared", count=cleared), reply_markup=main_menu(user))
            return

        if action in {"graph", "export"} and not await require_premium_chat(update, user):
            return

        if action == "graph":
            graph = GraphData.model_validate(search.graph)
            graph_path = export_pyvis_html(graph, Path("data/exports") / f"graph-{search.id}.html")
            await _send_document(update, graph_path, t("search.graph_caption"))
            return

        if action == "export":
            report = await session.scalar(select(Report).where(Report.search_id == search.id).order_by(Report.created_at.desc()))
            if not report:
                result = ScanResult.model_validate(search.result)
                report_path = render_html_report(result, report_id=search.id)
                report = Report(search_id=search.id, user_id=user.id, title=f"{t('report.title')}: {search.query[:80]}", html_path=str(report_path))
                session.add(report)
                await session.commit()
            await _send_document(update, Path(report.html_path), t("search.report_caption"))


async def _get_search(session, search_id: str, user) -> Search | None:
    statement = select(Search).where(Search.id == search_id)
    if user.role.value not in {"admin", "owner"}:
        statement = statement.where(Search.user_id == user.id)
    return await session.scalar(statement)


async def _send_document(update: Update, path: Path, caption: str) -> None:
    if not update.effective_message:
        return
    if not path.exists():
        await update.effective_message.reply_text(t("search.file_missing"))
        return
    with path.open("rb") as file_obj:
        await update.effective_message.reply_document(document=InputFile(file_obj, filename=path.name), caption=caption)


def _format_sources(result: ScanResult) -> str:
    lines = [t("search.sources_title")]
    count = 0
    for hit in result.search_hits[:15]:
        lines.append(
            t(
                "search.source_line",
                url=html.escape(hit.url),
                title=html.escape((hit.title or hit.domain or hit.url)[:80]),
                engine=html.escape(hit.engine),
                confidence=f"{hit.confidence:.2f}",
                risk=f"{hit.risk_score:.2f}",
            )
        )
        count += 1
    for finding in result.findings:
        if finding.source_url:
            lines.append(t("search.source_finding_line", source=html.escape(finding.source), url=html.escape(finding.source_url)))
            count += 1
        hits = finding.data.get("hits", []) if finding.data else []
        for hit in hits[:5] if isinstance(hits, list) else []:
            url = hit.get("url") if isinstance(hit, dict) else None
            if url:
                lines.append(f"• {html.escape(str(url))}")
                count += 1
        if count >= 25:
            break
    if count == 0:
        lines.append(t("search.no_sources"))
    return "\n".join(lines)


def _format_related_accounts(result: ScanResult) -> str:
    lines = [t("search.related_title")]
    count = 0
    for finding in result.findings:
        profiles = finding.data.get("profiles", []) if isinstance(finding.data, dict) else []
        if not isinstance(profiles, list):
            continue
        for profile in profiles:
            if not isinstance(profile, dict):
                continue
            url = str(profile.get("url") or "")
            platform = str(profile.get("platform") or "")
            confidence = float(profile.get("confidence") or 0.0)
            if url and confidence >= 0.35:
                lines.append(f"• <a href=\"{html.escape(url)}\">{html.escape(platform or url)}</a> — {confidence:.2f}")
                count += 1
            if count >= 20:
                break
        if count >= 20:
            break
    if count == 0:
        lines.append(t("search.related_empty"))
    return "\n".join(lines)


def _force_kind_from_search(search: Search) -> str | None:
    return search.entity_type if search.entity_type in {"telegram", "phone", "email", "username"} else None


def _query_from_message(update: Update) -> str | None:
    message = update.effective_message
    if not message:
        return None
    origin = getattr(message, "forward_origin", None)
    chat = getattr(origin, "chat", None) if origin else getattr(message, "forward_from_chat", None)
    username = getattr(chat, "username", None)
    if username:
        return f"https://t.me/{username}"
    sender_user = getattr(origin, "sender_user", None) if origin else getattr(message, "forward_from", None)
    sender_username = getattr(sender_user, "username", None)
    if sender_username:
        return f"@{sender_username}"
    return None


def _bar(value: float, width: int = 10) -> str:
    value = max(0.0, min(1.0, value))
    filled = round(value * width)
    return "[" + "█" * filled + "░" * (width - filled) + "]"
