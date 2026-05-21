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

    mode = {
        "new_search": "basic",
        "deep_scan": "deep",
        "build_graph": "deep",
        "html_report": "deep",
    }.get(query.data or "", "basic")

    async with async_session() as session:
        user = await get_or_create_user(session, update)
        if await deny_if_banned(update, user):
            return ConversationHandler.END
        if mode == "deep" and not await require_premium_chat(update, user):
            return ConversationHandler.END
        await session.commit()

    context.user_data["search_mode"] = mode
    await query.edit_message_text("Send the public indicator or query to scan.")
    return WAITING_QUERY


async def receive_search_query(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    text = (update.effective_message.text or "").strip() if update.effective_message else ""
    mode = context.user_data.pop("search_mode", "basic")
    await run_search(update, context, text, deep=mode == "deep")
    return ConversationHandler.END


async def auto_text_search(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (update.effective_message.text or "").strip() if update.effective_message else ""
    if not text or text.startswith("/"):
        return
    await run_search(update, context, text, deep=False)


async def run_search(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    query_text: str,
    *,
    deep: bool,
    force_refresh: bool = False,
) -> None:
    if not update.effective_message:
        return
    if not query_text:
        await update.effective_message.reply_text("Send a username, email, phone, domain, URL, IP, image URL, PDF URL or text query.")
        return

    status_message = await update.effective_message.reply_text(
        "Stage 1/6: detecting entity...\n"
        "Stage 2/6: expanding queries...\n"
        "Stage 3/6: searching providers...\n"
        "Stage 4/6: enriching pages...\n"
        "Stage 5/6: ranking signals...\n"
        "Stage 6/6: building graph...",
    )
    async with async_session() as session:
        user = await get_or_create_user(session, update)
        if await deny_if_banned(update, user):
            return
        try:
            execution = await execute_search(session, user, query_text, deep=deep, force_refresh=force_refresh)
        except PermissionError as exc:
            await session.rollback()
            await status_message.edit_text(str(exc))
            return
        await session.commit()

    result = execution.result
    if result.status == "refused":
        text = f"<b>Request refused</b>\n{html.escape(result.refusal_reason or '')}"
    else:
        counters = result.summary.get("entity_counters", {})
        counter_text = ", ".join(f"{key}:{value}" for key, value in counters.items()) or "none"
        risk = float(result.summary.get("risk_score") or 0.0)
        text = (
            "<b>OSINT Search Complete</b>\n"
            f"Query: <code>{html.escape(query_text[:160])}</code>\n"
            f"Entity: <code>{result.entity.kind.value}</code>\n"
            f"Mode: <code>{result.mode}</code>\n"
            f"Findings: <b>{len(result.findings)}</b>\n"
            f"Search hits: <b>{len(result.search_hits)}</b>\n"
            f"Entities: <code>{html.escape(counter_text)}</code>\n"
            f"Confidence: <b>{result.confidence:.2f}</b> {_bar(result.confidence)}\n"
            f"Risk: <b>{risk:.2f}</b> {_bar(risk)}\n"
            f"Cache: <b>{'hit' if execution.from_cache else 'fresh'}</b>"
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
            await query.edit_message_text("Search not found.")
            return

        if action == "refresh":
            await session.commit()
            await run_search(update, context, search.query, deep=search.mode == "deep", force_refresh=True)
            return

        if action == "sources":
            result = ScanResult.model_validate(search.result)
            await query.edit_message_text(_format_sources(result), parse_mode=ParseMode.HTML, disable_web_page_preview=True)
            return

        if action == "clear_cache":
            if not await require_admin_chat(update, user):
                return
            cleared = await clear_cache(session, "search")
            await session.commit()
            await query.edit_message_text(f"Cleared cached search entries: {cleared}", reply_markup=main_menu(user))
            return

        if action in {"graph", "export"} and not await require_premium_chat(update, user):
            return

        if action == "graph":
            graph = GraphData.model_validate(search.graph)
            graph_path = export_pyvis_html(graph, Path("data/exports") / f"graph-{search.id}.html")
            await _send_document(update, graph_path, "Graph HTML")
            return

        if action == "export":
            report = await session.scalar(select(Report).where(Report.search_id == search.id).order_by(Report.created_at.desc()))
            if not report:
                result = ScanResult.model_validate(search.result)
                report_path = render_html_report(result, report_id=search.id)
                report = Report(search_id=search.id, user_id=user.id, title=f"OSINT report: {search.query[:80]}", html_path=str(report_path))
                session.add(report)
                await session.commit()
            await _send_document(update, Path(report.html_path), "HTML report")


async def _get_search(session, search_id: str, user) -> Search | None:
    statement = select(Search).where(Search.id == search_id)
    if user.role.value not in {"admin", "owner"}:
        statement = statement.where(Search.user_id == user.id)
    return await session.scalar(statement)


async def _send_document(update: Update, path: Path, caption: str) -> None:
    if not update.effective_message:
        return
    if not path.exists():
        await update.effective_message.reply_text("File is missing. Try refresh.")
        return
    with path.open("rb") as file_obj:
        await update.effective_message.reply_document(document=InputFile(file_obj, filename=path.name), caption=caption)


def _format_sources(result: ScanResult) -> str:
    lines = ["<b>Sources</b>"]
    count = 0
    for hit in result.search_hits[:15]:
        lines.append(
            f"• <a href=\"{html.escape(hit.url)}\">{html.escape((hit.title or hit.domain or hit.url)[:80])}</a> "
            f"[{html.escape(hit.engine)} | conf {hit.confidence:.2f} | risk {hit.risk_score:.2f}]"
        )
        count += 1
    for finding in result.findings:
        if finding.source_url:
            lines.append(f"• {html.escape(finding.source)}: {html.escape(finding.source_url)}")
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
        lines.append("No external source links in this result.")
    return "\n".join(lines)


def _bar(value: float, width: int = 10) -> str:
    value = max(0.0, min(1.0, value))
    filled = round(value * width)
    return "[" + "█" * filled + "░" * (width - filled) + "]"
