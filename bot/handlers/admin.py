from __future__ import annotations

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes
from sqlalchemy import select

from bot.keyboards.main import admin_menu
from bot.services.users import get_or_create_user
from core.accounts import platform_stats, set_admin_role, set_ban
from core.api_manager import get_api_manager
from core.cache import clear_cache
from core.config import get_settings
from core.database import async_session
from core.localization import t
from core.models import LogEntry, User
from core.security import is_admin, require_owner
from core.webapp import validate_webapp_url
from osint.parsers.entities import detect_entity
from osint.search.client import make_http_session
from osint.search.pipeline import expand_queries


async def admin_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    async with async_session() as session:
        user = await get_or_create_user(session, update)
        if not is_admin(user):
            await update.effective_message.reply_text(t("admin.role_required"))
            return
        args = context.args or []
        if args and args[0] in {"add", "remove"}:
            try:
                require_owner(user)
                telegram_id = int(args[1])
            except (PermissionError, IndexError, ValueError) as exc:
                await update.effective_message.reply_text(t("admin.owner_usage", error=exc))
                return
            target = await set_admin_role(session, telegram_id, enabled=args[0] == "add")
            await session.commit()
            await update.effective_message.reply_text(t("admin.role_changed", telegram_id=target.telegram_id, role=target.role.value))
            return
        await session.commit()
    await update.effective_message.reply_text(t("bot.admin_panel"), reply_markup=admin_menu())


async def stats_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    async with async_session() as session:
        user = await get_or_create_user(session, update)
        if not is_admin(user):
            await update.effective_message.reply_text(t("admin.role_required"))
            return
        stats = await platform_stats(session)
        await session.commit()
    labels = {"users": t("admin.stat_users"), "searches": t("admin.stat_searches"), "reports": t("admin.stat_reports"), "payments": t("admin.stat_payments")}
    await update.effective_message.reply_text("\n".join(f"{labels.get(key, key)}: {value}" for key, value in stats.items()))


async def users_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    async with async_session() as session:
        user = await get_or_create_user(session, update)
        if not is_admin(user):
            await update.effective_message.reply_text(t("admin.role_required"))
            return
        result = await session.execute(select(User).order_by(User.created_at.desc()).limit(30))
        rows = [
            t("admin.user_row", telegram_id=item.telegram_id, username=item.username or "-", role=item.role.value, banned=item.is_banned)
            for item in result.scalars()
        ]
        await session.commit()
    await update.effective_message.reply_text("\n".join(rows) or t("admin.no_users"))


async def logs_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    async with async_session() as session:
        user = await get_or_create_user(session, update)
        if not is_admin(user):
            await update.effective_message.reply_text(t("admin.role_required"))
            return
        result = await session.execute(select(LogEntry).order_by(LogEntry.created_at.desc()).limit(20))
        rows = [f"{item.created_at.isoformat()} | {item.level} | {item.action} | {item.details}" for item in result.scalars()]
        await session.commit()
    await update.effective_message.reply_text("\n".join(rows) or t("admin.no_logs"))


async def ban_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _ban_unban(update, context, banned=True)


async def unban_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await _ban_unban(update, context, banned=False)


async def _ban_unban(update: Update, context: ContextTypes.DEFAULT_TYPE, *, banned: bool) -> None:
    async with async_session() as session:
        user = await get_or_create_user(session, update)
        if not is_admin(user):
            await update.effective_message.reply_text(t("admin.role_required"))
            return
        try:
            telegram_id = int((context.args or [])[0])
        except (IndexError, ValueError):
            await update.effective_message.reply_text(t("admin.ban_usage"))
            return
        target = await set_ban(session, telegram_id, banned)
        await session.commit()
    await update.effective_message.reply_text(t("admin.banned", telegram_id=target.telegram_id, banned=target.is_banned))


async def cache_clear_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    async with async_session() as session:
        user = await get_or_create_user(session, update)
        if not is_admin(user):
            await update.effective_message.reply_text(t("admin.role_required"))
            return
        cleared = await clear_cache(session)
        await session.commit()
    await update.effective_message.reply_text(t("admin.cache_cleared", count=cleared))


async def broadcast_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = " ".join(context.args or [])
    if not text:
        await update.effective_message.reply_text(t("admin.broadcast_usage"))
        return
    async with async_session() as session:
        user = await get_or_create_user(session, update)
        if not is_admin(user):
            await update.effective_message.reply_text(t("admin.role_required"))
            return
        result = await session.execute(select(User.telegram_id).where(User.is_banned.is_(False)))
        telegram_ids = [row[0] for row in result.all()]
        await session.commit()
    sent = 0
    for telegram_id in telegram_ids:
        try:
            await context.bot.send_message(telegram_id, text, parse_mode=ParseMode.HTML)
            sent += 1
        except Exception:
            continue
    await update.effective_message.reply_text(t("admin.broadcast_sent", count=sent))


async def api_status_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _owner_guard(update):
        return
    diagnostics = get_api_manager().diagnostics()
    lines = [t("admin.api_status_title")]
    for provider in diagnostics["providers"]:
        enabled = t("admin.api_enabled") if provider["enabled"] else t("admin.api_missing")
        if provider["fallback"]:
            enabled = t("admin.api_fallback")
        latency = f"{provider['last_response_ms']}ms" if provider["last_response_ms"] else "-"
        error = provider["last_error"] or "-"
        lines.append(
            t("admin.provider_line", name=provider["name"], status=enabled, last=provider["last_status"], latency=latency, error=error)
        )
    lines.append(t("admin.api_cache_entries", count=diagnostics["cache_entries"]))
    await update.effective_message.reply_text("\n".join(lines), parse_mode=ParseMode.HTML)


async def api_test_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _owner_guard(update):
        return
    message = await update.effective_message.reply_text(t("admin.testing_providers"))
    async with make_http_session() as http:
        result = await get_api_manager().test_providers(http)
    tested = ", ".join(result["tested"]) or t("bot.none")
    await message.edit_text(t("admin.api_test_complete", tested=tested))


async def provider_reset_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _owner_guard(update):
        return
    provider = (context.args or [None])[0]
    get_api_manager().reset_provider_health(provider)
    await update.effective_message.reply_text(t("admin.provider_reset", provider=provider or t("web.all")))


async def search_debug_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await _owner_guard(update):
        return
    query = " ".join(context.args or []).strip()
    if not query:
        await update.effective_message.reply_text(t("admin.search_debug_usage"))
        return
    entity = detect_entity(query)
    expansions = expand_queries(entity, query)[:12]
    webapp = validate_webapp_url(get_settings().webapp_url)
    lines = [
        t("admin.search_debug_title"),
        f"{t('admin.debug_entity')}: <code>{entity.kind.value}</code>",
        f"{t('admin.debug_normalized')}: <code>{entity.normalized}</code>",
        f"{t('admin.debug_webapp')}: <code>{t('admin.debug_valid') if webapp.valid else webapp.reason}</code>",
        "",
        t("admin.search_debug_expansion"),
        *[f"{idx + 1}. <code>{item}</code>" for idx, item in enumerate(expansions)],
    ]
    await update.effective_message.reply_text("\n".join(lines), parse_mode=ParseMode.HTML, disable_web_page_preview=True)


async def _owner_guard(update: Update) -> bool:
    async with async_session() as session:
        user = await get_or_create_user(session, update)
        try:
            require_owner(user)
        except PermissionError:
            await update.effective_message.reply_text(t("admin.owner_required"))
            return False
        await session.commit()
    return True


async def admin_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.data:
        return
    await query.answer()
    command_map = {
        "admin_stats": t("admin.command_stats"),
        "admin_users": t("admin.command_users"),
        "admin_logs": t("admin.command_logs"),
        "admin_ban_help": t("admin.command_ban"),
        "admin_broadcast_help": t("admin.command_broadcast"),
        "admin_api_status_help": "/api_status",
        "admin_api_test_help": "/api_test",
    }
    await query.edit_message_text(command_map.get(query.data, t("bot.admin_panel")), reply_markup=admin_menu())
