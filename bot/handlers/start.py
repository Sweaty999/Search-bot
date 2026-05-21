from __future__ import annotations

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from bot.keyboards.main import admin_menu, main_menu, premium_menu
from bot.services.premium import subscription_status
from bot.services.users import get_or_create_user
from core.config import get_settings
from core.database import async_session
from core.security import is_owner_id
from core.webapp import validate_webapp_url


WELCOME = (
    "<b>Legal OSINT Platform</b>\n"
    "Search only public, lawful sources: DNS, WHOIS, SSL, public profiles, metadata, archives, screenshots and graphs.\n\n"
    "Send a query or use the menu."
)


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    async with async_session() as session:
        user = await get_or_create_user(session, update)
        await session.commit()
    if update.effective_message:
        await update.effective_message.reply_text(WELCOME, parse_mode=ParseMode.HTML, reply_markup=main_menu(user))
        check = validate_webapp_url(get_settings().webapp_url)
        if is_owner_id(user.telegram_id) and not check.valid:
            await update.effective_message.reply_text(
                "WebApp requires HTTPS URL. Use ngrok/cloudflared/render/railway domain.\n"
                f"Current diagnostic: {check.reason}",
            )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (
        "<b>Allowed</b>: public websites, search engines, public profiles, DNS, WHOIS, SSL, IP info, metadata, archives, screenshots and graphs.\n\n"
        "<b>Not allowed</b>: leaks, private databases, doxing, passwords, tokens, brute force, auth bypass or illegal people searches."
    )
    if update.effective_message:
        await update.effective_message.reply_text(text, parse_mode=ParseMode.HTML, disable_web_page_preview=True)


async def menu_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query:
        return
    await query.answer()
    async with async_session() as session:
        user = await get_or_create_user(session, update)
        status = await subscription_status(session, user)
        await session.commit()

    if query.data == "profile":
        text = (
            "<b>Profile</b>\n"
            f"Telegram ID: <code>{user.telegram_id}</code>\n"
            f"Username: @{user.username or '-'}\n"
            f"Role: <b>{user.role.value}</b>\n"
            f"Premium: <b>{'active' if status['active'] else 'inactive'}</b>"
        )
        await query.edit_message_text(text, parse_mode=ParseMode.HTML, reply_markup=main_menu(user))
    elif query.data == "settings":
        await query.edit_message_text("Settings are managed through .env and role-based controls.", reply_markup=main_menu(user))
    elif query.data == "help":
        await query.edit_message_text(
            "Use public-source OSINT only. Requests for credentials, leaks, doxing or access bypass are refused.",
            reply_markup=main_menu(user),
        )
    elif query.data == "premium":
        await query.edit_message_text("Premium is paid only with Telegram Stars.", reply_markup=premium_menu())
    elif query.data == "admin_panel":
        await query.edit_message_text("Admin Panel", reply_markup=admin_menu())
