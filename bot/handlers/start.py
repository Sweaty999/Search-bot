from __future__ import annotations

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from bot.keyboards.main import admin_menu, main_menu, premium_menu
from bot.services.premium import subscription_status
from bot.services.users import get_or_create_user
from core.config import get_settings
from core.database import async_session
from core.localization import t
from core.security import is_owner_id
from core.webapp import validate_webapp_url


WELCOME = t("bot.welcome")


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    async with async_session() as session:
        user = await get_or_create_user(session, update)
        await session.commit()
    if update.effective_message:
        await update.effective_message.reply_text(WELCOME, parse_mode=ParseMode.HTML, reply_markup=main_menu(user))
        check = validate_webapp_url(get_settings().webapp_url)
        if is_owner_id(user.telegram_id) and not check.valid:
            await update.effective_message.reply_text(
                t("bot.webapp_invalid", reason=check.reason),
            )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = t("bot.help")
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
            t(
                "bot.profile",
                telegram_id=user.telegram_id,
                username=user.username or "-",
                role=user.role.value,
                premium=t("bot.active") if status["active"] else t("bot.inactive"),
            )
        )
        await query.edit_message_text(text, parse_mode=ParseMode.HTML, reply_markup=main_menu(user))
    elif query.data == "settings":
        await query.edit_message_text(t("bot.settings"), reply_markup=main_menu(user))
    elif query.data == "help":
        await query.edit_message_text(
            t("bot.help_short"),
            reply_markup=main_menu(user),
        )
    elif query.data == "premium":
        await query.edit_message_text(t("bot.premium_intro"), reply_markup=premium_menu())
    elif query.data == "admin_panel":
        await query.edit_message_text(t("bot.admin_panel"), reply_markup=admin_menu())
