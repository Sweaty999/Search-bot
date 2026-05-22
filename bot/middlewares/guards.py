from __future__ import annotations

from telegram import Update

from core.localization import t
from core.models import User
from core.security import is_admin, is_premium


async def deny_if_banned(update: Update, user: User) -> bool:
    if not user.is_banned:
        return False
    if update.effective_message:
        await update.effective_message.reply_text(t("errors.banned"))
    return True


async def require_premium_chat(update: Update, user: User) -> bool:
    if is_premium(user):
        return True
    if update.effective_message:
        await update.effective_message.reply_text(t("errors.premium_only"))
    return False


async def require_admin_chat(update: Update, user: User) -> bool:
    if is_admin(user):
        return True
    if update.effective_message:
        await update.effective_message.reply_text(t("admin.role_required"))
    return False
