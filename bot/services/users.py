from __future__ import annotations

from telegram import Update
from sqlalchemy.ext.asyncio import AsyncSession

from core.accounts import upsert_telegram_user
from core.models import User


async def get_or_create_user(session: AsyncSession, update: Update) -> User:
    tg_user = update.effective_user
    if not tg_user:
        raise PermissionError("Telegram user is missing.")
    return await upsert_telegram_user(
        session,
        telegram_id=tg_user.id,
        username=tg_user.username,
        first_name=tg_user.first_name,
        last_name=tg_user.last_name,
    )

