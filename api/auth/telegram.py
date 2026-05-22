from __future__ import annotations

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from api.services.dependencies import get_db
from core.accounts import upsert_telegram_user
from core.config import get_settings
from core.localization import t
from core.models import User
from core.security import parse_telegram_init_data, verify_telegram_webapp_init_data


async def current_webapp_user(
    x_telegram_init_data: str | None = Header(default=None),
    x_dev_telegram_id: int | None = Header(default=None),
    session: AsyncSession = Depends(get_db),
) -> User:
    settings = get_settings()
    if x_telegram_init_data and verify_telegram_webapp_init_data(x_telegram_init_data, settings.bot_token):
        parsed = parse_telegram_init_data(x_telegram_init_data)
        raw_user = parsed.get("user") or {}
        telegram_id = int(raw_user.get("id"))
        user = await upsert_telegram_user(
            session,
            telegram_id=telegram_id,
            username=raw_user.get("username"),
            first_name=raw_user.get("first_name"),
            last_name=raw_user.get("last_name"),
        )
    elif settings.env == "development":
        user = await upsert_telegram_user(session, telegram_id=x_dev_telegram_id or 100000001, username="dev_user")
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=t("errors.invalid_webapp_data"))

    if user.is_banned:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=t("errors.user_banned"))
    return user
