from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.telegram import current_webapp_user
from api.services.dependencies import get_db
from core.accounts import platform_stats, set_ban
from core.api_manager import get_api_manager
from core.cache import clear_cache
from core.models import LogEntry, User
from core.security import is_admin

router = APIRouter(prefix="/api/admin", tags=["admin"])


class BanRequest(BaseModel):
    telegram_id: int
    banned: bool = True


def _require_admin(user: User) -> None:
    if not is_admin(user):
        raise HTTPException(status_code=403, detail="Admin role required.")


@router.get("/stats")
async def stats(user: User = Depends(current_webapp_user), session: AsyncSession = Depends(get_db)):
    _require_admin(user)
    return await platform_stats(session)


@router.get("/users")
async def users(user: User = Depends(current_webapp_user), session: AsyncSession = Depends(get_db)):
    _require_admin(user)
    result = await session.execute(select(User).order_by(User.created_at.desc()).limit(200))
    return {
        "items": [
            {
                "telegram_id": item.telegram_id,
                "username": item.username,
                "role": item.role.value,
                "is_banned": item.is_banned,
                "created_at": item.created_at.isoformat(),
            }
            for item in result.scalars()
        ]
    }


@router.post("/ban")
async def ban(payload: BanRequest, user: User = Depends(current_webapp_user), session: AsyncSession = Depends(get_db)):
    _require_admin(user)
    target = await set_ban(session, payload.telegram_id, payload.banned)
    return {"telegram_id": target.telegram_id, "is_banned": target.is_banned}


@router.get("/logs")
async def logs(user: User = Depends(current_webapp_user), session: AsyncSession = Depends(get_db)):
    _require_admin(user)
    result = await session.execute(select(LogEntry).order_by(LogEntry.created_at.desc()).limit(200))
    return {
        "items": [
            {
                "id": item.id,
                "action": item.action,
                "level": item.level,
                "details": item.details,
                "created_at": item.created_at.isoformat(),
            }
            for item in result.scalars()
        ]
    }


@router.get("/api-status")
async def api_status(user: User = Depends(current_webapp_user)):
    _require_admin(user)
    return get_api_manager().diagnostics()


@router.post("/cache/clear")
async def cache_clear(user: User = Depends(current_webapp_user), session: AsyncSession = Depends(get_db)):
    _require_admin(user)
    return {"cleared": await clear_cache(session)}
