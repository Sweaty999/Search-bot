from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.telegram import current_webapp_user
from api.services.dependencies import get_db
from core.config import get_settings
from core.models import Report, Search, User
from core.security import is_premium

router = APIRouter(tags=["web"])
templates = Jinja2Templates(directory="web/templates")


@router.get("/")
async def dashboard(request: Request):
    settings = get_settings()
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={"app_name": settings.app_name, "webapp_url": settings.webapp_url},
    )


@router.get("/api/profile")
async def profile_endpoint(user: User = Depends(current_webapp_user)) -> dict[str, object]:
    return {
        "telegram_id": user.telegram_id,
        "username": user.username,
        "role": user.role.value,
        "premium": is_premium(user),
        "is_banned": user.is_banned,
    }


@router.get("/api/reports/search/{search_id}")
async def report_by_search(
    search_id: str,
    user: User = Depends(current_webapp_user),
    session: AsyncSession = Depends(get_db),
):
    search_statement = select(Search).where(Search.id == search_id)
    if user.role.value not in {"admin", "owner"}:
        search_statement = search_statement.where(Search.user_id == user.id)
    search = await session.scalar(search_statement)
    if not search:
        raise HTTPException(status_code=404, detail="Search not found.")

    report = await session.scalar(select(Report).where(Report.search_id == search.id).order_by(Report.created_at.desc()))
    if not report:
        raise HTTPException(status_code=404, detail="Report not found or premium is required.")
    path = Path(report.html_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Report file missing.")
    return FileResponse(path, media_type="text/html", filename=path.name)
