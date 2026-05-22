from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.telegram import current_webapp_user
from api.services.dependencies import get_db
from api.services.search_service import execute_search
from core.localization import t
from core.models import Search, User

router = APIRouter(prefix="/api", tags=["search"])


class SearchRequest(BaseModel):
    query: str = Field(min_length=2, max_length=500)
    entity_type: str = "auto"
    deep: bool = False
    force_refresh: bool = False


@router.post("/search")
async def search_endpoint(
    payload: SearchRequest,
    user: User = Depends(current_webapp_user),
    session: AsyncSession = Depends(get_db),
) -> dict[str, object]:
    allowed_entity_types = {"auto", "telegram", "username", "email", "phone", "domain", "url", "ip", "image_url", "pdf_url"}
    if payload.entity_type not in allowed_entity_types:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=t("errors.invalid_entity_type"))
    try:
        execution = await execute_search(
            session,
            user,
            payload.query,
            deep=payload.deep,
            force_refresh=payload.force_refresh,
            force_kind=None if payload.entity_type == "auto" else payload.entity_type,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc

    report_url = f"/api/reports/search/{execution.search.id}" if execution.report else None
    return {
        "search_id": execution.search.id,
        "from_cache": execution.from_cache,
        "report_url": report_url,
        "result": execution.result.model_dump(mode="json"),
    }


@router.get("/history")
async def history_endpoint(
    user: User = Depends(current_webapp_user),
    session: AsyncSession = Depends(get_db),
) -> dict[str, object]:
    result = await session.execute(
        select(Search).where(Search.user_id == user.id).order_by(Search.created_at.desc()).limit(50)
    )
    searches = [
        {
            "id": item.id,
            "query": item.query,
            "entity_type": item.entity_type,
            "mode": item.mode,
            "status": item.status.value,
            "confidence": item.confidence,
            "created_at": item.created_at.isoformat(),
        }
        for item in result.scalars()
    ]
    return {"items": searches}


@router.get("/search/{search_id}")
async def search_result_endpoint(
    search_id: str,
    user: User = Depends(current_webapp_user),
    session: AsyncSession = Depends(get_db),
) -> dict[str, object]:
    statement = select(Search).where(Search.id == search_id)
    if user.role.value not in {"admin", "owner"}:
        statement = statement.where(Search.user_id == user.id)
    search = await session.scalar(statement)
    if not search:
        raise HTTPException(status_code=404, detail=t("errors.search_not_found"))
    return {"result": search.result, "graph": search.graph, "summary": search.summary}
