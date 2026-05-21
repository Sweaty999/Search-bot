from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from api.routes import admin, search, web
from core.accounts import seed_roles
from core.api_manager import get_api_manager
from core.config import get_settings
from core.database import async_session, init_db
from core.logger import setup_logging
from core.webapp import validate_webapp_url
import logging

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    get_api_manager().log_startup_status()
    webapp_check = validate_webapp_url(get_settings().webapp_url)
    if not webapp_check.valid:
        logger.warning("WEBAPP_URL disabled: %s", webapp_check.reason)
    await init_db()
    async with async_session() as session:
        await seed_roles(session)
        await session.commit()
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title=settings.app_name, version="1.0.0", lifespan=lifespan)
    app.mount("/static", StaticFiles(directory="web/static"), name="static")
    app.mount("/css", StaticFiles(directory="web/css"), name="css")
    app.mount("/js", StaticFiles(directory="web/js"), name="js")
    app.include_router(web.router)
    app.include_router(search.router)
    app.include_router(admin.router)
    return app


app = create_app()
