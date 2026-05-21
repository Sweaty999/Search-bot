from __future__ import annotations

import hashlib
import logging
from pathlib import Path

from core.config import Settings, get_settings
from core.validators import is_public_http_url

logger = logging.getLogger(__name__)


async def capture_screenshot(url: str, settings: Settings | None = None) -> str | None:
    settings = settings or get_settings()
    if not settings.enable_playwright_screenshots or not is_public_http_url(url):
        return None
    try:
        from playwright.async_api import async_playwright
    except Exception as exc:
        logger.warning("Playwright is not available: %s", exc)
        return None

    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
    path = Path(settings.export_dir) / f"screenshot-{digest}.png"
    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch()
            page = await browser.new_page(viewport={"width": 1440, "height": 1200})
            await page.goto(url, wait_until="networkidle", timeout=settings.http_timeout_seconds * 1000)
            await page.screenshot(path=str(path), full_page=True)
            await browser.close()
        return str(path)
    except Exception as exc:
        logger.warning("Screenshot capture failed for %s: %s", url, exc)
        return None

