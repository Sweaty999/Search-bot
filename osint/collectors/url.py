from __future__ import annotations

import base64

from core.localization import t
from osint.collectors.base import BaseCollector, CollectorContext, fetch_text
from osint.models import Finding
from osint.parsers.html import extract_page_metadata
from osint.screenshots.service import capture_screenshot


class UrlCollector(BaseCollector):
    name = "url"

    async def collect(self, context: CollectorContext) -> list[Finding]:
        fetched = await fetch_text(context, context.entity.normalized)
        if not fetched:
            return [
                Finding(
                    category="url",
                    title=t("findings.url_not_fetched_title"),
                    source=self.name,
                    description=t("findings.url_not_fetched_description"),
                    confidence=0.2,
                )
            ]

        metadata = extract_page_metadata(fetched.text or "", fetched.url)
        data = {
            "url": fetched.url,
            "status_code": fetched.status,
            "headers": dict(list(fetched.headers.items())[:40]),
            "metadata": metadata,
        }
        if context.api.enabled("virustotal"):
            data["virustotal"] = await _virustotal_url(context, fetched.url)
        if context.deep or context.premium:
            screenshot = await capture_screenshot(fetched.url, context.settings)
            if screenshot:
                data["screenshot"] = screenshot

        return [
            Finding(
                category="url",
                title=t("findings.url_metadata_title"),
                source=self.name,
                source_url=fetched.url,
                confidence=0.86 if fetched.status < 400 else 0.45,
                data=data,
            )
        ]


async def _virustotal_url(context: CollectorContext, url: str) -> dict[str, object]:
    url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").strip("=")
    payload = await context.api.get_json(
        "virustotal",
        context.http,
        f"https://www.virustotal.com/api/v3/urls/{url_id}",
        headers={"x-apikey": context.settings.vt_api_key or ""},
    )
    attributes = (payload or {}).get("data", {}).get("attributes", {})
    return {
        "last_analysis_stats": attributes.get("last_analysis_stats"),
        "reputation": attributes.get("reputation"),
        "categories": attributes.get("categories"),
        "times_submitted": attributes.get("times_submitted"),
    }
