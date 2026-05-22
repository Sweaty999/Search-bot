from __future__ import annotations

import hashlib
from io import BytesIO

import exifread
from PIL import Image

from core.localization import t
from osint.collectors.base import BaseCollector, CollectorContext, fetch_bytes
from osint.models import Finding


class ImageCollector(BaseCollector):
    name = "image"

    async def collect(self, context: CollectorContext) -> list[Finding]:
        fetched = await fetch_bytes(context, context.entity.normalized, max_bytes=12_000_000)
        if not fetched or not fetched.body:
            return [
                Finding(
                    category="image",
                    title=t("findings.image_not_fetched_title"),
                    source=self.name,
                    confidence=0.2,
                    description=t("findings.image_not_fetched_description"),
                )
            ]

        sha256 = hashlib.sha256(fetched.body).hexdigest()
        dimensions: dict[str, object] = {}
        exif: dict[str, str] = {}
        try:
            image = Image.open(BytesIO(fetched.body))
            dimensions = {"width": image.width, "height": image.height, "format": image.format, "mode": image.mode}
        except Exception as exc:
            dimensions = {"error": str(exc)}

        try:
            tags = exifread.process_file(BytesIO(fetched.body), details=False)
            exif = {str(key): str(value) for key, value in list(tags.items())[:80]}
        except Exception as exc:
            exif = {"error": str(exc)}

        vt_data = None
        if context.api.enabled("virustotal"):
            vt_data = await _virustotal_file_hash(context, sha256)

        return [
            Finding(
                category="image",
                title=t("findings.image_metadata_title"),
                source=self.name,
                source_url=fetched.url,
                confidence=0.82,
                data={
                    "status_code": fetched.status,
                    "content_type": fetched.headers.get("Content-Type"),
                    "sha256": sha256,
                    "dimensions": dimensions,
                    "exif": exif,
                    "virustotal": vt_data,
                    "ocr_enabled": context.settings.enable_ocr,
                    "ocr_note": t("findings.image_ocr_note"),
                },
            )
        ]


async def _virustotal_file_hash(context: CollectorContext, sha256: str) -> dict[str, object]:
    payload = await context.api.get_json(
        "virustotal",
        context.http,
        f"https://www.virustotal.com/api/v3/files/{sha256}",
        headers={"x-apikey": context.settings.vt_api_key or ""},
    )
    attributes = (payload or {}).get("data", {}).get("attributes", {})
    return {
        "last_analysis_stats": attributes.get("last_analysis_stats"),
        "reputation": attributes.get("reputation"),
        "type_description": attributes.get("type_description"),
        "meaningful_name": attributes.get("meaningful_name"),
        "size": attributes.get("size"),
    }
