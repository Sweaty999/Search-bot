from __future__ import annotations

import re
import hashlib
from io import BytesIO
from typing import Any

from pypdf import PdfReader

from osint.collectors.base import BaseCollector, CollectorContext, fetch_bytes
from osint.models import Entity, EntityKind, Finding


URL_RE = re.compile(r"https?://[^\s<>()\"']+", re.IGNORECASE)
EMAIL_RE = re.compile(r"[\w.\-+]+@[\w.\-]+\.[a-zA-Z]{2,}")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")


class PdfCollector(BaseCollector):
    name = "pdf"

    async def collect(self, context: CollectorContext) -> list[Finding]:
        fetched = await fetch_bytes(context, context.entity.normalized, max_bytes=16_000_000)
        if not fetched or not fetched.body:
            return [
                Finding(
                    category="pdf",
                    title="PDF was not fetched",
                    source=self.name,
                    confidence=0.2,
                    description="The PDF URL is not public HTTP(S) or could not be downloaded.",
                )
            ]

        try:
            reader = PdfReader(BytesIO(fetched.body))
            metadata = {str(key).strip("/"): _safe(value) for key, value in (reader.metadata or {}).items()}
            text = "\n".join((page.extract_text() or "") for page in reader.pages[:5])
        except Exception as exc:
            return [
                Finding(
                    category="pdf",
                    title="PDF parse error",
                    source=self.name,
                    confidence=0.25,
                    data={"error": str(exc), "status_code": fetched.status},
                )
            ]

        urls = sorted(set(URL_RE.findall(text)))[:50]
        emails = sorted(set(EMAIL_RE.findall(text)))[:50]
        domains = sorted(set(DOMAIN_RE.findall(text)))[:50]
        sha256 = hashlib.sha256(fetched.body).hexdigest()
        vt_data = await _virustotal_file_hash(context, sha256) if context.api.enabled("virustotal") else None
        entities = [
            *[Entity(kind=EntityKind.url, value=item, normalized=item, confidence=0.7) for item in urls[:20]],
            *[Entity(kind=EntityKind.email, value=item, normalized=item.lower(), confidence=0.72) for item in emails[:20]],
            *[Entity(kind=EntityKind.domain, value=item, normalized=item.lower(), confidence=0.68) for item in domains[:20]],
        ]
        return [
            Finding(
                category="pdf",
                title="PDF metadata and extracted public indicators",
                source=self.name,
                source_url=fetched.url,
                confidence=0.82,
                data={
                    "status_code": fetched.status,
                    "sha256": sha256,
                    "virustotal": vt_data,
                    "metadata": metadata,
                    "pages": len(reader.pages),
                    "urls": urls,
                    "emails": emails,
                    "domains": domains,
                    "text_preview": text[:1500],
                },
                entities=entities,
            )
        ]


def _safe(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


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
