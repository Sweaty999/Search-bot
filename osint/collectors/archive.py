from __future__ import annotations

from core.localization import t
from osint.collectors.base import BaseCollector, CollectorContext
from osint.models import Finding


class ArchiveCollector(BaseCollector):
    name = "archive"

    async def collect(self, context: CollectorContext) -> list[Finding]:
        if not context.settings.enable_archive_lookup:
            return []
        target = context.entity.normalized
        try:
            async with context.http.get(
                "https://web.archive.org/cdx",
                params={
                    "url": target,
                    "output": "json",
                    "fl": "timestamp,original,statuscode,mimetype,digest",
                    "collapse": "digest",
                    "limit": 20,
                },
            ) as response:
                rows = await response.json(content_type=None)
        except Exception as exc:
            return [
                Finding(
                    category="archive",
                    title=t("findings.archive_failed_title"),
                    source="wayback",
                    confidence=0.2,
                    data={"error": str(exc)},
                )
            ]

        snapshots = []
        for row in rows[1:] if isinstance(rows, list) and rows else []:
            if len(row) < 5:
                continue
            timestamp, original, status_code, mimetype, digest = row[:5]
            snapshots.append(
                {
                    "timestamp": timestamp,
                    "original": original,
                    "status_code": status_code,
                    "mimetype": mimetype,
                    "digest": digest,
                    "archive_url": f"https://web.archive.org/web/{timestamp}/{original}",
                }
            )
        return [
            Finding(
                category="archive",
                title=t("findings.archive_snapshots_title"),
                source="wayback",
                source_url=f"https://web.archive.org/web/*/{target}",
                confidence=0.72 if snapshots else 0.25,
                data={"snapshots": snapshots, "count": len(snapshots)},
            )
        ]
