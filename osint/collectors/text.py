from __future__ import annotations

from osint.collectors.base import BaseCollector, CollectorContext
from osint.models import Finding


class TextQueryCollector(BaseCollector):
    name = "text_query"

    async def collect(self, context: CollectorContext) -> list[Finding]:
        hits = await context.search.search(context.http, context.entity.normalized, limit=10 if context.deep else 5)
        return [
            Finding(
                category="search",
                title="Public web search summary",
                source="multi_engine_search",
                confidence=0.66 if hits else 0.2,
                data={"hits": [hit.model_dump() for hit in hits]},
            )
        ]

