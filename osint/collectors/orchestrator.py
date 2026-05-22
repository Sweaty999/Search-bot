from __future__ import annotations

import logging

from core.config import Settings, get_settings
from core.api_manager import get_api_manager
from core.localization import t
from core.security import assess_query_safety
from osint.assistant import build_ai_summary
from osint.collectors.archive import ArchiveCollector
from osint.collectors.base import BaseCollector, CollectorContext
from osint.collectors.domain import DomainCollector
from osint.collectors.email import EmailCollector
from osint.collectors.image import ImageCollector
from osint.collectors.ip import IpCollector
from osint.collectors.pdf import PdfCollector
from osint.collectors.phone import PhoneCollector
from osint.collectors.telegram import TelegramCollector
from osint.collectors.text import TextQueryCollector
from osint.collectors.url import UrlCollector
from osint.collectors.username import UsernameCollector
from osint.graph.builder import build_graph
from osint.models import EntityKind, Finding, ScanResult
from osint.parsers.entities import detect_entity
from osint.search.client import MultiEngineSearch, make_http_session
from osint.search.pipeline import run_deep_search_pipeline

logger = logging.getLogger(__name__)


COLLECTORS: dict[EntityKind, list[type[BaseCollector]]] = {
    EntityKind.telegram: [TelegramCollector],
    EntityKind.username: [UsernameCollector],
    EntityKind.email: [EmailCollector],
    EntityKind.phone: [PhoneCollector],
    EntityKind.domain: [DomainCollector],
    EntityKind.ip: [IpCollector],
    EntityKind.url: [UrlCollector],
    EntityKind.pdf_url: [PdfCollector],
    EntityKind.image_url: [ImageCollector],
    EntityKind.text: [TextQueryCollector],
}


async def scan_public_sources(
    query: str,
    *,
    deep: bool = False,
    premium: bool = False,
    force_kind: str | EntityKind | None = None,
    settings: Settings | None = None,
) -> ScanResult:
    settings = settings or get_settings()
    entity = detect_entity(query, settings.default_phone_region, force_kind=force_kind)
    safety = assess_query_safety(query)
    result = ScanResult(query=query, entity=entity, mode="deep" if deep else "basic")
    if not safety.allowed:
        result.status = "refused"
        result.refusal_reason = safety.reason
        result.findings.append(
            Finding(
                category="safety",
                title=t("findings.safety_refused_title"),
                source="policy",
                description=safety.reason or "",
                confidence=1.0,
            )
        )
        result.graph = build_graph(result)
        result.recompute_summary()
        result.summary["ai_summary"] = build_ai_summary(result)
        return result

    search = MultiEngineSearch(settings)
    async with make_http_session(settings) as http:
        context = CollectorContext(
            entity=entity,
            http=http,
            search=search,
            settings=settings,
            api=get_api_manager(),
            deep=deep,
            premium=premium,
        )
        collector_types = list(COLLECTORS.get(entity.kind, [TextQueryCollector]))
        if (deep or premium) and entity.kind in {EntityKind.domain, EntityKind.url}:
            collector_types.append(ArchiveCollector)

        for collector_type in collector_types:
            collector = collector_type()
            try:
                result.findings.extend(await collector.collect(context))
            except Exception as exc:
                logger.exception("Collector %s failed", collector.name)
                result.findings.append(
                    Finding(
                        category="error",
                        title=t("errors.collector_failed", collector=collector.name),
                        source=collector.name,
                        description=str(exc),
                        confidence=0.1,
                    )
                )

        pipeline = await run_deep_search_pipeline(
            entity=entity,
            query=query,
            http=http,
            search=search,
            settings=settings,
            deep=deep,
            premium=premium,
        )
        result.search_hits = pipeline.hits
        result.findings.append(pipeline.finding)
        result.timeline.extend(pipeline.timeline)

    result.graph = build_graph(result)
    result.recompute_summary()
    result.summary["ai_summary"] = build_ai_summary(result)
    return result
