from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

import aiohttp

from core.config import Settings
from core.api_manager import ApiManager
from core.validators import is_public_http_url
from osint.models import Entity, Finding
from osint.search.client import MultiEngineSearch


@dataclass(slots=True)
class CollectorContext:
    entity: Entity
    http: aiohttp.ClientSession
    search: MultiEngineSearch
    settings: Settings
    api: ApiManager
    deep: bool = False
    premium: bool = False


@dataclass(slots=True)
class FetchResult:
    url: str
    status: int
    headers: dict[str, str]
    text: str | None = None
    body: bytes | None = None


class BaseCollector(ABC):
    name: str

    @abstractmethod
    async def collect(self, context: CollectorContext) -> list[Finding]:
        raise NotImplementedError


async def fetch_text(context: CollectorContext, url: str, max_chars: int = 250_000) -> FetchResult | None:
    if not is_public_http_url(url):
        return None
    async with context.http.get(url, allow_redirects=True) as response:
        text = await response.text(errors="ignore")
        return FetchResult(
            url=str(response.url),
            status=response.status,
            headers={str(key): str(value) for key, value in response.headers.items()},
            text=text[:max_chars],
        )


async def fetch_bytes(context: CollectorContext, url: str, max_bytes: int = 8_000_000) -> FetchResult | None:
    if not is_public_http_url(url):
        return None
    async with context.http.get(url, allow_redirects=True) as response:
        body = await response.content.read(max_bytes + 1)
        if len(body) > max_bytes:
            body = body[:max_bytes]
        return FetchResult(
            url=str(response.url),
            status=response.status,
            headers={str(key): str(value) for key, value in response.headers.items()},
            body=body,
        )


def compact_dict(data: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in data.items() if value not in (None, "", [], {})}
