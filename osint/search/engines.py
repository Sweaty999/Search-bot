from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

import aiohttp
from bs4 import BeautifulSoup

from core.api_manager import ApiManager, get_api_manager
from core.config import Settings
from osint.models import SearchHit


class SearchEngine(ABC):
    name: str
    priority: int

    def __init__(self, settings: Settings, api: ApiManager | None = None) -> None:
        self.settings = settings
        self.api = api or get_api_manager()

    @property
    @abstractmethod
    def enabled(self) -> bool:
        raise NotImplementedError

    @abstractmethod
    async def search(self, http: aiohttp.ClientSession, query: str, limit: int) -> list[SearchHit]:
        raise NotImplementedError

    async def _json(self, http: aiohttp.ClientSession, url: str, **kwargs: Any) -> dict[str, Any]:
        async with http.get(url, timeout=self.settings.http_timeout_seconds, **kwargs) as response:
            response.raise_for_status()
            return await response.json(content_type=None)


class SerpApiSearchEngine(SearchEngine):
    name = "serpapi"
    priority = 100

    @property
    def enabled(self) -> bool:
        return self.api.enabled("serpapi")

    async def search(self, http: aiohttp.ClientSession, query: str, limit: int) -> list[SearchHit]:
        payload = await self.api.get_json(
            "serpapi",
            http,
            "https://serpapi.com/search.json",
            params={
                "engine": "google",
                "q": query,
                "api_key": self.settings.serpapi_key,
                "num": min(limit, 10),
                "safe": "active",
            },
        )
        if not payload:
            return []
        organic = payload.get("organic_results", [])
        return [
            SearchHit(
                title=item.get("title", ""),
                url=item.get("link", ""),
                snippet=item.get("snippet", ""),
                engine=self.name,
            )
            for item in organic
            if item.get("link")
        ]


class GoogleCustomSearchEngine(SearchEngine):
    name = "google_cse"
    priority = 60

    @property
    def enabled(self) -> bool:
        return self.api.enabled("google_cse")

    async def search(self, http: aiohttp.ClientSession, query: str, limit: int) -> list[SearchHit]:
        payload = await self.api.get_json(
            "google_cse",
            http,
            "https://www.googleapis.com/customsearch/v1",
            params={
                "key": self.settings.google_api_key,
                "cx": self.settings.google_cse_id,
                "q": query,
                "num": min(limit, 10),
                "safe": "active",
            },
        )
        if not payload:
            return []
        return [
            SearchHit(
                title=item.get("title", ""),
                url=item.get("link", ""),
                snippet=item.get("snippet", ""),
                engine=self.name,
            )
            for item in payload.get("items", [])
            if item.get("link")
        ]


class DuckDuckGoSearchEngine(SearchEngine):
    name = "duckduckgo"
    priority = 80

    @property
    def enabled(self) -> bool:
        return self.settings.enable_duckduckgo

    async def search(self, http: aiohttp.ClientSession, query: str, limit: int) -> list[SearchHit]:
        return await _duckduckgo_html(http, self.settings, query, limit, "https://duckduckgo.com/html/", self.name)


class PublicScrapingSearchEngine(SearchEngine):
    name = "public_scraping"
    priority = 20

    @property
    def enabled(self) -> bool:
        return True

    async def search(self, http: aiohttp.ClientSession, query: str, limit: int) -> list[SearchHit]:
        return await _duckduckgo_html(http, self.settings, query, limit, "https://html.duckduckgo.com/html/", self.name)


async def _duckduckgo_html(
    http: aiohttp.ClientSession,
    settings: Settings,
    query: str,
    limit: int,
    endpoint: str,
    engine: str,
) -> list[SearchHit]:
    async with http.get(endpoint, params={"q": query}, timeout=settings.http_timeout_seconds) as response:
        response.raise_for_status()
        html = await response.text()

    soup = BeautifulSoup(html, "lxml")
    hits: list[SearchHit] = []
    for result in soup.select(".result"):
        link = result.select_one(".result__a")
        snippet = result.select_one(".result__snippet")
        if not link:
            continue
        url = _decode_duckduckgo_url(link.get("href", ""))
        if not url:
            continue
        hits.append(
            SearchHit(
                title=link.get_text(" ", strip=True),
                url=url,
                snippet=snippet.get_text(" ", strip=True) if snippet else "",
                engine=engine,
            )
        )
        if len(hits) >= limit:
            break
    return hits


def default_engines(settings: Settings) -> list[SearchEngine]:
    api = get_api_manager()
    engines: list[SearchEngine] = [
        SerpApiSearchEngine(settings, api),
        DuckDuckGoSearchEngine(settings, api),
        GoogleCustomSearchEngine(settings, api),
        PublicScrapingSearchEngine(settings, api),
    ]
    return [engine for engine in engines if engine.enabled]


def _decode_duckduckgo_url(url: str) -> str:
    if not url:
        return ""
    parsed = urlparse(url)
    if parsed.netloc.endswith("duckduckgo.com"):
        uddg = parse_qs(parsed.query).get("uddg", [""])[0]
        return unquote(uddg)
    return url
