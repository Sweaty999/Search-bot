from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass
from typing import Any

import aiohttp

from core.config import Settings, get_settings

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class ApiProvider:
    name: str
    key_name: str | None
    enabled: bool
    fallback: bool = False


@dataclass(slots=True)
class CachedResponse:
    value: dict[str, Any]
    expires_at: float


@dataclass(slots=True)
class ProviderHealth:
    last_status: str = "not_tested"
    last_error: str | None = None
    last_response_ms: float | None = None
    rate_limited_until: float | None = None
    checked_at: float | None = None


class ApiManager:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._cache: dict[str, CachedResponse] = {}
        self._bad_until: dict[str, float] = {}
        self._health: dict[str, ProviderHealth] = {}

    def providers(self) -> list[ApiProvider]:
        return [
            ApiProvider("SerpAPI", "SERPAPI_KEY", bool(self.settings.serpapi_key)),
            ApiProvider("Google CSE", "GOOGLE_API_KEY + GOOGLE_CSE_ID", bool(self.settings.google_api_key and self.settings.google_cse_id)),
            ApiProvider("IPInfo", "IPINFO_TOKEN", bool(self.settings.ipinfo_token)),
            ApiProvider("Shodan", "SHODAN_API_KEY", bool(self.settings.shodan_api_key)),
            ApiProvider("Abstract Email", "ABSTRACT_API_KEY", bool(self.settings.abstract_api_key)),
            ApiProvider("VirusTotal", "VT_API_KEY", bool(self.settings.vt_api_key)),
            ApiProvider("DuckDuckGo fallback", None, True, fallback=True),
            ApiProvider("crt.sh fallback", None, True, fallback=True),
            ApiProvider("Wayback fallback", None, True, fallback=True),
        ]

    def startup_status_text(self) -> str:
        lines = ["[API STATUS]"]
        for provider in self.providers():
            status = "ENABLED" if provider.enabled else "MISSING"
            if provider.fallback:
                status = "ENABLED"
            lines.append(f"{provider.name}: {status}")
        return "\n".join(lines)

    def diagnostics(self) -> dict[str, Any]:
        providers = []
        now = time.time()
        for provider in self.providers():
            key = _provider_key(provider.name)
            health = self._health.get(key, ProviderHealth())
            providers.append(
                {
                    "name": provider.name,
                    "enabled": provider.enabled,
                    "fallback": provider.fallback,
                    "key_name": provider.key_name,
                    "last_status": health.last_status,
                    "last_error": health.last_error,
                    "last_response_ms": health.last_response_ms,
                    "rate_limited": bool(health.rate_limited_until and health.rate_limited_until > now),
                }
            )
        return {"providers": providers, "cache_entries": len(self._cache)}

    def reset_provider_health(self, provider: str | None = None) -> None:
        if provider:
            key = provider.casefold()
            self._bad_until.pop(key, None)
            self._health.pop(key, None)
            return
        self._bad_until.clear()
        self._health.clear()

    def log_startup_status(self) -> None:
        logger.info("\n%s", self.startup_status_text())
        for provider in self.providers():
            if not provider.enabled and not provider.fallback:
                logger.warning("%s missing; related intelligence will use fallback logic.", provider.key_name)

    def enabled(self, provider: str) -> bool:
        provider = provider.casefold()
        return {
            "serpapi": bool(self.settings.serpapi_key),
            "google_cse": bool(self.settings.google_api_key and self.settings.google_cse_id),
            "ipinfo": bool(self.settings.ipinfo_token),
            "shodan": bool(self.settings.shodan_api_key),
            "abstract": bool(self.settings.abstract_api_key),
            "virustotal": bool(self.settings.vt_api_key),
        }.get(provider, False) and not self._temporarily_disabled(provider)

    async def get_json(
        self,
        provider: str,
        http: aiohttp.ClientSession,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        ttl_seconds: int | None = None,
    ) -> dict[str, Any] | None:
        provider_key = provider.casefold()
        if self._temporarily_disabled(provider_key):
            logger.warning("%s is temporarily disabled after previous provider error.", provider)
            return None

        cache_key = self._cache_key(provider_key, url, params or {})
        cached = self._cache.get(cache_key)
        now = time.time()
        if cached and cached.expires_at > now:
            return cached.value

        try:
            start = time.perf_counter()
            async with http.get(url, params=params, headers=headers, timeout=self.settings.http_timeout_seconds) as response:
                elapsed = round((time.perf_counter() - start) * 1000, 2)
                if response.status in {401, 403}:
                    logger.warning("%s API key is invalid or unauthorized.", provider)
                    self._bad_until[provider_key] = now + 600
                    self._record_health(provider_key, "invalid", response.status, elapsed, "invalid_or_unauthorized")
                    return None
                if response.status == 429:
                    logger.warning("%s API is rate limited; switching provider/fallback.", provider)
                    self._bad_until[provider_key] = now + 120
                    self._record_health(provider_key, "rate_limited", response.status, elapsed, "rate_limited")
                    return None
                if response.status >= 400:
                    logger.warning("%s API returned HTTP %s.", provider, response.status)
                    self._record_health(provider_key, "error", response.status, elapsed, f"http_{response.status}")
                    return None
                payload = await response.json(content_type=None)
        except Exception as exc:
            logger.warning("%s API request failed: %s", provider, exc)
            self._record_health(provider_key, "error", None, None, str(exc))
            return None

        value = payload if isinstance(payload, dict) else {"items": payload}
        self._cache[cache_key] = CachedResponse(value=value, expires_at=now + (ttl_seconds or self.settings.cache_ttl_seconds))
        self._record_health(provider_key, "ok", 200, elapsed, None)
        return value

    async def test_providers(self, http: aiohttp.ClientSession) -> dict[str, Any]:
        tests: dict[str, dict[str, Any] | None] = {}
        if self.enabled("serpapi"):
            tests["serpapi"] = await self.get_json(
                "serpapi",
                http,
                "https://serpapi.com/search.json",
                params={"engine": "google", "q": "osint", "api_key": self.settings.serpapi_key, "num": 1},
                ttl_seconds=60,
            )
        if self.enabled("google_cse"):
            tests["google_cse"] = await self.get_json(
                "google_cse",
                http,
                "https://www.googleapis.com/customsearch/v1",
                params={"key": self.settings.google_api_key, "cx": self.settings.google_cse_id, "q": "osint", "num": 1},
                ttl_seconds=60,
            )
        if self.enabled("ipinfo"):
            tests["ipinfo"] = await self.get_json(
                "ipinfo",
                http,
                "https://ipinfo.io/8.8.8.8/json",
                params={"token": self.settings.ipinfo_token},
                ttl_seconds=60,
            )
        if self.enabled("shodan"):
            tests["shodan"] = await self.get_json(
                "shodan",
                http,
                "https://api.shodan.io/api-info",
                params={"key": self.settings.shodan_api_key},
                ttl_seconds=60,
            )
        if self.enabled("abstract"):
            tests["abstract"] = await self.get_json(
                "abstract",
                http,
                "https://emailvalidation.abstractapi.com/v1/",
                params={"api_key": self.settings.abstract_api_key, "email": "test@example.com"},
                ttl_seconds=60,
            )
        if self.enabled("virustotal"):
            tests["virustotal"] = await self.get_json(
                "virustotal",
                http,
                "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
                headers={"x-apikey": self.settings.vt_api_key or ""},
                ttl_seconds=60,
            )
        return {"tested": list(tests), "diagnostics": self.diagnostics()}

    def _temporarily_disabled(self, provider: str) -> bool:
        until = self._bad_until.get(provider)
        return bool(until and until > time.time())

    def _record_health(
        self,
        provider: str,
        status: str,
        http_status: int | None,
        response_ms: float | None,
        error: str | None,
    ) -> None:
        self._health[provider] = ProviderHealth(
            last_status=status if http_status is None else f"{status}:{http_status}",
            last_error=error,
            last_response_ms=response_ms,
            rate_limited_until=self._bad_until.get(provider),
            checked_at=time.time(),
        )

    @staticmethod
    def _cache_key(provider: str, url: str, params: dict[str, Any]) -> str:
        raw = json.dumps({"provider": provider, "url": url, "params": params}, sort_keys=True, default=str)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


_api_manager: ApiManager | None = None


def get_api_manager() -> ApiManager:
    global _api_manager
    if _api_manager is None:
        _api_manager = ApiManager()
    return _api_manager


def _provider_key(name: str) -> str:
    return {
        "SerpAPI": "serpapi",
        "Google CSE": "google_cse",
        "IPInfo": "ipinfo",
        "Shodan": "shodan",
        "Abstract Email": "abstract",
        "VirusTotal": "virustotal",
    }.get(name, name.casefold())
