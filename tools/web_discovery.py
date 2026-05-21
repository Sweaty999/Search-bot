from __future__ import annotations

from typing import Dict, List
from urllib.parse import quote, quote_plus

from tools.analyzer import AnalysisReport, Finding


def _search_links(query: str) -> Dict[str, str]:
    encoded = quote_plus(query)
    return {
        "google": f"https://www.google.com/search?q={encoded}",
        "bing": f"https://www.bing.com/search?q={encoded}",
        "duckduckgo": f"https://duckduckgo.com/?q={encoded}",
        "yandex": f"https://yandex.com/search/?text={encoded}",
    }


def _domain_links(domain: str) -> Dict[str, str]:
    quoted = quote(domain)
    return {
        "website": f"https://{quoted}",
        "rdap": f"https://rdap.org/domain/{quoted}",
        "crtsh": f"https://crt.sh/?q=%25.{quoted}",
        "urlscan_search": f"https://urlscan.io/search/#{quote_plus('domain:' + domain)}",
        "virustotal": f"https://www.virustotal.com/gui/domain/{quoted}",
        "securitytrails": f"https://securitytrails.com/domain/{quoted}/dns",
        "dnsdumpster": "https://dnsdumpster.com/",
        **_search_links(f'"{domain}"'),
    }


def _ip_links(ip: str) -> Dict[str, str]:
    quoted = quote(ip)
    return {
        "rdap": f"https://rdap.org/ip/{quoted}",
        "virustotal": f"https://www.virustotal.com/gui/ip-address/{quoted}",
        "abuseipdb": f"https://www.abuseipdb.com/check/{quoted}",
        "shodan": f"https://www.shodan.io/host/{quoted}",
        "censys": f"https://search.censys.io/hosts/{quoted}",
        "bgp_he": f"https://bgp.he.net/ip/{quoted}",
        **_search_links(f'"{ip}"'),
    }


def _url_links(url: str) -> Dict[str, str]:
    return {
        "urlscan_search": f"https://urlscan.io/search/#{quote_plus(url)}",
        "virustotal": f"https://www.virustotal.com/gui/search/{quote_plus(url)}",
        "google_exact": f"https://www.google.com/search?q={quote_plus(url)}",
        "bing_exact": f"https://www.bing.com/search?q={quote_plus(url)}",
    }


def _telegram_links(username: str) -> Dict[str, str]:
    username = username.lstrip("@")
    quoted = quote(username)
    exact = quote_plus(f'"{username}" OR "@{username}"')
    return {
        "profile": f"https://t.me/{quoted}",
        "channel_preview": f"https://t.me/s/{quoted}",
        "tgstat": f"https://tgstat.com/channel/@{quoted}",
        "google_exact": f"https://www.google.com/search?q={exact}",
        "google_tme": f"https://www.google.com/search?q={quote_plus('site:t.me/' + username + ' OR site:t.me/s/' + username)}",
        "yandex_exact": f"https://yandex.com/search/?text={exact}",
    }


def _username_links(username: str) -> Dict[str, str]:
    quoted = quote(username)
    exact = quote_plus(f'"{username}"')
    return {
        "telegram": f"https://t.me/{quoted}",
        "github": f"https://github.com/{quoted}",
        "x_twitter": f"https://x.com/{quoted}",
        "instagram": f"https://www.instagram.com/{quoted}/",
        "tiktok": f"https://www.tiktok.com/@{quoted}",
        "reddit": f"https://www.reddit.com/user/{quoted}",
        "youtube": f"https://www.youtube.com/@{quoted}",
        "google_exact": f"https://www.google.com/search?q={exact}",
        "bing_exact": f"https://www.bing.com/search?q={exact}",
    }


def _email_links(email: str) -> Dict[str, str]:
    _local, domain = email.rsplit("@", 1)
    exact_email = quote_plus(f'"{email}"')
    return {
        "domain_rdap": f"https://rdap.org/domain/{quote(domain)}",
        "domain_crtsh": f"https://crt.sh/?q=%25.{quote(domain)}",
        "domain_search": f"https://www.google.com/search?q={quote_plus(domain)}",
        "email_exact_search": f"https://www.google.com/search?q={exact_email}",
    }


def _phone_note() -> Dict[str, str]:
    return {
        "privacy_note": "По номеру бот не строит ссылки для поиска владельца. Показываются только технические метаданные номера и источники, где есть законное основание для проверки.",
    }


def _links_for(kind: str, normalized: str) -> Dict[str, str]:
    if kind == "domain":
        return _domain_links(normalized)
    if kind == "ip":
        return _ip_links(normalized)
    if kind == "url":
        return _url_links(normalized)
    if kind == "telegram":
        return _telegram_links(normalized)
    if kind == "username":
        return _username_links(normalized)
    if kind == "email":
        return _email_links(normalized)
    if kind == "phone":
        return _phone_note()
    return _search_links(f'"{normalized}"')


def enrich_with_web_discovery(report: AnalysisReport) -> None:
    pivots: List[Dict[str, object]] = []
    for indicator in report.indicators:
        if not indicator.valid or indicator.kind == "unknown":
            continue
        pivots.append(
            {
                "kind": indicator.kind,
                "target": indicator.normalized,
                "links": _links_for(indicator.kind, indicator.normalized),
            }
        )

    if not pivots:
        return

    report.findings.append(
        Finding(
            source="web_discovery",
            title="Публичные OSINT-пивоты в интернете",
            level="info",
            details={
                "pivots": pivots,
                "note": "Это ссылки на публичные источники и поисковые запросы. Бот не обходит доступ и не извлекает скрытые персональные данные.",
            },
        )
    )
