from __future__ import annotations

import html
import os
import re
from typing import Any, Dict, Iterable, List
from urllib.error import HTTPError, URLError
from urllib.parse import quote, quote_plus
from urllib.request import Request, urlopen

from tools.analyzer import AnalysisReport, Finding, normalize_telegram_username


def _enabled(name: str, default: bool = True) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on", "y"}


def _timeout() -> float:
    try:
        return float(os.getenv("TME_WEB_TIMEOUT", os.getenv("EXTERNAL_API_TIMEOUT", "4")))
    except ValueError:
        return 4.0


def _limit() -> int:
    try:
        return int(os.getenv("TME_PREVIEW_POST_LIMIT", "5"))
    except ValueError:
        return 5


def _dedupe(values: Iterable[str]) -> List[str]:
    seen = set()
    result = []
    for value in values:
        if not value:
            continue
        key = value.lower()
        if key in seen:
            continue
        result.append(value)
        seen.add(key)
    return result


def telegram_username(raw: str) -> str | None:
    normalized = normalize_telegram_username(raw)
    if normalized:
        return normalized.lstrip("@")

    value = raw.strip().lstrip("@")
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{4,31}", value):
        return value
    return None


def telegram_links(username: str) -> Dict[str, str]:
    query = quote_plus(f'"{username}" OR "@{username}"')
    site_query = quote_plus(f'site:t.me/{username} OR site:t.me/s/{username}')
    return {
        "profile": f"https://t.me/{quote(username)}",
        "public_channel_preview": f"https://t.me/s/{quote(username)}",
        "telegram_deep_link": f"tg://resolve?domain={quote(username)}",
        "telegram_me": f"https://telegram.me/{quote(username)}",
        "tgstat": f"https://tgstat.com/channel/@{quote(username)}",
        "google_exact": f"https://www.google.com/search?q={query}",
        "google_tme": f"https://www.google.com/search?q={site_query}",
        "yandex_exact": f"https://yandex.com/search/?text={query}",
    }


def telegram_username_variants(username: str) -> List[str]:
    base = username.strip().lstrip("@")
    variants = [base, base.lower()]
    variants.append(base.replace("_", ""))
    variants.append(base.replace("__", "_"))

    without_digits = re.sub(r"\d+$", "", base)
    if without_digits and without_digits != base:
        variants.append(without_digits)
        variants.append(without_digits.lower())

    parts = [part for part in re.split(r"[_\-.]+", base) if part]
    if len(parts) > 1:
        variants.extend(["_".join(parts), "".join(parts), ".".join(parts)])

    return _dedupe([item for item in variants if 5 <= len(item) <= 32])[:12]


def _http_text(url: str) -> Dict[str, Any]:
    request = Request(
        url,
        headers={
            "Accept": "text/html,application/xhtml+xml",
            "User-Agent": "Mozilla/5.0 osint-bot/2.0 public-telegram-lookup",
        },
    )
    try:
        with urlopen(request, timeout=_timeout()) as response:
            body = response.read(1_200_000)
            charset = response.headers.get_content_charset() or "utf-8"
            return {
                "ok": True,
                "status_code": getattr(response, "status", None),
                "final_url": response.geturl(),
                "text": body.decode(charset, errors="replace"),
            }
    except HTTPError as exc:
        detail = exc.read(4000).decode("utf-8", errors="replace")
        return {"ok": False, "status_code": exc.code, "error": detail[:600]}
    except (URLError, TimeoutError, OSError) as exc:
        return {"ok": False, "error": str(exc)}


def _strip_tags(value: str) -> str:
    value = re.sub(r"<br\s*/?>", "\n", value, flags=re.IGNORECASE)
    value = re.sub(r"<[^>]+>", " ", value)
    value = html.unescape(value)
    return re.sub(r"\s+", " ", value).strip()


def _meta(markup: str, key: str) -> str | None:
    patterns = [
        rf'<meta[^>]+property=["\']{re.escape(key)}["\'][^>]+content=["\']([^"\']*)["\']',
        rf'<meta[^>]+content=["\']([^"\']*)["\'][^>]+property=["\']{re.escape(key)}["\']',
        rf'<meta[^>]+name=["\']{re.escape(key)}["\'][^>]+content=["\']([^"\']*)["\']',
        rf'<meta[^>]+content=["\']([^"\']*)["\'][^>]+name=["\']{re.escape(key)}["\']',
    ]
    for pattern in patterns:
        match = re.search(pattern, markup, re.IGNORECASE | re.DOTALL)
        if match:
            return html.unescape(match.group(1)).strip()
    return None


def _class_text(markup: str, class_name: str) -> str | None:
    pattern = rf'<[^>]+class=["\'][^"\']*{re.escape(class_name)}[^"\']*["\'][^>]*>(.*?)</[^>]+>'
    match = re.search(pattern, markup, re.IGNORECASE | re.DOTALL)
    if not match:
        return None
    return _strip_tags(match.group(1))


def inspect_tme_profile(username: str) -> Dict[str, Any]:
    url = f"https://t.me/{quote(username)}"
    result = _http_text(url)
    if not result.get("ok"):
        return {"url": url, **result}

    markup = result.pop("text")
    title = _meta(markup, "og:title") or _class_text(markup, "tgme_page_title")
    description = _meta(markup, "og:description") or _class_text(markup, "tgme_page_description")
    extra = _class_text(markup, "tgme_page_extra")
    action = _class_text(markup, "tgme_page_action")

    flags = []
    lowered = markup.lower()
    if "tgme_page_icon" in lowered:
        flags.append("has_avatar_or_icon")
    if "tgme_page_photo" in lowered:
        flags.append("has_photo")
    if "tgme_page_context_link" in lowered:
        flags.append("has_context_link")
    if "username is not available" in lowered or "tgme_page_icon_user" in lowered and not title:
        flags.append("not_found_or_unavailable")

    return {
        "url": url,
        "ok": True,
        "status_code": result.get("status_code"),
        "final_url": result.get("final_url"),
        "title": title,
        "description": description,
        "extra": extra,
        "action": action,
        "image": _meta(markup, "og:image"),
        "flags": flags,
    }


def inspect_tme_channel_preview(username: str) -> Dict[str, Any]:
    url = f"https://t.me/s/{quote(username)}"
    result = _http_text(url)
    if not result.get("ok"):
        return {"url": url, **result}

    markup = result.pop("text")
    post_ids = re.findall(r'data-post=["\']([^"\']+)["\']', markup, re.IGNORECASE)
    dates = re.findall(r'<time[^>]+datetime=["\']([^"\']+)["\']', markup, re.IGNORECASE)
    text_blocks = re.findall(
        r'<div[^>]+class=["\'][^"\']*tgme_widget_message_text[^"\']*["\'][^>]*>(.*?)</div>',
        markup,
        re.IGNORECASE | re.DOTALL,
    )

    posts = []
    for index, post_id in enumerate(post_ids[: _limit()]):
        posts.append(
            {
                "post": post_id,
                "date": dates[index] if index < len(dates) else None,
                "text_preview": _strip_tags(text_blocks[index])[:700] if index < len(text_blocks) else "",
            }
        )

    return {
        "url": url,
        "ok": True,
        "status_code": result.get("status_code"),
        "final_url": result.get("final_url"),
        "public_posts_found": len(post_ids),
        "posts_sample": posts,
        "note": "t.me/s показывает только публичное веб-превью каналов, если оно доступно.",
    }


def _targets(report: AnalysisReport) -> List[str]:
    values = []
    for indicator in report.indicators:
        if indicator.kind == "telegram" and indicator.valid:
            values.append(indicator.normalized)
        elif indicator.kind == "username" and indicator.valid:
            values.append(indicator.normalized)
    return _dedupe([value for value in values if telegram_username(value)])


def enrich_with_telegram_utilities(report: AnalysisReport) -> None:
    for target in _targets(report):
        username = telegram_username(target)
        if not username:
            continue

        links = telegram_links(username)
        variants = telegram_username_variants(username)
        report.findings.append(
            Finding(
                source="telegram_tools",
                title="Telegram OSINT-навигация",
                level="info",
                details={
                    "username": f"@{username}",
                    "links": links,
                    "username_variants": variants,
                    "safe_note": "Это одиночная проверка публичных страниц и ссылок, без массового перебора аккаунтов.",
                },
            )
        )

        if _enabled("ENABLE_TME_WEB_LOOKUP", True):
            profile = inspect_tme_profile(username)
            report.findings.append(
                Finding(
                    source="telegram_web",
                    title="Публичная t.me-страница",
                    level="info" if profile.get("ok") else "warning",
                    details={"target": f"@{username}", **profile},
                )
            )

        if _enabled("ENABLE_TME_CHANNEL_PREVIEW", True):
            preview = inspect_tme_channel_preview(username)
            report.findings.append(
                Finding(
                    source="telegram_channel_preview",
                    title="Публичное веб-превью канала",
                    level="info" if preview.get("public_posts_found") else "warning",
                    details={"target": f"@{username}", **preview},
                )
            )


def format_telegram_links_text(raw: str) -> str:
    username = telegram_username(raw)
    if not username:
        return "Не похоже на Telegram username. Пример: /tglinks @username"

    links = telegram_links(username)
    variants = telegram_username_variants(username)
    lines = [
        f"<b>Telegram ссылки для @{html.escape(username)}</b>",
        f"Профиль: {html.escape(links['profile'])}",
        f"Публичное превью: {html.escape(links['public_channel_preview'])}",
        f"Deep link: <code>{html.escape(links['telegram_deep_link'])}</code>",
        "",
        "<b>Поиск:</b>",
        html.escape(links["google_exact"]),
        html.escape(links["google_tme"]),
        html.escape(links["yandex_exact"]),
        "",
        "<b>Варианты username:</b> " + html.escape(", ".join(variants)),
    ]
    return "\n".join(lines)
