from __future__ import annotations

import asyncio

from bs4 import BeautifulSoup

from osint.collectors.base import BaseCollector, CollectorContext
from osint.models import Entity, EntityKind, Finding
from osint.parsers.html import extract_page_metadata


SOCIAL_PLATFORMS: dict[str, str] = {
    "Telegram": "https://t.me/{username}",
    "GitHub": "https://github.com/{username}",
    "Reddit": "https://www.reddit.com/user/{username}",
    "TikTok": "https://www.tiktok.com/@{username}",
    "Instagram": "https://www.instagram.com/{username}/",
    "Facebook": "https://www.facebook.com/{username}",
    "Pinterest": "https://www.pinterest.com/{username}/",
    "Steam": "https://steamcommunity.com/id/{username}",
    "Twitch": "https://www.twitch.tv/{username}",
    "YouTube": "https://www.youtube.com/@{username}",
    "GitLab": "https://gitlab.com/{username}",
    "Medium": "https://medium.com/@{username}",
    "SoundCloud": "https://soundcloud.com/{username}",
    "Vimeo": "https://vimeo.com/{username}",
    "Behance": "https://www.behance.net/{username}",
    "DeviantArt": "https://www.deviantart.com/{username}",
}


class UsernameCollector(BaseCollector):
    name = "username"

    async def collect(self, context: CollectorContext) -> list[Finding]:
        username = context.entity.normalized.lstrip("@")
        profiles: list[dict[str, object]] = [
            {"platform": platform, "url": template.format(username=username), "status": None}
            for platform, template in SOCIAL_PLATFORMS.items()
        ]

        semaphore = asyncio.Semaphore(6)
        await asyncio.gather(*[_check_profile(context, profile, username, semaphore) for profile in profiles])

        entities = [
            Entity(
                kind=EntityKind.url,
                value=profile["url"],
                normalized=profile["url"],
                confidence=float(profile.get("confidence") or 0.35),
                metadata={"platform": profile["platform"]},
            )
            for profile in profiles
        ]
        findings = [
            Finding(
                category="social_profiles",
                title="Candidate public social profiles",
                source=self.name,
                confidence=max([float(profile.get("confidence") or 0.0) for profile in profiles], default=0.55),
                data={"profiles": profiles},
                entities=entities,
            )
        ]

        if context.deep or context.premium:
            hits = await context.search.search(context.http, f'"{username}"', limit=10)
            findings.append(
                Finding(
                    category="public_mentions",
                    title="Username public mentions",
                    source="multi_engine_search",
                    confidence=0.65 if hits else 0.2,
                    data={"hits": [hit.model_dump() for hit in hits]},
                )
            )
        return findings


async def _check_profile(
    context: CollectorContext,
    profile: dict[str, object],
    username: str,
    semaphore: asyncio.Semaphore,
) -> None:
    async with semaphore:
        try:
            async with context.http.get(str(profile["url"]), allow_redirects=True) as response:
                profile["status"] = response.status
                profile["final_url"] = str(response.url)
                html = await response.text(errors="ignore")
        except Exception as exc:
            profile["error"] = str(exc)
            profile["confidence"] = 0.15
            return

    metadata = extract_page_metadata(html[:250_000], str(profile.get("final_url") or profile["url"]))
    soup = BeautifulSoup(html or "", "lxml")
    profile["title"] = metadata.get("title")
    profile["description"] = metadata.get("description") or metadata.get("og_description")
    profile["avatar"] = metadata.get("og_image")
    profile["favicon"] = metadata.get("favicon")
    profile["links"] = _public_links(soup, str(profile.get("final_url") or profile["url"]))
    profile["bio"] = _public_bio(soup)
    profile["confidence"] = _profile_confidence(profile, username)


def _public_links(soup: BeautifulSoup, base_url: str) -> list[str]:
    from urllib.parse import urljoin

    links: list[str] = []
    for tag in soup.find_all("a", href=True)[:80]:
        href = urljoin(base_url, str(tag["href"]))
        if href.startswith(("http://", "https://")):
            links.append(href)
    return sorted(set(links))[:20]


def _public_bio(soup: BeautifulSoup) -> str:
    for selector in ('meta[name="description"]', 'meta[property="og:description"]'):
        tag = soup.select_one(selector)
        if tag and tag.get("content"):
            return str(tag["content"])[:500]
    for selector in ("[data-testid='UserDescription']", ".user-profile-bio", ".p-note", "header p"):
        tag = soup.select_one(selector)
        if tag:
            text = tag.get_text(" ", strip=True)
            if text:
                return text[:500]
    return ""


def _profile_confidence(profile: dict[str, object], username: str) -> float:
    status = int(profile.get("status") or 0)
    final_url = str(profile.get("final_url") or profile.get("url") or "").casefold()
    title = str(profile.get("title") or "").casefold()
    score = 0.2
    if status in {200, 301, 302}:
        score += 0.35
    if username.casefold() in final_url:
        score += 0.18
    if username.casefold() in title:
        score += 0.12
    if profile.get("avatar"):
        score += 0.08
    if profile.get("bio"):
        score += 0.07
    return round(min(score, 0.96), 2)
