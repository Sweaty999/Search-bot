from __future__ import annotations

from urllib.parse import urljoin
import warnings

from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning


def extract_page_metadata(html: str, base_url: str) -> dict[str, object]:
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
        soup = BeautifulSoup(html or "", "lxml")
    title = soup.title.get_text(" ", strip=True) if soup.title else ""

    def meta(*names: str) -> str:
        for name in names:
            tag = soup.find("meta", attrs={"name": name}) or soup.find("meta", attrs={"property": name})
            if tag and tag.get("content"):
                return str(tag["content"]).strip()
        return ""

    favicon = ""
    icon = soup.find("link", rel=lambda value: value and "icon" in value)
    if icon and icon.get("href"):
        favicon = urljoin(base_url, str(icon["href"]))

    socials: set[str] = set()
    social_hosts = (
        "twitter.com",
        "x.com",
        "facebook.com",
        "instagram.com",
        "linkedin.com",
        "youtube.com",
        "tiktok.com",
        "github.com",
        "reddit.com",
        "pinterest.com",
    )
    for link in soup.find_all("a", href=True):
        href = urljoin(base_url, str(link["href"]))
        if any(host in href for host in social_hosts):
            socials.add(href)

    technologies = []
    generator = meta("generator")
    if generator:
        technologies.append(generator)
    for script in soup.find_all("script", src=True):
        src = str(script["src"]).lower()
        if "wp-content" in src:
            technologies.append("WordPress")
        if "cdn.shopify" in src:
            technologies.append("Shopify")
        if "react" in src:
            technologies.append("React")

    return {
        "title": title,
        "description": meta("description", "og:description"),
        "og_title": meta("og:title"),
        "og_image": meta("og:image"),
        "favicon": favicon,
        "linked_socials": sorted(socials),
        "technologies": sorted(set(technologies)),
    }
