from __future__ import annotations

import dataclasses
import ipaddress
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import parse_qsl, urlparse

try:
    import phonenumbers
    from phonenumbers import carrier, geocoder, timezone as phone_timezone
except ImportError:  # pragma: no cover - useful message is returned at runtime.
    phonenumbers = None
    carrier = None
    geocoder = None
    phone_timezone = None

from tools.dns_utils import inspect_domain_dns, inspect_email_domain


EMAIL_RE = re.compile(r"(?<![\w.+-])([A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,63})(?![\w.+-])")
PHONE_RE = re.compile(r"(?<!\w)(\+?\d[\d\s().-]{7,}\d)(?!\w)")
URL_RE = re.compile(r"\b(?:https?://|www\.)[^\s<>()\"']+", re.IGNORECASE)
DOMAIN_RE = re.compile(r"(?<![@\w.-])((?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63})(?![\w.-])")
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
URL_TG_RE = re.compile(r"(?:https?://)?(?:t\.me|telegram\.me)/(?:s/)?([A-Za-z][A-Za-z0-9_]{4,31})", re.IGNORECASE)
TG_MENTION_RE = re.compile(r"(?<![\w@])@[A-Za-z][A-Za-z0-9_]{4,31}\b")
USERNAME_RE = re.compile(r"@?([A-Za-z][A-Za-z0-9_.-]{2,31})$")

TRACKING_QUERY_KEYS = {
    "fbclid",
    "gclid",
    "mc_cid",
    "mc_eid",
    "utm_campaign",
    "utm_content",
    "utm_medium",
    "utm_source",
    "utm_term",
}


@dataclasses.dataclass
class Indicator:
    kind: str
    raw: str
    normalized: str
    valid: bool
    metadata: Dict[str, Any]


@dataclasses.dataclass
class Finding:
    source: str
    title: str
    level: str
    details: Dict[str, Any]


@dataclasses.dataclass
class AnalysisReport:
    query: str
    generated_at: str
    indicators: List[Indicator]
    findings: List[Finding]


def _phone_type_name(value: int) -> str:
    if phonenumbers is None:
        return "unknown"

    mapping = {
        phonenumbers.PhoneNumberType.FIXED_LINE: "fixed_line",
        phonenumbers.PhoneNumberType.MOBILE: "mobile",
        phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed_line_or_mobile",
        phonenumbers.PhoneNumberType.TOLL_FREE: "toll_free",
        phonenumbers.PhoneNumberType.PREMIUM_RATE: "premium_rate",
        phonenumbers.PhoneNumberType.SHARED_COST: "shared_cost",
        phonenumbers.PhoneNumberType.VOIP: "voip",
        phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "personal_number",
        phonenumbers.PhoneNumberType.PAGER: "pager",
        phonenumbers.PhoneNumberType.UAN: "uan",
        phonenumbers.PhoneNumberType.VOICEMAIL: "voicemail",
        phonenumbers.PhoneNumberType.UNKNOWN: "unknown",
    }
    return mapping.get(value, "unknown")


def _unique(values: Iterable[str]) -> List[str]:
    seen = set()
    result = []
    for value in values:
        value = value.strip().strip(".,;:()[]{}<>\"'")
        if not value:
            continue
        key = value.lower()
        if key not in seen:
            result.append(value)
            seen.add(key)
    return result


def _is_valid_domain(domain: str) -> bool:
    labels = domain.rstrip(".").split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if not re.fullmatch(r"[A-Za-z0-9-]+", label):
            return False
    return bool(re.fullmatch(r"[A-Za-z]{2,63}", labels[-1]))


def _url_normalized(raw: str) -> str:
    value = raw.strip().strip(".,;:()[]{}<>\"'")
    if value.lower().startswith("www."):
        value = f"https://{value}"
    return value


def _url_host(raw: str) -> str | None:
    parsed = urlparse(_url_normalized(raw))
    host = parsed.hostname
    return host.lower() if host else None


def _email_spans(text: str) -> List[tuple[int, int]]:
    return [(match.start(), match.end()) for match in EMAIL_RE.finditer(text)]


def _inside_any_span(position: int, spans: List[tuple[int, int]]) -> bool:
    return any(start <= position < end for start, end in spans)


def analyze_phone(raw: str, default_region: str) -> Indicator:
    cleaned = re.sub(r"[^\d+]", "", raw)
    metadata: Dict[str, Any] = {"input": raw, "cleaned": cleaned}

    if phonenumbers is None:
        metadata["error"] = "Установи phonenumbers, чтобы разбирать номера телефонов."
        return Indicator("phone", raw, cleaned, False, metadata)

    try:
        parsed = phonenumbers.parse(cleaned, default_region.upper())
    except Exception as exc:
        metadata["error"] = str(exc)
        return Indicator("phone", raw, cleaned, False, metadata)

    possible = phonenumbers.is_possible_number(parsed)
    valid = phonenumbers.is_valid_number(parsed)
    normalized = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    region_code = phonenumbers.region_code_for_number(parsed)
    number_type = phonenumbers.number_type(parsed)

    metadata.update(
        {
            "e164": normalized,
            "international": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "national": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
            "country_code": parsed.country_code,
            "region_code": region_code,
            "possible": possible,
            "valid": valid,
            "type": _phone_type_name(number_type),
            "carrier": carrier.name_for_number(parsed, "ru") if carrier else "",
            "location": geocoder.description_for_number(parsed, "ru") if geocoder else "",
            "timezones": list(phone_timezone.time_zones_for_number(parsed)) if phone_timezone else [],
            "privacy_note": "Это технические метаданные формата номера, а не данные владельца.",
        }
    )
    return Indicator("phone", raw, normalized, bool(valid), metadata)


def analyze_email(raw: str) -> Indicator:
    local, domain = raw.rsplit("@", 1)
    normalized = f"{local}@{domain.lower()}"
    metadata: Dict[str, Any] = {
        "local_part_length": len(local),
        "domain": domain.lower(),
        "domain_length": len(domain),
        "looks_like_role_account": local.lower() in {"admin", "info", "support", "sales", "contact", "security", "abuse"},
    }

    valid = bool(EMAIL_RE.fullmatch(raw))
    metadata.update(inspect_email_domain(domain.lower()))
    return Indicator("email", raw, normalized, valid, metadata)


def analyze_ip(raw: str) -> Indicator:
    value = raw.strip().strip("[]")
    metadata: Dict[str, Any] = {"input": raw}

    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        metadata["error"] = str(exc)
        return Indicator("ip", raw, value, False, metadata)

    metadata.update(
        {
            "version": address.version,
            "compressed": address.compressed,
            "exploded": address.exploded,
            "is_global": address.is_global,
            "is_private": address.is_private,
            "is_reserved": address.is_reserved,
            "is_loopback": address.is_loopback,
            "is_multicast": address.is_multicast,
            "reverse_pointer": address.reverse_pointer,
        }
    )
    return Indicator("ip", raw, address.compressed, True, metadata)


def analyze_domain(raw: str, observed_in: List[str] | None = None) -> Indicator:
    normalized = raw.lower().strip().strip(".")
    valid = _is_valid_domain(normalized)
    metadata: Dict[str, Any] = {
        "domain": normalized,
        "labels": normalized.split(".") if normalized else [],
        "tld": normalized.rsplit(".", 1)[-1] if "." in normalized else "",
        "observed_in": observed_in or ["text"],
        "syntax_valid": valid,
    }
    if valid:
        metadata.update(inspect_domain_dns(normalized))
    return Indicator("domain", raw, normalized, valid, metadata)


def analyze_url(raw: str) -> Indicator:
    normalized = _url_normalized(raw)
    parsed = urlparse(normalized)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    query_keys = [key for key, _value in query_pairs]
    tracking_keys = sorted({key for key in query_keys if key.lower() in TRACKING_QUERY_KEYS})
    suspicious_flags = []

    if parsed.username or parsed.password:
        suspicious_flags.append("url_contains_credentials")
    if parsed.scheme not in {"http", "https"}:
        suspicious_flags.append("unexpected_scheme")
    if parsed.hostname:
        try:
            ipaddress.ip_address(parsed.hostname.strip("[]"))
            suspicious_flags.append("host_is_ip_address")
        except ValueError:
            pass
    if len(parsed.netloc) > 80:
        suspicious_flags.append("very_long_host")

    metadata = {
        "scheme": parsed.scheme,
        "host": parsed.hostname.lower() if parsed.hostname else None,
        "port": parsed.port,
        "path": parsed.path or "/",
        "path_depth": len([part for part in parsed.path.split("/") if part]),
        "query_keys": query_keys[:30],
        "query_parameter_count": len(query_pairs),
        "tracking_query_keys": tracking_keys,
        "has_fragment": bool(parsed.fragment),
        "suspicious_flags": suspicious_flags,
    }
    valid = parsed.scheme in {"http", "https"} and bool(parsed.hostname)
    return Indicator("url", raw, normalized, valid, metadata)


def normalize_telegram_username(raw: str) -> Optional[str]:
    value = raw.strip()
    url_match = URL_TG_RE.search(value)
    if url_match:
        value = url_match.group(1)
    value = value.lstrip("@")
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{4,31}", value):
        return f"@{value}"
    return None


def analyze_telegram(raw: str) -> Indicator:
    normalized = normalize_telegram_username(raw) or raw
    username = normalized.lstrip("@")
    valid = normalized.startswith("@") and 5 <= len(username) <= 32
    return Indicator(
        "telegram",
        raw,
        normalized,
        valid,
        {
            "username": username,
            "public_url": f"https://t.me/{username}" if valid else None,
            "public_channel_preview_url": f"https://t.me/s/{username}" if valid else None,
            "telegram_deep_link": f"tg://resolve?domain={username}" if valid else None,
            "syntax_valid": valid,
            "note": "Bot API видит только публичные или доступные этому боту Telegram-объекты. Глобального поиска приватных пользователей в Bot API нет.",
        },
    )


def analyze_username(raw: str) -> Indicator:
    username = raw.strip().lstrip("@")
    valid = bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{2,31}", username))
    links = {
        "telegram": f"https://t.me/{username}",
        "telegram_channel_preview": f"https://t.me/s/{username}",
        "github": f"https://github.com/{username}",
        "x_twitter": f"https://x.com/{username}",
        "instagram": f"https://www.instagram.com/{username}/",
        "tiktok": f"https://www.tiktok.com/@{username}",
        "reddit": f"https://www.reddit.com/user/{username}",
        "youtube": f"https://www.youtube.com/@{username}",
    }
    return Indicator(
        "username",
        raw,
        username,
        valid,
        {
            "username": username,
            "syntax_valid": valid,
            "manual_profile_links": links if valid else {},
            "note": "Бот не перебирает сайты на наличие аккаунта автоматически; ссылки нужны для ручной проверки публичных профилей.",
        },
    )


def _telegram_candidates(text: str) -> List[str]:
    spans = _email_spans(text)
    candidates: List[str] = []
    for match in URL_TG_RE.finditer(text):
        candidates.append(match.group(0))

    for match in TG_MENTION_RE.finditer(text):
        if _inside_any_span(match.start(), spans):
            continue
        candidates.append(match.group(0))

    return _unique(candidates)


def _url_candidates(text: str) -> List[str]:
    return _unique(match.group(0) for match in URL_RE.finditer(text))


def _ip_candidates(text: str) -> List[str]:
    candidates = []
    for match in IPV4_RE.finditer(text):
        value = match.group(0)
        try:
            ipaddress.ip_address(value)
        except ValueError:
            continue
        candidates.append(value)

    for token in re.split(r"[\s,;()<>\"']+", text):
        if ":" not in token:
            continue
        value = token.strip("[]{}")
        try:
            ipaddress.ip_address(value)
        except ValueError:
            continue
        candidates.append(value)

    return _unique(candidates)


def _domain_candidates(text: str, emails: List[str], urls: List[str]) -> Dict[str, List[str]]:
    result: Dict[str, List[str]] = {}

    for email in emails:
        domain = email.rsplit("@", 1)[1].lower()
        result.setdefault(domain, []).append("email")

    for url in urls:
        host = _url_host(url)
        if host:
            result.setdefault(host, []).append("url")

    email_spans = _email_spans(text)
    for match in DOMAIN_RE.finditer(text):
        if _inside_any_span(match.start(), email_spans):
            continue
        domain = match.group(1).lower()
        try:
            ipaddress.ip_address(domain)
            continue
        except ValueError:
            pass
        result.setdefault(domain, []).append("text")

    return {domain: sorted(set(sources)) for domain, sources in result.items()}


def _username_candidates(text: str, has_other_indicators: bool) -> List[str]:
    if has_other_indicators:
        return []

    value = text.strip()
    if any(char.isspace() for char in value):
        return []
    match = USERNAME_RE.fullmatch(value)
    if not match:
        return []
    return [match.group(1)]


def analyze_text(text: str, default_region: str = "UA") -> AnalysisReport:
    generated_at = datetime.now(timezone.utc).isoformat()
    indicators: List[Indicator] = []
    findings: List[Finding] = []

    emails = _unique(match.group(1) for match in EMAIL_RE.finditer(text))
    urls = _url_candidates(text)
    ips = _ip_candidates(text)
    phones = _unique(match.group(1) for match in PHONE_RE.finditer(text))
    telegrams = _telegram_candidates(text)
    domains = _domain_candidates(text, emails, urls)
    usernames = _username_candidates(text, bool(emails or urls or ips or phones or telegrams or domains))

    for email in emails:
        indicator = analyze_email(email)
        indicators.append(indicator)
        findings.append(
            Finding(
                source="email_metadata",
                title="Метаданные email-домена",
                level="info" if indicator.valid else "warning",
                details=indicator.metadata,
            )
        )

    for phone in phones:
        indicator = analyze_phone(phone, default_region)
        indicators.append(indicator)
        findings.append(
            Finding(
                source="phone_metadata",
                title="Метаданные номера телефона",
                level="info" if indicator.valid else "warning",
                details=indicator.metadata,
            )
        )

    for ip in ips:
        indicator = analyze_ip(ip)
        indicators.append(indicator)
        findings.append(
            Finding(
                source="ip_metadata",
                title="Метаданные IP-адреса",
                level="info" if indicator.valid else "warning",
                details=indicator.metadata,
            )
        )

    for url in urls:
        indicator = analyze_url(url)
        indicators.append(indicator)
        findings.append(
            Finding(
                source="url_metadata",
                title="Разбор URL",
                level="warning" if indicator.metadata.get("suspicious_flags") else "info",
                details=indicator.metadata,
            )
        )

    for domain, observed_in in domains.items():
        indicator = analyze_domain(domain, observed_in)
        indicators.append(indicator)
        findings.append(
            Finding(
                source="domain_dns",
                title="DNS и базовые признаки домена",
                level="info" if indicator.valid else "warning",
                details=indicator.metadata,
            )
        )

    for username in telegrams:
        indicator = analyze_telegram(username)
        indicators.append(indicator)
        findings.append(
            Finding(
                source="telegram_syntax",
                title="Синтаксис Telegram username",
                level="info" if indicator.valid else "warning",
                details=indicator.metadata,
            )
        )

    for username in usernames:
        indicator = analyze_username(username)
        indicators.append(indicator)
        findings.append(
            Finding(
                source="username_links",
                title="Ссылки для ручной проверки username",
                level="info" if indicator.valid else "warning",
                details=indicator.metadata,
            )
        )

    if not indicators:
        indicators.append(
            Indicator(
                "unknown",
                text,
                text,
                False,
                {
                    "note": "Не нашёл телефон, email, IP, домен, URL или Telegram username. Примеры: /scan +380501112233, /scan name@example.com, /scan 8.8.8.8, /scan example.com, /scan @username."
                },
            )
        )

    return AnalysisReport(text, generated_at, indicators, findings)
