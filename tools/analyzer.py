from __future__ import annotations

import dataclasses
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    import phonenumbers
    from phonenumbers import carrier, geocoder, timezone as phone_timezone
except ImportError:  # pragma: no cover - useful message is returned at runtime.
    phonenumbers = None
    carrier = None
    geocoder = None
    phone_timezone = None

from tools.dns_utils import inspect_email_domain


EMAIL_RE = re.compile(r"(?<![\w.+-])([A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,63})(?![\w.+-])")
PHONE_RE = re.compile(r"(?<!\w)(\+?\d[\d\s().-]{7,}\d)(?!\w)")
TG_RE = re.compile(
    r"(?:(?:https?://)?(?:t\.me|telegram\.me)/)?@?([A-Za-z][A-Za-z0-9_]{4,31})(?:\b|/)",
    re.IGNORECASE,
)
URL_TG_RE = re.compile(r"(?:https?://)?(?:t\.me|telegram\.me)/([A-Za-z][A-Za-z0-9_]{4,31})", re.IGNORECASE)


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


def analyze_phone(raw: str, default_region: str) -> Indicator:
    cleaned = re.sub(r"[^\d+]", "", raw)
    metadata: Dict[str, Any] = {"input": raw, "cleaned": cleaned}

    if phonenumbers is None:
        metadata["error"] = "Install phonenumbers to parse phone metadata."
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
            "carrier": carrier.name_for_number(parsed, "en") if carrier else "",
            "location": geocoder.description_for_number(parsed, "en") if geocoder else "",
            "timezones": list(phone_timezone.time_zones_for_number(parsed)) if phone_timezone else [],
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
        "looks_like_role_account": local.lower() in {"admin", "info", "support", "sales", "contact", "security"},
    }

    valid = bool(EMAIL_RE.fullmatch(raw))
    metadata.update(inspect_email_domain(domain.lower()))
    return Indicator("email", raw, normalized, valid, metadata)


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
            "syntax_valid": valid,
            "note": "Bot API can resolve only public or bot-accessible Telegram chats/users.",
        },
    )


def _unique(values: List[str]) -> List[str]:
    seen = set()
    result = []
    for value in values:
        key = value.lower()
        if key not in seen:
            result.append(value)
            seen.add(key)
    return result


def _telegram_candidates(text: str, emails: List[str]) -> List[str]:
    email_spans = []
    for match in EMAIL_RE.finditer(text):
        email_spans.append((match.start(), match.end()))

    candidates: List[str] = []
    for match in URL_TG_RE.finditer(text):
        candidates.append(match.group(0))

    for match in re.finditer(r"(?<![\w@])@[A-Za-z][A-Za-z0-9_]{4,31}\b", text):
        if any(start <= match.start() < end for start, end in email_spans):
            continue
        candidates.append(match.group(0))

    for token in re.split(r"\s+", text.strip()):
        if token in emails:
            continue
        if normalize_telegram_username(token):
            candidates.append(token)

    return _unique(candidates)


def analyze_text(text: str, default_region: str = "UA") -> AnalysisReport:
    generated_at = datetime.now(timezone.utc).isoformat()
    indicators: List[Indicator] = []
    findings: List[Finding] = []

    emails = _unique([match.group(1) for match in EMAIL_RE.finditer(text)])
    phones = _unique([match.group(1) for match in PHONE_RE.finditer(text)])
    telegrams = _telegram_candidates(text, emails)

    for email in emails:
        indicator = analyze_email(email)
        indicators.append(indicator)
        findings.append(
            Finding(
                source="email_metadata",
                title="Email domain metadata",
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
                title="Phone number metadata",
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
                title="Telegram username syntax",
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
                    "note": "Не знайшов телефон, email або Telegram username. Спробуй /scan +380501112233, /scan name@example.com або /scan @username."
                },
            )
        )

    return AnalysisReport(text, generated_at, indicators, findings)
