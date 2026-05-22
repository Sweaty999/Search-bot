from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

import phonenumbers
import tldextract
from email_validator import EmailNotValidError, validate_email

from core.localization import t
from core.validators import clean_query, normalize_domain
from osint.models import Entity, EntityKind


USERNAME_RE = re.compile(r"^@?[a-zA-Z0-9_.-]{3,64}$")
TELEGRAM_HOSTS = {"t.me", "telegram.me", "www.t.me", "www.telegram.me"}
TELEGRAM_USERNAME_RE = re.compile(r"^@?[a-zA-Z0-9_]{3,64}$")
DOMAIN_RE = re.compile(r"^(?!-)[a-zA-Z0-9.-]{1,253}(?<!-)\.[a-zA-Z]{2,63}$")
IMAGE_EXTENSIONS = (".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp", ".tiff")


def detect_entity(raw_query: str, default_phone_region: str = "UA", force_kind: str | EntityKind | None = None) -> Entity:
    query = clean_query(raw_query)
    lowered = query.lower()
    forced = EntityKind(force_kind) if force_kind else None

    if forced == EntityKind.telegram:
        return _telegram_entity(query)
    if forced == EntityKind.email:
        return _email_entity(query)
    if forced == EntityKind.phone:
        return _phone_entity(query, default_phone_region)
    if forced == EntityKind.username:
        return Entity(kind=EntityKind.username, value=query, normalized=query.lstrip("@"), confidence=0.86)

    parsed = urlparse(query)
    if _is_telegram_url(parsed) or lowered.startswith(("t.me/", "telegram.me/")):
        return _telegram_entity(query)

    if parsed.scheme in {"http", "https"} and parsed.netloc:
        if parsed.path.lower().endswith(".pdf"):
            return Entity(kind=EntityKind.pdf_url, value=query, normalized=query, confidence=0.98)
        if parsed.path.lower().endswith(IMAGE_EXTENSIONS):
            return Entity(kind=EntityKind.image_url, value=query, normalized=query, confidence=0.96)
        return Entity(kind=EntityKind.url, value=query, normalized=query, confidence=0.95)

    try:
        ip = ipaddress.ip_address(query)
        return Entity(kind=EntityKind.ip, value=query, normalized=str(ip), confidence=0.99)
    except ValueError:
        pass

    email_entity = _email_entity(query, raise_on_error=False)
    if email_entity:
        return email_entity

    phone_entity = _phone_entity(query, default_phone_region, strict=True, raise_on_error=False)
    if phone_entity:
        return phone_entity

    if DOMAIN_RE.match(lowered):
        extracted = tldextract.extract(lowered)
        if extracted.domain and extracted.suffix:
            domain = normalize_domain(lowered)
            return Entity(kind=EntityKind.domain, value=query, normalized=domain, confidence=0.93)

    if USERNAME_RE.match(query) and " " not in query and "." not in query.strip("@"):
        return Entity(kind=EntityKind.username, value=query, normalized=query.lstrip("@"), confidence=0.78)

    return Entity(kind=EntityKind.text, value=query, normalized=query, confidence=0.55)


def _email_entity(query: str, *, raise_on_error: bool = True) -> Entity | None:
    try:
        email = validate_email(query, check_deliverability=False)
        return Entity(kind=EntityKind.email, value=query, normalized=email.normalized, confidence=0.98)
    except EmailNotValidError:
        if raise_on_error:
            return Entity(kind=EntityKind.email, value=query, normalized=query.strip().lower(), confidence=0.35, metadata={"valid_syntax": False})
        return None


def _phone_entity(
    query: str,
    default_phone_region: str,
    *,
    strict: bool = False,
    raise_on_error: bool = True,
) -> Entity | None:
    try:
        phone = phonenumbers.parse(query, default_phone_region)
        possible = phonenumbers.is_possible_number(phone)
        valid = phonenumbers.is_valid_number(phone)
        if possible and (valid or not strict):
            normalized = phonenumbers.format_number(phone, phonenumbers.PhoneNumberFormat.E164)
            return Entity(
                kind=EntityKind.phone,
                value=query,
                normalized=normalized,
                confidence=0.95 if valid else 0.72,
                metadata={"valid": valid, "possible": possible},
            )
    except phonenumbers.NumberParseException:
        pass
    if raise_on_error:
        return Entity(kind=EntityKind.phone, value=query, normalized=query.strip(), confidence=0.35, metadata={"valid": False, "possible": False})
    return None


def _telegram_entity(query: str) -> Entity:
    value = query.strip()
    parsed = urlparse(value if "://" in value else f"https://{value}" if value.lower().startswith(("t.me/", "telegram.me/")) else value)
    username = ""
    metadata: dict[str, object] = {"input_type": "telegram"}
    if _is_telegram_url(parsed):
        parts = [part for part in parsed.path.split("/") if part]
        if parts and parts[0] == "s" and len(parts) > 1:
            username = parts[1]
            metadata["public_messages_url"] = f"https://t.me/s/{username}"
        elif parts:
            username = parts[0]
        metadata["public_url"] = f"https://t.me/{username}" if username else value
    elif value.startswith("@"):
        username = value.lstrip("@")
        metadata["public_url"] = f"https://t.me/{username}"
    elif value.isdigit() and 5 <= len(value) <= 15:
        metadata["telegram_id"] = value
        metadata["note"] = t("telegram.public_id_note")
        return Entity(kind=EntityKind.telegram, value=query, normalized=value, confidence=0.58, metadata=metadata)
    elif TELEGRAM_USERNAME_RE.match(value):
        username = value.lstrip("@")
        metadata["public_url"] = f"https://t.me/{username}"
    else:
        username = value.lstrip("@")

    username = username.strip("/")
    confidence = 0.92 if username and TELEGRAM_USERNAME_RE.match(username) else 0.62
    metadata["username"] = username
    return Entity(kind=EntityKind.telegram, value=query, normalized=username or value, confidence=confidence, metadata=metadata)


def _is_telegram_url(parsed) -> bool:
    return parsed.netloc.lower() in TELEGRAM_HOSTS
