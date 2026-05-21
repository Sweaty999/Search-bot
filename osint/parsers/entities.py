from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

import phonenumbers
import tldextract
from email_validator import EmailNotValidError, validate_email

from core.validators import clean_query, normalize_domain
from osint.models import Entity, EntityKind


USERNAME_RE = re.compile(r"^@?[a-zA-Z0-9_.-]{3,64}$")
DOMAIN_RE = re.compile(r"^(?!-)[a-zA-Z0-9.-]{1,253}(?<!-)\.[a-zA-Z]{2,63}$")
IMAGE_EXTENSIONS = (".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp", ".tiff")


def detect_entity(raw_query: str, default_phone_region: str = "UA") -> Entity:
    query = clean_query(raw_query)
    lowered = query.lower()

    parsed = urlparse(query)
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

    try:
        email = validate_email(query, check_deliverability=False)
        return Entity(kind=EntityKind.email, value=query, normalized=email.normalized, confidence=0.98)
    except EmailNotValidError:
        pass

    try:
        phone = phonenumbers.parse(query, default_phone_region)
        if phonenumbers.is_possible_number(phone) and phonenumbers.is_valid_number(phone):
            normalized = phonenumbers.format_number(phone, phonenumbers.PhoneNumberFormat.E164)
            return Entity(kind=EntityKind.phone, value=query, normalized=normalized, confidence=0.95)
    except phonenumbers.NumberParseException:
        pass

    if DOMAIN_RE.match(lowered):
        extracted = tldextract.extract(lowered)
        if extracted.domain and extracted.suffix:
            domain = normalize_domain(lowered)
            return Entity(kind=EntityKind.domain, value=query, normalized=domain, confidence=0.93)

    if lowered.startswith("t.me/"):
        username = lowered.rstrip("/").split("/")[-1]
        return Entity(kind=EntityKind.username, value=query, normalized=username.lstrip("@"), confidence=0.9)

    if USERNAME_RE.match(query) and " " not in query and "." not in query.strip("@"):
        return Entity(kind=EntityKind.username, value=query, normalized=query.lstrip("@"), confidence=0.78)

    return Entity(kind=EntityKind.text, value=query, normalized=query, confidence=0.55)

