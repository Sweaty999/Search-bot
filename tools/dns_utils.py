from __future__ import annotations

from typing import Any, Dict, List

try:
    import dns.exception
    import dns.resolver
except ImportError:  # pragma: no cover - runtime dependency message is returned.
    dns = None


def _resolve_records(domain: str, record_type: str, lifetime: float = 1.5) -> List[str]:
    if dns is None:
        return []

    resolver = dns.resolver.Resolver()
    resolver.lifetime = lifetime
    resolver.timeout = min(lifetime, 1.0)
    answers = resolver.resolve(domain, record_type)
    return [answer.to_text().strip('"') for answer in answers]


def inspect_email_domain(domain: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "domain": domain,
        "dns_available": dns is not None,
        "mx_records": [],
        "txt_records": [],
        "spf_records": [],
        "dmarc_records": [],
        "dns_errors": [],
    }

    if dns is None:
        result["dns_errors"].append("Install dnspython to inspect DNS records.")
        return result

    try:
        result["mx_records"] = _resolve_records(domain, "MX")
    except Exception as exc:
        result["dns_errors"].append(f"MX: {exc}")

    try:
        txt_records = _resolve_records(domain, "TXT")
        result["txt_records"] = txt_records[:20]
        result["spf_records"] = [record for record in txt_records if record.lower().startswith("v=spf1")]
    except Exception as exc:
        result["dns_errors"].append(f"TXT: {exc}")

    try:
        result["dmarc_records"] = _resolve_records(f"_dmarc.{domain}", "TXT")
    except Exception as exc:
        result["dns_errors"].append(f"DMARC: {exc}")

    result["has_mx"] = bool(result["mx_records"])
    result["has_spf"] = bool(result["spf_records"])
    result["has_dmarc"] = bool(result["dmarc_records"])
    return result
