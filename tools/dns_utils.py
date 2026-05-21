from __future__ import annotations

from typing import Any, Dict, List, Tuple

try:
    import dns.resolver
except ImportError:  # pragma: no cover - runtime dependency message is returned.
    dns = None


DNS_RECORD_TYPES = ("A", "AAAA", "CNAME", "NS", "MX", "TXT", "SOA", "CAA")


def _resolver(lifetime: float = 2.0) -> "dns.resolver.Resolver":
    resolver = dns.resolver.Resolver()
    resolver.lifetime = lifetime
    resolver.timeout = min(lifetime, 1.0)
    return resolver


def resolve_records(domain: str, record_type: str, lifetime: float = 2.0) -> List[str]:
    if dns is None:
        return []

    answers = _resolver(lifetime).resolve(domain, record_type)
    return [answer.to_text().strip('"') for answer in answers]


def _safe_records(domain: str, record_type: str, lifetime: float = 2.0) -> Tuple[List[str], str | None]:
    if dns is None:
        return [], "Установи dnspython, чтобы получать DNS-записи."

    try:
        return resolve_records(domain, record_type, lifetime), None
    except Exception as exc:
        return [], f"{record_type}: {exc}"


def inspect_domain_dns(domain: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "domain": domain,
        "dns_available": dns is not None,
        "dns_errors": [],
    }

    for record_type in DNS_RECORD_TYPES:
        records, error = _safe_records(domain, record_type)
        result[f"{record_type.lower()}_records"] = records[:30]
        if error:
            result["dns_errors"].append(error)

    txt_records = result.get("txt_records", [])
    result["spf_records"] = [record for record in txt_records if record.lower().startswith("v=spf1")]
    result["has_a"] = bool(result.get("a_records"))
    result["has_aaaa"] = bool(result.get("aaaa_records"))
    result["has_mx"] = bool(result.get("mx_records"))
    result["has_ns"] = bool(result.get("ns_records"))
    result["has_spf"] = bool(result["spf_records"])
    return result


def inspect_email_domain(domain: str) -> Dict[str, Any]:
    result = inspect_domain_dns(domain)
    result["dmarc_records"] = []

    if dns is None:
        result["dns_errors"].append("Установи dnspython, чтобы проверить DMARC.")
        result["has_dmarc"] = False
        return result

    records, error = _safe_records(f"_dmarc.{domain}", "TXT")
    result["dmarc_records"] = records[:10]
    if error:
        result["dns_errors"].append(f"DMARC: {error}")

    result["has_dmarc"] = bool(result["dmarc_records"])
    return result
