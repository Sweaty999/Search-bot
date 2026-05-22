from __future__ import annotations

from core.localization import t
from osint.models import EntityKind, ScanResult


def build_ai_summary(result: ScanResult) -> dict[str, object]:
    if result.status == "refused":
        return {"text": result.refusal_reason or t("ai.insufficient"), "next_steps": [], "warnings": []}

    risk = float(result.summary.get("risk_score") or 0.0)
    confidence = float(result.confidence or 0.0)
    public_signal_count = len(result.findings) + len(result.search_hits)
    public_evidence_count = len(result.search_hits) + _nested_public_items(result)
    if public_signal_count <= 2 or confidence < 0.35 or (result.entity.kind in {EntityKind.telegram, EntityKind.phone, EntityKind.email} and public_evidence_count == 0):
        text = t("ai.insufficient")
    else:
        text = " ".join(
            [
                t(
                    "ai.summary",
                    findings=len(result.findings),
                    sources=len(result.search_hits),
                    confidence=f"{confidence:.2f}",
                    risk=f"{risk:.2f}",
                ),
                _confidence_sentence(confidence),
                _risk_sentence(risk),
                t("ai.weak_evidence"),
            ]
        )
    return {
        "text": text,
        "next_steps": _next_steps(result.entity.kind),
        "warnings": [t("ai.weak_evidence")],
    }


def _confidence_sentence(value: float) -> str:
    if value >= 0.75:
        return t("ai.confidence_high")
    if value >= 0.45:
        return t("ai.confidence_medium")
    return t("ai.confidence_low")


def _risk_sentence(value: float) -> str:
    if value >= 0.7:
        return t("ai.risk_high")
    if value >= 0.35:
        return t("ai.risk_medium")
    return t("ai.risk_low")


def _next_steps(kind: EntityKind) -> list[str]:
    if kind == EntityKind.telegram:
        return [t("ai.next_telegram")]
    if kind == EntityKind.phone:
        return [t("ai.next_phone")]
    if kind == EntityKind.email:
        return [t("ai.next_email")]
    return []


def _nested_public_items(result: ScanResult) -> int:
    count = 0
    for finding in result.findings:
        data = finding.data if isinstance(finding.data, dict) else {}
        for key in ("hits", "messages", "profiles", "github_public_references", "public_websites", "ads", "public_profiles"):
            value = data.get(key)
            if isinstance(value, list):
                count += len(value)
    return count
