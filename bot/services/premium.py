from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from core.accounts import active_subscription, grant_premium_subscription, record_payment
from core.config import get_settings
from core.localization import t
from core.models import Subscription, User


@dataclass(frozen=True)
class PremiumPlan:
    code: str
    title: str
    stars: int
    days: int | None
    description: str


def premium_plans() -> dict[str, PremiumPlan]:
    settings = get_settings()
    return {
        "premium_30": PremiumPlan("premium_30", t("premium.plan_30_title"), settings.premium_30_stars, 30, t("premium.plan_30_description")),
        "premium_90": PremiumPlan("premium_90", t("premium.plan_90_title"), settings.premium_90_stars, 90, t("premium.plan_90_description")),
        "premium_lifetime": PremiumPlan("premium_lifetime", t("premium.plan_lifetime_title"), settings.premium_lifetime_stars, None, t("premium.plan_lifetime_description")),
    }


def make_invoice_payload(plan_code: str) -> str:
    return f"premium:{plan_code}:{uuid.uuid4().hex[:16]}"


def parse_invoice_payload(payload: str) -> tuple[str, str] | None:
    parts = payload.split(":")
    if len(parts) != 3 or parts[0] != "premium":
        return None
    plan_code = parts[1]
    payment_id = parts[2]
    if plan_code not in premium_plans():
        return None
    return plan_code, payment_id


async def activate_paid_plan(
    session: AsyncSession,
    user: User,
    *,
    plan_code: str,
    amount_stars: int,
    telegram_payment_charge_id: str,
    raw: dict,
    payment_id: str,
) -> Subscription:
    plan = premium_plans()[plan_code]
    if amount_stars != plan.stars:
        await record_payment(
            session,
            user,
            plan=plan_code,
            amount_stars=amount_stars,
            telegram_payment_charge_id=telegram_payment_charge_id,
            successful=False,
            raw={**raw, "error": "amount_mismatch"},
            payment_id=payment_id,
        )
        raise ValueError(t("premium.amount_mismatch"))

    await record_payment(
        session,
        user,
        plan=plan_code,
        amount_stars=amount_stars,
        telegram_payment_charge_id=telegram_payment_charge_id,
        successful=True,
        raw=raw,
        payment_id=payment_id,
    )
    return await grant_premium_subscription(session, user, plan_code)


async def subscription_status(session: AsyncSession, user: User) -> dict[str, object]:
    subscription = await active_subscription(session, user.id)
    if not subscription:
        return {"active": False, "plan": "free", "remaining_days": 0, "started_at": None, "expires_at": None}

    remaining_days = None
    if subscription.expires_at:
        expires_at = subscription.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        delta = expires_at - datetime.now(timezone.utc)
        remaining_days = max(0, delta.days)
    return {
        "active": True,
        "plan": subscription.plan,
        "remaining_days": remaining_days,
        "started_at": subscription.started_at.isoformat(),
        "expires_at": subscription.expires_at.isoformat() if subscription.expires_at else None,
    }
