from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import get_settings
from core.models import LogEntry, Payment, Report, Role, Search, Subscription, User, UserRole, utcnow


ROLE_DESCRIPTIONS = {
    UserRole.free.value: "Basic legal OSINT access with daily limits.",
    UserRole.premium.value: "Premium access unlocked through Telegram Stars.",
    UserRole.admin.value: "Operational admin role without owner privileges.",
    UserRole.owner.value: "Single owner role defined by OWNER_ID.",
}


async def seed_roles(session: AsyncSession) -> None:
    for name, description in ROLE_DESCRIPTIONS.items():
        existing = await session.scalar(select(Role).where(Role.name == name))
        if not existing:
            session.add(Role(name=name, description=description))
    await session.flush()


async def get_user_by_telegram_id(session: AsyncSession, telegram_id: int) -> User | None:
    return await session.scalar(select(User).where(User.telegram_id == telegram_id))


async def upsert_telegram_user(
    session: AsyncSession,
    telegram_id: int,
    username: str | None = None,
    first_name: str | None = None,
    last_name: str | None = None,
) -> User:
    settings = get_settings()
    user = await get_user_by_telegram_id(session, telegram_id)
    if not user:
        role = UserRole.owner if settings.owner_id and telegram_id == settings.owner_id else UserRole.free
        user = User(telegram_id=telegram_id, username=username, first_name=first_name, last_name=last_name, role=role)
        session.add(user)
    else:
        user.username = username
        user.first_name = first_name
        user.last_name = last_name
        if settings.owner_id and telegram_id == settings.owner_id:
            user.role = UserRole.owner
    user.last_seen_at = utcnow()
    await session.flush()
    return user


async def set_admin_role(session: AsyncSession, telegram_id: int, enabled: bool) -> User:
    user = await get_user_by_telegram_id(session, telegram_id)
    if not user:
        user = User(telegram_id=telegram_id, role=UserRole.admin if enabled else UserRole.free)
        session.add(user)
    elif enabled and user.role != UserRole.owner:
        user.role = UserRole.admin
    elif not enabled and user.role == UserRole.admin:
        user.role = UserRole.free
    await session.flush()
    return user


async def set_ban(session: AsyncSession, telegram_id: int, banned: bool) -> User:
    user = await get_user_by_telegram_id(session, telegram_id)
    if not user:
        user = User(telegram_id=telegram_id, is_banned=banned)
        session.add(user)
    else:
        user.is_banned = banned
    await session.flush()
    return user


async def active_subscription(session: AsyncSession, user_id: int) -> Subscription | None:
    now = utcnow()
    result = await session.execute(
        select(Subscription)
        .where(Subscription.user_id == user_id, Subscription.active.is_(True))
        .order_by(Subscription.started_at.desc())
    )
    for subscription in result.scalars():
        expires_at = _aware(subscription.expires_at)
        if expires_at is None or expires_at > now:
            return subscription
        subscription.active = False
    await session.flush()
    return None


async def grant_premium_subscription(session: AsyncSession, user: User, plan: str) -> Subscription:
    now = utcnow()
    for existing in (await session.execute(select(Subscription).where(Subscription.user_id == user.id))).scalars():
        existing.active = False

    expires_at: datetime | None
    if plan == "premium_30":
        expires_at = now + timedelta(days=30)
    elif plan == "premium_90":
        expires_at = now + timedelta(days=90)
    elif plan == "premium_lifetime":
        expires_at = None
    else:
        raise ValueError(f"Unknown premium plan: {plan}")

    subscription = Subscription(user_id=user.id, plan=plan, started_at=now, expires_at=expires_at, active=True)
    session.add(subscription)
    if user.role == UserRole.free:
        user.role = UserRole.premium
    await session.flush()
    return subscription


async def record_payment(
    session: AsyncSession,
    user: User,
    *,
    plan: str,
    amount_stars: int,
    telegram_payment_charge_id: str | None,
    successful: bool,
    raw: dict[str, Any],
    payment_id: str | None = None,
) -> Payment:
    if telegram_payment_charge_id:
        existing = await session.scalar(
            select(Payment).where(Payment.telegram_payment_charge_id == telegram_payment_charge_id)
        )
        if existing:
            return existing
    payment = Payment(
        payment_id=payment_id or str(uuid.uuid4()),
        telegram_payment_charge_id=telegram_payment_charge_id,
        user_id=user.id,
        amount_stars=amount_stars,
        plan=plan,
        successful=successful,
        raw=raw,
    )
    session.add(payment)
    await session.flush()
    return payment


async def log_action(
    session: AsyncSession,
    action: str,
    *,
    user_id: int | None = None,
    level: str = "info",
    details: dict[str, Any] | None = None,
) -> None:
    session.add(LogEntry(user_id=user_id, action=action, level=level, details=details or {}))
    await session.flush()


async def daily_search_count(session: AsyncSession, user_id: int) -> int:
    start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    return int(
        await session.scalar(
            select(func.count(Search.id)).where(Search.user_id == user_id, Search.created_at >= start)
        )
        or 0
    )


async def platform_stats(session: AsyncSession) -> dict[str, int]:
    return {
        "users": int(await session.scalar(select(func.count(User.id))) or 0),
        "searches": int(await session.scalar(select(func.count(Search.id))) or 0),
        "reports": int(await session.scalar(select(func.count(Report.id))) or 0),
        "payments": int(await session.scalar(select(func.count(Payment.id)).where(Payment.successful.is_(True))) or 0),
    }


def _aware(value: datetime | None) -> datetime | None:
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=timezone.utc)
