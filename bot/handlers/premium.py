from __future__ import annotations

from telegram import LabeledPrice, Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from bot.keyboards.main import buy_premium_menu, premium_menu
from bot.services.premium import (
    activate_paid_plan,
    make_invoice_payload,
    parse_invoice_payload,
    premium_plans,
    subscription_status,
)
from bot.services.users import get_or_create_user
from core.database import async_session


FEATURES = (
    "<b>Premium Features</b>\n"
    "Deep Scan\n"
    "Advanced Graph\n"
    "AI Analysis ready extension point\n"
    "Screenshot Intelligence\n"
    "Archive Search\n"
    "Extended Metadata\n"
    "Full HTML Reports"
)


async def premium_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.data:
        return
    await query.answer()

    if query.data in {"buy_premium", "renew_premium"}:
        await query.edit_message_text("Choose a Telegram Stars premium plan.", reply_markup=buy_premium_menu())
        return
    if query.data == "premium_features":
        await query.edit_message_text(FEATURES, parse_mode=ParseMode.HTML, reply_markup=premium_menu())
        return
    if query.data == "my_subscription":
        async with async_session() as session:
            user = await get_or_create_user(session, update)
            status = await subscription_status(session, user)
            await session.commit()
        text = (
            "<b>My Subscription</b>\n"
            f"Current plan: <code>{status['plan']}</code>\n"
            f"Remaining days: <code>{status['remaining_days'] if status['remaining_days'] is not None else 'lifetime'}</code>\n"
            f"Activation date: <code>{status['started_at'] or '-'}</code>\n"
            f"Expiry date: <code>{status['expires_at'] or 'never'}</code>\n"
            f"Premium status: <b>{'active' if status['active'] else 'inactive'}</b>"
        )
        await query.edit_message_text(text, parse_mode=ParseMode.HTML, reply_markup=premium_menu())


async def buy_plan_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not query.data or not query.message:
        return
    await query.answer()
    plan_code = query.data.split(":", 1)[1]
    plan = premium_plans().get(plan_code)
    if not plan:
        await query.edit_message_text("Unknown premium plan.")
        return

    payload = make_invoice_payload(plan.code)
    await context.bot.send_invoice(
        chat_id=query.message.chat_id,
        title=plan.title,
        description=plan.description,
        payload=payload,
        provider_token="",
        currency="XTR",
        prices=[LabeledPrice(label=plan.title, amount=plan.stars)],
    )


async def precheckout_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    precheckout = update.pre_checkout_query
    if not precheckout:
        return
    parsed = parse_invoice_payload(precheckout.invoice_payload)
    if not parsed:
        await precheckout.answer(ok=False, error_message="Invalid invoice payload.")
        return
    plan_code, _payment_id = parsed
    plan = premium_plans()[plan_code]
    if precheckout.currency != "XTR" or precheckout.total_amount != plan.stars:
        await precheckout.answer(ok=False, error_message="Payment amount does not match the selected plan.")
        return
    await precheckout.answer(ok=True)


async def successful_payment(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message = update.effective_message
    payment = message.successful_payment if message else None
    if not payment:
        return
    parsed = parse_invoice_payload(payment.invoice_payload)
    if not parsed:
        await message.reply_text("Payment received, but the invoice payload was invalid. Contact owner.")
        return
    plan_code, payment_id = parsed

    async with async_session() as session:
        user = await get_or_create_user(session, update)
        try:
            subscription = await activate_paid_plan(
                session,
                user,
                plan_code=plan_code,
                amount_stars=payment.total_amount,
                telegram_payment_charge_id=payment.telegram_payment_charge_id,
                raw=payment.to_dict(),
                payment_id=payment_id,
            )
        except ValueError as exc:
            await session.rollback()
            await message.reply_text(f"Payment verification failed: {exc}")
            return
        await session.commit()

    expires = subscription.expires_at.isoformat() if subscription.expires_at else "never"
    await message.reply_text(
        f"Premium activated instantly.\nPlan: {subscription.plan}\nExpires: {expires}",
        reply_markup=premium_menu(),
    )

