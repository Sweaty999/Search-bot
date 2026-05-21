from __future__ import annotations

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, WebAppInfo

from bot.services.premium import premium_plans
from core.config import get_settings
from core.models import User
from core.security import is_admin
from core.webapp import validate_webapp_url


def main_menu(user: User | None) -> InlineKeyboardMarkup:
    settings = get_settings()
    rows = [
        [
            InlineKeyboardButton("🔎 New Search", callback_data="new_search"),
            InlineKeyboardButton("🧠 Deep Scan", callback_data="deep_scan"),
        ],
        [
            InlineKeyboardButton("🕸 Build Graph", callback_data="build_graph"),
            InlineKeyboardButton("📄 HTML Report", callback_data="html_report"),
        ],
    ]
    if validate_webapp_url(settings.webapp_url).valid:
        rows.append([InlineKeyboardButton("🌐 Web Dashboard", web_app=WebAppInfo(url=settings.webapp_url))])
    rows.extend(
        [
            [
                InlineKeyboardButton("👤 Profile", callback_data="profile"),
                InlineKeyboardButton("⭐ Premium", callback_data="premium"),
            ],
            [
                InlineKeyboardButton("⚙️ Settings", callback_data="settings"),
                InlineKeyboardButton("❓ Help", callback_data="help"),
            ],
        ]
    )
    if user and is_admin(user):
        rows.append([InlineKeyboardButton("👑 Admin Panel", callback_data="admin_panel")])
    return InlineKeyboardMarkup(rows)


def after_search(search_id: str, has_report: bool, can_advanced_graph: bool) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("🔁 Refresh", callback_data=f"refresh:{search_id}"),
                InlineKeyboardButton("🕸 Open Graph", callback_data=f"graph:{search_id}"),
            ],
            [
                InlineKeyboardButton("📄 Export HTML", callback_data=f"export:{search_id}"),
                InlineKeyboardButton("🔍 Sources", callback_data=f"sources:{search_id}"),
            ],
            [InlineKeyboardButton("🧹 Clear Cache", callback_data=f"clear_cache:{search_id}")],
        ]
    )


def premium_menu() -> InlineKeyboardMarkup:
    rows = [[InlineKeyboardButton("⭐ Buy Premium", callback_data="buy_premium")]]
    rows.extend(
        [
            [
                InlineKeyboardButton("💎 Premium Features", callback_data="premium_features"),
                InlineKeyboardButton("📅 My Subscription", callback_data="my_subscription"),
            ],
            [InlineKeyboardButton("🔄 Renew Premium", callback_data="renew_premium")],
        ]
    )
    return InlineKeyboardMarkup(rows)


def buy_premium_menu() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton(f"{plan.title} - {plan.stars} Stars", callback_data=f"buy:{plan.code}")]
            for plan in premium_plans().values()
        ]
    )


def admin_menu() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("📊 Stats", callback_data="admin_stats"),
                InlineKeyboardButton("👥 Users", callback_data="admin_users"),
            ],
            [
                InlineKeyboardButton("🚫 Ban", callback_data="admin_ban_help"),
                InlineKeyboardButton("📢 Broadcast", callback_data="admin_broadcast_help"),
            ],
            [InlineKeyboardButton("🧾 Logs", callback_data="admin_logs")],
        ]
    )

