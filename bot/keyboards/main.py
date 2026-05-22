from __future__ import annotations

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, WebAppInfo

from bot.services.premium import premium_plans
from core.config import get_settings
from core.localization import t
from core.models import User
from core.security import is_admin
from core.webapp import validate_webapp_url


def main_menu(user: User | None) -> InlineKeyboardMarkup:
    settings = get_settings()
    rows = [
        [
            InlineKeyboardButton(t("buttons.main.new_search"), callback_data="new_search"),
            InlineKeyboardButton(t("buttons.main.telegram"), callback_data="telegram_scan"),
        ],
        [
            InlineKeyboardButton(t("buttons.main.phone"), callback_data="phone_scan"),
            InlineKeyboardButton(t("buttons.main.email"), callback_data="email_scan"),
        ],
        [
            InlineKeyboardButton(t("buttons.main.deep_search"), callback_data="deep_scan"),
            InlineKeyboardButton(t("buttons.main.graph"), callback_data="build_graph"),
        ],
        [
            InlineKeyboardButton(t("buttons.main.html_report"), callback_data="html_report"),
        ],
    ]
    if validate_webapp_url(settings.webapp_url).valid:
        rows.append([InlineKeyboardButton(t("buttons.main.web_dashboard"), web_app=WebAppInfo(url=settings.webapp_url))])
    rows.extend(
        [
            [
                InlineKeyboardButton(t("buttons.main.premium"), callback_data="premium"),
                InlineKeyboardButton(t("buttons.main.settings"), callback_data="settings"),
            ],
            [
                InlineKeyboardButton(t("buttons.main.help"), callback_data="help"),
            ],
        ]
    )
    if user and is_admin(user):
        rows.append([InlineKeyboardButton(t("buttons.main.admin_panel"), callback_data="admin_panel")])
    return InlineKeyboardMarkup(rows)


def after_search(search_id: str, has_report: bool, can_advanced_graph: bool) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton(t("buttons.after.refresh"), callback_data=f"refresh:{search_id}"),
                InlineKeyboardButton(t("buttons.after.deep_analysis"), callback_data=f"deep:{search_id}"),
            ],
            [
                InlineKeyboardButton(t("buttons.after.build_graph"), callback_data=f"graph:{search_id}"),
                InlineKeyboardButton(t("buttons.after.html_report"), callback_data=f"export:{search_id}"),
            ],
            [
                InlineKeyboardButton(t("buttons.after.sources"), callback_data=f"sources:{search_id}"),
                InlineKeyboardButton(t("buttons.after.related_accounts"), callback_data=f"related:{search_id}"),
            ],
            [
                InlineKeyboardButton(t("buttons.after.clear_cache"), callback_data=f"clear_cache:{search_id}"),
                InlineKeyboardButton(t("buttons.after.upgrade_premium"), callback_data="premium"),
            ],
        ]
    )


def premium_menu() -> InlineKeyboardMarkup:
    rows = [[InlineKeyboardButton(t("buttons.premium.buy"), callback_data="buy_premium")]]
    rows.extend(
        [
            [
                InlineKeyboardButton(t("buttons.premium.features"), callback_data="premium_features"),
                InlineKeyboardButton(t("buttons.premium.subscription"), callback_data="my_subscription"),
            ],
            [InlineKeyboardButton(t("buttons.premium.renew"), callback_data="renew_premium")],
        ]
    )
    return InlineKeyboardMarkup(rows)


def buy_premium_menu() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton(t("buttons.premium.plan_button", title=plan.title, stars=plan.stars), callback_data=f"buy:{plan.code}")]
            for plan in premium_plans().values()
        ]
    )


def admin_menu() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton(t("buttons.admin.stats"), callback_data="admin_stats"),
                InlineKeyboardButton(t("buttons.admin.users"), callback_data="admin_users"),
            ],
            [
                InlineKeyboardButton(t("buttons.admin.logs"), callback_data="admin_logs"),
                InlineKeyboardButton(t("buttons.admin.ban"), callback_data="admin_ban_help"),
            ],
            [
                InlineKeyboardButton(t("buttons.admin.broadcast"), callback_data="admin_broadcast_help"),
                InlineKeyboardButton(t("buttons.admin.api_status"), callback_data="admin_api_status_help"),
            ],
            [InlineKeyboardButton(t("buttons.admin.api_test"), callback_data="admin_api_test_help")],
        ]
    )
