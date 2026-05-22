from __future__ import annotations

from telegram import Update
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ConversationHandler,
    MessageHandler,
    PreCheckoutQueryHandler,
    filters,
)

from bot.handlers.admin import (
    admin_callback,
    admin_command,
    api_status_command,
    api_test_command,
    ban_command,
    broadcast_command,
    cache_clear_command,
    logs_command,
    provider_reset_command,
    search_debug_command,
    stats_command,
    unban_command,
    users_command,
)
from bot.handlers.errors import error_handler
from bot.handlers.premium import buy_plan_callback, precheckout_callback, premium_callback, successful_payment
from bot.handlers.search import WAITING_QUERY, ask_search, auto_text_search, receive_search_query, search_action_callback
from bot.handlers.start import help_command, menu_callback, start
from core.accounts import seed_roles
from core.api_manager import get_api_manager
from core.config import get_settings
from core.database import async_session, init_db
from core.localization import t
from core.logger import setup_logging
from core.webapp import validate_webapp_url
import logging

logger = logging.getLogger(__name__)


async def post_init(application: Application) -> None:
    get_api_manager().log_startup_status()
    webapp_check = validate_webapp_url(get_settings().webapp_url)
    if not webapp_check.valid:
        logger.warning("WEBAPP_URL disabled: %s", webapp_check.reason)
    await init_db()
    async with async_session() as session:
        await seed_roles(session)
        await session.commit()


def build_application() -> Application:
    settings = get_settings()
    if not settings.bot_token:
        raise SystemExit(t("errors.bot_token_required"))

    application = Application.builder().token(settings.bot_token).post_init(post_init).build()

    search_conversation = ConversationHandler(
        entry_points=[CallbackQueryHandler(ask_search, pattern="^(new_search|telegram_scan|phone_scan|email_scan|deep_scan|build_graph|html_report)$")],
        states={WAITING_QUERY: [MessageHandler(filters.TEXT & ~filters.COMMAND, receive_search_query)]},
        fallbacks=[],
        per_message=False,
    )

    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("admin", admin_command))
    application.add_handler(CommandHandler("stats", stats_command))
    application.add_handler(CommandHandler("users", users_command))
    application.add_handler(CommandHandler("logs", logs_command))
    application.add_handler(CommandHandler("ban", ban_command))
    application.add_handler(CommandHandler("unban", unban_command))
    application.add_handler(CommandHandler("cache_clear", cache_clear_command))
    application.add_handler(CommandHandler("broadcast", broadcast_command))
    application.add_handler(CommandHandler("api_status", api_status_command))
    application.add_handler(CommandHandler("api_test", api_test_command))
    application.add_handler(CommandHandler("search_debug", search_debug_command))
    application.add_handler(CommandHandler("provider_reset", provider_reset_command))

    application.add_handler(search_conversation)
    application.add_handler(CallbackQueryHandler(search_action_callback, pattern="^(refresh|deep|graph|export|sources|related|clear_cache):"))
    application.add_handler(CallbackQueryHandler(buy_plan_callback, pattern="^buy:"))
    application.add_handler(CallbackQueryHandler(premium_callback, pattern="^(buy_premium|premium_features|my_subscription|renew_premium)$"))
    application.add_handler(CallbackQueryHandler(admin_callback, pattern="^admin_"))
    application.add_handler(CallbackQueryHandler(menu_callback, pattern="^(profile|settings|help|premium|admin_panel)$"))
    application.add_handler(PreCheckoutQueryHandler(precheckout_callback))
    application.add_handler(MessageHandler(filters.SUCCESSFUL_PAYMENT, successful_payment))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, auto_text_search))
    application.add_error_handler(error_handler)
    return application


def main() -> None:
    setup_logging()
    build_application().run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
