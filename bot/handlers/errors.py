from __future__ import annotations

import logging

from telegram import Update
from telegram.ext import ContextTypes

from core.localization import t

logger = logging.getLogger(__name__)


async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger.exception("Telegram handler failed", exc_info=context.error)
    if isinstance(update, Update) and update.effective_message:
        await update.effective_message.reply_text(t("errors.safe_error"))
