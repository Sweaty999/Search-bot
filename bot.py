import asyncio
import logging
import os
from pathlib import Path
from typing import Optional

from telegram import InputFile, Update
from telegram.constants import ParseMode
from telegram.error import TelegramError
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters

from tools.analyzer import AnalysisReport, Finding, analyze_text
from tools.reporting import build_report_files, format_report_text


ROOT = Path(__file__).resolve().parent


def load_dotenv(path: Path = ROOT / ".env") -> None:
    if not path.exists():
        return

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


async def enrich_with_telegram(report: AnalysisReport, context: ContextTypes.DEFAULT_TYPE) -> None:
    for indicator in report.indicators:
        if indicator.kind != "telegram":
            continue

        username = indicator.normalized.lstrip("@")
        if not username:
            continue

        try:
            chat = await context.bot.get_chat(f"@{username}")
        except TelegramError as exc:
            report.findings.append(
                Finding(
                    source="telegram_bot_api",
                    title="Telegram lookup недоступний",
                    level="warning",
                    details={
                        "username": f"@{username}",
                        "reason": str(exc),
                        "note": "Bot API зазвичай бачить тільки публічні канали/групи або чати, доступні цьому боту.",
                    },
                )
            )
            continue

        public_details = {
            "id": chat.id,
            "type": chat.type,
            "username": getattr(chat, "username", None),
            "title": getattr(chat, "title", None),
            "first_name": getattr(chat, "first_name", None),
            "last_name": getattr(chat, "last_name", None),
            "description": getattr(chat, "description", None),
            "invite_link": getattr(chat, "invite_link", None),
        }
        public_details = {k: v for k, v in public_details.items() if v not in (None, "")}
        indicator.metadata["bot_api_accessible"] = True
        indicator.metadata["chat_type"] = chat.type
        report.findings.append(
            Finding(
                source="telegram_bot_api",
                title="Публічні Telegram-метадані",
                level="info",
                details=public_details,
            )
        )


async def handle_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "Привіт. Надішли /scan і телефон, email або Telegram username.\n\n"
        "Приклади:\n"
        "/scan +380501112233\n"
        "/scan name@example.com\n"
        "/scan @public_channel\n\n"
        "Бот збирає тільки технічні та публічно доступні метадані. Для чужих персональних даних використовуй його лише з дозволом.",
        parse_mode=ParseMode.HTML,
    )


async def handle_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "Команди:\n"
        "/scan <дані> - аналіз телефону, email або Telegram username\n"
        "/privacy - коротко про обмеження та безпеку\n\n"
        "Звіт повертається текстом, JSON, SVG-графом і HTML-сторінкою.",
    )


async def handle_privacy(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "Цей бот не лізе в приватні бази, не обходить захист і не робить масовий енумерейт акаунтів. "
        "Він нормалізує індикатори, бере DNS/технічні метадані та пробує Bot API тільки для доступних публічних Telegram-об'єктів.\n\n"
        "Токен бота зберігай тільки в .env. Якщо токен випадково був відправлений у чат, перевипусти його через BotFather.",
    )


async def scan_query(query: str, context: ContextTypes.DEFAULT_TYPE) -> AnalysisReport:
    default_region = os.getenv("DEFAULT_PHONE_REGION", "UA")
    report = await asyncio.to_thread(analyze_text, query, default_region)
    await enrich_with_telegram(report, context)
    return report


async def handle_scan(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = " ".join(context.args).strip()
    if not query:
        await update.message.reply_text("Напиши так: /scan +380501112233 або /scan name@example.com")
        return

    status_message = await update.message.reply_text("Аналізую індикатори і збираю звіт...")
    report = await scan_query(query, context)
    report_files = build_report_files(report, ROOT / os.getenv("REPORT_DIR", "reports"))

    text = format_report_text(report)
    await status_message.edit_text(text, parse_mode=ParseMode.HTML, disable_web_page_preview=True)

    for path in (report_files.json_path, report_files.svg_path, report_files.html_path):
        with path.open("rb") as file_obj:
            await update.message.reply_document(document=InputFile(file_obj, filename=path.name))


async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (update.message.text or "").strip()
    if not text:
        return

    if text.startswith("/"):
        return

    await update.message.reply_text("Для аналізу використай /scan <телефон/email/@telegram>.")


def build_application(token: str) -> Application:
    application = Application.builder().token(token).build()
    application.add_handler(CommandHandler("start", handle_start))
    application.add_handler(CommandHandler("help", handle_help))
    application.add_handler(CommandHandler("privacy", handle_privacy))
    application.add_handler(CommandHandler("scan", handle_scan))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    return application


def main() -> None:
    load_dotenv()
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    token: Optional[str] = os.getenv("BOT_TOKEN")
    if not token:
        raise SystemExit("BOT_TOKEN не заданий. Створи .env на основі .env.example і перевипусти засвічений токен.")

    build_application(token).run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
