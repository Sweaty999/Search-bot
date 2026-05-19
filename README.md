# OSINT Telegram Bot

Безпечний OSINT-бот для самоперевірки телефону, email та Telegram username.

Він робить:

- нормалізацію і технічні метадані телефону через `phonenumbers`;
- перевірку email-формату, MX/SPF/DMARC/TXT записів домену;
- перевірку Telegram username і публічний `Bot API` lookup там, де бот має доступ;
- JSON, SVG-граф і HTML-звіт для візуалізації.

Він не робить:

- злам, обхід доступу, приватні бази, масовий енумерейт акаунтів;
- автоматичне підключення сторонніх GitHub-утиліт, які можуть порушувати приватність або ToS сервісів.

## Запуск

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

Відкрий `.env`, встав новий токен з BotFather у `BOT_TOKEN`, потім:

```powershell
python bot.py
```

## Команди

```text
/start
/help
/privacy
/scan +380501112233
/scan name@example.com
/scan @public_channel
```

## Про GitHub OSINT tools

Популярні інструменти на кшталт Sherlock або PhoneInfoga можуть бути корисні в легальному OSINT, але їх не варто запускати з Telegram-бота без чіткої згоди, лімітів і перевірки ліцензій/ToS. Цей проєкт залишає безпечну основу: додавати можна тільки ті джерела, на які в тебе є право, API-ключі й зрозуміла мета.
