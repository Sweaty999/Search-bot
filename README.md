# Legal OSINT Platform

Production-grade Telegram OSINT platform for lawful public-source research:

- Telegram Bot with role-aware UI
- Telegram Web App dashboard
- Maltego-style graph visualization with vis-network and PyVis
- HTML-only reports
- Telegram Stars premium system
- FastAPI backend
- SQLAlchemy + Alembic database layer

The platform is designed for public information only: open websites, search engines, public profiles, DNS, WHOIS, SSL, IP metadata, archives, screenshots and file metadata.

It refuses requests that look like leaks, private databases, passwords, tokens, brute force, authorization bypass, doxing or illegal people searches.

## Search Pipeline

Every search runs a multi-stage public-source pipeline:

1. Entity detection: username, email, phone, domain, URL, IP or text.
2. Query expansion: exact match, quoted match, social platforms and targeted `site:` pivots.
3. Parallel search: SerpAPI, DuckDuckGo, Google CSE and public scraping fallback.
4. Enrichment: fetch result pages, extract titles, OpenGraph, favicon, canonical URL, emails, phones, usernames, social links, domains and IPs.
5. Ranking: dedupe URLs, group domains, score relevance, confidence, risk and noisy pages.
6. Graph: create entities and relationships for the Maltego-style graph.

Search priority:

1. `SERPAPI_KEY`
2. DuckDuckGo fallback
3. `GOOGLE_API_KEY` + `GOOGLE_CSE_ID`
4. Public scraping fallback

No Brave, Hunter or SecurityTrails integrations are used.

## Architecture

```text
bot/        Telegram entrypoint, handlers, keyboards, role/premium guards, Stars payments
api/        FastAPI app, WebApp pages, JSON API, admin/search/report routes
core/       settings, database, models, security, cache, limits, account services
osint/      entity detection, search engines, collectors, graph, reports, screenshots
web/        Jinja templates, CSS, JavaScript, Telegram WebApp SDK UI
data/       cache, exports, logs, temp, local SQLite database
alembic/    production migrations
```

## Dependencies

Core stack:

- Python 3.12+
- FastAPI, Uvicorn
- python-telegram-bot
- aiohttp
- SQLAlchemy async, Alembic
- SQLite by default, PostgreSQL in production
- Jinja2
- networkx, pyvis, vis-network
- BeautifulSoup4, lxml
- phonenumbers, dnspython, tldextract, python-whois
- Playwright
- pypdf, Pillow, exifread

Install from:

```bash
pip install -r requirements.txt
```

## Windows Setup

```powershell
py -3.12 -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python -m playwright install chromium
```

Edit `.env`, then run the bot:

```powershell
python -m bot.bot
```

Run the Web App API:

```powershell
uvicorn api.app:app --reload --host 127.0.0.1 --port 8000
```

## Linux Setup

```bash
python3.12 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python -m playwright install chromium
```

Run:

```bash
python -m bot.bot
uvicorn api.app:app --reload --host 0.0.0.0 --port 8000
```

## Docker Setup

```bash
docker compose up --build
```

Compose starts:

- `postgres`
- `api` on `http://localhost:8000`
- `bot`

For local SQLite, run without Docker. For Docker, PostgreSQL is recommended.

## Telegram Bot Setup

1. Create a bot in `@BotFather`.
2. Put the token in `.env`:

```env
BOT_TOKEN=123456:ABC...
OWNER_ID=123456789
```

3. Start the bot:

```bash
python -m bot.bot
```

Owner is controlled only by `OWNER_ID`. Only owner can run:

```text
/admin add <telegram_id>
/admin remove <telegram_id>
```

Admins can use stats, users, logs, ban, unban, broadcast and cache clear. Admins cannot grant premium manually.

## Telegram Stars Setup

Premium uses Telegram Stars only.

Plans:

- Premium 30 days: 100 Stars
- Premium 90 days: 500 Stars
- Premium Lifetime: 1000 Stars

The bot sends invoices with:

```text
currency = XTR
provider_token = ""
```

After Telegram sends `successful_payment`, the platform:

- verifies invoice payload and amount
- records the payment
- creates the subscription
- updates the user role to `premium`
- immediately unlocks premium features

Lifetime premium stores `expires_at = NULL`.

Official references:

- https://core.telegram.org/bots/payments-stars
- https://core.telegram.org/bots/api#sendinvoice

## WebApp Setup

Run FastAPI:

```bash
uvicorn api.app:app --host 0.0.0.0 --port 8000
```

Expose it through HTTPS in production, then set:

```env
WEBAPP_URL=https://your-domain.example
```

Telegram requires Web Apps to use HTTPS. If `WEBAPP_URL` is empty, starts with `http://`, uses `127.0.0.1`, `localhost` or a private IP, the bot hides the `Web Dashboard` button and logs a diagnostic warning. The owner also receives a warning after `/start`.

Configure the Web App URL in `@BotFather` for your bot.

### Option 1 - ngrok

```bash
uvicorn api.app:app --host 127.0.0.1 --port 8000
ngrok http 8000
```

Copy the HTTPS URL, for example:

```env
WEBAPP_URL=https://your-domain.ngrok-free.app
```

### Option 2 - cloudflared

```bash
uvicorn api.app:app --host 127.0.0.1 --port 8000
cloudflared tunnel --url http://localhost:8000
```

Copy the HTTPS URL into `.env`:

```env
WEBAPP_URL=https://your-domain.trycloudflare.com
```

### Option 3 - Render or Railway

Deploy the FastAPI app with:

```bash
uvicorn api.app:app --host 0.0.0.0 --port $PORT
```

Use the HTTPS domain from Render/Railway as `WEBAPP_URL`.

## Environment

Create or edit `.env`.

Required:

```env
BOT_TOKEN=
OWNER_ID=
WEBAPP_URL=
DATABASE_URL=sqlite:///data/app.db
```

Supported API keys:

```env
SERPAPI_KEY=
GOOGLE_API_KEY=
GOOGLE_CSE_ID=
IPINFO_TOKEN=
SHODAN_API_KEY=
ABSTRACT_API_KEY=
VT_API_KEY=
```

Search priority:

1. SerpAPI
2. DuckDuckGo fallback
3. Google Custom Search
4. Public scraping fallback

Intelligence priority:

- Email: Abstract API, then MX/DNS, Gravatar and public mentions.
- IP: IPInfo, then Shodan, then reverse DNS fallback.
- Domain: VirusTotal, Shodan, crt.sh, WHOIS, DNS and SSL.
- Threat: VirusTotal, then Shodan.

If a key is missing, invalid or rate limited, the API manager logs it and moves to the next provider or free fallback. The bot still works with only `BOT_TOKEN` and `OWNER_ID`.

Startup logs include:

```text
[API STATUS]
SerpAPI: ENABLED
Google CSE: ENABLED
IPInfo: ENABLED
Shodan: ENABLED
Abstract Email: ENABLED
VirusTotal: ENABLED
DuckDuckGo fallback: ENABLED
crt.sh fallback: ENABLED
Wayback fallback: ENABLED
```

## Database

Local dev can use SQLite. Production should use PostgreSQL.

Run migrations:

```bash
alembic upgrade head
```

The bot and API also call `create_all` on startup for smoother local development, but Alembic is the production path.

Tables:

- users
- roles
- searches
- reports
- payments
- subscriptions
- logs
- cache

## Premium Gates

Free:

- basic search
- daily request limit
- no deep scan
- no advanced graph export
- no full HTML report export

Premium:

- Deep Scan
- Advanced Graph
- AI Analysis extension point
- Screenshot Intelligence
- Archive Search
- Extended Metadata
- Full HTML Reports

## Admin Commands

```text
/admin
/admin add <telegram_id>
/admin remove <telegram_id>
/stats
/users
/logs
/broadcast <message>
/ban <telegram_id>
/unban <telegram_id>
/cache_clear
/api_status
/api_test
/search_debug <query>
/provider_reset [provider]
```

API diagnostics commands are owner-only. They show enabled providers, missing providers, fallback status, last error, response time and rate-limit state.

## Troubleshooting

`BOT_TOKEN is required`

- Set `BOT_TOKEN` in `.env`.

`Web Dashboard button is missing`

- Set `WEBAPP_URL` to an HTTPS domain.
- Do not use `http://127.0.0.1:8000` directly in Telegram.
- Use ngrok, cloudflared, Render or Railway.

`Deep Scan is a premium feature`

- Buy premium through Telegram Stars.
- Owner/admin roles also have access.

`Playwright screenshots do not work`

```bash
python -m playwright install chromium
```

Then set:

```env
ENABLE_PLAYWRIGHT_SCREENSHOTS=1
```

`Search has few results`

- Add `SERPAPI_KEY`, or use `GOOGLE_API_KEY` with `GOOGLE_CSE_ID`.
- DuckDuckGo remains available without a key but can be rate-limited by the upstream site.

`PostgreSQL connection fails in Docker`

- Use the compose defaults or set:

```env
DATABASE_URL=postgresql+asyncpg://osint:osint@postgres:5432/osint
```
