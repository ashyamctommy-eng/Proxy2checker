# 🔐 Proxy Checker Bot

A fast, concurrent **proxy checker** with live stats, transparency detection and a clean `.txt` export — available both as a **command-line tool** and a **Telegram bot**. Pure Python + `requests`; no external Telegram library required (it talks to the raw Bot API).

**Credits: [@Poriot_ke](https://t.me/Poriot_ke)**

---

## Features

- ⚡ **Concurrent checking** — CLI: 200 workers by default · Bot: 150 workers
- 📊 **Live stats** — progress bar, valid count, checks-per-minute (CPM), per-protocol breakdown, fastest proxy
- 🕵️ **Transparency detection** — every valid proxy is classified:
  - ✔ `OK` — exit IP differs from yours (anonymous)
  - 🚩 `TRANSPARENT` — exit IP equals your real IP (the proxy leaks your address)
  - ⚠ `FLAGGED` — anomaly (no exit IP / suspicious judge response)
- 🔌 **Protocols** — HTTP · HTTPS · SOCKS4 · SOCKS5 (auto-detected or forced)
- 📥 **Flexible input** — `.txt` files, `.zip` archives, directories (CLI), pasted text, or uploaded documents (bot)
- 🧹 **Smart parsing & dedup** — handles 5 proxy formats, drops malformed lines and duplicates
- 📤 **Clean export** — speed-sorted `approved.txt` plus `report.txt` with per-proxy status tags
- 🧵 **Responsive bot** — each job runs on its own thread; the progress message is live-edited (rate-limit aware)

## Supported formats

```
ip:port
ip:port:user:pass
user:pass:host:port        ← VPN-style (e.g. PureVPN/OpenVPN exports)
proto://ip:port
proto://user:pass@ip:port
```

`proto` can be `http`, `https`, `socks4`, or `socks5`. SOCKS4/SOCKS5 use remote DNS resolution (`socks4a` / `socks5h`).

The two 4-part layouts (`host:port:user:pass` and `user:pass:host:port`) are detected automatically — the parser uses the numeric port position to tell them apart.

**Output preserves the input format** — every valid proxy is written back exactly as it was written in your file (no normalization). A `user:pass:host:port` file comes back as `user:pass:host:port`, an `http://user:pass@host:port` file stays in that form, etc.

## Project structure

```
Proxycheckerbot/
├── proxy_checker.py        # Core checker — standalone CLI
├── telegram_proxy_bot.py   # Telegram bot wrapper (long-polling, raw Bot API)
├── requirements.txt        # requests + PySocks
├── Procfile.txt            # Heroku worker process definition
└── railway.json            # Railway deploy config (Nixpacks)
```

## Requirements

- Python 3.8+
- `pip install -r requirements.txt`

## Setup & usage

### 1. Clone & install

```bash
git clone https://github.com/ashyamctommy-eng/Proxycheckerbot.git
cd Proxycheckerbot
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Run the CLI checker

```bash
python3 proxy_checker.py proxies.txt
python3 proxy_checker.py proxies.txt socks_list.zip my_folder --threads 500 --timeout 5
python3 proxy_checker.py "1.2.3.4:8080" "5.6.7.8:3128:user:pass"
```

Any argument that isn't a file, `.zip`, or directory is treated as **raw pasted text** — handy for quick one-off checks.

**CLI options**

| Option | Default | Description |
|---|---|---|
| `inputs` (positional) | — | `.txt` / `.zip` / directory / raw pasted text |
| `--proto` | `auto` | Force a protocol: `http`, `https`, `socks4`, `socks5` |
| `--threads` | `200` | Number of concurrent workers |
| `--timeout` | `10` | Per-proxy timeout in seconds |
| `--out` | `valid_proxies.txt` | Output file for valid proxies |
| `--judge` | `http://httpbin.org/ip` | IP-echo URL used to validate each proxy |

### 3. Run the Telegram bot

1. Create a bot with [@BotFather](https://t.me/BotFather) and copy the token.
2. Set the token as an environment variable:

```bash
export TELEGRAM_BOT_TOKEN="123456789:ABC-DEF..."   # Windows: set TELEGRAM_BOT_TOKEN=...
```

3. Start the bot:

```bash
python3 telegram_proxy_bot.py
```

The bot polls the Telegram API (long-polling, no webhook) and stays online until you stop it with `Ctrl+C`.

**Bot commands**

| Command | What it does |
|---|---|
| `/start` | Show bot title, features & usage |
| `/mpx` | Reply to an uploaded `.txt` / `.zip` file to start checking it |

**Using the bot:**

1. Upload a `.txt` file with proxies (one per line) — or a `.zip` containing `.txt` files
2. Reply to the file with `/mpx` — checking starts with a live progress message
3. You get `approved.txt` (working proxies only) and `report.txt` (per-proxy status), each with inline **📢 Channel** / **👨💻 Dev** buttons

You can also just paste proxies directly in chat — they're checked immediately.

**Channel / Dev buttons** — configured via `PC_CHANNEL` and `PC_DEV` (see env vars below):
- A **link** (e.g. `https://t.me/my_channel`, `@username`, or `my_channel`) → the button opens that URL when tapped. Links are the recommended choice for buttons.
- A **numeric chat/user ID** (e.g. `-1001234567890` or `123456789`) → the button notifies that chat (or user) whenever someone taps it. Only use an ID if you want to be alerted on taps; the bot can only message a user who has started it, or a channel it is admin in.

**Example responses:**

Progress message:
```
🔍 Checking 120 proxies… ▰▰▰▱▱▱▱ 42% | ✅ 18 | ⚡ 1,240 CPM
```

Final summary:
```
✅ Done! 120 checked → 41 valid · Dead: 79
✔ anonymous: 33
🚩 transparent: 5
⚠ flagged: 3
⏱ Time: 8.4s
Fastest: purevpn0s8732217:i67s60ep:px031901.pointtoserver.com:10780 (112 ms) · OK
```

`report.txt` contents (mirrors your file's format):
```
purevpn0s8732217:i67s60ep:px031901.pointtoserver.com:10780   OK 112 ms
purevpn0s8732217:i67s60ep:px031901.pointtoserver.com:10781   TRANSPARENT
purevpn0s8732217:i67s60ep:px031901.pointtoserver.com:10782   FLAGGED
```
(If your file uses another format — e.g. `http://user:pass@host:port` — the lines are written back in that same format.)

### Environment variables (bot)

| Variable | Default | Description |
|---|---|---|
| `TELEGRAM_BOT_TOKEN` | *(required)* | Bot token from @BotFather |
| `PC_THREADS` | `150` | Concurrent workers per job |
| `PC_TIMEOUT` | `8` | Per-proxy timeout in seconds |
| `PC_PROTO` | `auto` | `auto` / `http` / `https` / `socks4` / `socks5` |
| `PC_JUDGE` | `http://httpbin.org/ip` | IP-echo URL used for validation |
| `PC_MAX` | `20000` | Safety cap: max proxies checked per job |
| `PC_CHANNEL` | `https://t.me/Poriot_ke` | 📢 Channel button target — link, `@username`, or numeric chat ID |
| `PC_DEV` | `https://t.me/Poriot_ke` | 👨💻 Dev button target — link, `@username`, or numeric chat/user ID |

## Deployment

### Railway (recommended — config included)

`railway.json` ships in the repo (Nixpacks builder, `restartPolicyType: ALWAYS`).

1. Push this repo to GitHub, then **New Project → Deploy from GitHub repo** in Railway.
2. Go to **Variables** and add `TELEGRAM_BOT_TOKEN`.
3. Railway builds and starts `telegram_proxy_bot.py` automatically. The bot keeps itself alive via the restart policy.

### Heroku

1. Rename `Procfile.txt` → `Procfile` (Heroku only reads files named exactly `Procfile`).
2. Create an app and set the config var: `heroku config:set TELEGRAM_BOT_TOKEN=123456789:ABC-DEF...`
3. Deploy. The `worker:` process type in the Procfile starts the bot, so a free worker dyno is enough.

## Troubleshooting

- **SOCKS proxies fail** → you're missing SOCKS support. `pip install PySocks` (already in `requirements.txt`).
- **Progress message doesn't update often** → the bot throttles edits to ~every 2 seconds to respect Telegram's rate limits. The final summary is always sent.
- **Huge proxy lists** → jobs are capped at `PC_MAX` (20,000) proxies by default. Raise it if you really need more.
- **Bot exits immediately** → `TELEGRAM_BOT_TOKEN` isn't set. See step 3 above.

## Credits

Built and maintained by **[@Poriot_ke](https://t.me/Poriot_ke)** 💙

- 🤖 Telegram: [@Poriot_ke](https://t.me/Poriot_ke)
- 📦 Repository: [github.com/ashyamctommy-eng/Proxycheckerbot](https://github.com/ashyamctommy-eng/Proxycheckerbot)

Found a bug or want a feature? Open an issue on the repo — or hit the **📢 Channel** / **👨💻 Dev** buttons on the bot's result files.

## Disclaimer

Only check proxies you are authorized to use. The tool validates each proxy by routing a request through it to a public IP-echo service (`httpbin.org/ip` by default) — the proxy's exit IP is visible to the judge. Use responsibly and respect the terms of service of the services you connect through.
