# 🔐 Proxy Checker Bot

A fast, resilient **proxy checker** with live streaming, country sorting, IP scoring and a persistent vault — as a **command-line tool** and a **Telegram bot**. Pure Python; the bot talks to the raw Bot API with `requests`, no Telegram library needed.

**Credits: [@Poriot_ke](https://t.me/Poriot_ke)**

---

## Features

- ⚡ **Concurrent checking** — TCP-gated, protocol-probing engine; threads by default, `aiohttp` opt-in
- 🌐 **Resilient judge pool** — 5 independent IP-echo endpoints, health-checked; a bad judge can no longer silently corrupt your countries and scores
- 📡 **Live per-proxy streaming** — every result is pushed the moment it lands, with **CPM + ETA**, through the Nth proxy line
- 🌍 **Country sorting** — each proxy geolocated by its **exit IP**, grouped, and offered behind tier-colored inline buttons
- 🧠 **IP score (0-100)** — speed × anonymity, so a fast proxy that leaks your IP can't outrank a fast anonymous one
- 🎛 **Filter / sort bar** — one tap for `⭐ ≥70`, `🔒 anonymous only`, `⚡ <500ms`, protocol, top-N, and sorting
- 📦 **Export format picker** — `ip:port` · `host:port:user:pass` · `user:pass@host:port` · `proto://…` · JSON
- 🔁 **Re-verify** — re-check a country's proxies and update the vault in place (dead ones get dropped from exports)
- 💾 **SQLite vault** — every scan plus an all-time deduped pool; `/vault` and `/pool` reopen a country keypad without re-scanning
- 🧵 **Bounded scheduling** — one scan per chat, a global job cap and a shared thread budget, so concurrent users can't take the box down

## Why the checker is fast now

| Change | Effect |
|---|---|
| **TCP gate** before protocol guessing | A dead host is rejected in ~1-3s instead of burning 4 × timeout (up to 32s). Most real lists are mostly dead, so this dominates. |
| **Protocol order** `http → socks5 → socks4 → https` | Working proxies stop the chain early instead of walking all four schemes. |
| **Shorter fallback timeouts** | First guess gets the full timeout; later guesses get `max(3s, timeout/2)`. |
| **Judge pool** | The old single `httpbin.org/ip` meant a slow or unparseable response silently wiped out exit IPs, countries *and* scores. |

Measured on the same public 200-proxy list (mostly dead), 100 workers, 6s timeout:

```
before (single judge, 4 x full-timeout attempts):  200 checked in ~35s
after  (TCP gate + tuned fallbacks + judge pool):  200 checked in ~24s   (-31%)
```

**Honest note on asyncio:** the `async` backend exists (`PC_ENGINE=async`, needs `pip install aiohttp`) and shares the same code path, but on these workloads it measured **~20% slower** than threads — the wall-clock is dominated by the serial protocol fallbacks, not thread overhead. `auto` therefore stays on threads; use `async` for very large runs on memory-constrained hosts. SOCKS attempts without `aiohttp_socks` are delegated to a small thread pool.

## Project structure

```
Proxy2checker/
├── proxy_checker.py        # CLI: loading, progress, per-country export
├── telegram_proxy_bot.py   # Telegram bot (long-polling, raw Bot API)
├── engine.py               # parsing, TCP gate, thread + asyncio backends
├── judges.py               # judge pool: health checks, pick, degraded warning
├── geoip.py                # exit-IP -> country (GeoDB + in-flight GeoPipeline)
├── vault.py                # SQLite: scans, records, all-time pool, migration
├── ui.py                   # inline-button formatting, filter views, filtering
├── formats.py             # export formats (ip:port / url / json / …)
├── jobs.py                 # bounded, per-chat-serialised job queue
├── tests/                  # 92 offline tests (mock proxy + stubbed API)
├── requirements.txt        # requests + PySocks (aiohttp optional)
├── Procfile.txt            # Heroku worker process definition
└── railway.json            # Railway deploy config (Nixpacks)

vault/                      # created at runtime (do not commit)
├── vault.db                # SQLite: scans · records · pool
└── geo_cache.json          # IP -> country cache
```

## Supported formats

```
ip:port
ip:port:user:pass
user:pass:host:port        ← VPN-style (e.g. PureVPN/OpenVPN exports)
proto://ip:port
proto://user:pass@ip:port
```

`proto` can be `http`, `https`, `socks4` or `socks5`. SOCKS4/SOCKS5 use remote DNS (`socks4a` / `socks5h`).

The two 4-part layouts (`host:port:user:pass` and `user:pass:host:port`) are detected automatically — the parser uses the numeric port position to tell them apart.

**Output mirrors the input format by default** — a `user:pass:host:port` file comes back in that shape. Use the format picker (bot) or `--geo`/files (CLI) to convert.

## Install

```bash
git clone https://github.com/ashyamctommy-eng/Proxy2checker.git
cd Proxy2checker
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
pip install aiohttp          # optional: only for --engine async
```

## CLI

```bash
python3 proxy_checker.py proxies.txt
python3 proxy_checker.py proxies.txt list.zip ./folder --threads 500 --timeout 5
python3 proxy_checker.py "1.2.3.4:8080" "5.6.7.8:3128:user:pass"
python3 proxy_checker.py proxies.txt --geo            # valid_by_country/US.txt, DE.txt, …
```

| Option | Default | Description |
|---|---|---|
| `inputs` (positional) | — | `.txt` / `.zip` / directory / raw pasted text |
| `--proto` | `auto` | Force a protocol: `http`, `https`, `socks4`, `socks5` |
| `--threads` | `200` | Concurrent workers |
| `--timeout` | `10` | Per-proxy timeout (seconds) |
| `--out` | `valid_proxies.txt` | Output file for valid proxies |
| `--judge` | *pool* | Force a single IP-echo URL instead of the judge pool |
| `--engine` | `auto` | `auto` / `thread` / `async` |
| `--no-tcp-gate` | off | Disable the reachability gate (slow, only useful for debugging) |
| `--geo` | off | Also write valid proxies grouped by country |
| `--geo-out` | `valid_by_country` | Directory for per-country files + geo cache |
| `--geo-max` | `2500` | Max *new* exit IPs geolocated per run (cached IPs are free) |

## Bot

```bash
export TELEGRAM_BOT_TOKEN="123456789:ABC-DEF..."   # from @BotFather
python3 telegram_proxy_bot.py
```

| Command | What it does |
|---|---|
| `/start` | Bot title, features & usage |
| `/mpx` | Reply to an uploaded `.txt` / `.zip` to start checking |
| `/countries` | Re-open the country keypad for the most recent scan |
| `/vault` | Browse saved scans + the all-time country pool |
| `/pool` | Country keypad over every proxy ever found |
| `/cancel` | Drop scans queued behind the running one |

### What a scan looks like

**1. Live feed** — every result the moment it lands, with rate and ETA:

```
⚡ Live scan · 3822/5000 (76%) · ✅ 412 valid · ⚡ 1,240 CPM · ⏳ ETA 1m 02s
✔ 3821/5000  203.0.71.38:11901   🇺🇸US   341ms 🔒  64/100
✔ 3822/5000  203.0.72.39:11902   🇩🇪DE   128ms 🔒  95/100
✖ 3823/5000  196.64.96.66:1443   dead (TCP timeout)
```

Lists up to `PC_STREAM_MAX` (default 20) get **one real message per proxy**; larger lists get one message that keeps updating, because Telegram allows roughly one message per second per chat — one-per-proxy on a 5,000-line file would take over an hour *and* get the bot throttled.

Country flags show up live as the geo pipeline resolves exit IPs *during* the scan (previously geolocation ran only after checking finished).

**2. Full report** — countries, speed and score, fastest first:

```
🏆 Full report — 421 working proxies · 7f3a91c2
📊 sorted fastest → slowest (score = speed × anonymity)

🌍 Countries (19)
🇺🇸 US 183 · 🇩🇪 DE 74 · 🇫🇷 FR 22 · 🇸🇬 SG 19 · 🇷🇺 RU 14 · +14 more

🥇 Best: 201.0.1.0:8080 · 242ms · score 74/100 · United States

Top 30 of 421
  1 201.0.1.0:8080      🇺🇸US     242ms  74/100 🔒
  2 202.1.2.1:8081      🇺🇸US     288ms  69/100 🔒
 10 209.0.9.0:8080      🇩🇪DE    1029ms  19/100 🚩
```

**IP score** = speed × anonymity, `0-100`:

| Component | Rule |
|---|---|
| Speed | log scale — `100 ms → 100`, `3 s → 0` |
| Anonymity | `🔒 OK ×1.0` · `🚩 TRANSPARENT ×0.6` (leaks your IP) · `⚠ FLAGGED ×0.35` |

**3. Filter / sort bar** — the report carries its own controls; ✅ marks what's active:

```
[⭐ ≥70] [🔒 anon] [⚡ fast] [top 10]
[🔌 http] [↕️ speed] [✅ no leaks] [↺ reset]
[📄 report.txt] [🌍 all .txt] [🔙 Countries]
[📦 ip:port] [📦 u:p@h:p] [📦 url] [📦 json]
```

Filters apply to **everything** — the keypad counts, copy blocks and exported files all reflect what you're looking at. `✅ no leaks` is on by default: `TRANSPARENT` proxies (which leak your IP) are visible in the report but excluded from downloads until you tap it.

**4. Country keypad** — tier-colored by share, 🟢 ≥25% · 🟡 ≥10% · 🟠 ≥3% · 🔴 under 3%:

```
🌍 Pick a country to copy · page 1/4

  🟢 🇺🇸 US · 183    🟡 🇩🇪 DE · 74    🟠 🇫🇷 FR · 22
  🟠 🇸🇬 SG · 19     🟠 🇷🇺 RU · 14     🔴 🇬🇧 GB · 9
                  ◀️  1/4  ▶️
```

Tapping a country gives that country's file, a **📋 Copy** tap-to-copy block, a **🧾 report**, a format picker, and **🔁 Re-verify**.

Special buckets: `🚫 no exit IP` (proxy answered, judge gave no IP) and `🌐 Unknown` (exit IP known, country unresolvable) — previously merged, now distinct.

> **On "colored" buttons:** Telegram's Bot API accepts only plain text for button labels — no HTML, no Markdown, no colour field. Formatting is therefore Unicode (flags + status/tier emoji), applied consistently by `ui.btn()`. This is a platform limit, not a design choice.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `TELEGRAM_BOT_TOKEN` | *(required)* | Bot token from @BotFather |
| `PC_THREADS` | `150` | Per-job worker cap |
| `PC_GLOBAL_THREADS` | `300` | Shared thread budget across all jobs |
| `PC_MAX_JOBS` | `4` | Concurrent scans across all chats |
| `PC_ENGINE` | `thread` | `thread` / `async` / `auto` (see the asyncio note) |
| `PC_TIMEOUT` | `8` | Per-proxy timeout (seconds) |
| `PC_PROTO` | `auto` | `auto` / `http` / `https` / `socks4` / `socks5` |
| `PC_JUDGE` | *pool* | Force one judge URL (disables the pool) |
| `PC_MAX` | `20000` | Max proxies checked per job |
| `PC_GEO` | `1` | `0` disables country lookup |
| `PC_GEO_MAX` | `2500` | Max *new* exit IPs geolocated per scan |
| `PC_VAULT_DIR` | `vault` | SQLite + geo cache location |
| `PC_STREAM` | `1` | `0` reverts to a single progress bar |
| `PC_STREAM_MAX` | `20` | Up to this many proxies → one message each (capped at 50) |
| `PC_STREAM_EDIT` | `1.2` | Seconds between feed re-renders (≥1.0) |
| `PC_STREAM_MSG_DELAY` | `0.5` | Gap between per-proxy messages (≥0.25) |
| `PC_FEED_LINES` | `22` | Lines in the rolling feed window |
| `PC_TOP_N` | `30` | Rows in the ranked report message |
| `PC_PAGE` | `6` | Countries per keypad page |
| `PC_RECHECK` | `50` | Proxies re-verified per 🔁 tap |
| `PC_COPY_LINES` / `PC_COPY_MSGS` | `120` / `3` | Copy-block sizing |
| `PC_CHANNEL` / `PC_DEV` | `t.me/nativecodes` / `t.me/Poriot_ke` | Button targets — link, `@name`, or numeric chat ID |

## Deployment

### Railway (config included)

1. Push the repo, then **New Project → Deploy from GitHub repo**.
2. Add `TELEGRAM_BOT_TOKEN` under **Variables**.
3. Railway builds and runs `telegram_proxy_bot.py` (`restartPolicyType: ALWAYS`).

> ⚠️ **Attach a volume** — mount it at `/app/vault` and set `PC_VAULT_DIR=/app/vault`, or the vault/geo cache are wiped on every deploy.

### Heroku

1. Rename `Procfile.txt` → `Procfile`.
2. `heroku config:set TELEGRAM_BOT_TOKEN=...`
3. Deploy; the `worker:` process runs the bot.

## Tests

```bash
python3 -m unittest discover -s tests -v      # 92 tests, no token, no internet
```

The suite drives the **real engine against a mock HTTP proxy on localhost** (TCP gate, protocol attempts, both backends, judge-unreadable handling), and stubs only the Telegram API and the remote judge. It also covers country grouping, tier buttons, pagination, filters/sorting, export formats, vault SQLite + legacy migration, the job queue, the geo pipeline and the bot's full scan-to-report path. One optional smoke test hits ip-api.com and skips itself if offline.

## Troubleshooting

- **"Judge degraded" warning** → no IP-echo endpoint answered. Exit IPs, countries and scores are incomplete; the bot says so instead of quietly guessing. Check outbound HTTP/HTTPS.
- **Everything in `🚫 no exit IP`** → the judge returned a 200 with no parsable IP. That's a judge problem, and it's reported separately from proxy death.
- **Feed is one edited message, not one per proxy** → that's `PC_STREAM_MAX` (default 20, capped 50). Telegram allows ~1 message/second per chat; a 5,000-proxy file sent individually would take over an hour and get 429'd.
- **`/mpx` says "queued (position N)"** → one scan at a time per chat, deliberately. `/cancel` clears the queue.
- **SOCKS proxies fail in async mode** → `pip install aiohttp_socks`, or stay on the default thread engine (SOCKS without it is delegated to threads automatically).
- **Vault empty after a deploy** → container filesystems are ephemeral; mount a volume (see Railway note).
- **Old `pool.jsonl` / `scans/*.json`** → imported automatically on first run of this version and renamed `*.migrated`.

## Credits

Built and maintained by **[@Poriot_ke](https://t.me/Poriot_ke)** 💙

- 🤖 Telegram: [@Poriot_ke](https://t.me/Poriot_ke)
- 📦 Repository: [github.com/ashyamctommy-eng/Proxy2checker](https://github.com/ashyamctommy-eng/Proxy2checker)

## Disclaimer

Only check proxies you are authorized to use. The tool validates each proxy by routing a request through it to a public IP-echo service — the proxy's exit IP is visible to that judge. Use responsibly and respect the terms of service of the services you connect through.
