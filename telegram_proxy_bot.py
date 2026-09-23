#!/usr/bin/env python3
"""
PROXY CHECKER TELEGRAM BOT  -  Credits: @Poriot_ke
Wraps the checking engine behind a Telegram bot.

Commands:
    /start         Show bot title, features & usage
    /mpx           Reply to an uploaded .txt/.zip to start checking
    /countries     Re-open the country keypad for the latest scan
    /vault         Browse saved scans + the all-time country pool
    /pool          Country keypad over every proxy ever found
    /cancel        Drop queued scans for this chat

Flow:
    1. Upload a .txt file with proxies (one per line)
    2. Reply to it with /mpx
    3. Every result is streamed live (per-proxy messages, or a rolling feed for
       big lists) with CPM + ETA; exit IPs are geolocated *while* it runs
    4. Working proxies are saved to the vault, then you get a ranked report with
       countries, speed and an IP score, behind a filter/sort bar
    5. Tap a country to copy it, export it in any format, or re-verify it

Notes on the platform limits this code works within:
  * inline buttons accept plain text only — no HTML, no Markdown, no colour.
    Formatting is therefore Unicode (flags + status emoji), applied in ui.btn().
  * messages are capped at 4096 chars, captions at 1024, callback_data at 64
    bytes, and bots may send ~1 message/second per chat.

Setup:
    export TELEGRAM_BOT_TOKEN="123456:ABC..."   # from @BotFather
    python3 telegram_proxy_bot.py

No external Telegram library required (uses the raw Bot API via requests).
"""
import html
import io
import json
import math
import os
import random
import re
import sys
import time
import zipfile
import threading
import concurrent.futures as cf
from collections import Counter, deque

import requests

from engine import parse_proxy, check_many, resolve_engine, JUDGE_UNREADABLE, bounded_get
from judges import JudgePool, extract_ip
from geoip import (GeoDB, GeoPipeline, clean_ip, flag_emoji,
                   UNKNOWN_CC, UNKNOWN_NAME, NO_IP_CC, NO_IP_NAME)
from vault import Vault
import formats
import ui
from ui import btn, get_view, set_view, reset_view, toggle, view_header, \
    filter_records, export_records, NO_IP_CC as _NOIP
from jobs import JobQueue

TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
if not TOKEN:
    sys.exit("ERROR: set TELEGRAM_BOT_TOKEN environment variable (get it from @BotFather).")

API = f"https://api.telegram.org/bot{TOKEN}"
FILE_API = f"https://api.telegram.org/file/bot{TOKEN}"


def _num_env(name, default, lo, hi, cast=float):
    try:
        return max(lo, min(cast(os.environ.get(name, default)), hi))
    except (TypeError, ValueError):
        return cast(default)


# tuning (override via env)
THREADS_CAP = int(_num_env("PC_THREADS", 150, 1, 2000))
GLOBAL_THREADS = int(_num_env("PC_GLOBAL_THREADS", 300, 8, 4000))
MAX_JOBS = int(_num_env("PC_MAX_JOBS", 4, 1, 32))
TIMEOUT = int(_num_env("PC_TIMEOUT", 8, 1, 120))
PROTO = os.environ.get("PC_PROTO", "auto")
JUDGE_OVERRIDE = os.environ.get("PC_JUDGE", "").strip() or None
ENGINE_MODE = os.environ.get("PC_ENGINE", "thread")      # thread | async | auto
MAX_PROXIES = int(_num_env("PC_MAX", 20000, 1, 500000))
GEO_ENABLED = os.environ.get("PC_GEO", "1") not in ("0", "false", "no")
GEO_MAX = int(_num_env("PC_GEO_MAX", 2500, 0, 100000))
PAGE_SIZE = int(_num_env("PC_PAGE", 6, 1, 24))
COPY_LINES_PER_MSG = int(_num_env("PC_COPY_LINES", 120, 1, 500))
COPY_MAX_MSGS = int(_num_env("PC_COPY_MSGS", 3, 1, 20))
MAX_COPY_LINE = 300
RECHECK_LIMIT = int(_num_env("PC_RECHECK", 50, 1, 500))
# Where the vault lives. `PC_VAULT_DIR` wins if set; otherwise Railway's
# RAILWAY_VOLUME_MOUNT_PATH (injected automatically when a volume is attached) is
# used, so attaching a volume is enough — no variable to remember.
VAULT_DIR = (os.environ.get("PC_VAULT_DIR", "").strip()
             or os.environ.get("RAILWAY_VOLUME_MOUNT_PATH", "").strip()
             or "vault")

STREAM_ENABLED = os.environ.get("PC_STREAM", "1") not in ("0", "false", "no")
STREAM_MAX = int(_num_env("PC_STREAM_MAX", 20, 0, 50))
STREAM_EDIT = _num_env("PC_STREAM_EDIT", 1.2, 1.0, 30.0)
STREAM_MSG_DELAY = _num_env("PC_STREAM_MSG_DELAY", 0.5, 0.25, 5.0)
FEED_LINES = int(_num_env("PC_FEED_LINES", 22, 1, 200))
MAX_FEED_LINE = 64
TOP_N = int(_num_env("PC_TOP_N", 30, 1, 200))
MAX_RAW_DISPLAY = 80
JUDGE_WARN_RATIO = 0.2

CHANNEL = os.environ.get("PC_CHANNEL", "https://t.me/nativecodes").strip()
DEV = os.environ.get("PC_DEV", "https://t.me/Poriot_ke").strip()

OK_FILE = "approved.txt"
REPORT_FILE = "report.txt"

VAULT = Vault(VAULT_DIR)
GEO = GeoDB(VAULT.geo_path)
JUDGES = JudgePool(timeout=min(TIMEOUT, 8))
QUEUE = JobQueue(max_jobs=MAX_JOBS, global_threads=GLOBAL_THREADS,
                 min_threads=max(8, GLOBAL_THREADS // (MAX_JOBS * 2)))

# UNKNOWN = the proxy answered and gave an exit IP, but we could not learn this
# host's own IP, so transparent-vs-anonymous could not be decided. It is a
# distinct state: previously this silently fell through to "OK", so every proxy
# was advertised as anonymous (and scored 1.0) whenever the judge was unreachable
# from the bot itself.
STATUS_ICON = {"OK": "🔒", "TRANSPARENT": "🚩", "FLAGGED": "⚠", "UNKNOWN": "❔"}
SCORE_MULT = {"OK": 1.0, "UNKNOWN": 0.75, "TRANSPARENT": 0.6, "FLAGGED": 0.35}
TIER_LEGEND = "🟢 ≥25% · 🟡 ≥10% · 🟠 ≥3% · 🔴 under 3%"

BANNER = (
    "🔐 <b>PROXY CHECKER BOT</b>\n"
    "Fast concurrent proxy checker with live streaming, country sorting, "
    "IP scoring and a persistent vault.\n\n"
    "<b>How to use</b>\n"
    "1️⃣ Upload a <code>.txt</code> file with proxies (one per line)\n"
    "2️⃣ Reply to it with <code>/mpx</code>\n"
    "3️⃣ Watch every result stream in live, through the last line\n"
    "4️⃣ Get the ranked report (countries · speed · IP score) + a country keypad\n\n"
    "💬 <b>Or</b> just paste proxies directly in chat.\n\n"
    "<b>Formats</b>\n"
    "<code>ip:port</code> · <code>ip:port:user:pass</code> · "
    "<code>user:pass:host:port</code> · <code>proto://ip:port</code> · "
    "<code>proto://user:pass@ip:port</code>\n\n"
    "<b>Protocols:</b> HTTP · HTTPS · SOCKS4 · SOCKS5\n"
    "<b>Accepts:</b> 📄 .txt · 📦 .zip · 💬 paste\n\n"
    "<b>Status tags</b> — every valid proxy is classified:\n"
    "✔ <code>OK</code> anonymous · 🚩 <code>TRANSPARENT</code> (leaks your IP) · "
    "⚠ <code>FLAGGED</code>\n\n"
    "<b>Country sorting</b> — each proxy is geolocated by its exit IP, saved to "
    "the vault, then offered per country behind colored buttons:\n"
    "🟢 big share · 🟡 medium · 🟠 small · 🔴 tiny\n\n"
    "<b>IP score</b> — 0-100, speed × anonymity (fast + anonymous wins):\n"
    "100 ms → 100 · 3 s → 0 · 🔒 ×1.0 · 🚩 ×0.6 · ⚠ ×0.35\n\n"
    "<b>Commands:</b> <code>/start</code> · <code>/mpx</code> · "
    "<code>/countries</code> · <code>/vault</code> · <code>/pool</code> · "
    "<code>/cancel</code>\n"
    "📢 Dev: @nativecodes\n"
    "<i>Reply to an uploaded file with /mpx to begin</i> ↓"
)

CHANNEL_MSG = ("📢 <b>Channel</b>\n\nThanks for your interest — stay tuned for "
               "updates and more tools! ❤️")
DEV_MSG = ("👨‍💻 <b>Dev</b>\n\n@Poriot_ke\n"
           "🔗 <a href=\"https://github.com/ashyamctommy-eng/Proxy2checker\">GitHub</a>\n\n"
           "Found a bug or want a feature? Open an issue!")


# --------------------------------------------------------------- helpers -----
def esc(text):
    return html.escape(str(text), quote=False)


def clip_caption(text, limit=1024):
    text = str(text)
    if len(text) <= limit:
        return text
    cut = re.sub(r"<[^>]*$", "", text[:limit - 1])
    cut = re.sub(r"&[a-zA-Z#0-9]*$", "", cut)
    return cut + "…"


def _fit_lines(lines, budget=3000):
    kept, size = [], 0
    for ln in reversed(list(lines)):
        elen = len(esc(ln)) + 1
        if size + elen > budget:
            break
        kept.append(ln)
        size += elen
    kept.reverse()
    return kept


def short_raw(raw, n=MAX_RAW_DISPLAY):
    raw = str(raw if raw is not None else "")
    return raw if len(raw) <= n else raw[:n - 3] + "..."


def short_lat(latency):
    return f"{latency:.0f}ms" if isinstance(latency, (int, float)) else "n/a"


def bar(done, total, width=18):
    filled = int(width * done / total) if total else width
    return "▰" * filled + "▱" * (width - filled)


def score_of(latency, status="OK"):
    """IP score 0-100: speed (log scale) x anonymity."""
    if not isinstance(latency, (int, float)) or not math.isfinite(latency):
        return 0
    lat = min(max(float(latency), 100.0), 3000.0)
    speed = 100.0 * (math.log(3000.0) - math.log(lat)) / (math.log(3000.0) - math.log(100.0))
    return int(round(max(0.0, min(100.0, speed)) * SCORE_MULT.get(status, 0.5)))


def grade_of(score):
    for cut, grade in ((85, "A+"), (70, "A"), (55, "B"), (40, "C")):
        if score >= cut:
            return grade
    return "D"


def new_scan_id():
    return f"{int(time.time() * 1000):x}{random.randrange(0x1000):03x}"


def safe_cc(cc) -> str:
    """Callback-supplied country code -> at most 3 safe characters."""
    cc = re.sub(r"[^A-Za-z0-9]", "", str(cc or "")).upper()
    return cc[:3] or NO_IP_CC


def button_target(value):
    v = (value or "").strip()
    if not v:
        return "msg", None
    if v.lstrip("-").isdigit():
        return "id", int(v)
    if v.startswith("@"):
        v = "https://t.me/" + v[1:]
    elif v.startswith("t.me/"):
        v = "https://" + v
    elif not v.startswith(("http://", "https://")):
        v = "https://t.me/" + v
    return "url", v


def social_row():
    kind_c, target_c = button_target(CHANNEL)
    kind_d, target_d = button_target(DEV)
    return ui.row(
        btn("📢 Channel", "channel", url=target_c if kind_c == "url" else None),
        btn("👨‍💻 Dev", "dev", url=target_d if kind_d == "url" else None),
    )


def keyboard(*rows):
    out = [r for r in rows if r]
    out.append(social_row())
    return {"inline_keyboard": out}


# ---------------------------------------------------------------- records ----
def country_of(record):
    return (record.get("cc") or UNKNOWN_CC).upper()


def is_unknown(cc):
    return not cc or cc in (UNKNOWN_CC, NO_IP_CC, "XX")


def country_name_of(cc, records):
    for r in records:
        if country_of(r) == cc and r.get("country"):
            return r["country"]
    if cc == NO_IP_CC:
        return NO_IP_NAME
    return UNKNOWN_NAME if cc == UNKNOWN_CC else cc


def label_of(cc, records=None):
    if cc == NO_IP_CC:
        return "🚫 no exit IP"
    if cc == UNKNOWN_CC or not cc:
        return "🌐 Unknown"
    return f"{flag_emoji(cc)} {cc}"


def group_by_country(records):
    groups = {}
    for r in records:
        groups.setdefault(country_of(r), []).append(r)
    ordered = sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    for _, recs in ordered:
        recs.sort(key=lambda r: r.get("lat") if isinstance(r.get("lat"), (int, float)) else 9e9)
    return ordered


def tier_emoji(n, total):
    share = (n / total) if total else 0
    for cut, icon in ((0.25, "🟢"), (0.10, "🟡"), (0.03, "🟠")):
        if share >= cut:
            return icon
    return "🔴"


def proxy_lines(records):
    return [str(r.get("raw", "")).strip() for r in records if str(r.get("raw", "")).strip()]


def report_lines(records):
    out = []
    for r in records:
        lat = r.get("lat")
        lat = f"{lat:.0f} ms" if isinstance(lat, (int, float)) else "n/a"
        out.append(f"{r.get('raw','')}  {r.get('st','?'):<11} {lat:>8}  "
                   f"{country_of(r)}  {r.get('sc', 0):>3}/100  {grade_of(r.get('sc', 0))}")
    return out


# ------------------------------------------------------------------- feed ----
def feed_line(n, total, raw, ok, latency=None, ip=None, err="", st=None, cc=None):
    name = str(raw or "")
    if len(name) > MAX_FEED_LINE:
        name = name[:MAX_FEED_LINE - 3] + "..."
    if not ok:
        return f"✖ {n:>4}/{total}  {name}  dead ({str(err or 'failed')[:24]})"
    place = f"{flag_emoji(cc)}{cc}" if cc else "  "
    icon = STATUS_ICON.get(st, "✔")
    return (f"✔ {n:>4}/{total}  {name}  {place} "
            f"{latency:>5.0f}ms {icon} {score_of(latency, st):>3}/100")


def render_feed_lines(entries, cc_lookup=None):
    """Render stored feed entries, resolving country at *render* time.

    Entries are kept raw so a line rendered a second ago can pick up the country
    the geo pipeline resolved in the meantime — that is what makes country flags
    actually show up live instead of only for previously cached IPs.
    """
    out = []
    for e in entries:
        n, total, raw, ok, latency, ip, err, st = e
        cc = ""
        if cc_lookup and ok and ip:
            try:
                cc = cc_lookup(ip)
            except Exception:
                cc = ""
        out.append(feed_line(n, total, raw, ok, latency, ip, err, st, cc))
    return out


def feed_text(done, total, valid, lines, cpm=None, eta=None, warning=None):
    pct = int(done / total * 100) if total else 100
    header = f"⚡ <b>Live scan</b> · {done}/{total} ({pct}%) · ✅ <b>{valid}</b> valid"
    if cpm:
        header += f" · ⚡ {cpm} CPM"
    if eta:
        header += f" · ⏳ ETA {eta}"
    if warning:
        header += f"\n{warning}"
    window = _fit_lines(lines)
    body = esc("\n".join(window)) if window else "waiting for the first result..."
    return f"{header}\n<pre>{body}</pre>\n✔ working · ✖ dead — full report follows"


def human_eta(seconds):
    if not seconds or seconds <= 0:
        return "0s"
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60:02d}s"
    return f"{seconds // 3600}h {(seconds % 3600) // 60:02d}m"


# ---------------------------------------------------------------- telegram ---
def _redact(text):
    """The API URL embeds the bot token, and requests' exception strings contain
    the URL — so an unredacted log line hands over full control of the bot."""
    text = str(text)
    return text.replace(TOKEN, "<token>") if TOKEN else text


def api(method, **params):
    """Call the Bot API, honouring 429 retry_after instead of dropping updates."""
    data = {}
    for attempt in range(3):
        try:
            r = requests.post(f"{API}/{method}", data=params, timeout=60)
            data = r.json()
        except Exception as e:
            print("api err", method, _redact(e))
            return {}
        if isinstance(data, dict) and data.get("error_code") == 429:
            if attempt == 2:
                break
            wait = (data.get("parameters") or {}).get("retry_after", 2)
            time.sleep(min(float(wait), 30) + 0.5)
            continue
        return data
    return data


def send(chat_id, text, markup=None, **kw):
    params = dict(chat_id=chat_id, text=text, parse_mode="HTML",
                  disable_web_page_preview=True)
    if markup:
        params["reply_markup"] = json.dumps(markup)
    params.update(kw)
    return api("sendMessage", **params)


def edit(chat_id, msg_id, text, markup=None):
    params = dict(chat_id=chat_id, message_id=msg_id, text=text,
                  parse_mode="HTML", disable_web_page_preview=True)
    if markup:
        params["reply_markup"] = json.dumps(markup)
    return api("editMessageText", **params)


def send_doc(chat_id, filename, data, caption="", markup=None):
    files = {"document": (filename, io.BytesIO(data if isinstance(data, bytes) else data.encode()))}
    payload = {"chat_id": chat_id, "caption": clip_caption(caption), "parse_mode": "HTML"}
    if markup:
        payload["reply_markup"] = json.dumps(markup)
    try:
        return requests.post(f"{API}/sendDocument", data=payload, files=files,
                             timeout=120).json()
    except Exception as e:
        print("send_doc err", _redact(e))
        return {}


def download_file(file_id):
    try:
        info = api("getFile", file_id=file_id)
        path = info.get("result", {}).get("file_path")
        if not path:
            return None
        return requests.get(f"{FILE_API}/{path}", timeout=120).content
    except Exception as e:
        print("download err", _redact(e))
        return None


def notify(chat_id, text, markup=None):
    try:
        return send(chat_id, text, markup=markup)
    except Exception as e:
        print("notify err", e)
        return {}


def notify_edit(chat_id, msg_id, text, markup=None):
    try:
        return edit(chat_id, msg_id, text, markup=markup)
    except Exception as e:
        print("edit err", e)
        return {}


# ------------------------------------------------------------------ views ----
def records_for(chat_id, scan_id):
    """(records, label) for a saved scan or the all-time pool; (None, None) if gone."""
    if scan_id in ("pool", "P"):
        return VAULT.load_pool(), "all-time pool"
    data = VAULT.load_scan(chat_id, scan_id)
    if not data:
        return None, None
    return data.get("records", []), scan_id


def view_records(chat_id, scan_id):
    """Records with the current view's filters applied."""
    records, label = records_for(chat_id, scan_id)
    if records is None:
        return None, None
    view = get_view(chat_id, scan_id)
    return filter_records(records, view), label


# ---------------------------------------------------------------- rendering --
def keypad_text(records, source_label, page, pages, countries, view):
    total = len(records)
    by_status = Counter(r.get("st") for r in records)
    best = min((r.get("lat") for r in records
                if isinstance(r.get("lat"), (int, float))), default=None)
    lines = [
        f"✅ <b>Results</b> · <code>{esc(source_label)}</code>",
        f"Working proxies: <b>{total}</b> · countries: <b>{countries}</b>",
        f"🔒 {by_status.get('OK', 0)} anonymous · 🚩 {by_status.get('TRANSPARENT', 0)} "
        f"transparent · ⚠ {by_status.get('FLAGGED', 0)} flagged",
        f"⚡ fastest {short_lat(best)} · page {page + 1}/{max(pages, 1)}",
    ]
    head = view_header(view)
    if head:
        lines.append(f"🔎 filter: <b>{esc(head)}</b>")
    lines.append(f"<i>{TIER_LEGEND}</i>")
    return "\n".join(lines)


def keypad_markup(records, scan_id, page, view):
    groups = group_by_country(records)
    total = len(records)
    pages = max((len(groups) + PAGE_SIZE - 1) // PAGE_SIZE, 1)
    page = max(0, min(page, pages - 1))
    chunk = groups[page * PAGE_SIZE:page * PAGE_SIZE + PAGE_SIZE]

    rows, current = [], []
    for cc, recs in chunk:
        icon = tier_emoji(len(recs), total)
        current.append(btn(f"{icon} {label_of(cc)} · {len(recs)}", f"S|{scan_id}|{cc}"))
        if len(current) == 3:
            rows.append(current)
            current = []
    if current:
        rows.append(current)

    if pages > 1:
        rows.append(ui.row(
            btn("◀️", f"K|{scan_id}|{page - 1}") if page > 0 else btn("⏸", "noop"),
            btn(f"{page + 1}/{pages}", "noop"),
            btn("▶️", f"K|{scan_id}|{page + 1}") if page < pages - 1 else btn("⏸", "noop"),
        ))
    rows.append(ui.row(btn(f"🌍 All countries ({total})", f"A|{scan_id}")))
    return {"inline_keyboard": rows + [social_row()]}


SORT_LABEL = {"speed": "sorted fastest → slowest", "score": "sorted by score",
              "country": "sorted by country"}


def sort_records(records, view=None):
    """Order records the way the view asks for — one place, so the on-screen
    report, the keypad and the exported file can never disagree."""
    sort = (view or {}).get("sort", "speed")
    lat = lambda r: r.get("lat") if isinstance(r.get("lat"), (int, float)) else 9e9
    if sort == "score":
        return sorted(records, key=lambda r: (-(r.get("sc") or 0), lat(r)))
    if sort == "country":
        return sorted(records, key=lambda r: (str(r.get("cc") or UNKNOWN_CC), lat(r)))
    return sorted(records, key=lat)


def ranked_lines(records, top_n=TOP_N, view=None):
    rows = sort_records(records, view)
    out = []
    for i, r in enumerate(rows[:top_n], 1):
        cc = country_of(r)
        place = f"{flag_emoji(cc)}{cc}"
        raw = str(r.get("raw", ""))
        if len(raw) > 46:
            raw = raw[:43] + "..."
        out.append(f"{i:>3} {raw:<46} {place:<5} {short_lat(r.get('lat')):>7} "
                   f"{r.get('sc', 0):>3}/100 {STATUS_ICON.get(r.get('st'), '✔')}")
    return out, len(rows)


def report_text(records, source_label, view, judge_warning=None):
    rows, total = ranked_lines(records, view=view)
    groups = group_by_country(records)
    shown = groups[:12]
    countries = " · ".join(f"{label_of(cc)} {len(recs)}" for cc, recs in shown)
    if len(groups) > len(shown):
        countries += f" · +{len(groups) - len(shown)} more"
    head = [
        f"🏆 <b>Full report</b> — {total} working proxies · <code>{esc(source_label)}</code>",
        f"📊 {SORT_LABEL.get(view.get('sort', 'speed'), 'sorted fastest → slowest')}"
        f" (score = speed × anonymity)",
    ]
    if judge_warning:
        head.append(judge_warning)
    head += ["", f"🌍 <b>Countries ({len(groups)})</b>", esc(countries), ""]
    if records:
        best = sort_records(records, view)[0]
        best_label = "🥇 Best score:" if view.get("sort") == "score" else "🥇 Fastest:"
        head.append(f"{best_label} <code>{esc(short_raw(best.get('raw')))}</code> · "
                    f"{short_lat(best.get('lat'))} · score <b>{best.get('sc', 0)}/100</b> · "
                    f"{esc(country_name_of(country_of(best), records))}")
        head.append("")
    head.append(f"<b>Top {len(rows)} of {total}</b>")
    table = "\n".join(esc(r) for r in _fit_lines(rows, budget=3400))
    tail = "\n\n📄 Full ranked list in <code>report.txt</code>"
    return "\n".join(head) + f"<pre>{table}</pre>" + tail


def _toggle_row(scan_id, view):
    def t(label, field, active):
        return btn(("✅ " if active else "") + label, f"T|{scan_id}|{field}")

    score = view.get("min_score")
    lat = view.get("max_lat")
    top = view.get("top")
    return ui.row(
        t(f"⭐ ≥{score}" if score else "⭐ ≥70", "score", bool(score)),
        t("🔒 anon", "anon", view.get("only_anon")),
        t(f"⚡ ≤{lat:.0f}ms" if lat else "⚡ fast", "fast", bool(lat)),
        t(f"top {top}" if top else "top 10", "top", bool(top)),
    )


def _toggle_row2(scan_id, view):
    sort_now = view.get("sort", "speed")
    return ui.row(
        btn(f"🔌 {view.get('proto') or 'proto'}", f"T|{scan_id}|proto"),
        btn(f"↕️ {sort_now}", f"T|{scan_id}|sort"),
        btn(("✅ " if view.get("hide_leaks", True) else "🚩 ") + "no leaks",
            f"T|{scan_id}|leaks"),
        btn("↺ reset", f"T|{scan_id}|reset"),
    )


def report_markup(scan_id, view):
    return keyboard(
        ui.row(btn("📄 report.txt", f"F|{scan_id}"),
               btn("🌍 all .txt", f"A|{scan_id}"),
               btn("🔙 Countries", f"K|{scan_id}|0")),
        ui.row(*[btn(f"📦 {formats.FORMAT_LABELS[f]}", f"X|{scan_id}|{f}")
                 for f in ("ip:port", "user:pass@host:port", "url", "json")]),
        _toggle_row(scan_id, view),
        _toggle_row2(scan_id, view),
    )


def country_caption(cc, recs, scan_id, view):
    by_status = Counter(r.get("st") for r in recs)
    protos = Counter(r.get("proto") for r in recs)
    lats = [r["lat"] for r in recs if isinstance(r.get("lat"), (int, float))]
    scores = [r.get("sc", 0) for r in recs]
    avg = int(round(sum(scores) / len(scores))) if scores else 0
    name = country_name_of(cc, recs)
    title = f"{flag_emoji(cc)} <b>{esc(name)}</b>" if not is_unknown(cc) else f"<b>{esc(name)}</b>"
    proto_txt = " · ".join(f"{k} {v}" for k, v in protos.most_common()) or "n/a"
    return (
        f"{title}\n"
        f"<b>{len(recs)}</b> proxies · ⚡ {short_lat(min(lats) if lats else None)} → "
        f"{short_lat(max(lats) if lats else None)}\n"
        f"⭐ avg score <b>{avg}/100</b> · 🔌 {esc(proto_txt)}\n"
        f"🔒 {by_status.get('OK', 0)} anonymous · 🚩 {by_status.get('TRANSPARENT', 0)} "
        f"transparent · ⚠ {by_status.get('FLAGGED', 0)} flagged\n"
        f"📦 <code>{esc(view.get('fmt', 'raw'))}</code> · "
        f"💾 <code>{esc(scan_id)}</code>"
    )


def country_markup(scan_id, cc, view):
    fmt = view.get("fmt", "raw")
    fmt_row = ui.row(*[
        btn(("✅" if fmt == f else "") + formats.FORMAT_LABELS[f], f"X|{scan_id}|{f}")
        for f in ("raw", "ip:port", "user:pass@host:port", "url", "json")])
    return keyboard(
        ui.row(btn("📋 Copy", f"C|{scan_id}|{cc}"),
               btn("📄 .txt", f"S|{scan_id}|{cc}"),
               btn("🧾 Report", f"R|{scan_id}|{cc}")),
        fmt_row,
        ui.row(btn("🔁 Re-verify", f"RE|{scan_id}|{cc}"),
               btn(("✅ " if view.get("hide_leaks", True) else "🚩 ") + "no leaks",
                   f"T|{scan_id}|leaks"),
               btn("🔙 Countries", f"K|{scan_id}|0")),
    )


# ------------------------------------------------------------------ churn ----
def chunk_lines(lines, per_msg=COPY_LINES_PER_MSG, max_chars=3200):
    chunks, cur, size = [], [], 0
    for ln in lines:
        if len(ln) > MAX_COPY_LINE:
            ln = ln[:MAX_COPY_LINE - 3] + "..."
        elen = len(esc(ln)) + 1
        if cur and (size + elen > max_chars or len(cur) >= per_msg):
            chunks.append(cur)
            cur, size = [], 0
        cur.append(ln)
        size += elen
    if cur:
        chunks.append(cur)
    return chunks


def extract_lines(raw_bytes=None, filename="", text=""):
    lines = []
    if text:
        lines += [ln for ln in text.splitlines() if ln.strip()]
    if raw_bytes is not None:
        if filename.lower().endswith(".zip"):
            try:
                with zipfile.ZipFile(io.BytesIO(raw_bytes)) as z:
                    for name in z.namelist():
                        if name.lower().endswith(".txt"):
                            lines += [ln for ln in z.read(name).decode("utf-8", "ignore").splitlines()
                                      if ln.strip()]
            except zipfile.BadZipFile:
                pass
        else:
            lines += [ln for ln in raw_bytes.decode("utf-8", "ignore").splitlines() if ln.strip()]
    return lines


def fetch_real_ip():
    """This host's own IP, via the judge pool (so transparent proxies stand out)."""
    judge = JUDGE_OVERRIDE or JUDGES.pick()
    try:
        status, body = bounded_get(judge, min(TIMEOUT, 6))
        if status == 200:
            ip = extract_ip(body)
            if ip:
                return ip
    except Exception:
        pass
    return None


def classify_status(exit_ip, real_ip):
    """TRANSPARENT only on an *exact* match — substring matching used to flag
    1.2.3.45 as transparent when your real IP was 1.2.3.4."""
    if not exit_ip:
        return "FLAGGED"
    real = clean_ip(real_ip)
    if not real:
        # We never learned our own IP, so we cannot claim this proxy is anonymous.
        return "UNKNOWN"
    if clean_ip(exit_ip) == real:
        return "TRANSPARENT"
    return "OK"


# -------------------------------------------------------------------- job ----
def _show_keypad(chat_id, scan_id, page=0, msg_id=None):
    records, label = view_records(chat_id, scan_id)
    if records is None:
        text = "⚠️ That scan is no longer in the vault."
        return notify_edit(chat_id, msg_id, text) if msg_id else notify(chat_id, text)
    if not records:
        text = "📭 Nothing matches the current filter."
        return notify_edit(chat_id, msg_id, text) if msg_id else notify(chat_id, text)
    view = get_view(chat_id, scan_id)
    groups = group_by_country(records)
    pages = max((len(groups) + PAGE_SIZE - 1) // PAGE_SIZE, 1)
    page = max(0, min(page, pages - 1))
    text = keypad_text(records, label, page, pages, len(groups), view)
    markup = keypad_markup(records, scan_id, page, view)
    if msg_id:
        notify_edit(chat_id, msg_id, text, markup)
        set_view(chat_id, scan_id, keypad_msg=msg_id)
    else:
        res = notify(chat_id, text, markup=markup)
        mid = (res.get("result") or {}).get("message_id")
        if mid:
            set_view(chat_id, scan_id, keypad_msg=mid)


def _send_report_message(chat_id, records, label, scan_id, msg_id=None,
                         judge_warning=None):
    view = get_view(chat_id, scan_id)
    text = report_text(records, label, view, judge_warning=judge_warning)
    markup = report_markup(scan_id, view)
    if msg_id:
        notify_edit(chat_id, msg_id, text, markup)
    else:
        res = notify(chat_id, text, markup=markup)
        mid = (res.get("result") or {}).get("message_id")
        if mid:
            set_view(chat_id, scan_id, report_msg=mid)


def _refresh_panels(chat_id, scan_id):
    """Re-render the report + keypad after a filter/format change."""
    view = get_view(chat_id, scan_id)
    records, label = view_records(chat_id, scan_id)
    if records is None:
        return
    if view.get("report_msg"):
        _send_report_message(chat_id, records, label, scan_id,
                             msg_id=view["report_msg"])
    if view.get("keypad_msg"):
        _show_keypad(chat_id, scan_id, 0, msg_id=view["keypad_msg"])


def run_job(chat_id, lines):
    """Entry point used by the queue: parse, check, geolocate, save, report."""
    try:
        _run_job(chat_id, lines)
    except Exception as e:
        print("job err", type(e).__name__, e)
        notify(chat_id, "⚠️ That job failed unexpectedly. Please try again.")


def _run_job(chat_id, lines, threads=None):
    threads = threads or min(THREADS_CAP, QUEUE.threads_for_job())
    parsed, seen = [], set()
    for ln in lines:
        p = parse_proxy(ln, default_proto="http" if PROTO == "auto" else PROTO)
        if not p:
            continue
        key = (p["host"], p["port"], p["user"])
        if key in seen:
            continue
        seen.add(key)
        parsed.append(p)
        if len(parsed) >= MAX_PROXIES:
            break

    total = len(parsed)
    if total == 0:
        notify(chat_id, "⚠️ Invalid Format . Check the format and try again.")
        return

    JUDGES.maybe_refresh()
    real_ip = fetch_real_ip()
    backend = resolve_engine(ENGINE_MODE)

    # ---- live feed ----------------------------------------------------------
    per_proxy_msgs = STREAM_ENABLED and total <= STREAM_MAX
    feed_entries = deque(maxlen=FEED_LINES)
    msg_id = None
    if STREAM_ENABLED and not per_proxy_msgs:
        m = notify(chat_id, feed_text(0, total, 0, []))
        msg_id = (m.get("result") or {}).get("message_id")
    elif not STREAM_ENABLED:
        m = notify(chat_id, f"🔍 Checking <b>{total}</b> proxies...\n{bar(0, total)} 0%")
        msg_id = (m.get("result") or {}).get("message_id")

    # ---- geo resolved *while* checking (slice 3) ---------------------------
    pipeline = GeoPipeline(GEO, max_uncached=GEO_MAX).start() if GEO_ENABLED else None

    results, done, t0, last_edit = [], 0, time.time(), 0.0
    unreadable = [0]

    def on_result(idx, p, res, n_done, n_total):
        nonlocal done, last_edit
        ok, proto, latency, ip, err = res
        st = classify_status(ip, real_ip) if ok else None
        if ok and err == JUDGE_UNREADABLE:
            unreadable[0] += 1
        if ok:
            results.append((p, proto, latency, ip, st))
        if pipeline and ok and ip:
            pipeline.submit(ip)

        cc = ""
        if ok and ip and pipeline:
            cc = pipeline.cc_for(ip)
        elif ok and ip:
            cc = GEO.cached_cc(ip)
        line = feed_line(n_done, n_total, p["raw"], ok, latency, ip, err, st, cc)
        feed_entries.append((n_done, n_total, p["raw"], ok, latency, ip, err, st))
        done = n_done
        now = time.time()
        if per_proxy_msgs:
            notify(chat_id, f"<pre>{esc(line)}</pre>")
            if n_done < n_total:
                time.sleep(STREAM_MSG_DELAY)
            return
        if msg_id and (now - last_edit > STREAM_EDIT or n_done == n_total):
            last_edit = now
            elapsed = now - t0
            cpm = int(n_done / elapsed * 60) if elapsed > 0 else 0
            rate = n_done / elapsed if elapsed > 0 else 0
            eta = human_eta((n_total - n_done) / rate) if rate else None
            lookup = pipeline.cc_for if pipeline else GEO.cached_cc
            notify_edit(chat_id, msg_id,
                        feed_text(n_done, n_total, len(results),
                                  render_feed_lines(feed_entries, lookup),
                                  cpm=cpm, eta=eta))

    check_many(parsed, proto=PROTO, timeout=TIMEOUT, judge=JUDGE_OVERRIDE,
               judge_pool=None if JUDGE_OVERRIDE else JUDGES, threads=threads,
               on_result=on_result, engine=ENGINE_MODE, tcp_gate=True)
    elapsed = time.time() - t0

    geo_map = pipeline.close() if pipeline else {}

    # ---- annotate + save ----------------------------------------------------
    records = []
    for p, proto, latency, ip, st in results:
        lookup_ip = clean_ip(ip) or ""
        if not lookup_ip:
            cc, country = NO_IP_CC, NO_IP_NAME
        else:
            info = geo_map.get(lookup_ip) or {}
            cc = (info.get("cc") or UNKNOWN_CC)
            country = info.get("country") or UNKNOWN_NAME
        records.append({"raw": p["raw"], "proto": proto,
                        "lat": round(latency, 1) if latency is not None else None,
                        "ip": lookup_ip, "st": st, "cc": cc, "country": country,
                        "sc": score_of(latency, st)})
    records.sort(key=lambda r: r["lat"] if isinstance(r["lat"], (int, float)) else 9e9)

    # a lot of empty exit IPs = judge trouble, not proxy trouble
    judge_warning = JUDGES.status_line()
    if not judge_warning and results and unreadable[0] / max(1, len(results)) > JUDGE_WARN_RATIO:
        JUDGES.check_health(force=True)
        judge_warning = JUDGES.status_line()
    if not real_ip:
        # Without our own IP every proxy lands in UNKNOWN, so leak detection is
        # off for this run. Say so instead of presenting them as anonymous.
        anon_warning = ("❔ Could not determine this host's own IP — leak detection "
                        "is unavailable, so anonymous/transparent is unverified "
                        "(shown as ❔ UNKNOWN).")
        judge_warning = f"{judge_warning}\n{anon_warning}" if judge_warning else anon_warning

    scan_id = new_scan_id()
    meta = {"total": total, "valid": len(records), "elapsed": round(elapsed, 1),
            "real_ip": real_ip, "engine": backend, "threads": threads}
    saved = False
    try:
        VAULT.save_scan(chat_id, scan_id, records, meta)
        VAULT.push_pool(records)
        saved = True
    except Exception as e:
        print("vault err", e)

    by_proto = Counter(r["proto"] for r in records)
    by_status = Counter(r["st"] for r in records)
    groups = group_by_country(records)
    avg = int(round(sum(r.get("sc", 0) for r in records) / len(records))) if records else 0

    summary = (
        f"✅ <b>Done!</b> Checked: <b>{total}</b> → Valid: <b>{len(records)}</b>"
        f" · Dead: <b>{total - len(records)}</b>\n"
        f"🔒 anonymous: <b>{by_status.get('OK', 0)}</b> · "
        f"🚩 transparent: <b>{by_status.get('TRANSPARENT', 0)}</b> · "
        f"⚠ flagged: <b>{by_status.get('FLAGGED', 0)}</b>\n"
        f"🌍 countries: <b>{len(groups)}</b> · ⏱ {elapsed:.1f}s"
        f" · 🧵 {threads} · ⚙️ {backend}\n"
    )
    if by_proto:
        summary += "🔌 By protocol: " + ", ".join(f"{k}={v}" for k, v in by_proto.most_common()) + "\n"
    if records:
        f = records[0]
        summary += (f"⭐ avg score: <b>{avg}/100</b> · "
                    f"🥇 best: <b>{max(r.get('sc', 0) for r in records)}/100</b>\n"
                    f"⚡ Fastest: <code>{esc(short_raw(f['raw']))}</code> "
                    f"({short_lat(f['lat'])}) · {f['st']}\n")
    if judge_warning:
        summary += judge_warning + "\n"
    summary += (f"💾 Saved to vault · scan <code>{scan_id}</code>" if saved else
                "⚠️ <b>Could not save to the vault</b> — results below are still complete.")
    if msg_id:
        notify_edit(chat_id, msg_id, summary)
    else:
        send(chat_id, summary)

    if not records:
        notify(chat_id, "😕 No valid proxies this time.")
        return

    # ---- report, files, keypad ---------------------------------------------
    set_view(chat_id, scan_id)                 # fresh view for a fresh scan
    try:
        _send_report_message(chat_id, records, scan_id, scan_id,
                             judge_warning=judge_warning)
    except Exception as e:
        print("report err", e)

    view = get_view(chat_id, scan_id)
    exported = export_records(records, view)
    kb = keyboard()
    send_doc(chat_id, OK_FILE, formats.body_for(exported, view.get("fmt", "raw")),
             caption=f"💾 {len(exported)} proxies · {esc(formats.FORMAT_LABELS.get(view.get('fmt','raw'),'raw'))} "
                     f"· no IP leaks · @Poriot_ke", markup=kb)
    send_doc(chat_id, REPORT_FILE, "\n".join(report_lines(records)),
             caption="🏷 Full ranked report — country · speed · score · status", markup=kb)

    if not saved:
        notify(chat_id, "ℹ️ The country keypad needs the vault, so it is unavailable "
                        "for this scan — the report above is complete.")
        return

    try:
        _show_keypad(chat_id, scan_id, 0)
    except Exception as e:
        print("keypad err", e)


# --------------------------------------------------------------- senders -----
def _country_file(chat_id, scan_id, cc, as_report=False):
    records, label = records_for(chat_id, scan_id)
    if records is None:
        notify(chat_id, "⚠️ That scan is no longer in the vault.")
        return
    cc = safe_cc(cc)
    view = get_view(chat_id, scan_id)
    recs = [r for r in filter_records(records, view) if country_of(r) == cc]
    if not recs:
        notify(chat_id, f"⚠️ Nothing for {esc(label_of(cc))} under the current filter.")
        return
    fmt = view.get("fmt", "raw")
    if as_report:
        body = "\n".join(report_lines(recs))
        name = formats.filename("report", cc, "txt")
        cap = f"🧾 <b>{esc(country_name_of(cc, recs))}</b> · {len(recs)} proxies with status"
    else:
        exported = export_records(recs, view)
        dropped = len(recs) - len(exported)
        body = formats.body_for(exported, fmt)
        name = formats.filename("proxies", cc, fmt)
        cap = country_caption(cc, exported, scan_id, view)
        if dropped:
            cap += f"\n🚩 {dropped} IP-leaking proxies excluded (toggle 🚩 to include)"
    send_doc(chat_id, name, body, caption=cap, markup=country_markup(scan_id, cc, view))


def _all_file(chat_id, scan_id):
    records, label = records_for(chat_id, scan_id)
    if records is None:
        notify(chat_id, "⚠️ Nothing in the vault for that scan.")
        return
    view = get_view(chat_id, scan_id)
    exported = export_records(records, view)
    fmt = view.get("fmt", "raw")
    send_doc(chat_id, formats.filename("approved", None, fmt),
             formats.body_for(exported, fmt),
             caption=f"🌍 All {len(exported)} proxies ({esc(label)}) · "
                     f"{esc(formats.FORMAT_LABELS.get(fmt, fmt))}",
             markup=keyboard(ui.row(btn("🔙 Countries", f"K|{scan_id}|0"))))


def _ranked_file(chat_id, scan_id):
    records, label = records_for(chat_id, scan_id)
    if records is None:
        notify(chat_id, "⚠️ Nothing in the vault for that scan.")
        return
    view = get_view(chat_id, scan_id)
    shown = filter_records(records, view)
    send_doc(chat_id, REPORT_FILE, "\n".join(report_lines(shown)),
             caption=f"🏆 Ranked report — <b>{len(shown)}</b> proxies, fastest first "
                     f"({esc(label)})",
             markup=keyboard(ui.row(btn("🔙 Countries", f"K|{scan_id}|0"))))


def _copy_text(chat_id, scan_id, cc):
    records, label = records_for(chat_id, scan_id)
    if records is None:
        notify(chat_id, "⚠️ That scan is no longer in the vault.")
        return
    cc = safe_cc(cc)
    view = get_view(chat_id, scan_id)
    recs = [r for r in export_records(records, view) if country_of(r) == cc]
    if not recs:
        notify(chat_id, f"⚠️ Nothing to copy for {esc(label_of(cc))}.")
        return
    fmt = view.get("fmt", "raw")
    lines = formats.format_lines(recs, fmt) if fmt != "json" else \
        [json.dumps(formats.format_record(r, "json"), ensure_ascii=False) for r in recs]
    chunks = chunk_lines(lines)
    shown = chunks[:COPY_MAX_MSGS]
    header = (f"📋 <b>{esc(country_name_of(cc, recs))}</b> · {len(lines)} proxies "
              f"· <code>{esc(fmt)}</code>\n<i>Tap the block to copy</i>")
    for i, chunk in enumerate(shown):
        text = header if i == 0 else f"<i>…continued ({i + 1}/{len(chunks)})</i>"
        send(chat_id, text + "\n<pre>" + esc("\n".join(chunk)) + "</pre>")
    if len(chunks) > len(shown):
        rest = sum(len(c) for c in chunks) - sum(len(c) for c in shown)
        send(chat_id, f"➕ {rest} more not shown — use the 📄 .txt button.",
             markup=country_markup(scan_id, cc, view))


def _recheck(chat_id, scan_id, cc, limit=RECHECK_LIMIT):
    records, label = records_for(chat_id, scan_id)
    if records is None:
        notify(chat_id, "⚠️ That scan is no longer in the vault.")
        return
    cc = safe_cc(cc)
    view = get_view(chat_id, scan_id)
    recs = [r for r in filter_records(records, view) if country_of(r) == cc][:limit]
    if not recs:
        notify(chat_id, "⚠️ Nothing to re-verify for that country.")
        return

    m = notify(chat_id, f"🔁 Re-verifying <b>{len(recs)}</b> proxies "
                        f"({esc(label_of(cc))})...")
    msg_id = (m.get("result") or {}).get("message_id")

    parsed = []
    for r in recs:
        p = parse_proxy(str(r.get("raw", "")))
        parsed.append(p if p else None)
    real_ip = fetch_real_ip()
    checked = check_many([p for p in parsed if p], proto=PROTO, timeout=TIMEOUT,
                         judge=JUDGE_OVERRIDE,
                         judge_pool=None if JUDGE_OVERRIDE else JUDGES,
                         threads=min(THREADS_CAP, 40), engine=ENGINE_MODE)
    by_raw = {p["raw"]: res for p, res in zip([p for p in parsed if p], checked)}

    updated, alive = [], 0
    for src in recs:
        raw = str(src.get("raw", ""))
        ok, proto, latency, ip, err = by_raw.get(raw, (False, None, None, None, "Unparseable"))
        if not ok:
            updated.append({"raw": raw, "lat": None, "ip": "", "st": "DEAD",
                            "cc": src.get("cc") or NO_IP_CC,
                            "country": src.get("country"), "sc": 0})
            continue
        alive += 1
        st = classify_status(ip, real_ip)
        lookup_ip = clean_ip(ip) or ""
        cc_new = src.get("cc") if lookup_ip else NO_IP_CC
        country = src.get("country") if lookup_ip else NO_IP_NAME
        updated.append({"raw": raw, "lat": round(latency, 1), "ip": lookup_ip,
                        "st": st, "cc": cc_new, "country": country,
                        "sc": score_of(latency, st)})

    updated.sort(key=lambda r: r["lat"] if isinstance(r["lat"], (int, float)) else 9e9)

    # re-resolve the *new* exit IPs: a proxy can come back from another country
    new_ips = [u["ip"] for u in updated if u["st"] != "DEAD" and u.get("ip")]
    geo = {}
    if GEO_ENABLED and new_ips:
        try:
            geo = GEO.lookup(new_ips, max_uncached=len(new_ips) + 1)
        except Exception as e:
            print("recheck geo err", e)
    for u in updated:
        if u["st"] == "DEAD" or not u.get("ip"):
            continue
        info = geo.get(u["ip"]) or {}
        if info.get("cc"):
            u["cc"] = info["cc"]
            u["country"] = info.get("country") or UNKNOWN_NAME
        elif not u.get("country"):
            u["cc"], u["country"] = UNKNOWN_CC, UNKNOWN_NAME

    try:
        VAULT.update_records(scan_id, updated)
        VAULT.push_pool([u for u in updated if u["st"] != "DEAD"])
    except Exception as e:
        print("recheck save err", e)

    alive_rows = [u for u in updated if u["st"] != "DEAD"]
    text = (f"🔁 <b>Re-verified</b> {len(recs)} proxies ({esc(label_of(cc))})\n"
            f"✅ still alive: <b>{alive}</b> · ❌ dead: <b>{len(recs) - alive}</b>")
    if alive_rows:
        text += (f"\n⚡ fastest now: <code>{esc(short_raw(alive_rows[0]['raw']))}</code> "
                 f"{short_lat(alive_rows[0]['lat'])} · score <b>{alive_rows[0]['sc']}/100</b>")
    text += "\n💾 Vault + pool updated."
    if msg_id:
        notify_edit(chat_id, msg_id, text,
                    markup=keyboard(ui.row(btn("🔙 Countries", f"K|{scan_id}|0"))))
    else:
        notify(chat_id, text)


# -------------------------------------------------------------- callbacks ----
def handle_callback(cb):
    cid = (cb.get("message") or {}).get("chat", {}).get("id")
    msg_id = (cb.get("message") or {}).get("message_id")
    data = cb.get("data", "") or ""
    api("answerCallbackQuery", callback_query_id=cb["id"])
    if not cid:
        return

    if data in ("noop",):
        return
    if data in ("channel", "dev"):
        label = "Channel" if data == "channel" else "Dev"
        value = CHANNEL if data == "channel" else DEV
        kind, target = button_target(value)
        if kind == "id":
            api("sendMessage", chat_id=target,
                text=f"🔔 Someone tapped <b>{label}</b> in the bot!", parse_mode="HTML")
            send(cid, f"📬 <b>{label}</b> notified. Thanks for your interest!")
        else:
            send(cid, CHANNEL_MSG if data == "channel" else DEV_MSG)
        return

    parts = data.split("|")
    action = parts[0]
    try:
        if action == "K":
            _show_keypad(cid, parts[1], int(parts[2]), msg_id=msg_id)
        elif action == "S":
            _country_file(cid, parts[1], parts[2])
        elif action == "R":
            _country_file(cid, parts[1], parts[2], as_report=True)
        elif action == "C":
            _copy_text(cid, parts[1], parts[2])
        elif action == "A":
            _all_file(cid, parts[1])
        elif action == "F":
            _ranked_file(cid, parts[1])
        elif action == "V":
            _show_keypad(cid, parts[1], 0)
        elif action == "P":
            _show_keypad(cid, "pool", 0)
        elif action == "X":
            set_view(cid, parts[1], fmt=parts[2] if parts[2] in formats.FORMATS else "raw")
            _refresh_panels(cid, parts[1])
        elif action == "T":
            _toggle_filter(cid, parts[1], parts[2])
        elif action == "RE":
            _queue_recheck(cid, parts[1], parts[2])
    except Exception as e:
        print("callback err", data, type(e).__name__, e)
        notify(cid, "⚠️ Something went wrong with that button. Try again.")


def _toggle_filter(chat_id, scan_id, field):
    if field == "reset":
        reset_view(chat_id, scan_id)
    elif field == "anon":
        toggle(chat_id, scan_id, "only_anon")
    elif field == "leaks":
        toggle(chat_id, scan_id, "hide_leaks")
    elif field == "fast":
        toggle(chat_id, scan_id, "max_lat", None, 500, 1000, 2000)
    elif field == "proto":
        toggle(chat_id, scan_id, "proto", None, "http", "socks5", "socks4")
    elif field == "score":
        toggle(chat_id, scan_id, "min_score", None, 70, 40, 85)
    elif field == "top":
        toggle(chat_id, scan_id, "top", None, 10, 50)
    elif field == "sort":
        toggle(chat_id, scan_id, "sort", "speed", "score", "country")
    _refresh_panels(chat_id, scan_id)


def _queue_recheck(chat_id, scan_id, cc):
    job_id = f"re{new_scan_id()}"

    def work(threads):
        try:
            _recheck(chat_id, scan_id, cc, limit=min(RECHECK_LIMIT, max(8, threads)))
        except Exception as e:
            print("recheck err", type(e).__name__, e)
            notify(chat_id, "⚠️ Re-verify failed unexpectedly. Please try again.")

    state = QUEUE.submit(chat_id, job_id, work)
    if state == "queued":
        pos = QUEUE.position(chat_id, job_id)
        notify(chat_id, f"⏳ Queued (position {pos}) — one scan at a time per chat.")


# --------------------------------------------------------------- commands ----
def show_vault(chat_id):
    scans = VAULT.list_scans(chat_id, limit=5)
    pool = VAULT.pool_size()
    pool_countries = len(VAULT.pool_countries())
    lines = ["💾 <b>Vault</b>", ""]
    rows = []
    if pool:
        lines.append(f"🌍 All-time pool: <b>{pool}</b> proxies across "
                     f"<b>{pool_countries}</b> countries")
        rows.append(ui.row(btn(f"🌍 Browse all-time pool ({pool})", "P")))
    else:
        lines.append("🌍 All-time pool: empty")

    if scans:
        lines += ["", "🗂 <b>Recent scans</b> (tap to reopen)"]
        for s in scans:
            when = time.strftime("%Y-%m-%d %H:%M", time.localtime(s.get("ts", 0)))
            cc_counts = s.get("countries") or {}
            top = ""
            if cc_counts:
                cc, n = next(iter(cc_counts.items()))
                top = f" · top {label_of(cc)} {n}"
            lines.append(f"• <code>{esc(s.get('scan_id'))}</code> — {when} · "
                         f"<b>{s.get('valid', 0)}</b> valid{top}")
            rows.append(ui.row(btn(f"📂 {when} · {s.get('valid', 0)} valid",
                                   f"V|{s.get('scan_id')}")))
    else:
        lines += ["", "No scans saved yet — send a proxy file and reply with <code>/mpx</code>."]
    notify(chat_id, "\n".join(lines), markup=keyboard(*rows))


def latest_scan_id(chat_id):
    scans = VAULT.list_scans(chat_id, limit=1)
    if scans:
        return scans[0].get("scan_id")
    if VAULT.pool_size():
        return "pool"
    return None


def _start_job(chat_id, lines):
    job_id = new_scan_id()

    def work(threads):
        try:
            _run_job(chat_id, lines, threads=min(THREADS_CAP, threads))
        except Exception as e:
            print("job err", type(e).__name__, e)
            notify(chat_id, "⚠️ That job failed unexpectedly. Please try again.")

    state = QUEUE.submit(chat_id, job_id, work)
    if state == "queued":
        pos = QUEUE.position(chat_id, job_id)
        notify(chat_id, f"⏳ Another scan is running — queued (position {pos}).")


def handle_update(upd):
    cb = upd.get("callback_query")
    if cb:
        handle_callback(cb)
        return

    msg = upd.get("message") or upd.get("channel_post")
    if not msg:
        return
    chat_id = msg["chat"]["id"]
    text = msg.get("text", "") or msg.get("caption", "")
    stripped = text.strip()

    if stripped.startswith("/start") or stripped.startswith("/help"):
        send(chat_id, BANNER)
        return

    if stripped == "/cancel":
        dropped = QUEUE.cancel_waiting(chat_id)
        send(chat_id, f"🗑 Dropped <b>{dropped}</b> queued scan(s). "
                      f"Running scans are not affected." if dropped
             else "Nothing queued for this chat.")
        return

    if stripped == "/countries":
        scan_id = latest_scan_id(chat_id)
        if not scan_id:
            send(chat_id, "📭 Nothing in the vault yet — run a scan first.")
            return
        _show_keypad(chat_id, scan_id, 0)
        return

    if stripped == "/vault":
        show_vault(chat_id)
        return

    if stripped == "/pool":
        if not VAULT.pool_size():
            send(chat_id, "📭 The all-time pool is empty — run a scan first.")
            return
        _show_keypad(chat_id, "pool", 0)
        return

    if stripped == "/mpx":
        reply = msg.get("reply_to_message") or {}
        doc = reply.get("document") or {}
        name = doc.get("file_name", "")
        if not doc or not name.lower().endswith((".txt", ".zip")):
            send(chat_id, "⚠️ <b>Reply to an uploaded <code>.txt</code>/<code>.zip</code> "
                          "file with <code>/mpx</code>.</b>\n\n"
                          "1. Upload your proxy file\n2. Tap it → Reply → <code>/mpx</code>")
            return
        data = download_file(doc["file_id"])
        if not data:
            send(chat_id, "⚠️ Could not download the file. Try uploading it again.")
            return
        lines = extract_lines(raw_bytes=data, filename=name)
        if not lines:
            send(chat_id, "⚠️ No proxies found in that file.")
            return
        _start_job(chat_id, lines)
        return

    if "document" in msg:
        doc = msg["document"]
        name = doc.get("file_name", "")
        if name.lower().endswith((".txt", ".zip")):
            send(chat_id, "📄 File received! Reply to it with <code>/mpx</code> to start checking.")
        else:
            send(chat_id, "⚠️ Please send a <code>.txt</code> or <code>.zip</code> file.")
        return

    if stripped and not stripped.startswith("/"):
        lines = extract_lines(text=text)
        if lines:
            _start_job(chat_id, lines)


def poll_error_action(error_code, conflicts):
    """Decide what to do with a failed getUpdates response.

    Returns (action, sleep_seconds, conflicts) where action is "retry" or "exit".
    Telegram returns failures as a body (ok=false, error_code=...), so a 409 from
    a second instance used to look like "no updates" and spin the loop flat out.
    """
    if error_code == 409:
        conflicts += 1
        if conflicts >= 5:
            return "exit", 0, conflicts
        return "retry", min(5 * conflicts, 30), conflicts
    if error_code in (401, 403):
        return "exit", 0, conflicts
    return "retry", 3, conflicts


def main():
    print("PROXY CHECKER TELEGRAM BOT running. Press Ctrl+C to stop.")
    print(f"vault={VAULT_DIR} ({VAULT.pool_size()} pooled) · engine={resolve_engine(ENGINE_MODE)} "
          f"· geo={'on' if GEO_ENABLED else 'off'} · jobs={MAX_JOBS} · "
          f"threads={GLOBAL_THREADS}")
    JUDGES.check_health_async()
    # No drop_pending_updates: the default is false, and passing the *string*
    # "false" risked being coerced truthy (silently discarding updates) or being
    # rejected invisibly.
    api("deleteWebhook")
    offset = None
    conflicts = 0
    while True:
        try:
            r = requests.get(f"{API}/getUpdates",
                             params={"timeout": 30, "offset": offset}, timeout=40).json()

            # Telegram reports failures as a JSON *body* (ok=false, error_code=...),
            # not an exception. Without this check a 409 (another instance or a
            # rolling deploy's overlap) silently yields no updates and the loop
            # re-polls in a tight loop — the process stays alive and looks healthy
            # to the platform's restart policy while serving nobody.
            if not isinstance(r, dict) or not r.get("ok", True):
                code = r.get("error_code") if isinstance(r, dict) else None
                desc = r.get("description", "") if isinstance(r, dict) else ""
                action, wait, conflicts = poll_error_action(code, conflicts)
                if action == "exit":
                    print(f"fatal poll error {code}: {_redact(desc)} — exiting")
                    sys.exit(1)
                print("poll error", code, _redact(desc))
                time.sleep(wait)
                continue

            conflicts = 0
            for upd in r.get("result", []):
                offset = upd["update_id"] + 1
                try:
                    handle_update(upd)
                except Exception as e:
                    print("handler err", _redact(e))
        except KeyboardInterrupt:
            print("\nStopped.")
            break
        except Exception as e:
            print("poll err", _redact(e))
            time.sleep(3)


if __name__ == "__main__":
    main()
