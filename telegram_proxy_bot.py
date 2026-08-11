#!/usr/bin/env python3
"""
PROXY CHECKER TELEGRAM BOT  -  Credits: @Poriot_ke
Wraps proxy_checker.py behind a Telegram bot.

Commands:
    /start         Show bot title, features & usage
    /mpx           Reply to an uploaded .txt/.zip to start checking

Flow:
    1. Upload a .txt file with proxies (one per line)
    2. Reply to it with /mpx
    3. Bot checks concurrently with a live-updating progress message
    4. Results: approved.txt (working proxies) + report.txt (with status tags)

Every valid proxy is classified:
    OK          - exit IP differs from yours (anonymous)
    TRANSPARENT - exit IP equals your real IP (proxy leaks your address)
    FLAGGED     - anomaly (no exit IP / suspicious judge response)

Setup:
    export TELEGRAM_BOT_TOKEN="123456:ABC..."   # from @BotFather
    python3 telegram_proxy_bot.py

No external Telegram library required (uses the raw Bot API via requests).
"""
import io
import json
import os
import re
import sys
import time
import zipfile
import threading
import concurrent.futures as cf
from collections import Counter

import requests

# reuse the core checker logic
from proxy_checker import (
    parse_proxy, check_one, load_lines_from_text, PROTOS,
)

TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
if not TOKEN:
    sys.exit("ERROR: set TELEGRAM_BOT_TOKEN environment variable (get it from @BotFather).")

API = f"https://api.telegram.org/bot{TOKEN}"
FILE_API = f"https://api.telegram.org/file/bot{TOKEN}"

# tuning (override via env)
THREADS = int(os.environ.get("PC_THREADS", "150"))
TIMEOUT = int(os.environ.get("PC_TIMEOUT", "8"))
PROTO = os.environ.get("PC_PROTO", "auto")            # auto/http/https/socks4/socks5
JUDGE = os.environ.get("PC_JUDGE", "http://httpbin.org/ip")
MAX_PROXIES = int(os.environ.get("PC_MAX", "20000"))  # safety cap per job

# inline button targets — link (https://t.me/... or @username) opens the URL on tap;
# a numeric chat/user ID makes the button notify that chat when tapped.
CHANNEL = os.environ.get("PC_CHANNEL", "https://t.me/nativecodes").strip()
DEV = os.environ.get("PC_DEV", "https://t.me/Poriot_ke").strip()

OK_FILE = "approved.txt"      # clean list of working proxies
REPORT_FILE = "report.txt"    # same list with per-proxy status tags

BANNER = (
    "*🔐 PROXY CHECKER BOT*\n"
    "Fast concurrent proxy checker with live stats, "
    "transparency detection & clean export.\n\n"
    "*How to use*\n"
    "1️⃣ Upload a `.txt` file with proxies (one per line)\n"
    "2️⃣ Reply to it with `/mpx`\n"
    "3️⃣ Get live progress + `approved.txt` download\n\n"
    "💬 *Or* just paste proxies directly in chat.\n\n"
    "*Formats*\n"
    "`ip:port` · `ip:port:user:pass` · `user:pass:host:port` · `proto://ip:port` · `proto://user:pass@ip:port`\n\n"
    "*Protocols:* HTTP · HTTPS · SOCKS4 · SOCKS5\n"
    "*Accepts:* 📄 .txt · 📦 .zip · 💬 paste\n\n"
    "*Status tags* — every valid proxy is classified:\n"
    "✔ `OK` · 🚩 `TRANSPARENT` (leaks your IP) · ⚠ `FLAGGED`\n\n"
    "*Commands:* `/start` · `/mpx`\n"
    "📢 Dev: @nativecodes\n"
    "_Reply to an uploaded file with /mpx to begin_ ↓"
)

CHANNEL_MSG = (
    "📢 *Channel*\n\n"
    "Thanks for your interest — stay tuned for updates and more tools! ❤️"
)

DEV_MSG = (
    "👨\u200d💻 *Dev*\n\n"
    "@Poriot_ke\n"
    "🔗 [GitHub](https://github.com/ashyamctommy-eng/Proxycheckerbot)\n\n"
    "Found a bug or want a feature? Open an issue!"
)


def button_target(value):
    """Classify a configured target -> ('url', link) | ('id', chat_id) | ('msg', None)."""
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


def results_keyboard():
    """Inline buttons on result files — 📢 Channel + 👨💻 Dev.

    A link (or @username) becomes a URL button that opens on tap;
    a numeric chat/user ID becomes a callback button that notifies that chat.
    """
    def key(label, value, callback):
        kind, _ = button_target(value)
        if kind == "url":
            return {"text": label, "url": button_target(value)[1]}
        return {"text": label, "callback_data": callback}

    return {"inline_keyboard": [[
        key("📢 Channel", CHANNEL, "channel"),
        key("👨\u200d💻 Dev", DEV, "dev"),
    ]]}


# ---------------------------------------------------------------- telegram ---
def api(method, **params):
    try:
        r = requests.post(f"{API}/{method}", data=params, timeout=60)
        return r.json()
    except Exception as e:
        print("api err", method, e)
        return {}


def send(chat_id, text, **kw):
    return api("sendMessage", chat_id=chat_id, text=text,
               parse_mode="Markdown", disable_web_page_preview=True, **kw)


def edit(chat_id, msg_id, text):
    return api("editMessageText", chat_id=chat_id, message_id=msg_id,
               text=text, parse_mode="Markdown", disable_web_page_preview=True)


def send_doc(chat_id, filename, data: bytes, caption="", markup=None):
    files = {"document": (filename, io.BytesIO(data))}
    data = {"chat_id": chat_id, "caption": caption}
    if markup:
        data["reply_markup"] = json.dumps(markup)
    return requests.post(f"{API}/sendDocument",
                         data=data, files=files, timeout=120).json()


def download_file(file_id):
    info = api("getFile", file_id=file_id)
    path = info.get("result", {}).get("file_path")
    if not path:
        return None
    return requests.get(f"{FILE_API}/{path}", timeout=120).content


# ---------------------------------------------------------------- job logic --
def extract_lines(raw_bytes=None, filename="", text=""):
    lines = []
    if text:
        lines += load_lines_from_text(text)
    if raw_bytes is not None:
        if filename.lower().endswith(".zip"):
            try:
                with zipfile.ZipFile(io.BytesIO(raw_bytes)) as z:
                    for name in z.namelist():
                        if name.lower().endswith(".txt"):
                            lines += load_lines_from_text(
                                z.read(name).decode("utf-8", "ignore"))
            except zipfile.BadZipFile:
                pass
        else:  # treat as text/.txt
            lines += load_lines_from_text(raw_bytes.decode("utf-8", "ignore"))
    return lines


def fetch_real_ip(judge, timeout):
    """Fetch our own IP directly (no proxy) so we can spot transparent proxies."""
    try:
        r = requests.get(judge, timeout=timeout,
                         headers={"User-Agent": "proxy-checker/1.0"})
        if r.status_code == 200:
            try:
                origin = str(r.json().get("origin", "")).strip()
                if origin:
                    return origin.split(",")[0].strip()
            except Exception:
                m = re.search(r"\d+\.\d+\.\d+\.\d+", r.text)
                if m:
                    return m.group(0)
    except Exception:
        pass
    return None


def classify_status(exit_ip, real_ip):
    """OK / TRANSPARENT / FLAGGED for a valid proxy."""
    if not exit_ip:
        return "FLAGGED"
    if real_ip and real_ip in exit_ip:
        return "TRANSPARENT"
    return "OK"


def bar(done, total, width=18):
    filled = int(width * done / total) if total else width
    return "▰" * filled + "▱" * (width - filled)


def run_job(chat_id, lines):
    # parse + dedupe
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
        send(chat_id, "⚠️ Invalid Format . Check the format and try again.")
        return

    real_ip = fetch_real_ip(JUDGE, min(TIMEOUT, 5))

    m = send(chat_id, f"🔍 Checking *{total}* proxies...\n{bar(0, total)} 0%")
    msg_id = m.get("result", {}).get("message_id")

    results, done, t0, last_edit = [], 0, time.time(), 0.0
    with cf.ThreadPoolExecutor(max_workers=THREADS) as ex:
        futs = {ex.submit(check_one, p, PROTO, TIMEOUT, JUDGE): p for p in parsed}
        for fut in cf.as_completed(futs):
            p = futs[fut]
            ok, proto, latency, ip, err = fut.result()
            if ok:
                results.append((p, proto, latency, ip))
            done += 1
            now = time.time()
            # edit at most ~every 2s to respect Telegram rate limits
            if msg_id and (now - last_edit > 2 or done == total):
                last_edit = now
                pct = int(done / total * 100)
                cpm = int(done / (now - t0) * 60) if now > t0 else 0
                edit(chat_id, msg_id,
                     f"🔍 Checking *{total}* proxies...\n"
                     f"{bar(done, total)} {pct}%\n"
                     f"✅ valid: *{len(results)}*  |  ⚡ CPM: {cpm}")

    # classify + speed-sort
    tagged = [(p, proto, latency, ip, classify_status(ip, real_ip))
              for p, proto, latency, ip in results]
    tagged.sort(key=lambda r: r[2])
    elapsed = time.time() - t0
    by_proto = Counter(r[1] for r in tagged)
    by_status = Counter(r[4] for r in tagged)

    summary = (
        "✅ *Done!* "
        f"Checked: *{total}*  →  Valid: *{len(tagged)}*  ·  Dead: *{total - len(tagged)}*\n"
        f"✔ anonymous: *{by_status.get('OK', 0)}*\n"
        f"🚩 transparent: *{by_status.get('TRANSPARENT', 0)}*\n"
        f"⚠ flagged: *{by_status.get('FLAGGED', 0)}*\n"
        f"⏱ Time: {elapsed:.1f}s\n"
    )
    if by_proto:
        summary += "By protocol: " + ", ".join(f"{k}={v}" for k, v in by_proto.items()) + "\n"
    if tagged:
        f = tagged[0]
        summary += f"Fastest: `{f[0]['raw']}` ({f[2]:.0f} ms) · {f[4]}"
    if msg_id:
        edit(chat_id, msg_id, summary)
    else:
        send(chat_id, summary)

    if not tagged:
        send(chat_id, "😕 No valid proxies this time.")
        return

    # output preserves each line's original input format (no normalization)
    ok_lines = "\n".join(p["raw"] for p, proto, _, _, _ in tagged)
    report_lines = "\n".join(
        f"{p['raw']}  {status} {latency:.0f} ms"
        for p, proto, latency, _, status in tagged)

    kb = results_keyboard()
    send_doc(chat_id, OK_FILE, ok_lines.encode(),
             caption=f"💾 {len(tagged)} valid proxies · @Poriot_ke", markup=kb)
    send_doc(chat_id, REPORT_FILE, report_lines.encode(),
             caption="🏷 Status per proxy (OK / TRANSPARENT / FLAGGED)", markup=kb)


def handle_update(upd):
    cb = upd.get("callback_query")
    if cb:
        cid = (cb.get("message") or {}).get("chat", {}).get("id")
        data = cb.get("data", "")
        api("answerCallbackQuery", callback_query_id=cb["id"])
        if not cid:
            return
        if data in ("channel", "dev"):
            label = "Channel" if data == "channel" else "Dev"
            value = CHANNEL if data == "channel" else DEV
            kind, target = button_target(value)
            if kind == "id":
                # notify the configured chat/user directly
                api("sendMessage", chat_id=target,
                    text=f"🔔 Someone tapped *{label}* in the bot!",
                    parse_mode="Markdown")
                send(cid, f"📬 *{label}* notified. Thanks for your interest!")
            else:
                send(cid, CHANNEL_MSG if data == "channel" else DEV_MSG)
        return

    msg = upd.get("message") or upd.get("channel_post")
    if not msg:
        return
    chat_id = msg["chat"]["id"]
    text = msg.get("text", "") or msg.get("caption", "")
    stripped = text.strip()

    if stripped in ("/start", "/help"):
        send(chat_id, BANNER)
        return

    if stripped == "/mpx":
        # must be a reply to an uploaded .txt/.zip
        reply = msg.get("reply_to_message") or {}
        doc = reply.get("document") or {}
        name = doc.get("file_name", "")
        if not doc or not name.lower().endswith((".txt", ".zip")):
            send(chat_id, "⚠️ *Reply to an uploaded `.txt`/`.zip` file with `/mpx`.*\n\n"
                          "1. Upload your proxy file\n"
                          "2. Tap it → Reply → `/mpx`")
            return
        data = download_file(doc["file_id"])
        if not data:
            send(chat_id, "⚠️ Could not download the file. Try uploading it again.")
            return
        lines = extract_lines(raw_bytes=data, filename=name)
        if not lines:
            send(chat_id, "⚠️ No proxies found in that file.")
            return
        threading.Thread(target=run_job, args=(chat_id, lines), daemon=True).start()
        return

    # a plain document upload (no command) -> hint how to start
    if "document" in msg:
        doc = msg["document"]
        name = doc.get("file_name", "")
        if name.lower().endswith((".txt", ".zip")):
            send(chat_id, "📄 File received! Reply to it with `/mpx` to start checking.")
        else:
            send(chat_id, "⚠️ Please send a `.txt` or `.zip` file.")
        return

    # pasted text -> check immediately
    if stripped:
        lines = extract_lines(text=text)
        if lines:
            threading.Thread(target=run_job, args=(chat_id, lines), daemon=True).start()


def main():
    print("PROXY CHECKER TELEGRAM BOT running. Press Ctrl+C to stop.")
    api("deleteWebhook", drop_pending_updates="false")
    offset = None
    while True:
        try:
            r = requests.get(f"{API}/getUpdates",
                             params={"timeout": 30, "offset": offset},
                             timeout=40).json()
            for upd in r.get("result", []):
                offset = upd["update_id"] + 1
                try:
                    handle_update(upd)
                except Exception as e:
                    print("handler err", e)
        except KeyboardInterrupt:
            print("\nStopped.")
            break
        except Exception as e:
            print("poll err", e)
            time.sleep(3)


if __name__ == "__main__":
    main()
