#!/usr/bin/env python3
"""
PROXY CHECKER BOT  -  Credits: @Poriot_ke
Fast concurrent proxy checker with live stats & clean .txt export.

Supported input formats (auto-detected, one per line):
    ip:port
    ip:port:user:pass
    user:pass:host:port
    proto://ip:port
    proto://user:pass@ip:port

Protocols: http, https, socks4, socks5
Accepts:   .txt files, .zip archives, raw pasted text

Usage:
    python3 proxy_checker.py <input(.txt/.zip/dir) ...> [options]

Options:
    --proto {auto,http,https,socks4,socks5}   default: auto
    --threads N        concurrent workers           (default 200)
    --timeout N        per-proxy timeout seconds     (default 10)
    --out FILE         valid proxies output          (default valid_proxies.txt)
    --judge URL        IP-echo test URL              (default http://httpbin.org/ip)
"""
import argparse
import concurrent.futures as cf
import ipaddress
import os
import re
import sys
import time
import zipfile
from collections import Counter

import requests

# ---------------------------------------------------------------- parsing ----
PROTOS = ("http", "https", "socks4", "socks5")
_PROTO_RE = re.compile(r"^(https?|socks4a?|socks5h?)://", re.I)


def parse_proxy(line, default_proto="http"):
    """Return dict {proto, host, port, user, pass, raw} or None if unparseable."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    proto = default_proto
    creds_user = creds_pass = None

    # proto://...
    m = _PROTO_RE.match(line)
    if m:
        proto = m.group(1).lower()
        proto = {"socks4a": "socks4", "socks5h": "socks5"}.get(proto, proto)
        rest = line[m.end():]
    else:
        rest = line

    # user:pass@host:port
    if "@" in rest:
        cred, hostpart = rest.rsplit("@", 1)
        if ":" in cred:
            creds_user, creds_pass = cred.split(":", 1)
        else:
            creds_user = cred
        parts = hostpart.split(":")
    else:
        parts = rest.split(":")

    # 4-part line without "@" — two layouts exist:
    #   host:port:user:pass   (e.g. 1.2.3.4:8080:user:pass)
    #   user:pass:host:port   (e.g. user:pass:1.2.3.4:8080)
    # A port must be a number, so the digit field disambiguates the layout.
    if creds_user is None and len(parts) == 4:
        if parts[1].isdigit() and 0 < int(parts[1]) < 65536:
            host, port, creds_user, creds_pass = parts            # host:port:user:pass
        elif parts[3].isdigit() and 0 < int(parts[3]) < 65536:
            creds_user, creds_pass, host, port = parts            # user:pass:host:port
        else:
            host, port = parts[0], parts[1]
    elif len(parts) >= 2:
        host, port = parts[0], parts[1]
    else:
        return None

    host = host.strip()
    port = port.strip()
    if not host or not port.isdigit():
        return None
    if not (0 < int(port) < 65536):
        return None

    return {
        "proto": proto,
        "host": host,
        "port": int(port),
        "user": creds_user,
        "pass": creds_pass,
        "raw": line,
    }


def proxy_url(p, proto=None):
    proto = proto or p["proto"]
    scheme = "socks5h" if proto == "socks5" else ("socks4a" if proto == "socks4" else proto)
    auth = ""
    if p["user"]:
        auth = p["user"] + (":" + p["pass"] if p["pass"] else "") + "@"
    return f"{scheme}://{auth}{p['host']}:{p['port']}"


def canonical(p, proto):
    """Clean output form: proto://[user:pass@]host:port"""
    auth = ""
    if p["user"]:
        auth = p["user"] + (":" + p["pass"] if p["pass"] else "") + "@"
    return f"{proto}://{auth}{p['host']}:{p['port']}"


# ---------------------------------------------------------------- loading ----
def load_lines_from_text(text):
    return [ln for ln in text.splitlines() if ln.strip()]


def load_input(paths):
    lines = []
    for path in paths:
        if os.path.isdir(path):
            for root, _, files in os.walk(path):
                for f in files:
                    if f.lower().endswith(".txt"):
                        with open(os.path.join(root, f), "r", errors="ignore") as fh:
                            lines += load_lines_from_text(fh.read())
        elif path.lower().endswith(".zip"):
            with zipfile.ZipFile(path) as z:
                for name in z.namelist():
                    if name.lower().endswith(".txt"):
                        lines += load_lines_from_text(z.read(name).decode("utf-8", "ignore"))
        elif os.path.isfile(path):
            with open(path, "r", errors="ignore") as fh:
                lines += load_lines_from_text(fh.read())
        else:  # treat as raw pasted text
            lines += load_lines_from_text(path)
    return lines


# ---------------------------------------------------------------- checking ---
def check_one(p, default_proto, timeout, judge):
    """Return (ok, proto_used, latency_ms, exit_ip, err)."""
    protos = PROTOS if default_proto == "auto" else (default_proto,)
    # If the line itself declared a proto, trust it first.
    if default_proto == "auto" and _PROTO_RE.match(p["raw"]):
        protos = (p["proto"],) + tuple(x for x in PROTOS if x != p["proto"])

    last_err = ""
    for proto in protos:
        url = proxy_url(p, proto)
        proxies = {"http": url, "https": url}
        try:
            t0 = time.time()
            r = requests.get(judge, proxies=proxies, timeout=timeout,
                             headers={"User-Agent": "proxy-checker/1.0"})
            if r.status_code == 200:
                latency = (time.time() - t0) * 1000
                ip = ""
                try:
                    ip = r.json().get("origin", "")
                except Exception:
                    m = re.search(r"\d+\.\d+\.\d+\.\d+", r.text)
                    ip = m.group(0) if m else ""
                return True, proto, latency, ip, ""
            last_err = f"HTTP {r.status_code}"
        except Exception as e:
            last_err = type(e).__name__
    return False, None, None, None, last_err


def bar(done, total, width=30):
    filled = int(width * done / total) if total else width
    return "[" + "#" * filled + "-" * (width - filled) + "]"


def main():
    ap = argparse.ArgumentParser(description="PROXY CHECKER BOT - @Poriot_ke")
    ap.add_argument("inputs", nargs="+", help=".txt / .zip / dir / raw text")
    ap.add_argument("--proto", default="auto",
                    choices=["auto", "http", "https", "socks4", "socks5"])
    ap.add_argument("--threads", type=int, default=200)
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--out", default="valid_proxies.txt")
    ap.add_argument("--judge", default="http://httpbin.org/ip")
    args = ap.parse_args()

    raw_lines = load_input(args.inputs)
    parsed, seen, bad = [], set(), 0
    for ln in raw_lines:
        p = parse_proxy(ln, default_proto="http" if args.proto == "auto" else args.proto)
        if not p:
            bad += 1
            continue
        key = (p["host"], p["port"], p["user"])
        if key in seen:
            continue
        seen.add(key)
        parsed.append(p)

    total = len(parsed)
    print("=" * 50)
    print("  PROXY CHECKER BOT   -   @Poriot_ke")
    print("=" * 50)
    print(f"  Loaded     : {len(raw_lines)} lines")
    print(f"  Valid fmt  : {total} unique  |  Bad/skipped: {bad}")
    print(f"  Protocol   : {args.proto}   Threads: {args.threads}   Timeout: {args.timeout}s")
    print("=" * 50)
    if total == 0:
        print("No parseable proxies. Nothing to check.")
        return

    results, done, t_start = [], 0, time.time()
    with cf.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futs = {ex.submit(check_one, p, args.proto, args.timeout, args.judge): p
                for p in parsed}
        for fut in cf.as_completed(futs):
            p = futs[fut]
            ok, proto, latency, ip, err = fut.result()
            if ok:
                results.append((p, proto, latency, ip))
            done += 1
            if done % 5 == 0 or done == total:
                elapsed = time.time() - t_start
                cpm = int(done / elapsed * 60) if elapsed else 0
                sys.stdout.write(
                    f"\r{bar(done, total)} {done}/{total}  "
                    f"valid:{len(results)}  CPM:{cpm}   ")
                sys.stdout.flush()
    print()

    # speed-sorted
    results.sort(key=lambda r: r[2])
    with open(args.out, "w") as fh:
        for p, proto, latency, ip in results:
            fh.write(p["raw"] + "\n")

    elapsed = time.time() - t_start
    by_proto = Counter(r[1] for r in results)
    print("-" * 50)
    print(f"  Done in {elapsed:.1f}s")
    print(f"  VALID : {len(results)}/{total}   DEAD : {total - len(results)}")
    if by_proto:
        print("  By protocol: " + ", ".join(f"{k}={v}" for k, v in by_proto.items()))
    if results:
        fastest = results[0]
        print(f"  Fastest: {fastest[0]['raw']}  "
              f"({fastest[2]:.0f} ms)  exit IP {fastest[3]}")
    print(f"  Saved valid proxies -> {args.out}")
    print("-" * 50)


if __name__ == "__main__":
    main()
