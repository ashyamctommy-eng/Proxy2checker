#!/usr/bin/env python3
"""
PROXY CHECKER  -  Credits: @Poriot_ke
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
    --judge URL        force a single IP-echo URL    (default: judge pool)
    --engine MODE      auto | thread | async         (default auto)
    --no-tcp-gate      disable the TCP reachability gate
    --geo              also write one file per country (see --geo-out)
    --geo-out DIR      per-country output directory  (default valid_by_country)
    --geo-max N        max new exit IPs to geolocate per run (default 2500)

Parsing, the TCP gate and the checking engine live in engine.py and are
re-exported here so existing imports (`from proxy_checker import parse_proxy`)
keep working.
"""
import argparse
import concurrent.futures as cf
import os
import re
import sys
import time
import zipfile
from collections import Counter, defaultdict

# re-exported for backwards compatibility
from engine import (          # noqa: F401
    PROTOS, parse_proxy, proxy_url, canonical, check_one, check_many,
    tcp_probe, resolve_engine,
)
from judges import JudgePool

JUDGE_UNREADABLE = "JudgeUnreadable"


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
    ap.add_argument("--judge", default=None,
                    help="force one IP-echo URL instead of the judge pool")
    ap.add_argument("--engine", default="auto", choices=["auto", "thread", "async"])
    ap.add_argument("--no-tcp-gate", action="store_true")
    ap.add_argument("--geo", action="store_true",
                    help="write valid proxies grouped by exit-IP country")
    ap.add_argument("--geo-out", default="valid_by_country")
    ap.add_argument("--geo-max", type=int, default=2500)
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
    backend = resolve_engine(args.engine)
    pool = None if args.judge else JudgePool(timeout=min(args.timeout, 8))
    print("=" * 50)
    print("  PROXY CHECKER BOT   -   @Poriot_ke")
    print("=" * 50)
    print(f"  Loaded     : {len(raw_lines)} lines")
    print(f"  Valid fmt  : {total} unique  |  Bad/skipped: {bad}")
    print(f"  Protocol   : {args.proto}   Threads: {args.threads}   Timeout: {args.timeout}s")
    print(f"  Engine     : {backend}   TCP gate: {'off' if args.no_tcp_gate else 'on'}")
    print("=" * 50)
    if total == 0:
        print("No parseable proxies. Nothing to check.")
        return

    results, done, t_start = [], 0, time.time()
    last_print = [0.0]

    def on_result(idx, p, res, n_done, n_total):
        nonlocal done
        done = n_done
        if res[0]:
            results.append((p, res[1], res[2], res[3]))
        now = time.time()
        if now - last_print[0] > 0.3 or n_done == n_total:
            last_print[0] = now
            elapsed = now - t_start
            cpm = int(n_done / elapsed * 60) if elapsed else 0
            remaining = (n_total - n_done) / (n_done / elapsed) if n_done and elapsed else 0
            sys.stdout.write(
                f"\r{bar(n_done, n_total)} {n_done}/{n_total}  "
                f"valid:{len(results)}  CPM:{cpm}  ETA:{remaining:.0f}s   ")
            sys.stdout.flush()

    check_many(parsed, proto=args.proto, timeout=args.timeout,
               judge=args.judge, judge_pool=pool, threads=args.threads,
               on_result=on_result, engine=args.engine,
               tcp_gate=not args.no_tcp_gate)
    print()

    # speed-sorted
    results.sort(key=lambda r: r[2] if r[2] is not None else 9e9)
    with open(args.out, "w") as fh:
        for p, proto, latency, ip in results:
            fh.write(p["raw"] + "\n")

    # optional: group the valid proxies by exit-IP country
    if args.geo and results:
        try:
            from geoip import GeoDB, flag_emoji
            db = GeoDB(os.path.join(args.geo_out, "geo_cache.json"))
            ips = [(ip or "").split(",")[0].strip() for _, _, _, ip in results]
            info = db.lookup(ips, max_uncached=args.geo_max)
            groups = defaultdict(list)
            for p, proto, latency, ip in results:
                key = (ip or "").split(",")[0].strip()
                cc = (info.get(key) or {}).get("cc", "ZZ")
                groups[cc].append((p["raw"], latency))
            os.makedirs(args.geo_out, exist_ok=True)
            summary = []
            for cc, rows in sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0])):
                if not re.fullmatch(r"[A-Z]{2}", str(cc)):
                    cc = "ZZ"          # never let a provider value name a file
                rows.sort(key=lambda r: r[1] if r[1] is not None else 9e9)
                with open(os.path.join(args.geo_out, f"{cc}.txt"), "w") as fh:
                    fh.write("\n".join(raw for raw, _ in rows) + "\n")
                summary.append(f"{flag_emoji(cc)} {cc}={len(rows)}")
            print("  By country: " + ", ".join(summary))
            print(f"  Per-country files -> {args.geo_out}/<CC>.txt")
        except Exception as e:
            print(f"  (geo lookup failed: {type(e).__name__}: {e})")

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
