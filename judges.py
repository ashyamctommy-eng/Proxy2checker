#!/usr/bin/env python3
"""
JUDGE POOL  -  resilient "what is my exit IP?" endpoints.
Credits: @Poriot_ke

A proxy check is only as good as the judge it talks through. The old code had a
single hard-coded judge (`http://httpbin.org/ip`); when that host slowed down or
returned an unparseable body, every proxy silently lost its exit IP, which in
turn corrupted *country*, *status* and *score* — the bot kept answering, just
wrongly. That class of silent corruption is worse than an outage.

This module keeps a pool of independent IP-echo endpoints and:

  * health-checks them directly (no proxy) to find which are actually usable,
  * prefers the fastest healthy one,
  * reports `degraded` when none respond, so the UI can say so out loud,
  * falls back optimistically to the first judge when health is still unknown.

Usage:
    pool = JudgePool()
    pool.check_health()            # direct probes, cheap; safe to call lazily
    judge = pool.pick()            # best URL right now
    ip = fetch_exit_ip(judge, proxy_url, timeout)
    pool.status_line()             # None when healthy, else a UI warning
"""
from __future__ import annotations

import ipaddress
import json
import re
import threading
import time

import requests

# Order matters: cheapest/most machine-readable first, legacy httpbin last.
DEFAULT_JUDGES = (
    "https://api.ipify.org?format=json",
    "https://ifconfig.co/json",
    "https://ipinfo.io/ip",
    "https://api.myip.com",
    "http://httpbin.org/ip",
)

_UA = {"User-Agent": "proxy-checker/1.0 (+judge)"}
_IP_CANDIDATE = re.compile(r"[0-9a-fA-F:.]{3,45}")


def _canon_ip(value) -> str:
    """Validate/clean a single IP string -> canonical form, or ''."""
    if not isinstance(value, str):
        return ""
    cand = value.split(",")[0].strip().strip("[]")
    try:
        return str(ipaddress.ip_address(cand))
    except ValueError:
        return ""


def extract_ip(text) -> str:
    """Pull the exit IP out of a judge response (JSON or plain text)."""
    if not text:
        return ""
    body = text.strip()
    data = None
    if body[:1] in "{[":
        try:
            data = json.loads(body)
        except ValueError:
            data = None

    if isinstance(data, dict):
        for key in ("ip", "origin", "query", "address", "client_ip", "IPv4"):
            ip = _canon_ip(data.get(key))
            if ip:
                return ip
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                for key in ("ip", "origin", "query", "address"):
                    ip = _canon_ip(item.get(key))
                    if ip:
                        return ip

    for match in _IP_CANDIDATE.finditer(body):
        ip = _canon_ip(match.group(0))
        if ip:
            return ip
    return ""


class JudgePool:
    """Thread-safe pool of IP-echo judges with health tracking."""

    def __init__(self, judges=None, timeout: int = 8, ttl: int = 300):
        self.judges = [j for j in (judges or DEFAULT_JUDGES) if j]
        if not self.judges:
            self.judges = [DEFAULT_JUDGES[0]]
        self.timeout = timeout
        self.ttl = ttl
        self._lock = threading.RLock()   # RLock: stats()/degraded nest inside it
        self._health: dict = {}        # url -> {ok, ms, ip, ts, err}
        self._checking = False

    # ------------------------------------------------------------ health ----
    def _probe(self, url: str) -> dict:
        started = time.time()
        try:
            r = requests.get(url, timeout=self.timeout, headers=_UA)
            ms = (time.time() - started) * 1000
            if r.status_code != 200:
                return {"ok": False, "ms": ms, "ip": "", "ts": time.time(),
                        "err": f"HTTP {r.status_code}"}
            ip = extract_ip(r.text)
            if not ip:
                return {"ok": False, "ms": ms, "ip": "", "ts": time.time(),
                        "err": "unreadable body"}
            return {"ok": True, "ms": ms, "ip": ip, "ts": time.time(), "err": ""}
        except Exception as e:
            return {"ok": False, "ms": None, "ip": "", "ts": time.time(),
                    "err": type(e).__name__}

    def check_health(self, force: bool = False) -> dict:
        """Probe every judge directly. Skips fresh results unless `force`.

        Each probe runs in its own thread so one slow judge cannot stall the
        others (and the caller's job) for `timeout` seconds apiece.
        """
        with self._lock:
            stale = [u for u in self.judges
                     if force or not self._is_fresh(self._health.get(u))]
            if not stale:
                return dict(self._health)
        out = {}
        threads = []

        def run(url):
            out[url] = self._probe(url)

        for url in stale:
            t = threading.Thread(target=run, args=(url,), daemon=True)
            t.start()
            threads.append(t)
        for t in threads:
            t.join(timeout=self.timeout + 5)
        with self._lock:
            self._health.update(out)
            return dict(self._health)

    def check_health_async(self) -> None:
        """Fire-and-forget health check (never blocks the scan)."""
        with self._lock:
            if self._checking:
                return
            self._checking = True

        def run():
            try:
                self.check_health()
            finally:
                with self._lock:
                    self._checking = False

        threading.Thread(target=run, daemon=True).start()

    def maybe_refresh(self) -> None:
        """Refresh in the background when the oldest data is stale."""
        if any(self._is_fresh(self._health.get(u)) for u in self.judges):
            return
        self.check_health_async()

    def _is_fresh(self, entry) -> bool:
        return bool(entry) and (time.time() - entry.get("ts", 0)) < self.ttl

    # ------------------------------------------------------------ picking ---
    def healthy(self) -> list:
        with self._lock:
            return [u for u in self.judges
                    if (self._health.get(u) or {}).get("ok")
                    and self._is_fresh(self._health.get(u))]

    def pick(self) -> str:
        """Best judge URL right now (fastest healthy, else optimistic first)."""
        with self._lock:
            healthy = [u for u in self.judges
                       if (self._health.get(u) or {}).get("ok")
                       and self._is_fresh(self._health.get(u))]
            if healthy:
                return min(healthy,
                           key=lambda u: (self._health.get(u) or {}).get("ms") or 9e9)
        self.maybe_refresh()
        return self.judges[0]

    @property
    def degraded(self) -> bool:
        """True only when we have *evidence* that no judge works."""
        with self._lock:
            known = [u for u in self.judges if self._is_fresh(self._health.get(u))]
            if not known:
                return False                     # unknown -> optimistic
            return not any((self._health.get(u) or {}).get("ok") for u in known)

    def note(self, url: str, ok: bool, err: str = "") -> None:
        """Record a per-proxy observation (used to spot a judge going bad)."""
        if not url:
            return
        with self._lock:
            entry = self._health.setdefault(url, {"ok": True, "ms": None, "ip": "",
                                                  "ts": time.time(), "err": ""})
            if not ok:
                entry["err"] = err or entry.get("err", "")
                entry["ts"] = time.time() - self.ttl + 30   # go stale sooner

    def status_line(self) -> str | None:
        """A one-line UI warning when the pool is unhealthy, else None."""
        with self._lock:
            known = {u: self._health.get(u) for u in self.judges
                     if self._is_fresh(self._health.get(u))}
            if not known:
                return None
            ok = [u for u, e in known.items() if e.get("ok")]
            if not ok:
                return ("⚠️ <b>Judge degraded</b> — no IP-echo endpoint answered, so "
                        "exit IPs, countries and scores are incomplete.")
            if len(ok) == 1 and len(known) > 1:
                return ("⚠️ <b>Judge degraded</b> — only 1 of "
                        f"{len(known)} IP-echo endpoints is responding.")
            return None

    def stats(self) -> dict:
        with self._lock:
            return {"judges": len(self.judges), "degraded": self.degraded,
                    "health": {u: dict(e) for u, e in self._health.items()}}


def fetch_exit_ip(judge: str, proxies: dict, timeout: int) -> tuple:
    """Fetch the exit IP through `proxies` -> (ip, err). '' + reason on failure."""
    try:
        r = requests.get(judge, proxies=proxies, timeout=timeout, headers=_UA)
    except Exception as e:
        return "", type(e).__name__
    if r.status_code != 200:
        return "", f"HTTP {r.status_code}"
    ip = extract_ip(r.text)
    return ip, ("" if ip else "JudgeUnreadable")
