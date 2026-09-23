#!/usr/bin/env python3
"""
GEOIP  -  country resolution for proxy exit IPs.
Credits: @Poriot_ke

Given a batch of exit IPs (the `ip` returned by check_one), work out which
country each one lives in, so the bot can sort/group proxies by country.

Design notes
------------
* Primary provider is ip-api.com's *batch* endpoint (100 IPs per HTTP call,
  free tier ~15 batch calls/minute).  It is HTTP-only on the free plan — that
  is a provider limitation, not a bug.
* Fallback provider is ipwho.is (HTTPS, per-IP, free tier) used only for a
  small number of IPs the batch call could not resolve.
* Every real answer is cached on disk (vault/geo_cache.json) so repeated scans
  and repeated exit IPs cost zero API calls.  Cache entries expire after
  CACHE_TTL_DAYS days.
* Private / loopback / malformed IPs short-circuit to the UNKNOWN bucket and
  are cached too (they are deterministic — never worth an API call).
* A *public* IP we did not actually get an answer for is **never cached** as
  Unknown: caching a placeholder would freeze that IP out of every later scan
  for the whole TTL.  It just falls into this scan's Unknown bucket.
* A global sliding-window limiter keeps us inside the providers' per-minute
  quotas even when several scan jobs run in parallel threads.

Usage:
    from geoip import GeoDB, GeoPipeline, clean_ip
    db = GeoDB("vault/geo_cache.json")
    info = db.lookup([clean_ip("8.8.8.8")])
    info["8.8.8.8"]["cc"]      # "US"
    info["8.8.8.8"]["country"] # "United States"

Always key lookups with `clean_ip()` so the cache key and the caller's key are
the same canonical string.
"""
from __future__ import annotations

import collections
import ipaddress
import json
import os
import queue
import threading
import time

import requests

BATCH_URL = ("http://ip-api.com/batch?fields=status,message,country,countryCode,"
             "query,regionName,city,isp,as")
BATCH_SIZE = 100
BATCH_CALLS_PER_MIN = 13           # provider allows 15/min; stay under it
SINGLE_URL = "https://ipwho.is/{ip}"
SINGLE_CALLS_PER_MIN = 40          # ipwho.is free-ish limit
FALLBACK_MAX = 20                  # per-IP fallback budget (bounds wall-clock)
CACHE_TTL_DAYS = 7                 # was 30: a reassigned IP kept a stale country
                                   # (and a wrongly-resolved one kept it) for a month
# Cross-provider verification of newly resolved IPs. There is no free second
# *batch* source (tried ipwho.is, geojs, freeipapi, ipapi.co), so this is
# per-IP and must stay small: it exists to catch a systematically wrong primary
# provider, not to re-resolve everything.
VERIFY_MAX = 30                    # per lookup() call, 0 disables
HTTP_TIMEOUT = 20

# country code used for "we could not place this IP"
UNKNOWN_CC = "ZZ"
UNKNOWN_NAME = "Unknown"

# bucket for "the proxy answered but the judge gave us no exit IP" — distinct
# from ZZ, because that one means the exit IP is known but unplaceable
NO_IP_CC = "XX"
NO_IP_NAME = "No exit IP"

_SESSION = requests.Session()
_SESSION.headers.update({"User-Agent": "proxy-checker/1.0 (+geoip)"})


# --------------------------------------------------------------- helpers -----
def flag_emoji(cc: str) -> str:
    """'US' -> 🇺🇸  (falls back to a globe for ZZ/XX/bad input)."""
    cc = (cc or "").strip().upper()
    if len(cc) != 2 or not cc.isalpha() or cc in (UNKNOWN_CC, NO_IP_CC):
        return "🏳️"
    return "".join(chr(0x1F1E6 + (ord(c) - ord("A"))) for c in cc)


def clean_ip(value) -> str | None:
    """Normalise an exit-IP string to a canonical key, or None.

    httpbin's `origin` can be a comma separated list (proxy chains) and IPv6
    can arrive wrapped in brackets — take the first entry, strip brackets and
    canonicalise (so `2001:DB8::1` and `2001:db8::1` are the same cache key).
    Non-IP values (hostnames) are returned trimmed and unchanged.
    """
    if not value:
        return None
    ip = str(value).split(",")[0].strip().strip("[]")
    if not ip:
        return None
    try:
        return str(ipaddress.ip_address(ip.split("%")[0]))
    except ValueError:
        return ip


def is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    return addr.is_global


# ----------------------------------------------------------------- GeoDB -----
class GeoDB:
    """Disk-cached IP -> country resolver (thread safe)."""

    def __init__(self, cache_path: str, ttl_days: int = CACHE_TTL_DAYS,
                 verify_max: int = VERIFY_MAX):
        self.cache_path = cache_path
        self.ttl = ttl_days * 86400
        self.verify_max = max(0, int(verify_max))
        self._lock = threading.Lock()
        self._batch_calls = collections.deque()
        self._single_calls = collections.deque()
        self._cache = self._load()
        self.dirty = False
        # observability: how often the two providers disagreed this run
        self.disagreements = 0
        self.verified = 0
        self.last_disagreements: list = []
        self.pruned_last = 0

    # -- cache persistence ---------------------------------------------------
    def _load(self) -> dict:
        try:
            with open(self.cache_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def save(self) -> None:
        with self._lock:
            if not self.dirty:
                return
            # Drop expired entries instead of rewriting them forever: the old
            # code kept every IP it had ever resolved (and every deterministic
            # non-public key) in the file for good, and re-serialised the whole
            # cache on every batch.
            now = time.time()
            before = len(self._cache)
            self._cache = {ip: e for ip, e in self._cache.items()
                           if now - e.get("ts", 0) <= self.ttl}
            self.pruned_last = before - len(self._cache)
            directory = os.path.dirname(os.path.abspath(self.cache_path))
            os.makedirs(directory, exist_ok=True)
            tmp = self.cache_path + ".tmp"
            try:
                with open(tmp, "w", encoding="utf-8") as fh:
                    json.dump(self._cache, fh)
                os.replace(tmp, self.cache_path)
                self.dirty = False
            except OSError:
                pass

    def clear(self) -> int:
        """Forget every cached answer (used to recover from poisoned data)."""
        with self._lock:
            n = len(self._cache)
            self._cache = {}
            self.dirty = True
        self.save()
        return n

    def _cached(self, ip: str):
        with self._lock:
            entry = self._cache.get(ip)
        if not entry:
            return None
        if time.time() - entry.get("ts", 0) > self.ttl:
            return None
        cc = entry.get("cc", UNKNOWN_CC)
        # Self-heal cached placeholders: a *public* IP stored as Unknown was a
        # skipped/failed lookup, not a real answer — let it be queried again.
        if cc == UNKNOWN_CC and is_public_ip(ip):
            return None
        out = {"cc": cc, "country": entry.get("country", UNKNOWN_NAME)}
        for extra in ("region", "city", "isp"):
            if entry.get(extra):
                out[extra] = entry[extra]
        return out

    def _store(self, ip: str, cc: str, country: str, extra: dict | None = None) -> None:
        with self._lock:
            entry = {"cc": cc or UNKNOWN_CC,
                     "country": country or UNKNOWN_NAME,
                     "ts": int(time.time())}
            for key in ("region", "city", "isp"):
                val = (extra or {}).get(key)
                if val:
                    entry[key] = str(val)[:80]
            self._cache[ip] = entry
            self.dirty = True

    # -- rate limiting -------------------------------------------------------
    def _throttle(self, stamps: collections.deque, per_min: int) -> None:
        while True:
            with self._lock:
                now = time.monotonic()
                while stamps and now - stamps[0] > 60:
                    stamps.popleft()
                if len(stamps) < per_min:
                    stamps.append(now)
                    return
                wait = 60 - (now - stamps[0]) + 0.05
            time.sleep(min(max(wait, 0.05), 10))

    # -- providers ----------------------------------------------------------
    def _batch(self, ips: list[str]) -> dict:
        """ip-api.com batch call. Returns {ip: {cc, country}} for resolved IPs."""
        out = {}
        self._throttle(self._batch_calls, BATCH_CALLS_PER_MIN)
        try:
            r = _SESSION.post(BATCH_URL, json=[{"query": ip} for ip in ips],
                              timeout=HTTP_TIMEOUT)
        except Exception:
            return out
        if r.status_code != 200:
            return out
        try:
            rows = r.json()
        except ValueError:
            return out
        if not isinstance(rows, list):
            return out
        for row in rows:
            if not isinstance(row, dict):
                continue
            ip = clean_ip(row.get("query"))
            if not ip:
                continue
            if row.get("status") == "success" and row.get("countryCode"):
                out[ip] = {"cc": str(row["countryCode"]).upper(),
                           "country": row.get("country") or UNKNOWN_NAME,
                           "region": row.get("regionName") or "",
                           "city": row.get("city") or "",
                           "isp": row.get("isp") or row.get("as") or ""}
        return out

    def _single(self, ip: str):
        """ipwho.is fallback for one IP. Returns {cc, country} or None."""
        self._throttle(self._single_calls, SINGLE_CALLS_PER_MIN)
        try:
            r = _SESSION.get(SINGLE_URL.format(ip=ip), timeout=HTTP_TIMEOUT)
            if r.status_code != 200:
                return None
            row = r.json()
        except Exception:
            return None
        if not isinstance(row, dict) or not row.get("success"):
            return None
        cc = row.get("country_code")
        if not cc:
            return None
        return {"cc": str(cc).upper(), "country": row.get("country") or UNKNOWN_NAME}

    # -- public API ---------------------------------------------------------
    def lookup(self, ips, max_uncached: int = 2500, progress=None) -> dict:
        """Resolve a batch of IPs -> {canonical_ip: {"cc","country"}}.

        `max_uncached` caps how many *new* public IPs we will query per call;
        anything beyond that lands in this scan's Unknown bucket without being
        cached, so a later scan can still resolve it.  `progress(done,total)`
        is optional and always finishes with done == total.
        """
        wanted: list[str] = []
        seen = set()
        for raw in ips:
            ip = clean_ip(raw)
            if not ip or ip in seen:
                continue
            seen.add(ip)
            wanted.append(ip)

        result: dict = {}
        todo: list[str] = []
        for ip in wanted:
            hit = self._cached(ip)
            if hit:
                result[ip] = hit
            else:
                todo.append(ip)

        resolved: dict = {}
        query: list[str] = []
        for ip in todo:
            if is_public_ip(ip):
                query.append(ip)
            else:
                # deterministic: not a routable address, cache it as Unknown
                resolved[ip] = {"cc": UNKNOWN_CC, "country": UNKNOWN_NAME}
                self._store(ip, UNKNOWN_CC, UNKNOWN_NAME)

        skipped = query[max_uncached:] if len(query) > max_uncached else []
        query = query[:max_uncached]
        total = len(query)

        done = 0
        batch_resolved: set = set()
        for i in range(0, total, BATCH_SIZE):
            chunk = query[i:i + BATCH_SIZE]
            got = self._batch(chunk)
            batch_resolved |= set(got)
            resolved.update(got)
            done += len(chunk)
            if progress and total:
                progress(min(done, total), total)
        if progress and total:
            progress(total, total)          # guarantee a 100% tick

        # Bounded cross-provider verification. A confidently *wrong* country is
        # worse than an honest Unknown, so when the second provider disagrees we
        # drop the answer: this scan shows Unknown, and nothing is cached, so a
        # later scan can resolve it again.
        self.last_disagreements = []
        disputed: set = set()
        if self.verify_max:
            checked = 0
            for ip in query:
                if checked >= self.verify_max:
                    break
                if ip not in batch_resolved:
                    continue
                info = resolved.get(ip)
                if not info:
                    continue
                checked += 1
                second = self._single(ip)
                if not second:
                    continue
                self.verified += 1
                if second["cc"] != info["cc"]:
                    self.disagreements += 1
                    self.last_disagreements.append(
                        (ip, info["cc"], second["cc"]))
                    resolved.pop(ip, None)
                    batch_resolved.discard(ip)
                    disputed.add(ip)

        # bounded per-IP fallback for whatever the batch call missed (a disputed
        # IP is deliberately not re-resolved here: putting it back would undo the
        # whole point of the check)
        missing = [ip for ip in query if ip not in resolved and ip not in disputed]
        for ip in missing[:FALLBACK_MAX]:
            got = self._single(ip)
            if got:
                resolved[ip] = got

        for ip in query:
            info = resolved.get(ip)
            if not info:
                # do NOT cache a placeholder for a public IP
                result[ip] = {"cc": UNKNOWN_CC, "country": UNKNOWN_NAME}
                continue
            result[ip] = info
            self._store(ip, info["cc"], info["country"], info)
        for ip in skipped:
            result.setdefault(ip, {"cc": UNKNOWN_CC, "country": UNKNOWN_NAME})
        for ip, info in resolved.items():
            result.setdefault(ip, info)

        if self.dirty:
            self.save()
        return result

    def stats(self) -> dict:
        with self._lock:
            return {"cached": len(self._cache)}

    def is_cached(self, ip) -> bool:
        """True when this IP already has a real cached answer (no API call needed)."""
        return self._cached(clean_ip(ip) or "") is not None

    def cached_cc(self, ip) -> str:
        """Country code for an IP *if already cached* — never hits the network.

        Used by the bot's live feed, which must not spend API calls per proxy.
        Returns "" when unknown.
        """
        hit = self._cached(clean_ip(ip) or "")
        return hit["cc"] if hit else ""


class GeoPipeline:
    """Resolve exit IPs *while* the scan runs, instead of after it.

    The old flow geolocated everything once checking finished — minutes of dead
    time on a large list, and the live feed could not show country flags at all.

    Here each exit IP is pushed in as its result lands; a worker thread batches
    them (BATCH_SIZE or FLUSH seconds, whichever first) and calls GeoDB.lookup.

        pipe = GeoPipeline(db).start()
        pipe.submit(exit_ip)                  # from the check callback
        pipe.cc_for(exit_ip)                  # free, for the live feed
        geo_map = pipe.close()                # after the last check
    """

    def __init__(self, db: GeoDB, max_uncached: int = 2500,
                 batch_size: int = 100, flush: float = 1.0, close_grace: float = 15.0):
        self.db = db
        self.max_uncached = max_uncached
        self.batch_size = max(1, batch_size)
        self.flush = flush
        self.close_grace = close_grace
        self._queue: "queue.Queue" = queue.Queue()
        self._lock = threading.Lock()
        self._resolved: dict = {}
        self._seen: set = set()
        self._sent_uncached = 0
        self._thread = None

    def start(self):
        if self._thread is None:
            self._thread = threading.Thread(target=self._run, name="geopipe", daemon=True)
            self._thread.start()
        return self

    def submit(self, ip) -> None:
        ip = clean_ip(ip)
        if not ip:
            return
        with self._lock:
            if ip in self._seen:
                return
            self._seen.add(ip)
        self._queue.put(ip)

    def cc_for(self, ip) -> str:
        """Flag for the live feed: resolved in this run, or already cached."""
        ip = clean_ip(ip)
        if not ip:
            return ""
        with self._lock:
            hit = self._resolved.get(ip)
        if hit:
            return hit.get("cc") or ""
        if not is_public_ip(ip):
            return UNKNOWN_CC
        return self.db.cached_cc(ip)

    def resolved(self) -> dict:
        with self._lock:
            return dict(self._resolved)

    def _run(self) -> None:
        while True:
            try:
                first = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            if first is None:
                return
            batch = [first]
            deadline = time.monotonic() + self.flush
            stopped = False
            while len(batch) < self.batch_size:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    nxt = self._queue.get(timeout=remaining)
                except queue.Empty:
                    break
                if nxt is None:
                    stopped = True
                    break
                batch.append(nxt)
            self._resolve(batch)
            if stopped:
                return

    def _resolve(self, batch: list) -> None:
        public = [ip for ip in batch if is_public_ip(ip)]
        # only count IPs that actually need a network call, or the budget burns
        # out early on scans dominated by repeated exit IPs
        uncached = [ip for ip in public if not self.db.is_cached(ip)]
        budget = max(0, self.max_uncached - self._sent_uncached)
        try:
            got = self.db.lookup(batch, max_uncached=budget)
        except Exception:
            got = {}
        self._sent_uncached += min(len(uncached), budget)
        results = {}
        for ip in batch:
            results[ip] = got.get(ip) or {"cc": UNKNOWN_CC, "country": UNKNOWN_NAME}
        with self._lock:
            self._resolved.update(results)

    def close(self) -> dict:
        """Flush the queue, stop the worker and return {ip: {cc, country}}."""
        self._queue.put(None)
        if self._thread is not None:
            self._thread.join(timeout=self.flush + self.close_grace)
            if self._thread.is_alive():
                # the worker is stuck inside a slow provider call; resolve whatever
                # is still queued here rather than reporting it as Unknown
                rest = []
                while True:
                    try:
                        item = self._queue.get_nowait()
                    except queue.Empty:
                        break
                    if item is not None:
                        rest.append(item)
                if rest:
                    try:
                        self._resolve(rest)
                    except Exception:
                        pass
        out = self.resolved()
        for ip in list(getattr(self, "_seen", ())):
            out.setdefault(ip, {"cc": UNKNOWN_CC, "country": UNKNOWN_NAME})
        return out
