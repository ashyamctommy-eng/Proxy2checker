#!/usr/bin/env python3
"""
CHECK ENGINE  -  parsing + concurrent proxy verification.
Credits: @Poriot_ke

Two things the original checker got wrong, fixed here:

1. **No TCP gate.** `PROTOS` was tried in order (http -> https -> socks4 ->
   socks5) and each attempt got the *full* timeout. A dead host could therefore
   burn 4x timeout of worker time (32s at the default 8s timeout) before being
   written off — the dominant cost on the dead-heavy lists people actually feed
   this thing. A ~1-3s TCP connect gate rejects unreachable hosts up front.

2. **Delegation is per-protocol.** Some proxies speak SOCKS and some speak HTTP,
   so the gate is followed by the protocol attempts; that part stays.

Two backends, same behaviour and same result tuples:

  * ``thread``  — requests + ThreadPoolExecutor (always available)
  * ``async``   — aiohttp + asyncio (less memory per in-flight proxy, but on
    mostly-dead lists it measured no faster than threads — see README's benchmark
    note; ``auto`` therefore stays on threads and async is opt-in)

SOCKS attempts without ``aiohttp_socks`` are delegated to a thread pool, so the
async path still works for mixed lists.

Serial protocol guessing is also capped: the first attempt gets the full timeout,
later attempts get a shorter probe timeout, and schemes are tried in the order
that resolves common cases soonest (http -> socks5 -> socks4 -> https).

Result tuple (unchanged, so callers/tests keep working):
    (ok: bool, proto_used: str|None, latency_ms: float|None, exit_ip: str, err: str)

``err == "JudgeUnreadable"`` with ``ok is True`` means the proxy answered but the
judge's body could not be parsed — a *judge* problem, not a proxy problem. Callers
should surface that rather than silently scoring the proxy as bad.
"""
from __future__ import annotations

import asyncio
import concurrent.futures as cf
import re
import socket
import time

import requests

from judges import JudgePool, extract_ip

PROTOS = ("http", "https", "socks4", "socks5")
# Order for scheme-less lines: the scheme that resolves a case soonest comes
# first, so a working proxy stops the chain early instead of walking all four.
PROTO_ORDER_AUTO = ("http", "socks5", "socks4", "https")
_PROTO_RE = re.compile(r"^(https?|socks4a?|socks5h?)://", re.I)
_UA = {"User-Agent": "proxy-checker/1.0"}
JUDGE_UNREADABLE = "JudgeUnreadable"


# ---------------------------------------------------------------- parsing ----
def parse_proxy(line, default_proto="http"):
    """Return dict {proto, host, port, user, pass, raw} or None if unparseable."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    proto = default_proto
    creds_user = creds_pass = None

    m = _PROTO_RE.match(line)
    if m:
        proto = m.group(1).lower()
        proto = {"socks4a": "socks4", "socks5h": "socks5"}.get(proto, proto)
        rest = line[m.end():]
    else:
        rest = line

    if "@" in rest:
        cred, hostpart = rest.rsplit("@", 1)
        if ":" in cred:
            creds_user, creds_pass = cred.split(":", 1)
        else:
            creds_user = cred
        parts = hostpart.split(":")
    else:
        parts = rest.split(":")

    # 4-part lines: host:port:user:pass  vs  user:pass:host:port — the numeric
    # port position disambiguates them.
    if creds_user is None and len(parts) == 4:
        if parts[1].isdigit() and 0 < int(parts[1]) < 65536:
            host, port, creds_user, creds_pass = parts
        elif parts[3].isdigit() and 0 < int(parts[3]) < 65536:
            creds_user, creds_pass, host, port = parts
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

    return {"proto": proto, "host": host, "port": int(port),
            "user": creds_user, "pass": creds_pass, "raw": line}


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


def attempts_for(p, default_proto):
    """Protocols to try for one proxy, in resolution order."""
    if default_proto != "auto":
        return (default_proto,)
    if _PROTO_RE.match(p["raw"]):        # the line declared its scheme: trust it first
        return (p["proto"],) + tuple(x for x in PROTO_ORDER_AUTO if x != p["proto"])
    return PROTO_ORDER_AUTO


def attempt_timeout(timeout, index):
    """Full timeout for the first guess, a shorter probe for the fallbacks.

    A host that speaks *some* proxy protocol almost always answers the first or
    second attempt quickly; spending the full timeout on attempts 3 and 4 is what
    made the old checker take 4x timeout per unreachable-but-open port.
    """
    if index == 0:
        return timeout
    return max(3.0, float(timeout) / 2.0)


# -------------------------------------------------------------- tcp gate -----
def gate_timeout(timeout: int) -> float:
    return min(max(float(timeout) / 3.0, 1.0), 4.0)


def tcp_probe(host, port, timeout):
    """Cheap reachability gate -> (ok, connect_ms, err)."""
    try:
        started = time.perf_counter()
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True, (time.perf_counter() - started) * 1000, ""
    except socket.timeout:
        return False, None, "TCP timeout"
    except OSError as e:
        return False, None, f"TCP {type(e).__name__}"
    except Exception as e:                                  # bad host etc.
        return False, None, f"TCP {type(e).__name__}"


# ---------------------------------------------------------- single check -----
def check_one(p, default_proto, timeout, judge, tcp_gate=True):
    """Check one proxy -> (ok, proto_used, latency_ms, exit_ip, err)."""
    if tcp_gate:
        reachable, _ms, gate_err = tcp_probe(p["host"], p["port"], gate_timeout(timeout))
        if not reachable:
            return False, None, None, None, gate_err

    last_err = ""
    for index, proto in enumerate(attempts_for(p, default_proto)):
        url = proxy_url(p, proto)
        proxies = {"http": url, "https": url}
        try:
            t0 = time.time()
            r = requests.get(judge, proxies=proxies, timeout=attempt_timeout(timeout, index),
                             headers=_UA)
            if r.status_code == 200:
                ip = extract_ip(r.text)
                return True, proto, (time.time() - t0) * 1000, ip, \
                    ("" if ip else JUDGE_UNREADABLE)
            last_err = f"HTTP {r.status_code}"
        except Exception as e:
            last_err = type(e).__name__
    return False, None, None, None, last_err


# ------------------------------------------------------------ backends -------
def async_available() -> bool:
    try:
        import aiohttp  # noqa: F401
        return True
    except Exception:
        return False


def socks_async_available() -> bool:
    try:
        import aiohttp_socks  # noqa: F401
        return True
    except Exception:
        return False


def resolve_engine(requested: str = "auto") -> str:
    """'auto' | 'thread' | 'async' -> the backend actually used.

    `auto` deliberately stays on threads: measured on real free-proxy lists,
    asyncio gave no speed-up (it was ~15% slower on mostly-dead lists) because the
    wall-clock is dominated by the serial protocol fallbacks, not by thread
    overhead. Async is opt-in for very large runs / low-memory hosts.
    """
    requested = (requested or "auto").lower()
    if requested == "async":
        return "async" if async_available() else "thread"
    return "thread"


def _pick_judge(judge, judge_pool):
    if judge_pool is not None:
        return judge_pool.pick()
    return judge


# -- thread backend -----------------------------------------------------------
def _check_threads(items, proto, timeout, judge, judge_pool, threads, on_result, tcp_gate):
    results = [None] * len(items)
    total = len(items)
    done = 0
    batch = max(1, min(100, threads))
    with cf.ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {}
        for idx, p in enumerate(items):
            if idx % batch == 0:                 # re-pick periodically, not per proxy
                judge = _pick_judge(judge, judge_pool)
            futs[ex.submit(check_one, p, proto, timeout, judge, tcp_gate)] = idx
        for fut in cf.as_completed(futs):
            idx = futs[fut]
            try:
                res = fut.result()
            except Exception as e:
                res = (False, None, None, None, type(e).__name__)
            results[idx] = res
            done += 1
            if on_result:
                on_result(idx, items[idx], res, done, total)
    return results


# -- asyncio backend ----------------------------------------------------------
def _check_async(items, proto, timeout, judge, judge_pool, threads, on_result, tcp_gate):
    import aiohttp

    async def gate(host, port):
        try:
            started = time.perf_counter()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, int(port)), timeout=gate_timeout(timeout))
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True, (time.perf_counter() - started) * 1000, ""
        except asyncio.TimeoutError:
            return False, None, "TCP timeout"
        except Exception as e:
            return False, None, f"TCP {type(e).__name__}"

    def sync_attempt(p, one_proto, one_judge, one_timeout):
        url = proxy_url(p, one_proto)
        proxies = {"http": url, "https": url}
        try:
            t0 = time.time()
            r = requests.get(one_judge, proxies=proxies, timeout=one_timeout, headers=_UA)
            if r.status_code == 200:
                ip = extract_ip(r.text)
                return True, one_proto, (time.time() - t0) * 1000, ip, \
                    ("" if ip else JUDGE_UNREADABLE)
            return False, one_proto, None, None, f"HTTP {r.status_code}"
        except Exception as e:
            return False, one_proto, None, None, type(e).__name__

    async def attempt(session, p, one_proto, one_judge, socks_pool, one_timeout):
        if one_proto in ("socks4", "socks5") and not socks_async_available():
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(socks_pool, sync_attempt, p, one_proto,
                                              one_judge, one_timeout)
        url = proxy_url(p, one_proto)
        try:
            t0 = time.perf_counter()
            async with session.get(one_judge, proxy=url, headers=_UA,
                                   timeout=aiohttp.ClientTimeout(total=one_timeout)) as resp:
                body = await resp.text()
                if resp.status == 200:
                    ip = extract_ip(body)
                    return True, one_proto, (time.perf_counter() - t0) * 1000, ip, \
                        ("" if ip else JUDGE_UNREADABLE)
                return False, one_proto, None, None, f"HTTP {resp.status}"
        except Exception as e:
            return False, one_proto, None, None, type(e).__name__

    async def one(session, idx, p, socks_pool, sem):
        async with sem:
            judge_url = _pick_judge(judge, judge_pool)
            if tcp_gate:
                reachable, _ms, gate_err = await gate(p["host"], p["port"])
                if not reachable:
                    return idx, (False, None, None, None, gate_err)
            last_err = ""
            for index, one_proto in enumerate(attempts_for(p, proto)):
                res = await attempt(session, p, one_proto, judge_url, socks_pool,
                                    attempt_timeout(timeout, index))
                if res[0]:
                    return idx, res
                last_err = res[4]
            return idx, (False, None, None, None, last_err)

    async def safe_one(session, idx, p, socks_pool, sem):
        """Never raises: one bad task must not abort the whole batch."""
        try:
            return await one(session, idx, p, socks_pool, sem)
        except Exception as e:
            return idx, (False, None, None, None, type(e).__name__)

    async def runner():
        results = [None] * len(items)
        done = 0
        sem = asyncio.Semaphore(max(1, threads))
        socks_pool = cf.ThreadPoolExecutor(max_workers=max(16, min(64, threads)))
        connector = aiohttp.TCPConnector(limit=0, ttl_dns_cache=300)
        try:
            async with aiohttp.ClientSession(connector=connector) as session:
                tasks = [asyncio.create_task(safe_one(session, i, p, socks_pool, sem))
                         for i, p in enumerate(items)]
                for fut in asyncio.as_completed(tasks):
                    idx, res = await fut
                    results[idx] = res
                    done += 1
                    if on_result:
                        on_result(idx, items[idx], res, done, len(items))
        finally:
            socks_pool.shutdown(wait=False)
        return results

    return asyncio.run(runner())


def check_many(items, proto="auto", timeout=8, judge=None, judge_pool=None,
               threads=150, on_result=None, engine="auto", tcp_gate=True):
    """Check every parsed proxy, streaming results through `on_result`.

    on_result(idx, proxy, result, done, total) is invoked as each check lands,
    on the caller's thread, so it is safe to update UI state there.

    Returns results in input order.
    """
    if not items:
        return []
    if judge_pool is None and judge is None:
        judge_pool = JudgePool(timeout=min(timeout, 8))
    chosen = resolve_engine(engine)

    fired = []

    def emit(idx, p, res, done, total):
        fired.append(1)
        if on_result:
            try:
                on_result(idx, p, res, done, total)
            except Exception as e:          # a UI hiccup must not kill the scan
                print("on_result err", type(e).__name__, e)

    if chosen == "async":
        try:
            return _check_async(items, proto, timeout, judge, judge_pool, threads,
                                emit, tcp_gate)
        except Exception as e:
            if fired:
                # results were already streamed; re-running the batch here would
                # report every proxy twice
                raise RuntimeError(f"async engine failed mid-batch: {e!r}") from e
            print("async engine unavailable, falling back to threads:", type(e).__name__)
    return _check_threads(items, proto, timeout, judge, judge_pool, threads,
                          emit, tcp_gate)
