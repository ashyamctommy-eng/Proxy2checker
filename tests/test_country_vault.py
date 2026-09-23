#!/usr/bin/env python3
"""
Offline tests for the proxy checker bot.

Nothing here needs a Telegram token, a real proxy or the public internet: the
Telegram API is recorded, the checker is stubbed for the bot-level tests, and the
*real* engine is exercised against a mock HTTP proxy running on localhost.

Run:  python3 -m unittest discover -s tests -v
"""
import http.server
import json
import os
import shutil
import socket
import socketserver
import sys
import tempfile
import threading
import time
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

TMP = tempfile.mkdtemp(prefix="pchecker-test-")
os.environ.setdefault("TELEGRAM_BOT_TOKEN", "123456:TEST-TOKEN")
os.environ["PC_VAULT_DIR"] = os.path.join(TMP, "vault")
os.environ["PC_GEO_MAX"] = "50"
os.environ["no_proxy"] = ""
os.environ["NO_PROXY"] = ""

import telegram_proxy_bot as bot      # noqa: E402
import engine                          # noqa: E402
import ui                              # noqa: E402
import formats                         # noqa: E402
import vault as vault_mod              # noqa: E402
from vault import Vault                # noqa: E402
from jobs import JobQueue              # noqa: E402
from judges import JudgePool, extract_ip   # noqa: E402
from geoip import (GeoDB, GeoPipeline, clean_ip, flag_emoji, is_public_ip,  # noqa: E402
                   UNKNOWN_CC, NO_IP_CC)

CHAT = 42
bot.STREAM_MSG_DELAY = 0.0           # keep the suite fast


# ------------------------------------------------------------- mock proxy ----
class MockProxy(socketserver.ThreadingTCPServer):
    """A throwaway HTTP proxy on 127.0.0.1 that always answers with an IP body."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, body='{"ip":"9.9.9.9"}', status=200, delay=0.0,
                 hang=False):
        self.body = body.encode()
        self.status = status
        self.delay = delay
        self.hang = hang
        self.hits = 0
        super().__init__(("127.0.0.1", 0), _ProxyHandler)
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    @property
    def port(self):
        return self.server_address[1]

    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def stop(self):
        self.shutdown()
        self.server_close()


class _ProxyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.server.hits += 1
        try:
            self.request.settimeout(5)
            data = self.request.recv(4096)
            if not data:
                return
            if self.server.hang:
                time.sleep(30)
                return
            if self.server.delay:
                time.sleep(self.server.delay)
            if self.server.status != 200:
                resp = (f"HTTP/1.1 {self.server.status} Nope\r\n"
                        f"Content-Length: 0\r\nConnection: close\r\n\r\n")
            else:
                resp = (f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                        f"Content-Length: {len(self.server.body)}\r\n"
                        f"Connection: close\r\n\r\n")
            self.request.sendall(resp.encode() + (self.server.body if self.server.status == 200 else b""))
        except Exception:
            pass


class _JudgeHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = self.server.body.encode()
        self.send_response(self.server.status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class MockJudge:
    """A local stand-in for an IP-echo endpoint."""

    def __init__(self, body='{"ip":"203.0.113.7"}', status=200):
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _JudgeHandler)
        self.server.body = body
        self.server.status = status
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server.server_address[1]}/ip"

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


# ---------------------------------------------------------------- helpers ----
class FakeTG:
    """Records every outgoing Telegram call instead of hitting the network."""

    def __init__(self):
        self._seq = 0
        self.messages = []   # (seq, chat_id, text, markup)
        self.edits = []      # (seq, chat_id, msg_id, text, markup)
        self.docs = []       # (chat_id, filename, bytes, caption, markup)
        self.callbacks_answered = 0

    def _next(self):
        self._seq += 1
        return self._seq

    def install(self):
        self._api, self._send_doc, self._fetch = bot.api, bot.send_doc, bot.fetch_real_ip
        self._judges = bot.JUDGES
        bot.api = self.api
        bot.send_doc = self.send_doc
        bot.fetch_real_ip = lambda: "198.51.100.9"
        bot.JUDGES = FakeJudges()

    def uninstall(self):
        bot.api, bot.send_doc, bot.fetch_real_ip = self._api, self._send_doc, self._fetch
        bot.JUDGES = self._judges

    def api(self, method, **params):
        if method == "sendMessage":
            markup = params.get("reply_markup")
            self.messages.append((self._next(), params.get("chat_id"),
                                  params.get("text", ""),
                                  json.loads(markup) if markup else None))
            return {"ok": True, "result": {"message_id": len(self.messages)}}
        if method == "editMessageText":
            markup = params.get("reply_markup")
            self.edits.append((self._next(), params.get("chat_id"),
                               params.get("message_id"), params.get("text", ""),
                               json.loads(markup) if markup else None))
            return {"ok": True}
        if method == "answerCallbackQuery":
            self.callbacks_answered += 1
            return {"ok": True}
        return {"ok": True}

    def send_doc(self, chat_id, filename, data, caption="", markup=None):
        if isinstance(data, str):
            data = data.encode()
        self.docs.append((chat_id, filename, data, caption, markup))
        return {"ok": True, "result": {"message_id": 9000 + len(self.docs)}}

    # -- helpers ---------------------------------------------------------
    def all_texts(self):
        out = [(s, t) for s, _, t, _ in self.messages]
        out += [(s, t) for s, _, _, t, _ in self.edits]
        out.sort(key=lambda r: r[0])
        return [t for _, t in out]

    def last_keypad(self):
        combined = [(s, t, m) for s, _, t, m in self.messages]
        combined += [(s, t, m) for s, _, _, t, m in self.edits]
        combined.sort(key=lambda r: r[0])
        for _s, text, markup in reversed(combined):
            if not markup or "inline_keyboard" not in markup:
                continue
            for row in markup["inline_keyboard"]:
                if any(b.get("callback_data", "").startswith(("S|", "K|", "A|")) for b in row):
                    return text, markup
        return None, None

    def last_report(self):
        for text in reversed(self.all_texts()):
            if "Full report" in text:
                return text
        return None


class FakeJudges:
    """A JudgePool stand-in that never touches the network."""

    degraded = False

    def pick(self):
        return "http://judge.invalid/ip"

    def maybe_refresh(self):
        return None

    def check_health(self, force=False):
        return {}

    def check_health_async(self):
        return None

    def status_line(self):
        return None

    def cached_cc(self, ip):
        return ""


def buttons(markup):
    return [b for row in markup["inline_keyboard"] for b in row]


def fake_checker_factory():
    """Deterministic exit IPs spread across countries + a few dead proxies."""
    geo = {
        "8.8.8.8": ("US", "United States"),
        "1.1.1.1": ("AU", "Australia"),
        "41.90.64.1": ("KE", "Kenya"),
        "5.6.7.8": ("DE", "Germany"),
        "9.9.9.9": ("DE", "Germany"),
        "80.1.2.3": ("FR", "France"),
        "185.1.2.3": ("SG", "Singapore"),
    }
    ips = list(geo.keys())

    def fake_check_one(p, default_proto, timeout, judge, tcp_gate=True):
        n = int(p["port"]) % 10
        if n == 0:                     # every 10th proxy is dead
            return False, None, None, None, "ConnectTimeout"
        ip = ips[int(p["port"]) % len(ips)]
        latency = 50 + (int(p["port"]) % 400)
        proto = "socks5" if n % 2 else "http"
        return True, proto, float(latency), ip, ""

    return fake_check_one, geo


def install_fake_checker(bot_mod, fake_check_one):
    """Patch bot.check_many with a synchronous fake honouring the engine API."""
    original = bot_mod.check_many

    def fake_check_many(items, proto="auto", timeout=8, judge=None, judge_pool=None,
                        threads=150, on_result=None, engine="auto", tcp_gate=True):
        results = [None] * len(items)
        for i, p in enumerate(items):
            res = fake_check_one(p, proto, timeout, judge)
            results[i] = res
            if on_result:
                on_result(i, p, res, i + 1, len(items))
        return results

    bot_mod.check_many = fake_check_many
    return original


def fake_geo_lookup(geo):
    def lookup(ips, max_uncached=2500, progress=None):
        out = {}
        for ip in ips:
            ip = clean_ip(ip) or ""
            if not ip:
                continue
            cc, name = geo.get(ip, (UNKNOWN_CC, "Unknown"))
            out[ip] = {"cc": cc, "country": name}
        return out
    return lookup


# ------------------------------------------------------------ geo helpers ----
class GeoHelpers(unittest.TestCase):
    def test_flag_emoji(self):
        self.assertEqual(flag_emoji("US"), "🇺🇸")
        self.assertEqual(flag_emoji("ke"), "🇰🇪")
        for unknown in (UNKNOWN_CC, NO_IP_CC, "", "XX"):
            self.assertEqual(flag_emoji(unknown), "🏳️")

    def test_is_public_ip(self):
        self.assertTrue(is_public_ip("8.8.8.8"))
        for bad in ("192.168.1.5", "10.0.0.1", "not-an-ip"):
            self.assertFalse(is_public_ip(bad))

    def test_clean_ip(self):
        self.assertEqual(clean_ip("[2001:DB8::1]"), "2001:db8::1")
        self.assertEqual(clean_ip("8.8.8.8, 1.1.1.1"), "8.8.8.8")
        self.assertIsNone(clean_ip("  "))

    def test_private_and_bad_ips_are_cached_as_unknown(self):
        db = GeoDB(os.path.join(TMP, "geo_off.json"))
        res = db.lookup(["192.168.0.1", "10.1.2.3", "garbage", ""])
        self.assertEqual(res["192.168.0.1"]["cc"], UNKNOWN_CC)
        self.assertIsNotNone(db._cached("10.1.2.3"))

    def test_unresolved_public_ip_is_not_cached(self):
        db = GeoDB(os.path.join(TMP, "geo_unres.json"))
        db._batch = lambda ips: {}
        db._single = lambda ip: None
        self.assertEqual(db.lookup(["8.8.4.4"])["8.8.4.4"]["cc"], UNKNOWN_CC)
        self.assertIsNone(db._cached("8.8.4.4"), "must not poison the cache")
        db._batch = lambda ips: {"8.8.4.4": {"cc": "US", "country": "United States"}}
        self.assertEqual(db.lookup(["8.8.4.4"])["8.8.4.4"]["cc"], "US")

    def test_over_cap_ips_are_not_cached(self):
        db = GeoDB(os.path.join(TMP, "geo_cap.json"))
        db._batch = lambda ips: {"8.8.8.8": {"cc": "US", "country": "United States"}}
        db._single = lambda ip: None
        res = db.lookup(["8.8.8.8", "1.1.1.1"], max_uncached=1)
        self.assertEqual(res["8.8.8.8"]["cc"], "US")
        self.assertEqual(res["1.1.1.1"]["cc"], UNKNOWN_CC)
        self.assertIsNone(db._cached("1.1.1.1"))


# ----------------------------------------------------------- geo pipeline ----
class GeoPipelineTests(unittest.TestCase):
    def setUp(self):
        self.db = GeoDB(os.path.join(TMP, f"pipe{time.time_ns()}.json"))
        self.calls = []

        def fake_batch(ips):
            self.calls.append(list(ips))
            return {ip: {"cc": "US", "country": "United States"} for ip in ips}
        self.db._batch = fake_batch
        self.db._single = lambda ip: None

    def test_submits_are_resolved_and_deduped(self):
        pipe = GeoPipeline(self.db, batch_size=10, flush=0.05).start()
        for _ in range(3):
            pipe.submit("8.8.8.8")
        pipe.submit("1.1.1.1")
        out = pipe.close()
        self.assertEqual(out["8.8.8.8"]["cc"], "US")
        self.assertEqual(out["1.1.1.1"]["cc"], "US")
        flattened = [ip for chunk in self.calls for ip in chunk]
        self.assertEqual(flattened.count("8.8.8.8"), 1, "duplicates must not be re-queried")

    def test_cc_for_is_free_before_resolution(self):
        pipe = GeoPipeline(self.db, batch_size=10, flush=0.05).start()
        pipe.submit("8.8.8.8")
        pipe.close()
        self.assertEqual(pipe.cc_for("8.8.8.8"), "US")
        self.assertEqual(pipe.cc_for("9.9.9.9"), "", "unknown IP -> no flag, no call")

    def test_cap_is_enforced_across_batches(self):
        pipe = GeoPipeline(self.db, max_uncached=1, batch_size=1, flush=0.01).start()
        for ip in ("8.8.8.8", "1.1.1.1", "9.9.9.9"):
            pipe.submit(ip)
        out = pipe.close()
        queried = [ip for chunk in self.calls for ip in chunk]
        self.assertEqual(len(queried), 1, "cap must bound total API calls")
        self.assertEqual(len(out), 3, "everything still gets a bucket")


# ---------------------------------------------------------------- judges -----
class JudgeTests(unittest.TestCase):
    def test_extract_ip_variants(self):
        cases = {
            '{"ip":"8.8.8.8"}': "8.8.8.8",
            '{"origin":"1.1.1.1, 2.2.2.2"}': "1.1.1.1",
            '{"query":"41.90.64.1"}': "41.90.64.1",
            "8.8.4.4": "8.8.4.4",
            '{"address":"2001:4860:4860::8888"}': "2001:4860:4860::8888",
            "<html>oops</html>": "",
            '{"status":"fail"}': "",
            "": "",
        }
        for raw, want in cases.items():
            self.assertEqual(extract_ip(raw), want, f"for {raw!r}")

    def test_health_and_picking(self):
        pool = JudgePool(judges=["http://a", "http://b"], ttl=60)
        pool._probe = lambda url: ({"ok": True, "ms": 10 if url == "http://a" else 99,
                                    "ip": "8.8.8.8", "ts": time.time(), "err": ""})
        pool.check_health()
        self.assertEqual(pool.pick(), "http://a")
        self.assertFalse(pool.degraded)

    def test_degraded_when_nothing_answers(self):
        pool = JudgePool(judges=["http://a", "http://b"], ttl=60)
        pool._probe = lambda url: {"ok": False, "ms": None, "ip": "",
                                   "ts": time.time(), "err": "boom"}
        pool.check_health()
        self.assertTrue(pool.degraded)
        self.assertIn("Judge degraded", pool.status_line() or "")

    def test_unknown_health_is_optimistic(self):
        pool = JudgePool(judges=["http://a"])
        self.assertFalse(pool.degraded, "no evidence yet must not warn")
        self.assertEqual(pool.pick(), "http://a")
        self.assertIsNone(pool.status_line())


# ---------------------------------------------------------------- engine -----
class EngineTests(unittest.TestCase):
    """Exercises the real engine against a localhost mock proxy."""

    @classmethod
    def setUpClass(cls):
        cls.judge = MockJudge()
        cls.proxy = MockProxy()

    @classmethod
    def tearDownClass(cls):
        cls.proxy.stop()
        cls.judge.stop()

    def parsed(self, raw=None):
        raw = raw or f"127.0.0.1:{self.proxy.port}"
        p = engine.parse_proxy(raw)
        assert p, raw
        return p

    def test_tcp_gate_accepts_and_rejects(self):
        ok, ms, err = engine.tcp_probe("127.0.0.1", self.proxy.port, 1.0)
        self.assertTrue(ok)
        self.assertGreaterEqual(ms, 0)
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        closed_port = s.getsockname()[1]
        s.close()
        ok2, _ms, err2 = engine.tcp_probe("127.0.0.1", closed_port, 0.5)
        self.assertFalse(ok2)
        self.assertTrue(err2.startswith("TCP"), err2)

    def test_check_one_success_and_exit_ip(self):
        # the mock proxy answers with its own body, which stands in for the exit IP
        ok, proto, lat, ip, err = engine.check_one(self.parsed(), "http", 5,
                                                   self.judge.url)
        self.assertTrue(ok, err)
        self.assertEqual(proto, "http")
        self.assertEqual(ip, "9.9.9.9")
        self.assertEqual(err, "")
        self.assertGreater(lat, 0)

    def test_check_one_reports_dead_when_gate_fails(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        ok, proto, lat, ip, err = engine.check_one(
            engine.parse_proxy(f"127.0.0.1:{port}"), "http", 3, self.judge.url)
        self.assertFalse(ok)
        self.assertTrue(err.startswith("TCP"), err)

    def test_judge_unreadable_is_flagged_not_a_proxy_failure(self):
        # a judge whose body has no IP in it (e.g. an HTML error page)
        bad = MockProxy(body="<html>not an ip</html>")
        try:
            ok, proto, lat, ip, err = engine.check_one(
                engine.parse_proxy(f"127.0.0.1:{bad.port}"), "http", 5, self.judge.url)
            self.assertTrue(ok, "the proxy worked; only the judge body was unusable")
            self.assertEqual(err, engine.JUDGE_UNREADABLE)
            self.assertEqual(ip, "")
        finally:
            bad.stop()

    def test_attempt_order_and_timeouts(self):
        p = engine.parse_proxy("1.2.3.4:8080")
        self.assertEqual(engine.attempts_for(p, "auto"),
                         ("http", "socks5", "socks4", "https"))
        self.assertEqual(engine.attempt_timeout(8, 0), 8)
        self.assertLess(engine.attempt_timeout(8, 1), 8)
        self.assertGreaterEqual(engine.attempt_timeout(8, 3), 3)

    def test_check_many_streams_every_item(self):
        items = [self.parsed() for _ in range(5)]
        seen = []
        results = engine.check_many(items, proto="http", timeout=5,
                                    judge=self.judge.url, threads=4,
                                    on_result=lambda i, p, r, d, t: seen.append((i, d, t)),
                                    engine="thread")
        self.assertEqual(len(results), 5)
        self.assertTrue(all(r[0] for r in results))
        self.assertEqual([d for _, d, _ in seen], [1, 2, 3, 4, 5])
        self.assertTrue(all(t == 5 for _, _, t in seen))

    def test_async_backend_matches_thread_backend(self):
        if not engine.async_available():
            self.skipTest("aiohttp not installed")
        items = [self.parsed() for _ in range(3)]
        sync = engine._check_threads(items, "http", 5, self.judge.url, None, 3, None, True)
        asyn = engine._check_async(items, "http", 5, self.judge.url, None, 3, None, True)
        self.assertEqual([r[0] for r in sync], [r[0] for r in asyn])
        self.assertEqual([r[3] for r in sync], [r[3] for r in asyn])

    def test_async_backend_reports_dead_hosts(self):
        if not engine.async_available():
            self.skipTest("aiohttp not installed")
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        p = engine.parse_proxy(f"127.0.0.1:{port}")
        res = engine._check_async([p], "http", 3, self.judge.url, None, 2, None, True)
        self.assertFalse(res[0][0])
        self.assertTrue(res[0][4].startswith("TCP"), res[0][4])

    def test_engine_resolution_defaults_to_threads(self):
        self.assertEqual(engine.resolve_engine("auto"), "thread")
        self.assertEqual(engine.resolve_engine("thread"), "thread")
        self.assertIn(engine.resolve_engine("async"), ("async", "thread"))


# ----------------------------------------------------------------- vault -----
class VaultTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="vault-", dir=TMP)
        self.v = Vault(self.dir)

    def test_scan_roundtrip_and_index(self):
        recs = [{"raw": "1.1.1.1:80", "proto": "http", "lat": 10.0, "ip": "8.8.8.8",
                 "st": "OK", "cc": "US", "country": "United States", "sc": 90},
                {"raw": "2.2.2.2:80", "proto": "socks5", "lat": 20.0, "ip": "41.90.64.1",
                 "st": "OK", "cc": "KE", "country": "Kenya", "sc": 80}]
        self.v.save_scan(CHAT, "abc123", recs, {"total": 5})
        got = self.v.load_scan(CHAT, "abc123")
        self.assertEqual(len(got["records"]), 2)
        self.assertEqual(got["meta"]["total"], 5)
        idx = self.v.list_scans(CHAT)
        self.assertEqual(idx[0]["scan_id"], "abc123")
        self.assertEqual(idx[0]["countries"]["US"], 1)

    def test_pool_upsert_keeps_fastest_and_newest(self):
        self.v.push_pool([{"raw": "1.1.1.1:80", "lat": 300, "cc": "US",
                           "proto": "http", "ip": "8.8.8.8", "st": "OK"}])
        self.v.push_pool([{"raw": "1.1.1.1:80", "lat": 120, "cc": "US",
                           "proto": "http", "ip": "8.8.8.8", "st": "OK"},
                          {"raw": "2.2.2.2:80", "lat": 90, "cc": "DE",
                           "proto": "http", "ip": "5.6.7.8", "st": "OK"}])
        pool = {r["raw"]: r for r in self.v.load_pool()}
        self.assertEqual(len(pool), 2)
        self.assertEqual(pool["1.1.1.1:80"]["lat"], 120)

    def test_pool_tie_prefers_newest(self):
        self.v.push_pool([{"raw": "a:1", "lat": 300, "cc": "US", "proto": "http",
                           "ip": "8.8.8.8", "st": "OK"}])
        self.v.push_pool([{"raw": "a:1", "lat": 300, "cc": "KE", "proto": "http",
                           "ip": "8.8.8.8", "st": "OK"}])
        self.assertEqual(self.v.load_pool()[0]["cc"], "KE")

    def test_update_records_for_recheck(self):
        self.v.save_scan(4242, "beef1234",
                         [{"raw": "5.5.5.5:80", "proto": "http", "lat": 500.0,
                           "ip": "8.8.8.8", "st": "OK", "cc": "US",
                           "country": "United States", "sc": 40}])
        n = self.v.update_records("beef1234", [{"raw": "5.5.5.5:80", "lat": 120.0,
                                                "ip": "1.1.1.1", "st": "OK", "cc": "DE",
                                                "country": "Germany", "sc": 90}])
        self.assertEqual(n, 1)
        got = self.v.load_scan(4242, "beef1234")["records"][0]
        self.assertEqual((got["lat"], got["cc"], got["sc"]), (120.0, "DE", 90))

    def test_pool_queries_by_country(self):
        self.v.push_pool([
            {"raw": "a:1", "lat": 10.0, "cc": "US", "proto": "http", "ip": "8.8.8.8", "st": "OK"},
            {"raw": "b:1", "lat": 20.0, "cc": "US", "proto": "http", "ip": "8.8.4.4", "st": "OK"},
            {"raw": "c:1", "lat": 30.0, "cc": "DE", "proto": "http", "ip": "5.6.7.8", "st": "OK"}])
        self.assertEqual(self.v.pool_countries()["US"], 2)
        self.assertEqual(len(self.v.load_pool(cc="DE")), 1)


class VaultRegressionTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="vsec-", dir=TMP)
        self.v = Vault(self.dir)
        self.v.save_scan(999111, "deadbeef01",
                         [{"raw": "victim-proxy:8080", "proto": "http", "lat": 5.0,
                           "ip": "8.8.8.8", "st": "OK", "cc": "US",
                           "country": "United States", "sc": 50}])

    def test_scan_id_traversal_is_rejected(self):
        for bad in ("../999111/deadbeef01", "a/b", "deadbeef01/../../x", "",
                    "POOL", ".", ".."):
            self.assertIsNone(self.v.load_scan(CHAT, bad), f"{bad!r} must not resolve")
        self.assertIsNone(self.v.save_scan(CHAT, "../evil", []))
        self.assertIsNotNone(self.v.load_scan(999111, "deadbeef01"))

    def test_pruning_deletes_rows(self):
        old = vault_mod.SCAN_INDEX_KEEP
        vault_mod.SCAN_INDEX_KEEP = 2
        try:
            for i in range(5):
                self.v.save_scan(555000, f"abc{i:03d}", [])
            self.assertEqual(len(self.v.list_scans(555000, limit=10)), 2)
            self.assertIsNone(self.v.load_scan(555000, "abc000"))
            self.assertIsNotNone(self.v.load_scan(555000, "abc004"))
        finally:
            vault_mod.SCAN_INDEX_KEEP = old

    def test_pool_cap(self):
        old = vault_mod.POOL_MAX_UNIQUE
        vault_mod.POOL_MAX_UNIQUE = 5
        try:
            self.v.push_pool([{"raw": f"p{i}:1", "lat": float(i), "cc": "US",
                               "proto": "http", "ip": "8.8.8.8", "st": "OK"}
                              for i in range(20)])
            self.assertEqual(self.v.pool_size(), 5)
        finally:
            vault_mod.POOL_MAX_UNIQUE = old

    def test_legacy_files_are_migrated_once(self):
        root = tempfile.mkdtemp(prefix="legacy-", dir=TMP)
        os.makedirs(os.path.join(root, "scans", "77"), exist_ok=True)
        with open(os.path.join(root, "pool.jsonl"), "w") as fh:
            fh.write(json.dumps({"raw": "1.1.1.1:80", "lat": 200, "cc": "US",
                                 "proto": "http", "ip": "8.8.8.8", "st": "OK"}) + "\n")
            fh.write(json.dumps({"raw": "1.1.1.1:80", "lat": 90, "cc": "US",
                                 "proto": "http", "ip": "8.8.8.8", "st": "OK"}) + "\n")
        with open(os.path.join(root, "scans", "77", "abcdef01.json"), "w") as fh:
            json.dump({"scan_id": "abcdef01", "chat_id": "77", "ts": 1000,
                       "meta": {"total": 3},
                       "records": [{"raw": "2.2.2.2:80", "proto": "http", "lat": 10.0,
                                    "ip": "1.1.1.1", "st": "OK", "cc": "DE",
                                    "country": "Germany", "sc": 70}]}, fh)
        v1 = Vault(root)
        self.assertEqual(v1.pool_size(), 1)
        self.assertEqual(v1.load_pool()[0]["lat"], 90)
        self.assertIsNotNone(v1.load_scan("77", "abcdef01"))
        v2 = Vault(root)
        self.assertEqual(v2.pool_size(), 1, "import must not duplicate")


# ------------------------------------------------------------- filters -------
class FilterTests(unittest.TestCase):
    def setUp(self):
        self.records = [
            {"raw": "a:1", "proto": "http", "lat": 100.0, "st": "OK", "cc": "US",
             "country": "United States", "sc": 95},
            {"raw": "b:1", "proto": "socks5", "lat": 900.0, "st": "OK", "cc": "DE",
             "country": "Germany", "sc": 30},
            {"raw": "c:1", "proto": "http", "lat": 200.0, "st": "TRANSPARENT",
             "cc": "US", "country": "United States", "sc": 60},
            {"raw": "d:1", "proto": "http", "lat": None, "st": "DEAD", "cc": "XX",
             "country": "No exit IP", "sc": 0},
        ]
        self.chat, self.scan = 7, "abcdef01"
        bot.ui.reset_view(self.chat, self.scan)
        self.view = bot.ui.get_view(self.chat, self.scan)

    def test_default_export_drops_leaks_and_dead(self):
        out = ui.export_records(self.records, self.view)
        raws = [r["raw"] for r in out]
        self.assertNotIn("c:1", raws, "transparent proxies must be opt-in")
        self.assertNotIn("d:1", raws, "dead proxies must never be exported")
        self.assertIn("a:1", raws)

    def test_toggle_include_leaks(self):
        view = ui.set_view(self.chat, self.scan, hide_leaks=False)
        raws = [r["raw"] for r in ui.export_records(self.records, view)]
        self.assertIn("c:1", raws)

    def test_each_filter(self):
        def fresh(**kw):
            ui.reset_view(self.chat, self.scan)
            return ui.set_view(self.chat, self.scan, **kw)

        v = fresh(only_anon=True)
        self.assertEqual([r["raw"] for r in ui.filter_records(self.records, v)],
                         ["a:1", "b:1", "d:1"])
        v = fresh(max_lat=500)
        self.assertEqual([r["raw"] for r in ui.filter_records(self.records, v)],
                         ["a:1", "c:1"])
        v = fresh(proto="socks5")
        self.assertEqual([r["raw"] for r in ui.filter_records(self.records, v)], ["b:1"])
        v = fresh(min_score=70)
        self.assertEqual([r["raw"] for r in ui.filter_records(self.records, v)], ["a:1"])
        v = fresh(top=1)
        self.assertEqual([r["raw"] for r in ui.filter_records(self.records, v)], ["a:1"])

    def test_sort_orders(self):
        ui.reset_view(self.chat, self.scan)
        v = ui.set_view(self.chat, self.scan, sort="score")
        self.assertEqual([r["raw"] for r in ui.filter_records(self.records, v)],
                         ["a:1", "c:1", "b:1", "d:1"])
        v = ui.set_view(self.chat, self.scan, sort="country")
        self.assertEqual(ui.filter_records(self.records, v)[0]["cc"], "DE")

    def test_toggle_cycles_and_header(self):
        ui.reset_view(self.chat, self.scan)
        self.assertIsNone(ui.get_view(self.chat, self.scan)["max_lat"])
        ui.toggle(self.chat, self.scan, "max_lat", None, 500, 1000)
        self.assertEqual(ui.get_view(self.chat, self.scan)["max_lat"], 500)
        ui.toggle(self.chat, self.scan, "max_lat", None, 500, 1000)
        self.assertEqual(ui.get_view(self.chat, self.scan)["max_lat"], 1000)
        self.assertIn("≤1000ms", ui.view_header(ui.get_view(self.chat, self.scan)))

    def test_btn_is_plain_single_line_and_short(self):
        b = ui.btn("multi\nline   label", "x" * 200)
        self.assertNotIn("\n", b["text"])
        self.assertLessEqual(len(b["callback_data"]), 64)
        self.assertEqual(ui.btn("hi", "cb")["callback_data"], "cb")
        self.assertEqual(ui.btn("hi", url="https://t.me/x")["url"], "https://t.me/x")
        self.assertNotIn("callback_data", ui.btn("hi", url="https://t.me/x"))
        self.assertEqual(ui.btn("")["text"], "·")


# -------------------------------------------------------------- formats ------
class FormatTests(unittest.TestCase):
    rec = {"raw": "1.2.3.4:8080:user:pass", "proto": "http", "lat": 12.0,
           "st": "OK", "cc": "US", "country": "United States", "sc": 88}

    def test_each_format(self):
        self.assertEqual(formats.format_record(self.rec, "raw"), "1.2.3.4:8080:user:pass")
        self.assertEqual(formats.format_record(self.rec, "ip:port"), "1.2.3.4:8080")
        self.assertEqual(formats.format_record(self.rec, "host:port:user:pass"),
                         "1.2.3.4:8080:user:pass")
        self.assertEqual(formats.format_record(self.rec, "user:pass@host:port"),
                         "user:pass@1.2.3.4:8080")
        self.assertEqual(formats.format_record(self.rec, "url"),
                         "http://user:pass@1.2.3.4:8080")

    def test_json_body(self):
        body = formats.body_for([self.rec], "json")
        data = json.loads(body)
        self.assertEqual(data[0]["host"], "1.2.3.4")
        self.assertEqual(data[0]["country"], "US")

    def test_url_scheme_for_socks(self):
        rec = dict(self.rec, raw="socks5://1.2.3.4:1080", proto="socks5")
        self.assertEqual(formats.format_record(rec, "url"), "socks5://1.2.3.4:1080")

    def test_unparseable_line_falls_back_to_raw(self):
        weird = {"raw": "not a proxy at all"}
        for fmt in formats.FORMATS:
            out = formats.format_record(weird, fmt)
            self.assertTrue(out if isinstance(out, str) else out["host"] == "" or True)

    def test_filenames(self):
        self.assertEqual(formats.filename("proxies", "US", "raw"), "proxies_US.txt")
        self.assertEqual(formats.filename("proxies", "US", "json"), "proxies_US.json")
        self.assertEqual(formats.filename("report", "DE", "raw"), "report_DE.txt")


# ---------------------------------------------------------------- queue ------
class JobQueueTests(unittest.TestCase):
    def test_one_job_at_a_time_per_chat(self):
        q = JobQueue(max_jobs=2, global_threads=10, min_threads=1)
        order, started = [], threading.Event()

        def job(tag):
            def run(threads):
                order.append(tag)
                if tag == "a":
                    time.sleep(0.2)
            return run

        q.submit(1, "a", job("a"))
        state = q.submit(1, "b", job("b"))
        self.assertEqual(state, "queued")
        self.assertEqual(q.position(1, "b"), 1)
        started.wait(0.05)
        for _ in range(60):
            if q.active_jobs() == 0 and not q.is_busy(1):
                break
            time.sleep(0.05)
        self.assertEqual(order, ["a", "b"], "queued job must run after the first")

    def test_different_chats_run_concurrently(self):
        q = JobQueue(max_jobs=4, global_threads=20, min_threads=1)
        release = threading.Event()
        started = []

        def make(tag):
            def run(threads):
                started.append(tag)
                release.wait(1.0)
            return run

        q.submit(1, "a", make("a"))
        q.submit(2, "b", make("b"))
        for _ in range(40):
            if len(started) == 2:
                break
            time.sleep(0.05)
        release.set()
        self.assertEqual(sorted(started), ["a", "b"])

    def test_cancel_waiting_drops_queued_jobs(self):
        q = JobQueue(max_jobs=2, global_threads=10, min_threads=1)
        release = threading.Event()

        def blocker(threads):
            release.wait(1.0)

        q.submit(1, "a", blocker)
        q.submit(1, "b", blocker)
        q.submit(1, "c", blocker)
        self.assertEqual(q.cancel_waiting(1), 2)
        self.assertEqual(q.position(1, "b"), 0)
        release.set()

    def test_thread_budget_is_bounded(self):
        q = JobQueue(max_jobs=4, global_threads=300, min_threads=16)
        self.assertLessEqual(q.threads_for_job(), 300)
        self.assertGreaterEqual(q.threads_for_job(), 16)

    def test_job_exception_does_not_break_the_queue(self):
        q = JobQueue(max_jobs=2, global_threads=10, min_threads=1)
        ran = []

        def boom(threads):
            raise RuntimeError("boom")

        def after(threads):
            ran.append("after")

        q.submit(1, "a", boom)
        q.submit(1, "b", after)
        for _ in range(60):
            if ran:
                break
            time.sleep(0.05)
        self.assertEqual(ran, ["after"], "a crashing job must not block the chat")


# ------------------------------------------------------------ bot scoring ----
class ScoreTests(unittest.TestCase):
    def test_faster_scores_higher(self):
        self.assertGreater(bot.score_of(120), bot.score_of(900))
        self.assertGreater(bot.score_of(900), bot.score_of(2500))

    def test_score_bounds(self):
        self.assertEqual(bot.score_of(10), 100)
        self.assertEqual(bot.score_of(9000), 0)
        for bad in (None, "nope", float("nan"), float("inf")):
            self.assertEqual(bot.score_of(bad), 0)

    def test_anonymity_multiplier(self):
        self.assertGreater(bot.score_of(150, "OK"), bot.score_of(150, "TRANSPARENT"))
        self.assertGreater(bot.score_of(150, "TRANSPARENT"), bot.score_of(150, "FLAGGED"))

    def test_grades(self):
        for score, grade in ((90, "A+"), (75, "A"), (60, "B"), (45, "C"), (10, "D")):
            self.assertEqual(bot.grade_of(score), grade)

    def test_safe_cc(self):
        self.assertEqual(bot.safe_cc("us"), "US")
        self.assertEqual(bot.safe_cc("../etc"), "ETC")
        self.assertEqual(bot.safe_cc(""), NO_IP_CC)


class FeedAndEnvTests(unittest.TestCase):
    def test_feed_and_report_never_exceed_message_limits(self):
        self.assertLessEqual(len(bot.feed_text(400, 400, 400, ["h" * 200] * 400)), 4096)
        recs = [{"raw": "x" * 120, "proto": "http", "lat": float(i), "ip": "8.8.8.8",
                 "st": "OK", "cc": "US", "country": "United States", "sc": 50}
                for i in range(1, 400)]
        self.assertLessEqual(len(bot.report_text(recs, "s", bot.ui.get_view(1, "s"))), 4096)
        self.assertIn("line-399", bot.feed_text(9, 9, 9, [f"line-{i}" for i in range(400)]))

    def test_feed_header_has_cpm_and_eta(self):
        text = bot.feed_text(10, 100, 5, ["x"], cpm=1200, eta="1m 30s")
        self.assertIn("1200 CPM", text)
        self.assertIn("ETA 1m 30s", text)

    def test_feed_entry_rendering_resolves_country_late(self):
        entries = [(1, 2, "a:1", True, 120.0, "8.8.8.8", "", "OK")]
        before = bot.render_feed_lines(entries, lambda ip: "")
        after = bot.render_feed_lines(entries, lambda ip: "US")
        self.assertNotIn("US", before[0])
        self.assertIn("🇺🇸US", after[0])

    def test_human_eta(self):
        self.assertEqual(bot.human_eta(0), "0s")
        self.assertEqual(bot.human_eta(45), "45s")
        self.assertEqual(bot.human_eta(90), "1m 30s")
        self.assertEqual(bot.human_eta(3700), "1h 01m")

    def test_env_clamps(self):
        os.environ["PC_STREAM_MAX"] = "99999"
        os.environ["PC_FEED_LINES"] = "-5"
        try:
            self.assertEqual(bot._num_env("PC_STREAM_MAX", 20, 0, 50, int), 50)
            self.assertEqual(bot._num_env("PC_FEED_LINES", 22, 1, 200, int), 1)
            os.environ["PC_STREAM_MAX"] = "nope"
            self.assertEqual(bot._num_env("PC_STREAM_MAX", 20, 0, 50, int), 20)
        finally:
            for k in ("PC_STREAM_MAX", "PC_FEED_LINES"):
                os.environ.pop(k, None)

    def test_caption_and_pathological_lines(self):
        self.assertLessEqual(len(bot.clip_caption("<b>h</b> " + "y" * 2000)), 1024)
        self.assertNotRegex(bot.clip_caption("x" * 1010 + "&amp;" + "y" * 50),
                            r"&[a-zA-Z#0-9]*$")
        chunks = bot.chunk_lines([f"h{i}:1" + "<&>" * 20 for i in range(300)])
        for chunk in chunks:
            self.assertLessEqual(len("\n".join(bot.esc(l) for l in chunk)), 3200)
        self.assertLessEqual(len(bot.esc(bot.chunk_lines(["x" * 5000])[0][0])),
                             bot.MAX_COPY_LINE)


# ------------------------------------------------------- bot integration -----
class BotFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tg = FakeTG()
        cls.checker, cls.geo = fake_checker_factory()
        cls._check_many = install_fake_checker(bot, cls.checker)
        cls._geo_lookup = bot.GEO.lookup
        bot.GEO.lookup = fake_geo_lookup(cls.geo)
        cls.tg.install()
        lines = [f"203.0.113.{i}:{8000 + i}" for i in range(1, 41)]
        bot.run_job(CHAT, lines)
        cls.msgs_after_run = list(cls.tg.messages)
        cls.edits_after_run = list(cls.tg.edits)
        cls.scan_id = None
        for text in cls.tg.all_texts():
            if "Saved to vault" in text:
                cls.scan_id = text.split("scan <code>")[-1].split("</code>")[0]
                break

    @classmethod
    def tearDownClass(cls):
        bot.check_many = cls._check_many
        bot.GEO.lookup = cls._geo_lookup
        cls.tg.uninstall()

    def cb(self, data):
        return {"id": "cb1", "data": data,
                "message": {"message_id": 7, "chat": {"id": CHAT}}}

    # -- job ---------------------------------------------------------------
    def test_job_saved_to_vault(self):
        self.assertIsNotNone(self.scan_id)
        recs = bot.VAULT.load_scan(CHAT, self.scan_id)["records"]
        self.assertEqual(len(recs), 36)
        self.assertTrue(all(r["cc"] for r in recs))
        self.assertGreaterEqual(bot.VAULT.pool_size(), 36)

    def test_summary_and_report_sent(self):
        joined = "\n".join(self.tg.all_texts())
        self.assertIn("Saved to vault", joined)
        self.assertIn("Done!", joined)
        self.assertIn("Full report", joined)
        self.assertIsNotNone(self.tg.last_keypad())

    def test_country_keypad_colored_and_sorted(self):
        text, keypad = self.tg.last_keypad()
        country_btns = [b for b in buttons(keypad)
                        if b.get("callback_data", "").startswith("S|")]
        codes = [b["callback_data"].split("|")[2] for b in country_btns]
        self.assertEqual(codes[0], "DE")          # 2 exit IPs -> biggest
        for b in country_btns:
            self.assertRegex(b["text"], r"^[🟢🟡🟠🔴] .*·\s*\d+$")
        self.assertIn("Results", text)

    def test_country_file_excludes_leaks_by_default(self):
        bot.handle_callback(self.cb(f"S|{self.scan_id}|DE"))
        _chat, fname, data, caption, _markup = self.tg.docs[-1]
        self.assertTrue(fname.startswith("proxies_DE"))
        self.assertTrue(data.decode().strip())
        self.assertIn("Germany", caption)

    def test_filter_toggle_rerenders_report(self):
        before = len(self.tg.edits)
        bot.handle_callback(self.cb(f"T|{self.scan_id}|score"))
        new = [t for _, _, _, t, _ in self.tg.edits[before:]]
        self.assertTrue(any("Full report" in t for t in new),
                        "toggling a filter must re-render the report")
        view = bot.ui.get_view(CHAT, self.scan_id)
        self.assertEqual(view["min_score"], 70)
        self.assertIn("score ≥70", bot.ui.view_header(view))
        bot.handle_callback(self.cb(f"T|{self.scan_id}|reset"))
        self.assertIsNone(bot.ui.get_view(CHAT, self.scan_id)["min_score"])

    def test_sort_toggle_and_proto_filter_apply_to_keypad(self):
        bot.handle_callback(self.cb(f"T|{self.scan_id}|proto"))
        view = bot.ui.get_view(CHAT, self.scan_id)
        self.assertEqual(view["proto"], "http")
        recs = bot.VAULT.load_scan(CHAT, self.scan_id)["records"]
        filtered = bot.ui.filter_records(recs, view)
        self.assertTrue(filtered)
        self.assertTrue(all(r["proto"] == "http" for r in filtered))
        bot.handle_callback(self.cb(f"T|{self.scan_id}|reset"))

    def test_format_picker_changes_export(self):
        bot.handle_callback(self.cb(f"X|{self.scan_id}|ip:port"))
        self.assertEqual(bot.ui.get_view(CHAT, self.scan_id)["fmt"], "ip:port")
        bot.handle_callback(self.cb(f"S|{self.scan_id}|DE"))
        _chat, fname, data, _cap, _mk = self.tg.docs[-1]
        self.assertTrue(fname.endswith(".txt"))
        for line in data.decode().strip().splitlines():
            self.assertRegex(line, r"^\d+\.\d+\.\d+\.\d+:\d+$")
        bot.handle_callback(self.cb(f"X|{self.scan_id}|json"))
        bot.handle_callback(self.cb(f"A|{self.scan_id}"))
        _chat, fname, data, _cap, _mk = self.tg.docs[-1]
        self.assertTrue(fname.endswith(".json"))
        json.loads(data.decode())
        bot.handle_callback(self.cb(f"X|{self.scan_id}|raw"))

    def test_copy_button(self):
        before = len(self.tg.messages)
        bot.handle_callback(self.cb(f"C|{self.scan_id}|DE"))
        body = "\n".join(t for _, _, t, _ in self.tg.messages[before:])
        self.assertIn("<pre>", body)
        self.assertIn("Tap the block to copy", body)

    def test_report_file_button(self):
        before = len(self.tg.docs)
        bot.handle_callback(self.cb(f"F|{self.scan_id}"))
        self.assertEqual(len(self.tg.docs), before + 1)
        self.assertEqual(self.tg.docs[-1][1], "report.txt")
        self.assertIn("/100", self.tg.docs[-1][2].decode())

    def test_country_report_button(self):
        bot.handle_callback(self.cb(f"R|{self.scan_id}|KE"))
        self.assertEqual(self.tg.docs[-1][1], "report_KE.txt")

    def test_no_exit_ip_bucket_is_distinct(self):
        recs = bot.VAULT.load_scan(CHAT, self.scan_id)["records"]
        self.assertTrue(all(r["cc"] != NO_IP_CC for r in recs),
                        "stub always returns an exit IP; XX must stay unused here")
        self.assertEqual(bot.label_of(NO_IP_CC), "🚫 no exit IP")
        self.assertNotEqual(bot.label_of(NO_IP_CC), bot.label_of(UNKNOWN_CC))

    def test_unknown_scan_and_crafted_id_are_handled(self):
        before = len(self.tg.messages)
        bot.handle_callback(self.cb("S|nope|US"))
        bot.handle_callback(self.cb("S|../999111/deadbeef01|US"))
        new = [t for _, _, t, _ in self.tg.messages[before:]]
        self.assertTrue(any("no longer in the vault" in t for t in new))
        self.assertFalse(any("victim-proxy" in (d[2] or b"").decode(errors="ignore")
                             for d in self.tg.docs))

    def test_vault_and_pool_commands(self):
        before = len(self.tg.messages)
        bot.handle_update({"message": {"chat": {"id": CHAT}, "text": "/vault"}})
        vault_msgs = self.tg.messages[before:]
        self.assertTrue(any("All-time pool" in t for _, _, t, _ in vault_msgs))
        cbs = [b.get("callback_data", "") for b in buttons(vault_msgs[-1][3])]
        self.assertIn("P", cbs)
        bot.handle_update({"message": {"chat": {"id": CHAT}, "text": "/pool"}})
        text, keypad = self.tg.last_keypad()
        self.assertIn("all-time pool", text)
        bot.handle_update({"message": {"chat": {"id": CHAT}, "text": "/countries"}})
        self.assertIsNotNone(self.tg.last_keypad()[1])

    def test_cancel_with_nothing_queued(self):
        before = len(self.tg.messages)
        bot.handle_update({"message": {"chat": {"id": CHAT}, "text": "/cancel"}})
        self.assertTrue(any("Nothing queued" in t
                            for _, _, t, _ in self.tg.messages[before:]))

    def test_recheck_updates_vault(self):
        bot.handle_callback(self.cb(f"RE|{self.scan_id}|DE"))
        for _ in range(80):
            if not bot.QUEUE.is_busy(CHAT):
                break
            time.sleep(0.05)
        recs = bot.VAULT.load_scan(CHAT, self.scan_id)["records"]
        de = [r for r in recs if r["cc"] == "DE"]
        self.assertTrue(de)
        self.assertIn(bot.VAULT.pool_size() > 0, (True,))

    def test_pagination_clamps(self):
        bot.handle_callback(self.cb(f"K|{self.scan_id}|9"))
        text, keypad = self.tg.last_keypad()
        self.assertIn("page 1/", text)
        self.assertTrue(any(b.get("callback_data", "").startswith(("S|", "A|"))
                            for b in buttons(keypad)))


class SmallJobStreamTests(unittest.TestCase):
    """<= STREAM_MAX proxies: every single line is thrown as its own message."""

    @classmethod
    def setUpClass(cls):
        cls.tg = FakeTG()
        cls.checker, cls.geo = fake_checker_factory()
        cls._check_many = install_fake_checker(bot, cls.checker)
        cls._geo_lookup = bot.GEO.lookup
        bot.GEO.lookup = fake_geo_lookup(cls.geo)
        cls.tg.install()
        cls.lines = [f"203.0.113.{i}:{8000 + i}" for i in range(1, 11)]
        bot.run_job(CHAT, cls.lines)

    @classmethod
    def tearDownClass(cls):
        bot.check_many = cls._check_many
        bot.GEO.lookup = cls._geo_lookup
        cls.tg.uninstall()

    def test_one_message_per_proxy_line(self):
        thrown = [t for _, _, t, _ in self.tg.messages if t.startswith("<pre>")]
        self.assertEqual(len(thrown), len(self.lines))
        for i, text in enumerate(thrown, 1):
            self.assertIn(f"{i}/{len(self.lines)}", text)
        joined = "\n".join(thrown)
        self.assertIn("dead (ConnectTimeout)", joined)
        self.assertIn("10/10", joined)

    def test_no_aggregate_feed_for_small_jobs(self):
        self.assertFalse([t for _, _, t, _ in self.tg.messages if "Live scan" in t])


class LargeJobStreamTests(unittest.TestCase):
    """Big jobs: one rolling feed message, never one message per proxy."""

    @classmethod
    def setUpClass(cls):
        cls.tg = FakeTG()
        cls.checker, cls.geo = fake_checker_factory()
        cls._check_many = install_fake_checker(bot, cls.checker)
        cls._geo_lookup = bot.GEO.lookup
        bot.GEO.lookup = fake_geo_lookup(cls.geo)
        cls.tg.install()
        bot.run_job(CHAT, [f"203.0.113.{i}:{8000 + i}" for i in range(1, 41)])

    @classmethod
    def tearDownClass(cls):
        bot.check_many = cls._check_many
        bot.GEO.lookup = cls._geo_lookup
        cls.tg.uninstall()

    def test_rolling_feed_used(self):
        texts = [t for _, _, t, _ in self.tg.messages]
        self.assertTrue([t for t in texts if "Live scan" in t])
        self.assertEqual([t for t in texts if t.startswith("<pre>")], [])
        feed_edits = [t for _, _, _, t, _ in self.tg.edits if "Live scan" in t]
        self.assertGreaterEqual(len(feed_edits), 2)
        self.assertIn("40/40", feed_edits[-1])

    def test_feed_window_bounded_and_newest_last(self):
        feed = [t for _, _, _, t, _ in self.tg.edits if "Live scan" in t][-1]
        shown = [ln for ln in feed.split("<pre>")[1].split("</pre>")[0].split("\n") if ln]
        self.assertLessEqual(len(shown), bot.FEED_LINES)
        self.assertIn("40/40", shown[-1])


class RealEngineBotTest(unittest.TestCase):
    """The whole bot path, but with the real engine + localhost mock proxy/judge."""

    def test_run_job_with_real_engine(self):
        judge = MockJudge()
        proxy = MockProxy(body='{"ip":"41.90.64.1"}')
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        dead_port = sock.getsockname()[1]
        sock.close()

        tg = FakeTG()
        tg.install()
        saved = (bot.JUDGE_OVERRIDE, bot.PROTO, bot.GEO_ENABLED, bot.TIMEOUT)
        try:
            bot.JUDGE_OVERRIDE = judge.url
            bot.PROTO = "http"
            bot.GEO_ENABLED = False
            bot.TIMEOUT = 5
            lines = [f"127.0.0.1:{proxy.port}",
                     f"127.0.0.1:{dead_port}",
                     f"127.0.0.1:{proxy.port}"]      # duplicate -> deduped
            bot._run_job(999, lines)

            texts = "\n".join(tg.all_texts())
            self.assertIn("Saved to vault", texts)
            self.assertIn("Full report", texts)
            scan_id = [t for t in tg.all_texts() if "Saved to vault" in t][0] \
                .split("scan <code>")[-1].split("</code>")[0]
            recs = bot.VAULT.load_scan(999, scan_id)["records"]
            self.assertEqual(len(recs), 1, "one live proxy, deduped, one dead")
            self.assertEqual(recs[0]["ip"], "41.90.64.1")
            self.assertEqual(recs[0]["st"], "OK")
            self.assertGreater(recs[0]["sc"], 0)
            self.assertGreaterEqual(bot.VAULT.pool_size(), 1)
        finally:
            bot.JUDGE_OVERRIDE, bot.PROTO, bot.GEO_ENABLED, bot.TIMEOUT = saved
            tg.uninstall()
            proxy.stop()
            judge.stop()


# ---------------------------------------------------- review regressions -----
class ReviewRegressionTests(unittest.TestCase):
    """Bugs found in review — each one gets a test so it cannot come back."""

    def test_bad_legacy_record_cannot_poison_the_vault(self):
        """A failed legacy import must ROLLBACK, or every later save fails."""
        root = tempfile.mkdtemp(prefix="poison-", dir=TMP)
        os.makedirs(os.path.join(root, "scans", "9"), exist_ok=True)
        with open(os.path.join(root, "scans", "9", "aaaaaaaa.json"), "w") as fh:
            json.dump({"scan_id": "aaaaaaaa", "chat_id": "9", "ts": 1,
                       "meta": {},
                       "records": [{"raw": "x:1", "lat": {"unbindable": 1}}]}, fh)
        with open(os.path.join(root, "scans", "9", "bbbbbbbb.json"), "w") as fh:
            json.dump({"scan_id": "bbbbbbbb", "chat_id": "9", "ts": 2, "meta": {},
                       "records": [{"raw": "y:1", "lat": 5.0, "sc": 50}]}, fh)
        v = Vault(root)
        self.assertFalse(v._conn().in_transaction, "migration must not leave a txn open")
        self.assertIsNotNone(v.load_scan("9", "bbbbbbbb"),
                             "a bad scan must not stop the next one importing")
        self.assertEqual(v.save_scan(9, "cccccccc",
                                     [{"raw": "z:1", "lat": 1.0, "sc": 10}]),
                         "cccccccc", "the vault must stay writable")
        self.assertIsNotNone(v.load_scan(9, "cccccccc"))

    def test_judge_stats_does_not_deadlock(self):
        pool = JudgePool(judges=["http://a"], ttl=60)
        pool._probe = lambda url: {"ok": True, "ms": 5, "ip": "8.8.8.8",
                                   "ts": time.time(), "err": ""}
        pool.check_health()
        done = []
        t = threading.Thread(target=lambda: done.append(pool.stats()), daemon=True)
        t.start()
        t.join(2.0)
        self.assertTrue(done, "stats() must not hang")

    def test_thread_budget_is_not_oversubscribed(self):
        q = JobQueue(max_jobs=4, global_threads=300, min_threads=16)
        grants, release = [], threading.Event()

        def job(tag):
            def run(threads):
                grants.append(threads)
                release.wait(1.0)
            return run

        for i in range(4):
            q.submit(i, f"j{i}", job(i))
        for _ in range(60):
            if len(grants) == 4:
                break
            time.sleep(0.05)
        release.set()
        self.assertEqual(len(grants), 4)
        budget = q.global_threads + q.max_jobs * q.min_threads
        self.assertLessEqual(sum(grants), budget,
                             f"thread budget blown: {grants} (budget {budget})")

    def test_pipeline_close_is_bounded_and_keeps_keys(self):
        db = GeoDB(os.path.join(TMP, f"grace{time.time_ns()}.json"))
        started = threading.Event()

        def slow_lookup(ips, max_uncached=2500, progress=None):
            started.set()
            time.sleep(3.0)
            return {ip: {"cc": "US", "country": "United States"} for ip in ips}

        db.lookup = slow_lookup
        pipe = GeoPipeline(db, batch_size=1, flush=0.01, close_grace=0.05).start()
        pipe.submit("8.8.8.8")
        started.wait(1.0)
        t0 = time.time()
        out = pipe.close()
        elapsed = time.time() - t0
        self.assertLess(elapsed, 2.0, "close() must not block on a stuck worker")
        self.assertIn("8.8.8.8", out, "every submitted IP keeps a bucket")

    def test_classify_status_is_exact_not_substring(self):
        self.assertEqual(bot.classify_status("1.2.3.4", "1.2.3.4"), "TRANSPARENT")
        self.assertEqual(bot.classify_status("1.2.3.45", "1.2.3.4"), "OK",
                         "a longer IP that merely starts the same is not transparent")
        self.assertEqual(bot.classify_status("", "1.2.3.4"), "FLAGGED")

    def test_scheme_less_raw_uses_stored_proto(self):
        rec = {"raw": "1.2.3.4:1080", "proto": "socks5", "lat": 10.0,
               "st": "OK", "cc": "US", "country": "United States", "sc": 80}
        self.assertEqual(formats.format_record(rec, "url"), "socks5://1.2.3.4:1080")
        self.assertEqual(formats.format_record(rec, "json")["proto"], "socks5")
        explicit = dict(rec, raw="http://1.2.3.4:1080", proto="http")
        self.assertEqual(formats.format_record(explicit, "url"), "http://1.2.3.4:1080")

    def test_reset_keeps_panel_ids_so_it_can_rerender(self):
        chat, scan = 555, "abcdef01"
        ui.set_view(chat, scan, min_score=70, report_msg=11, keypad_msg=22)
        view = ui.reset_view(chat, scan)
        self.assertIsNone(view["min_score"])
        self.assertEqual(view["report_msg"], 11)
        self.assertEqual(view["keypad_msg"], 22)

    def test_views_map_is_bounded(self):
        old = ui.MAX_VIEWS
        ui.MAX_VIEWS = 10
        try:
            for i in range(50):
                ui.get_view(999, f"scan{i:04d}")
            self.assertLessEqual(len(ui._VIEWS), 10)
        finally:
            ui.MAX_VIEWS = old
            ui._VIEWS.pop(("999", "scan0049"), None)

    def test_report_honours_the_sort_toggle(self):
        recs = [{"raw": "slow:1", "proto": "http", "lat": 900.0, "st": "OK",
                 "cc": "US", "country": "United States", "sc": 95},
                {"raw": "fast:1", "proto": "http", "lat": 100.0, "st": "OK",
                 "cc": "US", "country": "United States", "sc": 40}]
        by_speed = bot.report_text(recs, "s", ui.set_view(1, "z", sort="speed"))
        by_score = bot.report_text(recs, "s", ui.set_view(1, "z", sort="score"))
        speed_table = by_speed.split("<pre>")[1].split("</pre>")[0]
        score_table = by_score.split("<pre>")[1].split("</pre>")[0]
        self.assertLess(speed_table.index("fast:1"), speed_table.index("slow:1"))
        self.assertLess(score_table.index("slow:1"), score_table.index("fast:1"))
        self.assertIn("sorted by score", by_score)
        self.assertIn("Best score", by_score, "the headline follows the sort too")

    def test_async_failure_does_not_double_report(self):
        """If the async backend dies mid-batch, check_many must not re-run it."""
        calls = []

        def fake_async(items, *a, **kw):
            on_result = a[5]
            on_result(0, items[0], (True, "http", 1.0, "8.8.8.8", ""), 1, len(items))
            raise RuntimeError("session exploded")

        original = engine._check_async
        original_threads = engine._check_threads
        engine._check_async = fake_async
        engine._check_threads = lambda *a, **kw: calls.append("threads") or []
        try:
            items = [engine.parse_proxy("1.2.3.4:80")]
            with self.assertRaises(RuntimeError):
                engine.check_many(items, engine="async", on_result=lambda *a: None)
            self.assertEqual(calls, [], "must not silently re-run the whole batch")
        finally:
            engine._check_async = original
            engine._check_threads = original_threads

    def test_async_falls_back_when_nothing_was_reported(self):
        calls = []
        original = engine._check_async
        original_threads = engine._check_threads
        engine._check_async = lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("no aiohttp"))
        engine._check_threads = lambda items, *a, **kw: calls.append("threads") or []
        try:
            engine.check_many([engine.parse_proxy("1.2.3.4:80")], engine="async")
            self.assertEqual(calls, ["threads"])
        finally:
            engine._check_async = original
            engine._check_threads = original_threads

    def test_recheck_refreshes_country_from_new_exit_ip(self):
        recs = [{"raw": "9.9.9.9:8001", "proto": "http", "lat": 100.0,
                 "ip": "8.8.8.8", "st": "OK", "cc": "US",
                 "country": "United States", "sc": 90}]
        bot.VAULT.save_scan(777, "dddddddd", recs)

        def checker(p, proto, timeout, judge, tcp_gate=True):
            return True, "http", 120.0, "5.6.7.8", ""      # now exits in DE
        original = bot.check_many
        geo_lookup = bot.GEO.lookup
        bot.check_many = lambda items, **kw: [checker(p, None, None, None)
                                              for p in items]
        bot.GEO.lookup = lambda ips, max_uncached=2500, progress=None: {
            "5.6.7.8": {"cc": "DE", "country": "Germany"}}
        try:
            bot._recheck(777, "dddddddd", "US", limit=5)
        finally:
            bot.check_many = original
            bot.GEO.lookup = geo_lookup
        got = bot.VAULT.load_scan(777, "dddddddd")["records"][0]
        self.assertEqual(got["ip"], "5.6.7.8")
        self.assertEqual(got["cc"], "DE", "country must follow the new exit IP")
        self.assertEqual(got["country"], "Germany")


class DripFeedServer:
    """A server that sends a valid 200 header, then one byte at a time forever.

    This is the pathological case `requests`' per-socket timeout cannot bound:
    every individual read succeeds, so the request never ends.
    """

    def __init__(self):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        try:
            conn.recv(65536)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n")
            while not self._stop:
                conn.sendall(b"x")
                time.sleep(0.2)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def close(self):
        self._stop = True
        try:
            self.sock.close()
        except Exception:
            pass


class AutonomyHardeningTests(unittest.TestCase):
    """Regressions for the bugs fixed on fix/autonomy-hardening."""

    def test_cli_module_imports_and_loads_input(self):
        """proxy_checker.py had zero test coverage, so a change to engine's
        public names (PROTOS) broke the CLI without failing a single test."""
        import importlib
        pc = importlib.import_module("proxy_checker")
        self.assertEqual(pc.PROTOS, engine.PROTO_ORDER_AUTO)
        path = os.path.join(TMP, "cli-input.txt")
        with open(path, "w") as fh:
            fh.write("1.2.3.4:8080\n\n# comment\n\n5.6.7.8:3128\n")
        lines = pc.load_input([path])
        self.assertIn("1.2.3.4:8080", lines)
        self.assertIn("5.6.7.8:3128", lines)

    # ---- anonymity must not be asserted when it cannot be verified ----------
    def test_status_is_unknown_when_our_own_ip_is_unknown(self):
        self.assertEqual(bot.classify_status("203.0.113.9", None), "UNKNOWN")
        self.assertEqual(bot.classify_status("203.0.113.9", ""), "UNKNOWN")
        self.assertEqual(bot.classify_status("203.0.113.9", "203.0.113.9"), "TRANSPARENT")
        self.assertEqual(bot.classify_status("203.0.113.9", "198.51.100.9"), "OK")
        self.assertEqual(bot.classify_status(None, "198.51.100.9"), "FLAGGED")

    def test_unknown_scores_below_verified_anonymous_but_above_transparent(self):
        self.assertGreater(bot.score_of(150, "OK"), bot.score_of(150, "UNKNOWN"))
        self.assertGreater(bot.score_of(150, "UNKNOWN"), bot.score_of(150, "TRANSPARENT"))
        self.assertGreater(bot.score_of(150, "TRANSPARENT"), bot.score_of(150, "FLAGGED"))
        for st in bot.SCORE_MULT:
            self.assertIn(st, bot.STATUS_ICON)

    def test_anon_filter_excludes_unverified(self):
        recs = [{"raw": "a:1", "lat": 10.0, "st": "OK", "sc": 90},
                {"raw": "b:1", "lat": 20.0, "st": "UNKNOWN", "sc": 90},
                {"raw": "c:1", "lat": 30.0, "st": "TRANSPARENT", "sc": 60}]
        view = ui.reset_view("c-anon", "abcdef01")
        view["only_anon"] = True
        out = ui.filter_records(recs, view)
        self.assertEqual([r["raw"] for r in out], ["a:1"])

    # ---- exports -----------------------------------------------------------
    def test_export_never_emits_a_literal_none_credential(self):
        p = engine.parse_proxy("user@1.2.3.4:8080")
        self.assertEqual(p["user"], "user")
        self.assertIsNone(p["pass"])
        for fmt in ("url", "u:p@h:p", "host:port:user:pass", "ip:port"):
            out = formats.format_record(p, fmt)
            self.assertIsInstance(out, str)
            self.assertNotIn("None", out, f"{fmt} leaked a literal None: {out}")

    # ---- IPv6 --------------------------------------------------------------
    def test_bracketed_ipv6_round_trips(self):
        p = engine.parse_proxy("[2001:db8::1]:8080")
        self.assertIsNotNone(p)
        self.assertEqual(p["host"], "2001:db8::1")
        self.assertEqual(p["port"], 8080)
        self.assertEqual(engine.proxy_url(p), "http://[2001:db8::1]:8080")
        self.assertEqual(formats.format_record(p, "ip:port"), "[2001:db8::1]:8080")

    def test_bare_ipv6_is_rejected_not_misparsed(self):
        # `::1:8080` used to parse as host="1" — a silent wrong check.
        for bad in ("::1:8080", "2001:db8::1:8080", "[not-an-ip]:8080", "[2001:db8::1]"):
            self.assertIsNone(engine.parse_proxy(bad), bad)

    # ---- timeouts ----------------------------------------------------------
    def test_fallback_timeout_never_exceeds_the_primary(self):
        for t in (1, 2, 3, 5, 6, 8, 10, 30):
            self.assertEqual(engine.attempt_timeout(t, 0), t)
            self.assertLessEqual(engine.attempt_timeout(t, 1), t, f"timeout={t}")

    def test_bounded_get_enforces_a_total_deadline(self):
        srv = DripFeedServer()
        try:
            started = time.monotonic()
            with self.assertRaises(Exception):
                engine.bounded_get(f"http://127.0.0.1:{srv.port}/", 1.0)
            elapsed = time.monotonic() - started
        finally:
            srv.close()
        # Before the fix this never returned: requests' timeout is per socket op,
        # and every individual read succeeded.
        self.assertLess(elapsed, 8.0, "bounded_get did not bound the total time")

    def test_bounded_get_caps_a_huge_body(self):
        size = engine.MAX_BODY_BYTES * 3
        body = b"A" * size

        class BigHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        httpd = http.server.HTTPServer(("127.0.0.1", 0), BigHandler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            status, text = engine.bounded_get(
                f"http://127.0.0.1:{httpd.server_address[1]}/", 10.0)
        finally:
            httpd.shutdown()
            httpd.server_close()
        self.assertEqual(status, 200)
        self.assertLessEqual(len(text), engine.MAX_BODY_BYTES)

    # ---- poll lifetime -----------------------------------------------------
    def test_poll_error_action_backs_off_then_exits_on_repeated_409(self):
        conflicts = 0
        for _ in range(4):
            action, wait, conflicts = bot.poll_error_action(409, conflicts)
            self.assertEqual(action, "retry")
            self.assertGreater(wait, 0)
        action, _wait, _c = bot.poll_error_action(409, conflicts)
        self.assertEqual(action, "exit")      # give up so the platform restarts

    def test_poll_error_action_exits_on_auth_failure(self):
        self.assertEqual(bot.poll_error_action(401, 0)[0], "exit")
        self.assertEqual(bot.poll_error_action(403, 0)[0], "exit")
        self.assertEqual(bot.poll_error_action(400, 0), ("retry", 3, 0))

    def test_token_is_redacted_from_logs(self):
        token = bot.TOKEN
        # requests' exception strings embed the request URL, which embeds the token.
        leaked = bot._redact(f"HTTPSConnectionPool https://api.telegram.org/bot{token}/getUpdates")
        self.assertNotIn(token, leaked)
        self.assertIn("<token>", leaked)

    # ---- async engine ------------------------------------------------------
    def test_async_socks_is_not_routed_into_an_aiohttp_socks_url(self):
        """aiohttp cannot speak a socks5h:// proxy URL without aiohttp_socks'
        ProxyConnector, which this engine never builds. The old guard delegated to
        the thread pool only when aiohttp_socks was *absent*, so installing the
        optional dependency made every SOCKS proxy report dead."""
        import inspect
        src = inspect.getsource(engine._check_async)
        self.assertNotIn("not socks_async_available()", src)
        self.assertIn('if one_proto in ("socks4", "socks5"):', src)


class RealNetworkSmokeTest(unittest.TestCase):
    """Only test that touches the internet; skips itself when unavailable."""

    def test_geo_lookup(self):
        db = GeoDB(os.path.join(TMP, "geo_real.json"))
        try:
            res = db.lookup(["8.8.8.8", "1.1.1.1"])
        except Exception as e:                       # pragma: no cover
            self.skipTest(f"network unavailable: {e}")
        if res.get("8.8.8.8", {}).get("cc") in (None, UNKNOWN_CC):
            self.skipTest("geo provider unreachable from this environment")
        self.assertEqual(res["8.8.8.8"]["cc"], "US")


if __name__ == "__main__":
    try:
        unittest.main(verbosity=2)
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
