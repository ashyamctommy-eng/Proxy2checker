#!/usr/bin/env python3
"""
EXPORT FORMATS  -  turn a stored record back into whatever the user's tool wants.
Credits: @Poriot_ke

Records in the vault keep the proxy line *as the user wrote it* (`raw`) plus the
parsed fields. Re-parsing `raw` on export means one stored record can be rendered
in any of these shapes without changing the vault schema:

    raw    1.2.3.4:8080:user:pass        exactly as it appeared in the input
    ip:port                1.2.3.4:8080
    host:port:user:pass    1.2.3.4:8080:user:pass
    user:pass@host:port    user:pass@1.2.3.4:8080
    url                    socks5://user:pass@1.2.3.4:8080
    json                   [{"host":..,"port":..,"proto":..,...}, ...]

Most people just want a paste-ready list for their tool of choice, which is why
this is a first-class UI action rather than a config flag.
"""
from __future__ import annotations

import json

FORMATS = ("raw", "ip:port", "host:port:user:pass", "user:pass@host:port", "url", "json")

# short labels for inline buttons (no HTML/Markdown allowed in button text)
FORMAT_LABELS = {
    "raw": "as-is",
    "ip:port": "ip:port",
    "host:port:user:pass": "h:p:u:p",
    "user:pass@host:port": "u:p@h:p",
    "url": "url",
    "json": "json",
}

EXT = {"json": "json"}


def _parts(record):
    """Parse the stored raw line -> (proto, host, port, user, pass) or None.

    A scheme-less line (`1.2.3.4:1080`) parses as http by default, which would
    mislabel a stored SOCKS proxy in `url`/`json` exports — so the protocol the
    checker actually used wins for those.
    """
    try:
        from engine import parse_proxy, _PROTO_RE
        raw = str(record.get("raw", ""))
        p = parse_proxy(raw)
    except Exception:
        return None
    if not p:
        return None
    proto = p["proto"]
    if not _PROTO_RE.match(raw.strip()) and record.get("proto"):
        proto = str(record["proto"])
    return (proto, p["host"], p["port"], p["user"], p["pass"])


def _scheme(proto):
    return {"socks5": "socks5", "socks4": "socks4"}.get(proto, proto or "http")


def format_record(record, fmt="raw"):
    """Render one record in the requested format (falls back to raw)."""
    fmt = fmt if fmt in FORMATS else "raw"
    raw = str(record.get("raw", "")).strip()
    if fmt == "raw":
        return raw

    parsed = _parts(record)
    if not parsed:
        return raw                     # unparseable line: never lose it
    proto, host, port, user, pwd = parsed

    if fmt == "json":
        return {
            "host": host, "port": port, "proto": _scheme(proto),
            "username": user, "password": pwd,
            "country": record.get("cc"), "status": record.get("st"),
            "latency_ms": record.get("lat"), "score": record.get("sc"),
        }
    if fmt == "ip:port":
        return f"{host}:{port}"
    if fmt == "host:port:user:pass":
        return f"{host}:{port}:{user}:{pwd}" if user else f"{host}:{port}"
    if fmt == "user:pass@host:port":
        return f"{user}:{pwd}@{host}:{port}" if user else f"{host}:{port}"
    if fmt == "url":
        auth = f"{user}:{pwd}@" if user else ""
        return f"{_scheme(proto)}://{auth}{host}:{port}"
    return raw


def format_lines(records, fmt="raw"):
    """List of rendered lines (JSON handled by `body_for`)."""
    if fmt == "json":
        return [json.dumps(format_record(r, "json"), ensure_ascii=False) for r in records]
    return [format_record(r, fmt) for r in records]


def body_for(records, fmt="raw"):
    """Full file body for a set of records in the given format."""
    if fmt == "json":
        payload = [format_record(r, "json") for r in records]
        return json.dumps(payload, indent=2, ensure_ascii=False)
    return "\n".join(format_lines(records, fmt))


def filename(base, cc=None, fmt="raw"):
    """proxies_US.txt / proxies_US.json / report_US.txt"""
    ext = EXT.get(fmt, "txt")
    if cc:
        return f"{base}_{cc}.{ext}"
    return f"{base}.{ext}"
