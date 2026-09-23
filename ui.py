#!/usr/bin/env python3
"""
UI LAYER  -  inline-button formatting, per-view filter state, result filtering.
Credits: @Poriot_ke

**On "colored"/"formatted" buttons.** Telegram's Bot API accepts only plain text
in `inline_keyboard` button labels: no HTML, no Markdown, no colour field. So the
only formatting available is Unicode — flags, and status/tier emoji. `btn()`
applies that consistently: one line, trimmed, emoji-led, with ✅ marking an active
toggle (the closest thing to a "pressed" state the platform offers).

**Views.** One filter/sort state per (chat, scan). It is applied to *everything*
downstream — the report, the country keypad counts, the copy blocks and the
exported files — so what you see is exactly what you get. State lives in memory
(cheap, defaults restored on restart); the records themselves live in the vault.
"""
from __future__ import annotations

import re
import threading

from geoip import NO_IP_CC, UNKNOWN_CC   # one definition, one meaning


# ------------------------------------------------------------ buttons --------
def btn(text, callback_data=None, url=None):
    """Build one inline button with platform-legal (plain-Unicode) formatting."""
    label = re.sub(r"\s+", " ", str(text or "")).strip()
    if not label:
        label = "·"
    # Telegram rejects empty callback_data and >64 bytes; keep both safe.
    if url:
        return {"text": label[:64], "url": url}
    data = (callback_data or "noop")[:64]
    return {"text": label[:64], "callback_data": data}


def row(*buttons):
    return [b for b in buttons if b]


# ------------------------------------------------------------ view state -----
_DEFAULT_VIEW = {
    "only_anon": False,       # hide TRANSPARENT (leaks your IP)
    "max_lat": None,          # ms ceiling
    "proto": None,            # restrict to one protocol
    "min_score": None,        # score floor
    "sort": "speed",          # speed | score | country
    "top": None,              # cap rows
    "hide_leaks": True,       # exports exclude TRANSPARENT unless toggled
    "fmt": "raw",             # export format
    "report_msg": None,       # message ids so a toggle can re-render both panels
    "keypad_msg": None,
}

_VIEWS: dict = {}
_LOCK = threading.Lock()
MAX_VIEWS = 500            # bounded: one entry per (chat, scan) ever touched


def _key(chat_id, scan_id):
    return (str(chat_id), str(scan_id))


def get_view(chat_id, scan_id) -> dict:
    with _LOCK:
        view = _VIEWS.get(_key(chat_id, scan_id))
        if view is None:
            view = dict(_DEFAULT_VIEW)
            _VIEWS[_key(chat_id, scan_id)] = view
            _trim_locked()
        return view


def _trim_locked():
    """Drop the oldest views once the map grows past MAX_VIEWS (insertion order)."""
    while len(_VIEWS) > MAX_VIEWS:
        _VIEWS.pop(next(iter(_VIEWS)), None)


def set_view(chat_id, scan_id, **changes) -> dict:
    with _LOCK:
        view = _VIEWS.setdefault(_key(chat_id, scan_id), dict(_DEFAULT_VIEW))
        view.update(changes)
        return view


def reset_view(chat_id, scan_id) -> dict:
    """Reset every filter — but keep the panel message ids, so the caller can
    still re-render the report/keypad it already sent."""
    with _LOCK:
        old = _VIEWS.get(_key(chat_id, scan_id)) or {}
        view = dict(_DEFAULT_VIEW)
        view["report_msg"] = old.get("report_msg")
        view["keypad_msg"] = old.get("keypad_msg")
        _VIEWS[_key(chat_id, scan_id)] = view
        return view


def toggle(chat_id, scan_id, field, *values):
    """Cycle a field through `values` (or True/False when none are given)."""
    view = get_view(chat_id, scan_id)
    if values:
        current = view.get(field)
        nxt = values[(values.index(current) + 1) % len(values)] if current in values else values[0]
    else:
        nxt = not view.get(field)
    return set_view(chat_id, scan_id, **{field: nxt})


def drop_view(chat_id, scan_id) -> None:
    with _LOCK:
        _VIEWS.pop(_key(chat_id, scan_id), None)


# ------------------------------------------------------------ filtering ------
def _lat(record):
    lat = record.get("lat")
    return float(lat) if isinstance(lat, (int, float)) else 9e9


def filter_records(records, view):
    """Apply the view's filters + sort. Never returns a different record set
    than the one shown, so exports and UI stay consistent."""
    out = list(records or [])

    if view.get("only_anon"):
        # "anon" means *proven* anonymous: both transparent (proven leak) and
        # unknown (leak never verified) are excluded.
        out = [r for r in out if r.get("st") not in ("TRANSPARENT", "UNKNOWN")]
    if view.get("max_lat") is not None:
        out = [r for r in out if _lat(r) <= view["max_lat"]]
    if view.get("proto"):
        out = [r for r in out if r.get("proto") == view["proto"]]
    if view.get("min_score") is not None:
        out = [r for r in out if (r.get("sc") or 0) >= view["min_score"]]

    sort = view.get("sort", "speed")
    if sort == "score":
        out.sort(key=lambda r: (-(r.get("sc") or 0), _lat(r)))
    elif sort == "country":
        out.sort(key=lambda r: (str(r.get("cc") or UNKNOWN_CC), _lat(r)))
    else:
        out.sort(key=_lat)

    if view.get("top"):
        out = out[:view["top"]]
    return out


def export_records(records, view):
    """Records for a *file* export: same view, minus proxies you cannot use —
    IP-leaking ones unless explicitly included, and ones a re-check found dead."""
    out = filter_records(records, view)
    out = [r for r in out if r.get("st") != "DEAD"]
    if view.get("hide_leaks", True):
        out = [r for r in out if r.get("st") != "TRANSPARENT"]
    return out


def view_header(view) -> str:
    """Human summary of the active filters ('' when nothing is filtered)."""
    bits = []
    if view.get("only_anon"):
        bits.append("no leaks")
    if view.get("max_lat"):
        bits.append(f"≤{view['max_lat']:.0f}ms")
    if view.get("proto"):
        bits.append(str(view["proto"]))
    if view.get("min_score"):
        bits.append(f"score ≥{view['min_score']}")
    if view.get("top"):
        bits.append(f"top {view['top']}")
    if view.get("sort") and view["sort"] != "speed":
        bits.append(f"sort: {view['sort']}")
    return " · ".join(bits)


def is_filtered(view) -> bool:
    return bool(view_header(view))
