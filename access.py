#!/usr/bin/env python3
"""
ACCESS  -  who is allowed to use the bot.
Credits: @Poriot_ke

The bot is otherwise wide open: any Telegram user who learns its username could
queue scans, download files and read the pool. This module is the gate.

Model
-----
* **Admins** are configured out of band via `PC_ADMIN_IDS` (comma or semicolon
  separated Telegram *user* ids). They always have access and are the only ones
  who can mint redeem keys.
* **Everyone else** needs an entry in the `access` table, which they get by
  redeeming a key an admin generated (`/redeem PC-XXXX-XXXX-XXXX`). A grant can
  carry an expiry.
* **Enforcement is switched on by configuring `PC_ADMIN_IDS`.** With no admins
  set the bot stays open (and says so at startup) — that way a deploy cannot
  lock the operator out of their own bot by omission.

State lives in the vault's SQLite file, so it survives restarts as long as the
volume is mounted (see the Railway notes in the README).
"""
from __future__ import annotations

import os

DEFAULT_ADMIN_ENV = "PC_ADMIN_IDS"


def parse_admins(raw) -> set:
    """'1,2; 3' -> {'1','2','3'} (ids are compared as strings)."""
    out = set()
    for part in str(raw or "").replace(";", ",").replace(" ", ",").split(","):
        part = part.strip()
        if part:
            out.add(part)
    return out


ADMIN_IDS = parse_admins(os.environ.get(DEFAULT_ADMIN_ENV, ""))


def enabled() -> bool:
    """Enforcement is on iff at least one admin is configured."""
    return bool(ADMIN_IDS)


def is_admin(user_id) -> bool:
    return user_id is not None and str(user_id) in ADMIN_IDS


def check(vault, user_id):
    """-> (allowed: bool, reason: str)."""
    if not enabled():
        return True, "open"
    if is_admin(user_id):
        return True, "admin"
    if not user_id:
        return False, "anonymous"
    entry = vault.access_entry(user_id)
    if entry:
        return True, "granted"
    return False, "denied"


def sender_id(update_msg):
    """The *user* id behind an update (falls back to the chat id for channels)."""
    frm = update_msg.get("from") or {}
    if frm.get("id") is not None:
        return str(frm["id"])
    chat = update_msg.get("chat") or {}
    if chat.get("id") is not None:
        return str(chat["id"])
    return ""


DENIED_TEXT = (
    "🔒 <b>This bot is private.</b>\n\n"
    "Ask the operator for a redeem key, then send:\n"
    "<code>/redeem PC-XXXX-XXXX-XXXX</code>"
)

OPEN_WARNING = (
    "access: PC_ADMIN_IDS is not set — the bot is OPEN to anyone who finds it. "
    "Set PC_ADMIN_IDS to your Telegram user id to lock it down."
)
