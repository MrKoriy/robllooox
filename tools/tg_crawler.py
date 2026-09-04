#!/usr/bin/env python3
"""tg_crawler - Telegram bot state-machine walker + hidden command fuzzer.

Usage:
  pip install telethon
  python3 tg_crawler.py --bot kaifrentbot --api-id <ID> --api-hash <HASH> --session burner
  python3 tg_crawler.py --bot kaifrentbot --api-id <ID> --api-hash <HASH> --session burner --fuzz
  python3 tg_crawler.py --bot kaifrentbot --api-id <ID> --api-hash <HASH> --session burner --params "ref=1,ref=2,ref=admin"
"""

import argparse
import asyncio
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime

from telethon import TelegramClient, events, errors
from telethon.tl import types

FUZZ_WORDLIST = [
    "admin", "админ", "admin_panel", "panel", "панель", "staff", "stats", "статистика",
    "stat", "keys", "key", "keys_all", "gen", "genkey", "generate", "generate_key",
    "create_key", "newkey", "add_key", "grant", "grant_key", "renew", "extend",
    "activate", "activation", "promo", "promocode", "промокод", "code", "coupon",
    "discount", "free", "getfree", "trial", "test", "test_key", "debug", "dev",
    "devmode", "hidden", "secret", "sudo", "root", "owner", "superadmin", "super",
    "god", "adminaccess", "backup", "export", "dump", "db", "database", "sql",
    "query", "users", "userlist", "orders", "orderlist", "sales", "profits",
    "balance", "wallet", "ref", "referral", "refs", "invite", "bonus", "daily",
    "check", "checkkey", "verify", "verifykey", "keyinfo", "info", "help",
    "settings", "config", "logs", "log", "errors", "error", "crash", "report",
    "feedback", "support", "ticket", "api", "token", "webhook", "botinfo", "me",
    "myid", "id", "pay", "payment", "invoice", "pay_status", "confirm",
    "confirmpay", "sber", "sbp", "card", "crypto", "usdt", "xrocket", "stars",
    "gifts", "nft", "promo_activate", "promo_use", "trial_key", "vip", "premium",
    "plus", "upgrade", "downgrade", "cancel", "delete", "unban", "ban", "kick",
    "mute", "warn", "give", "givekey", "addbalance", "setbalance", "setkey",
    "setpromo", "settariff", "setprice", "price", "tariff", "tariff1", "tariff2",
    "tariff3", "subscription", "sub", "subscribe", "unsubscribe", "profile",
    "cabinet", "lk", "account", "sessions", "session", "active_sessions", "url",
    "urls", "site", "domain", "docs", "doc", "about", "version", "test_pay",
    "pay_test", "stub", "mock", "sandbox", "hidden_menu", "backdoor", "staff_menu",
]

URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


def sig(msg):
    text = (msg.text or msg.raw_text or "").strip()
    buttons = []
    try:
        for row in (msg.buttons or []):
            buttons.append(tuple((b.text, getattr(b, "data", None) is not None,
                                  getattr(b, "url", None) or "") for b in row))
    except Exception:
        pass
    return hashlib.sha256((text + json.dumps(buttons)).encode()).hexdigest()[:16]


class Crawler:
    def __init__(self, client, bot, out_dir, delay):
        self.client = client
        self.bot = bot
        self.out_dir = out_dir
        self.delay = delay
        self.q = asyncio.Queue()
        self.transcript = []
        self.seen = set()
        self.seen_texts = set()
        self.clicks = 0
        self.urls = set()
        self.invoices = []

    def log(self, entry):
        entry["t"] = datetime.now().isoformat(timespec="seconds")
        self.transcript.append(entry)
        print(json.dumps(entry, ensure_ascii=False, default=str))

    async def drain(self, timeout=6.0, quiet=2.5):
        out = []
        last = time.monotonic()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                m = await asyncio.wait_for(self.q.get(), timeout=0.5)
            except asyncio.TimeoutError:
                if time.monotonic() - last >= quiet:
                    break
                continue
            out.append(m)
            last = time.monotonic()
        return out

    def describe(self, msg):
        text = (msg.text or msg.raw_text or "").strip()
        kind = "text"
        if msg.media:
            if isinstance(msg.media, types.MessageMediaInvoice):
                kind = "invoice"
            elif isinstance(msg.media, types.MessageMediaPhoto):
                kind = "photo"
            elif isinstance(msg.media, types.MessageMediaDocument):
                kind = "document"
            else:
                kind = "media"
        return kind, text

    def button_meta(self, b):
        meta = {"text": b.text}
        if getattr(b, "data", None) is not None:
            meta["type"] = "callback"
            meta["data"] = b.data.hex()
        elif getattr(b, "url", None):
            meta["type"] = "url"
            meta["url"] = b.url
            self.urls.add(b.url)
        elif getattr(b, "request_contact", False):
            meta["type"] = "contact"
        elif getattr(b, "request_location", False):
            meta["type"] = "location"
        elif getattr(b, "inline_query", None):
            meta["type"] = "inline"
        else:
            under = getattr(b, "button", None)
            if isinstance(under, types.KeyboardButtonBuy):
                meta["type"] = "buy"
            elif isinstance(under, (types.KeyboardButtonRequestPhone,
                                    types.KeyboardButtonRequestGeoLocation)):
                meta["type"] = "request"
            else:
                meta["type"] = "other"
        return meta

    async def record(self, msg, depth, source):
        kind, text = self.describe(msg)
        entry = {"source": source, "depth": depth, "kind": kind, "text": text[:2000]}
        for u in URL_RE.findall(text):
            self.urls.add(u)
        try:
            rows = msg.buttons or []
            entry["buttons"] = [[self.button_meta(b) for b in row] for row in rows]
        except Exception as e:
            entry["buttons"] = []
            entry["btn_err"] = str(e)
        if kind == "invoice":
            m = msg.media
            inv = {
                "title": getattr(m, "title", None),
                "description": getattr(m, "description", None),
                "currency": getattr(m, "currency", None),
                "total_amount": getattr(m, "total_amount", None),
                "provider": getattr(m, "provider_id", None),
            }
            self.invoices.append(inv)
            entry["invoice"] = inv
        if text and text not in self.seen_texts:
            self.seen_texts.add(text)
        self.log(entry)

    async def click_button(self, b, parent_text, depth):
        self.clicks += 1
        entry = {"source": "click", "depth": depth, "button": b.text,
                 "parent": parent_text[:300]}
        try:
            await b.click()
            entry["clicked"] = True
            self.log(entry)
            replies = await self.drain()
            for r in replies:
                await self.record(r, depth + 1, "click_reply")
            return replies
        except errors.FloodWaitError as e:
            entry["error"] = f"flood {e.seconds}s"
            self.log(entry)
            await asyncio.sleep(min(e.seconds, 30))
        except Exception as e:
            entry["error"] = f"{type(e).__name__}: {e}"
            self.log(entry)
        await asyncio.sleep(self.delay)
        return []

    async def walk(self, max_depth, max_clicks):
        await self.client.send_message(self.bot, "/start")
        await asyncio.sleep(self.delay)
        first = await self.drain()
        for m in first:
            await self.record(m, 0, "start")
        frontier = [(m, 0) for m in first if m.buttons]
        visited_states = set()
        while frontier and self.clicks < max_clicks:
            msg, depth = frontier.pop(0)
            if depth >= max_depth:
                continue
            state = sig(msg)
            if state in visited_states:
                continue
            visited_states.add(state)
            for row in msg.buttons or []:
                for b in row:
                    meta = self.button_meta(b)
                    if meta["type"] in ("buy", "contact", "location", "request", "inline", "url"):
                        continue
                    if self.clicks >= max_clicks:
                        return
                    replies = await self.click_button(b, msg.text or "", depth)
                    for r in replies:
                        if r.buttons:
                            frontier.append((r, depth + 1))
        print(f"\n[+] walk done: {self.clicks} clicks")

    async def fuzz(self):
        await self.client.send_message(self.bot, "/start")
        await asyncio.sleep(self.delay)
        await self.drain()
        baseline = set()
        for cmd in ["/help", "/start", "привет"]:
            await self.client.send_message(self.bot, cmd)
            await asyncio.sleep(self.delay)
            for r in await self.drain():
                _, text = self.describe(r)
                baseline.add(text.strip()[:120])
        distinct = {}
        for cmd in FUZZ_WORDLIST:
            await self.client.send_message(self.bot, "/" + cmd)
            await asyncio.sleep(self.delay)
            for r in await self.drain():
                _, text = self.describe(r)
                key = text.strip()[:120]
                if key and key not in baseline:
                    distinct.setdefault(cmd, []).append(text[:2000])
        hits = {c: t for c, t in distinct.items() if t}
        print(f"\n[+] fuzz done: {len(FUZZ_WORDLIST)} commands, "
              f"{len(hits)} produced non-baseline replies")
        for cmd, texts in hits.items():
            print(f"\n--- /{cmd} ---")
            for t in texts[:3]:
                print(t[:500])

    async def params(self, params):
        await self.client.send_message(self.bot, "/start")
        await asyncio.sleep(self.delay)
        await self.drain()
        baseline = set()
        for r in [x for x in self.transcript if x.get("source") == "start"]:
            baseline.add(r.get("text", "")[:120])
        seen = {}
        for p in params:
            await self.client.send_message(self.bot, f"/start {p}")
            await asyncio.sleep(self.delay)
            for r in await self.drain():
                _, text = self.describe(r)
                key = text.strip()[:120]
                if key and key not in baseline:
                    seen.setdefault(p, []).append(text[:2000])
        hits = {p: t for p, t in seen.items() if t}
        print(f"\n[+] params done: {len(params)} tried, "
              f"{len(hits)} produced non-baseline replies")
        for p, texts in hits.items():
            print(f"\n--- start {p} ---")
            for t in texts[:3]:
                print(t[:500])

    def save(self, name):
        path = os.path.join(self.out_dir, name)
        with open(path, "w", encoding="utf-8") as f:
            for e in self.transcript:
                f.write(json.dumps(e, ensure_ascii=False, default=str) + "\n")
        print(f"\n[+] transcript: {path}")
        if self.urls:
            print("[+] URLs seen:")
            for u in sorted(self.urls):
                print("    " + u)
        if self.invoices:
            print("[+] invoices seen:")
            for i in self.invoices:
                print("    " + json.dumps(i, ensure_ascii=False))
        print(f"[+] distinct bot messages: {len(self.seen_texts)}")


async def main():
    ap = argparse.ArgumentParser(description="Telegram bot crawler")
    ap.add_argument("--bot", required=True)
    ap.add_argument("--api-id", required=True)
    ap.add_argument("--api-hash", required=True)
    ap.add_argument("--session", default="burner")
    ap.add_argument("--fuzz", action="store_true")
    ap.add_argument("--params", default="")
    ap.add_argument("--depth", type=int, default=5)
    ap.add_argument("--max-clicks", type=int, default=150)
    ap.add_argument("--delay", type=float, default=1.2)
    ap.add_argument("--out", default="crawls")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    client = TelegramClient(args.session, int(args.api_id), args.api_hash)
    await client.start()
    bot = await client.get_entity(args.bot)
    bot_id = bot.id

    c = Crawler(client, bot, args.out, args.delay)

    @client.on(events.NewMessage(chats=bot_id))
    async def on_new(e):
        if e.is_private and not e.out:
            c.q.put_nowait(e.message)

    @client.on(events.MessageEdited(chats=bot_id))
    async def on_edit(e):
        if e.is_private and not e.out:
            c.q.put_nowait(e.message)

    try:
        if args.fuzz:
            await c.fuzz()
        elif args.params:
            await c.params([p.strip() for p in args.params.split(",") if p.strip()])
        else:
            await c.walk(args.depth, args.max_clicks)
    finally:
        name = f"{args.bot.lstrip('@')}_{int(time.time())}.jsonl"
        c.save(name)
        await client.disconnect()


if __name__ == "__main__":
    asyncio.run(main())