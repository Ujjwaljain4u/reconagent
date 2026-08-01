from __future__ import annotations

import os

import requests

from reconagent.collectors.base import BaseCollector
from reconagent.models import CollectorResult, Confidence, Finding, timeit


class TelegramCollector(BaseCollector):
    """Checks Telegram username existence via the official Bot API's
    getChat method — not scraping t.me (which always shows the same "open
    in app" landing page regardless of whether the username is real, a
    confirmed false-positive trap). Requires a free bot token from
    @BotFather (message it on Telegram, /newbot, instant, no card) — this
    is the only way to get a real signal from Telegram without scraping."""

    accepts = ("username",)
    name = "telegram"
    requires_key = True
    key_env_var = "TELEGRAM_BOT_TOKEN"

    @timeit
    def run(self, target: str, target_type: str) -> CollectorResult:
        result = CollectorResult(collector=self.name, target=target, ok=False)
        if not self.is_configured():
            result.error = (
                "TELEGRAM_BOT_TOKEN not set — skipping (free: message @BotFather on "
                "Telegram, send /newbot, get a token instantly, no card needed)"
            )
            return result

        token = os.getenv(self.key_env_var)
        username = target.lstrip("@")

        try:
            resp = requests.get(
                f"https://api.telegram.org/bot{token}/getChat",
                params={"chat_id": f"@{username}"},
                timeout=10,
            )
            data = resp.json()
        except Exception as e:  # noqa: BLE001
            result.error = f"Telegram Bot API request failed: {e}"
            return result

        result.ok = True
        if not data.get("ok"):
            result.findings.append(
                Finding(source=self.name, category="telegram_status", value="no account/channel found",
                        confidence=Confidence.HIGH, notes=data.get("description", ""))
            )
            return result

        chat = data.get("result", {})
        result.findings.append(
            Finding(source=self.name, category="telegram_url", value=f"https://t.me/{username}",
                    confidence=Confidence.HIGH)
        )
        chat_type = chat.get("type")
        if chat_type:
            result.findings.append(
                Finding(source=self.name, category="telegram_type", value=chat_type, confidence=Confidence.HIGH)
            )
        for field, category in (("title", "telegram_title"), ("first_name", "telegram_first_name"),
                                  ("bio", "telegram_bio")):
            if chat.get(field):
                result.findings.append(
                    Finding(source=self.name, category=category, value=chat[field], confidence=Confidence.HIGH)
                )
        return result