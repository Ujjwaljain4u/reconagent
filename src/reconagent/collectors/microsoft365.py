from __future__ import annotations

import requests

from reconagent.collectors.base import BaseCollector
from reconagent.models import CollectorResult, Confidence, Finding, timeit


class Microsoft365Collector(BaseCollector):
    """Checks whether an email is a valid Microsoft/Office365 account via
    the GetCredentialType endpoint — a well-documented technique used by
    tools like o365creeper. Existence-check ONLY: sends the email, reads
    whether Microsoft recognizes it as a registered account (business or
    personal/Outlook.com/Hotmail), never attempts a password or login. Free,
    no key, no auth."""

    accepts = ("email",)
    name = "microsoft365"

    @timeit
    def run(self, target: str, target_type: str) -> CollectorResult:
        result = CollectorResult(collector=self.name, target=target, ok=False)
        try:
            resp = requests.post(
                "https://login.microsoftonline.com/common/GetCredentialType",
                json={"Username": target},
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:  # noqa: BLE001
            result.error = f"Microsoft account check failed: {e}"
            return result

        result.ok = True
        # IfExistsResult: 0 = exists, 1 = doesn't exist, 5/6 = exists but federated/managed differently
        exists_code = data.get("IfExistsResult")
        if exists_code in (0, 5, 6):
            result.findings.append(
                Finding(source=self.name, category="microsoft_account_status",
                        value="registered Microsoft/Office365 account", confidence=Confidence.HIGH)
            )
            if data.get("IsUnmanaged") is False:
                result.findings.append(
                    Finding(source=self.name, category="microsoft_account_type", value="managed (business/org)",
                            confidence=Confidence.MEDIUM,
                            notes="likely tied to a company Microsoft 365 tenant, not a personal account")
                )
        elif exists_code == 1:
            result.findings.append(
                Finding(source=self.name, category="microsoft_account_status",
                        value="no Microsoft account found", confidence=Confidence.HIGH)
            )
        else:
            result.findings.append(
                Finding(source=self.name, category="microsoft_account_status",
                        value="inconclusive", confidence=Confidence.NEEDS_REVIEW,
                        notes=f"unexpected response code: {exists_code}")
            )
        return result