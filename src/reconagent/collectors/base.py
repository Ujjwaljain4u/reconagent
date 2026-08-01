"""
Base interface every collector implements. Mirrors the pluggable-connector
pattern from the LLM Red Team Framework: add a new collector by subclassing
BaseCollector and dropping the file in collectors/ — no other code changes.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from reconagent.models import CollectorResult


class BaseCollector(ABC):
    #: which target types this collector accepts: "domain", "username", "email", "phone", "image", "pdf"
    accepts: tuple[str, ...] = ()

    #: human name shown in reports
    name: str = "base"

    #: does this collector need an API key the user must supply via config/env?
    requires_key: bool = False
    key_env_var: str | None = None

    def is_configured(self) -> bool:
        """Collectors requiring a key override this to check it's present."""
        if not self.requires_key:
            return True
        import os
        return bool(self.key_env_var and os.getenv(self.key_env_var))

    @abstractmethod
    def run(self, target: str, target_type: str) -> CollectorResult:
        ...
