from __future__ import annotations

from pypdf import PdfReader

from reconagent.collectors.base import BaseCollector
from reconagent.models import CollectorResult, Confidence, Finding, timeit


class PdfMetadataCollector(BaseCollector):
    """Extracts author/software/creation-date metadata from a locally
    downloaded PDF — same class of leak as EXIF, different file type.
    `target` is a local file path."""

    accepts = ("pdf",)
    name = "pdf_metadata"

    @timeit
    def run(self, target: str, target_type: str) -> CollectorResult:
        result = CollectorResult(collector=self.name, target=target, ok=False)
        try:
            reader = PdfReader(target)
            meta = reader.metadata or {}
        except Exception as e:  # noqa: BLE001
            result.error = f"could not read PDF metadata: {e}"
            return result

        result.ok = True
        field_map = {
            "/Author": "author",
            "/Producer": "producer_software",
            "/Creator": "creator_software",
            "/CreationDate": "created_date",
            "/ModDate": "modified_date",
        }
        for key, category in field_map.items():
            value = meta.get(key)
            if value:
                result.findings.append(
                    Finding(source=self.name, category=category, value=str(value),
                            confidence=Confidence.HIGH)
                )
        if not result.findings:
            result.findings.append(
                Finding(source=self.name, category="pdf_status",
                        value="no metadata present (stripped or never set)",
                        confidence=Confidence.HIGH)
            )
        return result
