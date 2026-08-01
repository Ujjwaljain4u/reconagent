from __future__ import annotations

import exifread
import requests

from reconagent.collectors.base import BaseCollector
from reconagent.models import CollectorResult, Confidence, Finding, timeit


def _dms_to_decimal(dms, ref) -> float:
    degrees, minutes, seconds = [float(x.num) / float(x.den) for x in dms.values]
    decimal = degrees + minutes / 60 + seconds / 3600
    if ref.values[0] in ("S", "W"):
        decimal = -decimal
    return round(decimal, 6)


def _reverse_geocode(lat: float, lon: float) -> str | None:
    """Turns raw GPS coordinates into a real street address via Nominatim
    (OpenStreetMap, free, no key). This used to be a separate collector
    (geo_correlate) that was never actually wired to receive EXIF's GPS
    output — it only activated for a "coordinate" target type nothing ever
    produced, so images always showed raw lat/lon and never a real address.
    Doing the lookup directly here fixes that gap."""
    try:
        resp = requests.get(
            "https://nominatim.openstreetmap.org/reverse",
            params={"lat": lat, "lon": lon, "format": "jsonv2"},
            headers={"User-Agent": "reconagent/0.1 (passive-osint-research)"},
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json().get("display_name")
    except Exception:  # noqa: BLE001
        return None


class ExifCollector(BaseCollector):
    """Reads EXIF metadata from an uploaded image file — GPS coordinates,
    device make/model, and timestamp are the highest-value leaks here.
    `target` is expected to be a local file path to the image. If GPS data
    is found, also reverse-geocodes it to a real address in the same run."""

    accepts = ("image",)
    name = "exif_metadata"

    @timeit
    def run(self, target: str, target_type: str) -> CollectorResult:
        result = CollectorResult(collector=self.name, target=target, ok=False)
        try:
            with open(target, "rb") as f:
                tags = exifread.process_file(f, details=False)
        except Exception as e:  # noqa: BLE001
            result.error = f"could not read EXIF data: {e}"
            return result

        if not tags:
            result.ok = True
            result.findings.append(
                Finding(source=self.name, category="exif_status",
                        value="no EXIF metadata present (stripped or never had any)",
                        confidence=Confidence.HIGH)
            )
            return result

        result.ok = True
        text_fields = {
            "Image Make": "device_make",
            "Image Model": "device_model",
            "Image Software": "editing_software",
            "EXIF DateTimeOriginal": "capture_timestamp",
        }
        for tag, category in text_fields.items():
            if tag in tags:
                result.findings.append(
                    Finding(source=self.name, category=category, value=str(tags[tag]),
                            confidence=Confidence.HIGH)
                )

        if all(k in tags for k in ("GPS GPSLatitude", "GPS GPSLatitudeRef",
                                    "GPS GPSLongitude", "GPS GPSLongitudeRef")):
            try:
                lat = _dms_to_decimal(tags["GPS GPSLatitude"], tags["GPS GPSLatitudeRef"])
                lon = _dms_to_decimal(tags["GPS GPSLongitude"], tags["GPS GPSLongitudeRef"])
                result.findings.append(
                    Finding(source=self.name, category="gps_coordinate",
                            value={"lat": lat, "lon": lon}, confidence=Confidence.HIGH,
                            notes="exact capture location embedded in image")
                )
                address = _reverse_geocode(lat, lon)
                if address:
                    result.findings.append(
                        Finding(source=self.name, category="approx_address", value=address,
                                confidence=Confidence.HIGH,
                                notes="reverse-geocoded from the exact GPS coordinates above")
                    )
            except Exception:  # noqa: BLE001
                pass
        return result