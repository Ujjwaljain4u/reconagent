from __future__ import annotations

import requests

from reconagent.collectors.base import BaseCollector
from reconagent.models import CollectorResult, Confidence, Finding, timeit


class GeoCollector(BaseCollector):
    """Reverse-geocodes GPS coordinates found by other collectors (e.g. EXIF)
    using Nominatim (OpenStreetMap, free, no key, please respect their 1
    req/sec usage policy). Also available standalone for a raw 'lat,lon'
    target string."""

    accepts = ("image", "coordinate")
    name = "geo_correlate"

    @timeit
    def run(self, target: str, target_type: str) -> CollectorResult:
        result = CollectorResult(collector=self.name, target=target, ok=False)

        lat, lon = self._extract_latlon(target, target_type)
        if lat is None:
            result.error = "no coordinates available to reverse-geocode"
            return result

        try:
            resp = requests.get(
                "https://nominatim.openstreetmap.org/reverse",
                params={"lat": lat, "lon": lon, "format": "jsonv2"},
                headers={"User-Agent": "reconagent/0.1 (passive-osint-research)"},
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:  # noqa: BLE001
            result.error = f"Nominatim reverse geocode failed: {e}"
            return result

        result.ok = True
        if data.get("display_name"):
            result.findings.append(
                Finding(source=self.name, category="approx_address", value=data["display_name"],
                        confidence=Confidence.MEDIUM, raw=data)
            )
        return result

    def _extract_latlon(self, target: str, target_type: str):
        if target_type == "coordinate" and "," in target:
            try:
                lat_str, lon_str = target.split(",")
                return float(lat_str.strip()), float(lon_str.strip())
            except ValueError:
                return None, None
        return None, None  # when target_type == "image", aggregator passes coords in separately


class IpGeoCollector(BaseCollector):
    """City-level IP geolocation via ip-api.com — free, no key, ~45 req/min."""

    accepts = ("domain",)
    name = "ip_geo"

    @timeit
    def run(self, target: str, target_type: str) -> CollectorResult:
        import socket
        result = CollectorResult(collector=self.name, target=target, ok=False)
        try:
            ip = socket.gethostbyname(target)
            resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
            data = resp.json()
        except Exception as e:  # noqa: BLE001
            result.error = f"ip-api lookup failed: {e}"
            return result

        if data.get("status") != "success":
            result.error = data.get("message", "ip-api lookup did not succeed")
            return result

        result.ok = True
        for key, category in {"city": "ip_city", "regionName": "ip_region",
                               "country": "ip_country", "isp": "ip_isp"}.items():
            if data.get(key):
                result.findings.append(
                    Finding(source=self.name, category=category, value=data[key],
                            confidence=Confidence.MEDIUM)
                )
        if data.get("lat") and data.get("lon"):
            result.findings.append(
                Finding(source=self.name, category="ip_gps_estimate",
                        value={"lat": data["lat"], "lon": data["lon"]},
                        confidence=Confidence.LOW,
                        notes="city-level estimate from IP, not precise location")
            )
        return result
