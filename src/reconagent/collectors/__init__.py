"""
Collector registry. Each entry maps a target_type to the collector classes
that can run against it. cli.py / aggregator.py import REGISTRY only —
they never import individual collector modules directly, so adding a new
collector here is the single wiring point.
"""

from reconagent.collectors.domain_whois import DomainWhoisCollector
from reconagent.collectors.dns_records import DnsRecordsCollector
from reconagent.collectors.crtsh_subdomains import CrtshCollector
from reconagent.collectors.ipwhois_asn import IpWhoisCollector
from reconagent.collectors.internetdb_shodan import InternetDbCollector
from reconagent.collectors.username_sherlock import SherlockCollector
from reconagent.collectors.github_footprint import GithubCollector
from reconagent.collectors.phone_lookup import PhoneCollector
from reconagent.collectors.abstractapi_phone import AbstractPhoneCollector
from reconagent.collectors.duckduckgo_search import DuckDuckGoSearchCollector
from reconagent.collectors.bluesky import BlueskyCollector
from reconagent.collectors.social_meta_check import SocialMetaCheckCollector
from reconagent.collectors.youtube import YouTubeCollector
from reconagent.collectors.telegram import TelegramCollector
from reconagent.collectors.gravatar import GravatarCollector
from reconagent.collectors.smtp_verify import SmtpVerifyCollector
from reconagent.collectors.github_email_search import GithubEmailSearchCollector
from reconagent.collectors.microsoft365 import Microsoft365Collector
from reconagent.collectors.email_security_posture import EmailSecurityPostureCollector
from reconagent.collectors.virustotal import VirusTotalCollector
from reconagent.collectors.exif_metadata import ExifCollector
from reconagent.collectors.pdf_metadata import PdfMetadataCollector
from reconagent.collectors.web_metadata import WebMetadataCollector
from reconagent.collectors.wayback_history import WaybackCollector
from reconagent.collectors.geo_correlate import GeoCollector, IpGeoCollector
# opencorporates disabled by default — its "free tier" turned out to require an
# approved open-data-project license application, not simple signup. See docs/SOURCES.md.
# from reconagent.collectors.opencorporates import OpenCorporatesCollector

REGISTRY: dict[str, list] = {
    "domain": [
        DomainWhoisCollector(),
        DnsRecordsCollector(),
        CrtshCollector(),
        IpWhoisCollector(),
        InternetDbCollector(),
        WebMetadataCollector(),
        WaybackCollector(),
        IpGeoCollector(),
        DuckDuckGoSearchCollector(),
        VirusTotalCollector(),
    ],
    "username": [
        SherlockCollector(),
        GithubCollector(),
        DuckDuckGoSearchCollector(),
        BlueskyCollector(),
        SocialMetaCheckCollector(),
        YouTubeCollector(),
        TelegramCollector(),
    ],
    "email": [
        DnsRecordsCollector(),  # runs MX/SPF/DMARC check on the email's domain part
        DuckDuckGoSearchCollector(),
        GravatarCollector(),
        SmtpVerifyCollector(),
        GithubEmailSearchCollector(),
        Microsoft365Collector(),
        EmailSecurityPostureCollector(),
    ],
    "phone": [
        PhoneCollector(),
        AbstractPhoneCollector(),
        DuckDuckGoSearchCollector(),
    ],
    "image": [
        ExifCollector(),
        GeoCollector(),  # reverse-geocodes any GPS EXIF found
    ],
    "pdf": [
        PdfMetadataCollector(),
    ],
}


def collectors_for(target_type: str) -> list:
    return REGISTRY.get(target_type, [])