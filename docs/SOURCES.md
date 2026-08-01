# Source Audit (verified July 2026)

Every collector's backing source was checked for current availability before
being included. APIs change fast — several sources that "everyone knows" are
free turned out to be dead or paid-only by 2026. This audit is why they're
in or out.

## Included — no key required

**AI/ML enrichment modules (not per-target-type collectors — run generically across scans):**

| Module | Real technique | Notes |
|---|---|---|
| pii_extractor | spaCy NER (`en_core_web_sm`) + regex | Scans genuine free-text fields only (bios, OCR output) — NOT structured fields like WHOIS org/dates, since live testing showed NER produces false positives (misread "DMARC" as a person name) and even zero results (no sentence context) on short context-free strings |
| avatar_similarity | Perceptual hashing (`imagehash.phash`) | Compares profile photos already found across GitHub/Gravatar/Bluesky within one scan — not a lookup against any external database, just a consistency check across accounts already gathered |
| ocr_extraction | Tesseract OCR (real trained model) | Preprocesses (upscale, grayscale, contrast, sharpen) + confidence-filters per-word — tuned against real test data after live testing showed default settings dropped legitimate words |
| stylometry | Classical NLP feature engineering (function-word frequency, cosine similarity) | Compares bio writing style across accounts — soft evidence, capped at LOW confidence |
| correlator (fuzzy upgrade) | rapidfuzz token-set similarity | Upgraded from exact/substring matching — catches formatting/word-order variations, does NOT catch true renamed-place aliases (e.g. Gurugram/Gurgaon — would need a gazetteer database) |

**Built, tested, then REMOVED after honest reconsideration:** face_detection.py (OpenCV FaceDetectorYN). Worked correctly after fixing a real OpenCV 5.0 API-removal bug, but for this tool's single-manual-image-upload interface, it added no value over just looking at the photo — its only honest justification (automated bulk triage) doesn't apply to a one-image-at-a-time UI. Kept out rather than shipped as dead weight.

| Collector | Source | Status |
|---|---|---|
| domain_whois | WHOIS protocol (python-whois) | stable, unauthenticated |
| dns_records | DNS resolution (dnspython) | stable, unauthenticated |
| crtsh_subdomains | crt.sh certificate transparency | free, public JSON API |
| ipwhois_asn | RDAP (ipwhois lib) | stable, unauthenticated |
| internetdb_shodan | internetdb.shodan.io | free, keyless, confirmed working |
| ip_geo | ip-api.com | free tier, ~45 req/min, no key |
| geo_correlate | Nominatim (OpenStreetMap) | free, rate-limited to 1 req/sec, no key |
| wayback_history | archive.org CDX API | free, public |
| github_footprint | api.github.com | unauthenticated, 60 req/hr limit |
| username_sherlock | direct HTTP checks, curated site list | no API, plain GET requests. Deliberately excludes Twitter/X, Instagram, Pinterest, and Telegram — these serve an identical client-rendered/static shell regardless of whether the username is real, so a plain status/text check always reports "exists" (false positives on every query). Only server-rendered sites/real JSON APIs are included, where a 404 genuinely means the account doesn't exist. |
| bluesky | public.api.bsky.app | real official AT Protocol public API, no login, no key |
| gravatar | gravatar.com | free avatar/profile check, SHA256-hash-based |
| github_email_search | api.github.com/search/users | note: `in:email` is fuzzy word-matching not exact, so every candidate is re-verified against their real public profile email before being reported |
| microsoft365 | login.microsoftonline.com | official Microsoft endpoint, existence-check only, never attempts login |
| smtp_verify | direct SMTP protocol | standard mailbox-verification technique; unreliable behind port-25 blocking (common on ISPs/cloud) and catch-all mail domains |
| email_security_posture | DNS only (DKIM selectors + Spamhaus/SpamCop/Barracuda DNSBL) | passive DNS lookups, no API |
| youtube | youtube.com channel pages | server-rendered channel metadata, more reliable than Instagram/X/TikTok's client-shell problem |
| social_meta_check | instagram.com, x.com, tiktok.com, pinterest.com, snapchat.com | EXPERIMENTAL meta-tag/status-code heuristic; live-tested and fixed twice (X's real 404 wasn't trusted, Threads removed after confirming it's login-walled for everyone) |
| duckduckgo_search | html.duckduckgo.com/html/ | **Note the distinction from other free sources here**: this queries DuckDuckGo's public HTML results page directly, not a documented JSON API — because no free official search API is left standing (Google CSE closed to new customers in 2025, Bing Search API retired Aug 2025). No login, no account, no personal-data wall (unlike the excluded sources below), but it's closer to "lightweight scraping of a search results page" than a stable API contract, and could break if DuckDuckGo changes their HTML structure or rate-limits more aggressively. Same category of tool as theHarvester's DuckDuckGo module. Added because it surfaces genuinely high-value OSINT (where a target is publicly mentioned — marketplace ads, forum posts, social bios) that no carrier/registry API can provide. |
| phone_lookup | phonenumbers (libphonenumber port) | fully offline, no API call |
| exif_metadata | exifread | fully offline, local file only |
| pdf_metadata | pypdf | fully offline, local file only |
| web_metadata | direct HTTP GET + regex | no API, plain page fetch |

## Included — free tier, requires signup key

| VirusTotal Public API | 500 req/day, 4/min, no card, verified July 2026 |
| Abstract Phone Intelligence API | 100 req/month, no card |
| Telegram Bot API | free via @BotFather, no card |

## Deliberately excluded (checked and rejected)

| Source | Why excluded |
|---|---|
| OpenCorporates API | **Correction (verified again):** not simple-signup-free as originally documented here. Self-serve API plans start at £2,250/year; the free tier only applies to approved open-data/research projects under a license application, not instant signup. Dropped from the default build — a paid, application-gated dependency doesn't belong in a "free public-source" tool. The collector code is still in the repo (disabled by default) in case you get approved access later. |
| Reddit `.json` public endpoints | Reddit deprecated unauthenticated `.json` access on May 28, 2026 — now returns 403, requires paid API |
| Google Custom Search JSON API | Closed to new customers since 2025; existing customers sunset Jan 1, 2027 |
| HIBP domain search | Paid-only ($4.39/mo+) as of 2026, AND only works on domains you've verified ownership of — not usable for arbitrary target recon regardless of price |
| Google Maps contributor/reviewer profile scraping | Not an API — scraping Google's own site, actively rate-limited/CAPTCHA'd, same ToS-violation category as social scraping |
| Dark web sources | Out of scope entirely — legal/ethical boundary, see docs/SCOPE.md |
| Breach-DB credential lookups (unauthorized) | Out of scope entirely — see docs/SCOPE.md |
| Login-walled social scraping (Instagram/LinkedIn/X internals) | Out of scope entirely — see docs/SCOPE.md |
| People-search brokers (Spokeo-type) | Out of scope entirely — see docs/SCOPE.md |

Re-verify this list periodically — free-tier terms and endpoint availability
change often; this snapshot reflects July 2026.