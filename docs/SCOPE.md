# Scope & Legal Boundary

This document exists so the boundary is explicit, not accidental — and so
you can answer "why doesn't it do X" confidently in an interview.

## What this tool does

Aggregates data that is already public and reachable without authentication:
WHOIS records, DNS, certificate transparency logs, public API endpoints
(GitHub, InternetDB, crt.sh, archive.org, OpenCorporates), and metadata
embedded in files the user provides (images, PDFs). Every request this tool
makes is one an anonymous browser or public API client could also make.

## What this tool deliberately does not do, and why

**Dark web scraping** — accessing markets/forums for target data implies
either illegal-marketplace access or handling stolen data. No legitimate
portfolio use case justifies this; real threat-intel teams that do this
operate under specific legal authorization most individuals don't have.

**Breach-DB credential lookups without an authorized paid API** — pulling
someone's leaked passwords/credentials from breach dumps is handling stolen
data. The legal path (e.g. HIBP's paid API) explicitly requires proving
domain ownership before you can even query it — by design, you cannot
legitimately look up an arbitrary third party's breach exposure without
their consent to have.

**Login-walled social scraping** — Instagram/LinkedIn/X (and Google Maps
contributor profiles) block and legally pursue this. It's a Terms of
Service violation and, depending on jurisdiction, can implicate computer-
fraud statutes. "It's technically possible" is not the same as "it's legal
or advisable to ship."

**People-search broker aggregation (Spokeo-type)** — these sites themselves
scrape data of uncertain provenance and operate in a legal grey zone
(especially GDPR-adjacent for EU subjects, and India's DPDP Act for Indian
subjects). Building on top of them inherits that risk.

## Why this boundary is the right call, not a limitation

1. **Legal exposure.** India's IT Act and most jurisdictions' computer-
   fraud/unauthorized-access laws don't care that the intent was "portfolio
   project" — unauthorized access is unauthorized access.
2. **Hiring signal.** AI-security and governance roles specifically test for
   judgment about what *should* be built, not just what *can* be built.
   A tool that respects platform ToS and legal boundaries is a stronger
   signal of role-fit than one that doesn't.
3. **Reusability.** A tool restricted to passive/public sources can be
   demoed, open-sourced, and discussed openly in an interview without any
   caveat about how it was obtained or whether it's currently violating
   someone's ToS.

If asked "what would you add with more time/budget," the honest answer is:
paid/authorized APIs with proper use-case review (e.g. HIBP Pro for a real
employer's own domain), not workarounds around the sources listed above.
