# ADR 0001 — Per-Source Fetch Strategy

**Date:** 2026-05-26  
**Status:** Accepted

---

## Context

vulnscan queries multiple upstream vulnerability databases. Three candidates were evaluated:

1. **OSV.dev** — Google's open source vulnerability database. Covers npm `CVE-*` entries and `MAL-*` malicious package entries from the OpenSSF Malicious Packages feed.
2. **GitHub Advisory Database** — GitHub's security advisory database. Direct coverage of npm ecosystem vulnerabilities, often before they propagate to npm's own advisory mirror.
3. **Socket.dev** — Commercial supply chain analysis API. Provides real-time malicious package detection with install-time signals.

---

## Decision

### OSV: full dump download

OSV publishes a complete per-ecosystem archive at a stable GCS URL (`https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip`). We download the full ZIP and import it into Local DB.

**Alternatives considered:**
- OSV batch query API (`POST /v1/querybatch`): requires knowing package names up front; cannot enumerate all advisories for DB pre-population.
- OSV GraphQL (not available): no streaming GraphQL endpoint exists.

**Why full dump:** One HTTP request per sync. No pagination, no incremental state, no cursor management. The ZIP is ~200MB but is streamed to disk then processed locally — acceptable for a daily sync cadence.

### GitHub Advisory: REST API pagination

GitHub exposes a public REST endpoint (`GET /advisories?ecosystem=npm`) with cursor-based pagination. We page through all reviewed advisories and upsert into Local DB.

**Alternatives considered:**
- GitHub GraphQL `securityAdvisories`: requires authentication even for public advisories (hits rate limit immediately without token). REST API returns 60 req/hr unauthenticated, which is sufficient for a cold sync over multiple minutes.
- npm Advisory Database (registry.npmjs.org): mirrors GitHub Advisory with propagation lag of days to weeks. Using it directly defeats the purpose of vulnscan.

**Why REST over GraphQL:** REST works without `GITHUB_TOKEN`. GraphQL requires a token for meaningful throughput. `GITHUB_TOKEN` is optional — it increases the rate limit from 60 to 5000 req/hr, enabling faster cold syncs.

### Socket.dev: dropped

Socket.dev provides real-time install-time signals (e.g., newly published suspicious packages, dependency confusion attacks). This capability requires Socket Firewall and is not achievable with a local DB scan model.

OSV's `MAL-*` feed via OpenSSF Malicious Packages covers the confirmed malicious package use case with a 1–3 day lag after confirmation. This is sufficient for scanning installed deps in a lockfile. The lag is acceptable: by the time a package appears in `node_modules`, it was already published; the `MAL-*` feed catches it within days.

Socket.dev also requires a paid API key. Avoiding API keys is a design goal (user story 17).

---

## Consequences

- No API keys required for core functionality. OSV is unauthenticated. GitHub Advisory REST works without a token (slower cold sync).
- `GITHUB_TOKEN` env var, when present, speeds up GitHub Advisory sync from ~10 min to ~1 min on first run.
- Supply chain detection (MAL-*) has a ~1–3 day lag vs. Socket's near-real-time. Accepted for a lockfile scanner; not acceptable for install-time blocking.
- OSV full dump is ~200MB. Sync must handle partial failures gracefully (re-download on next sync if interrupted).
