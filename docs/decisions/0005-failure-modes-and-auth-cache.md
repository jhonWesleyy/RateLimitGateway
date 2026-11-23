# ADR 0005: Redis failure modes and local auth cache

> Portuguese translation: [0005-failure-modes-and-auth-cache.pt-BR.md](0005-failure-modes-and-auth-cache.pt-BR.md).

- **Status:** Accepted
- **Date:** 2026-11-22

## Context
Both authentication and rate limiting depend on Redis. The specification requires a
configurable behavior (fail-open or fail-closed) when Redis fails, with a log and a metric.
There is no meaningful "fail-open" for authentication: accepting unknown keys would turn the
gateway into an open proxy.

## Decision
- **Fast failure detection:** ioredis with `commandTimeout` 50 ms,
  `enableOfflineQueue: false`, `maxRetriesPerRequest: 1`, and reconnection with backoff.
- **Authentication:** an in-memory LRU cache of validated keys (`AUTH_CACHE_TTL_MS`, default
  30 s; `AUTH_CACHE_MAX`, default 10,000). A cached key keeps working while Redis is down; a
  key that is not cached gets **503** regardless of the mode. Only valid keys are cached (no
  negative cache). Revocation invalidates the cache immediately on the instance that revoked.
- **Rate limit:** `REDIS_FAILURE_MODE=open` (default) lets requests through without
  `RateLimit-*` headers; `closed` responds 503. Both increment metrics and log a `warn`
  (at most one per second).
- **Brute-force guard:** skipped while Redis is down, and the skip is logged.

## Alternatives considered
- **Fail-closed only:** safest for limits, but a Redis blip takes the tax API offline.
- **Fail-open for auth too:** unacceptable; it bypasses authentication.
- **No auth cache:** every request needs Redis, so any outage means 503 for everyone.

## Consequences
- ✅ Short Redis outages are invisible to active clients in `open` mode.
- ✅ The behavior is explicit, configurable and observable.
- ❌ A revoked key stays valid on **other** instances until the cache TTL (default 30 s);
  documented as an accepted risk in the [threat model](../threat-model.md).
- ❌ In `open` mode there is a window without limits during an outage.
