# ADR 0004: API keys stored in Redis with noeviction and AOF

> Portuguese translation: [0004-api-keys-in-redis-noeviction-aof.pt-BR.md](0004-api-keys-in-redis-noeviction-aof.pt-BR.md).

- **Status:** Accepted
- **Date:** 2026-11-22

## Context
API key records (HMAC hash, plan, status, timestamps) must be durable: losing them locks
clients out. Rate-limit state, on the other hand, is ephemeral. The project should keep
dependencies minimal.

## Decision
Store key records in the same Redis used for rate limiting, configured with
`maxmemory-policy noeviction` and `appendonly yes` (AOF). Data model:
`rlg:key:<id>` (HASH, no TTL) and `rlg:keys:index` (ZSET by `createdAt`, for pagination).
All rate-limit state has a TTL, so it expires on its own and never depends on eviction.
The domain accesses keys through a `KeyStore` interface, so the storage can be replaced by
changing one adapter.

## Alternatives considered
- **PostgreSQL / SQLite:** proper durability and queries, but one more service (or a file
  that does not work with several instances) and more dependencies.
- **Redis with an eviction policy (e.g., `allkeys-lru`):** under memory pressure Redis would
  silently delete client keys.
- **Keys in the configuration file:** no runtime create/revoke, and secrets in a file.

## Consequences
- ✅ A single stateful dependency; simple compose and tests.
- ✅ No silent loss of keys.
- ❌ When memory is full, writes fail. Rate-limit writes then follow the failure mode
  ([ADR 0005](0005-failure-modes-and-auth-cache.md)), and key creation fails with an error.
  This is preferred over losing keys.
- ❌ AOF adds disk I/O; acceptable at this scale.
