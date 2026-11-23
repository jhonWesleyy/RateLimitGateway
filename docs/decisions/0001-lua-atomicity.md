# ADR 0001: Rate-limit logic as Lua scripts in Redis

> Portuguese translation: [0001-lua-atomicity.pt-BR.md](0001-lua-atomicity.pt-BR.md).

- **Status:** Accepted
- **Date:** 2026-11-22

## Context
Rate limiting means reading the current state, deciding, and writing the new state. If
these steps are separate commands sent by the client (for example `GET` then `SET`), two
concurrent requests can read the same value and both pass, so the limit is exceeded. The
gateway may run as several instances sharing one Redis, so an in-process lock does not
help.

## Decision
Each rate-limit check is a single Lua script executed by Redis (`rate-limit.lua`,
registered with ioredis `defineCommand`, which uses `EVALSHA` and resends the script on
`NOSCRIPT`). Redis runs a script to completion without interleaving other commands, so the
read-decide-write sequence is atomic by construction. The script uses the Redis clock
(`TIME`) as a single time source for all instances; tests may inject `now_ms` to control
time without `sleep`. Requires Redis 7 (effects replication by default).

## Alternatives considered
- **`WATCH`/`MULTI`/`EXEC` (optimistic locking):** needs retries on conflict, and conflicts
  grow exactly when load is high.
- **Distributed locks (e.g., Redlock):** extra round-trips, lock expiry edge cases, slower
  and more fragile.
- **Client-side logic with `INCR` only:** works for a fixed window but cannot express the
  token bucket or the two-phase multi-policy check ([ADR 0003](0003-two-phase-multi-policy-evaluation.md)).

## Consequences
- ✅ Correct under concurrency; proven by a test with 1,000 concurrent calls over 20
  connections that must allow exactly 100, plus a naive control implementation that must
  fail the same test.
- ✅ One round-trip per request for all policies.
- ✅ A single clock for all gateway instances.
- ❌ Logic lives in Lua, a second language to maintain; mitigated by a TypeScript reference
  model compared against the script in property tests.
- ❌ A slow script blocks Redis; the script is O(number of policies) and has no loops over
  data.
