# ADR 0002: Sliding window as a counter, not a log

> Portuguese translation: [0002-sliding-window-counter.pt-BR.md](0002-sliding-window-counter.pt-BR.md).

- **Status:** Accepted
- **Date:** 2026-11-22

## Context
The specification requires a sliding-window algorithm, implemented either as a log or as a
counter, with the choice justified. Plans may have large limits (e.g., 1,000 or 10,000
requests per minute), and state is kept per key and per policy.

## Decision
Use the **sliding window counter**. For each subject and policy, a single Redis HASH stores
the current window index (`w`), the current window count (`c`) and the previous window
count (`p`). The estimate is `p × (1 − f) + c`, where `f` is the elapsed fraction of the
current window; a request is allowed when `estimate + 1 ≤ limit`. The state has a TTL of
two windows. Keeping everything in one HASH lets the script compute the window from its own
clock, without time-dependent key names, and stays Redis Cluster compatible.

## Alternatives considered
- **Sliding window log (ZSET of timestamps):** exact, but memory is O(limit) per subject (a
  10,000 req/min plan stores 10,000 entries per key) and each check trims the set.
- **Fixed window:** simplest, but allows up to 2× the limit around a window boundary.

## Consequences
- ✅ O(1) memory and O(1) work per check, regardless of the limit.
- ✅ Tested guarantee: the estimate never exceeds the limit, and exactly `limit` requests pass
  in a fresh window (enough for the atomicity proof).
- ❌ Approximate: it assumes uniform traffic in the previous window. Documented as an
  accepted risk in the [threat model](../threat-model.md).
- ❌ `Retry-After` needs a closed-form computation that is less obvious than with a log;
  covered by a test that following the returned `retry` leads to an allowed request.
