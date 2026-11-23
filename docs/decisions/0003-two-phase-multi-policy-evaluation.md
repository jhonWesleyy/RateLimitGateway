# ADR 0003: Two-phase evaluation of multiple policies

> Portuguese translation: [0003-two-phase-multi-policy-evaluation.pt-BR.md](0003-two-phase-multi-policy-evaluation.pt-BR.md).

- **Status:** Accepted
- **Date:** 2026-11-22

## Context
The author decided that the plan policy and the route policy apply together: a request must
pass both. If each policy were checked and consumed one at a time, a request could consume a
plan token and then be blocked by the route policy, so blocked requests would still drain
the plan quota.

## Decision
A single script call receives every applicable policy. **Phase 1** evaluates all of them
without writing anything. **Phase 2** writes the new state of every policy only if **all**
of them allowed the request; if any blocked, nothing is written (all or nothing). The
script returns, per policy, `allowed`, `limit`, `remaining`, `reset_ms` and `retry_ms`. All
keys of one subject share the hash tag `{key:<id>}`, so the multi-key script stays valid on
Redis Cluster.

## Alternatives considered
- **Sequential checks with compensation (refund on block):** extra round-trips and a window
  where the refund has not happened yet; refunding a sliding window is not exact.
- **Check only the most restrictive policy:** "most restrictive" depends on current state,
  not only on configuration, so it cannot be chosen in advance.

## Consequences
- ✅ No partial consumption; verified by an integration test where the plan allows, the
  route blocks, and the plan state stays unchanged.
- ✅ One round-trip regardless of the number of policies.
- ❌ Slightly more complex script and return format (flattened array per policy).
- ❌ The headers must summarize several policies; the rule is defined in
  [ADR 0007](0007-rate-limit-headers-format.md).
