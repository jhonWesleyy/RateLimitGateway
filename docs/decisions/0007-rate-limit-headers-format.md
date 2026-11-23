# ADR 0007: Rate-limit response headers format

> Portuguese translation: [0007-rate-limit-headers-format.pt-BR.md](0007-rate-limit-headers-format.pt-BR.md).

- **Status:** Accepted
- **Date:** 2026-11-22

## Context
The specification requires `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset` and
`Retry-After`. The IETF "RateLimit header fields for HTTP" draft used these three separate
fields in its early versions; later versions moved to structured `RateLimit` and
`RateLimit-Policy` fields. A request may also be subject to several policies at once
([ADR 0003](0003-two-phase-multi-policy-evaluation.md)).

## Decision
- Send `RateLimit-Limit`, `RateLimit-Remaining` and `RateLimit-Reset` on every response that
  went through the limiter. `RateLimit-Reset` is in **relative seconds**, rounded up.
- On 429, also send `Retry-After` as an integer ≥ 1, and `retryAfterSeconds` in the JSON
  error body.
- With several policies: if blocked, show the policy with the largest `retry`; if allowed,
  the one with the lowest `remaining`.
- In fail-open mode, no `RateLimit-*` headers are sent (there is no reliable data).

## Alternatives considered
- **Latest draft (`RateLimit` + `RateLimit-Policy`):** more expressive, but it diverges from
  the specification and is less known by existing clients.
- **`X-RateLimit-*`:** common de facto, but the `X-` prefix is deprecated and the spec names
  the unprefixed fields.
- **One header set per policy:** not expressible with the three separate fields.

## Consequences
- ✅ Matches the specification and widely understood client behavior.
- ✅ A deterministic rule for multiple policies, unit-tested.
- ❌ Not the latest draft format; documented here so a future migration is a conscious
  change.
- ❌ Clients only see the most restrictive policy, not all of them.
