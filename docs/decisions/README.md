# Architecture Decision Records

This folder holds the project's Architecture Decision Records (ADRs): short documents that
capture one significant decision, its context, the alternatives and the consequences. Each
ADR exists in English (the original, which prevails) and in Brazilian Portuguese
(`*.pt-BR.md`, a translation).

The full context lives in the [implementation plan](../plan.md) and the
[threat model](../threat-model.md).

## Index

| # | Title | Status | pt-BR |
|---|---|---|---|
| 0001 | [Rate-limit logic as Lua scripts in Redis](0001-lua-atomicity.md) | Accepted | [pt-BR](0001-lua-atomicity.pt-BR.md) |
| 0002 | [Sliding window as a counter, not a log](0002-sliding-window-counter.md) | Accepted | [pt-BR](0002-sliding-window-counter.pt-BR.md) |
| 0003 | [Two-phase evaluation of multiple policies](0003-two-phase-multi-policy-evaluation.md) | Accepted | [pt-BR](0003-two-phase-multi-policy-evaluation.pt-BR.md) |
| 0004 | [API keys stored in Redis with noeviction and AOF](0004-api-keys-in-redis-noeviction-aof.md) | Accepted | [pt-BR](0004-api-keys-in-redis-noeviction-aof.pt-BR.md) |
| 0005 | [Redis failure modes and local auth cache](0005-failure-modes-and-auth-cache.md) | Accepted | [pt-BR](0005-failure-modes-and-auth-cache.pt-BR.md) |
| 0006 | [`@fastify/reply-from` as the proxy layer](0006-fastify-reply-from-proxy.md) | Accepted | [pt-BR](0006-fastify-reply-from-proxy.pt-BR.md) |
| 0007 | [Rate-limit response headers format](0007-rate-limit-headers-format.md) | Accepted | [pt-BR](0007-rate-limit-headers-format.pt-BR.md) |
| 0008 | [API key format and peppered HMAC storage](0008-api-key-format-and-hmac-pepper.md) | Accepted | [pt-BR](0008-api-key-format-and-hmac-pepper.pt-BR.md) |

## How to propose a new ADR

1. Pick the next free number (`NNNN`, zero-padded) and a short kebab-case English name,
   e.g. `0009-redis-cluster-support.md`.
2. Write the English file with the same sections as the existing ADRs: Title, Status,
   Date, Context, Decision, Alternatives considered, Consequences (positive and negative).
   Keep it to about one page.
3. Start with **Status: Proposed** and open a pull request. The decision is discussed in
   the PR.
4. Add the translation `NNNN-<name>.pt-BR.md` with the same number and the translation
   note at the top. Links inside each file point to documents in the same language.
5. When accepted, change the status to **Accepted** in both files, add the ADR to the index
   above, and record the change in both versions of the plan (`docs/plan.md` and
   `docs/plan.pt-BR.md`).
6. To reverse a decision, do not edit the old ADR: write a new one and mark the old one as
   **Superseded by ADR NNNN**.
