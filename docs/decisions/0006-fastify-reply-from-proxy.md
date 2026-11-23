# ADR 0006: `@fastify/reply-from` as the proxy layer

> Portuguese translation: [0006-fastify-reply-from-proxy.pt-BR.md](0006-fastify-reply-from-proxy.pt-BR.md).

- **Status:** Accepted
- **Date:** 2026-11-22

## Context
The gateway must forward method, path, query and body to the configured upstream, with
timeouts, a body limit, response streaming and correct header handling. Authentication and
rate limiting must run in `onRequest` hooks before the body is read. The specification asks
to evaluate `@fastify/http-proxy` or undici.

## Decision
Use `@fastify/reply-from` inside our own catch-all route. It is maintained by the Fastify
team, uses undici underneath, and already handles response streaming and upstream error
mapping. The security-relevant parts are **our own tested code**, not library defaults: the
canonical target URL (`origin + basePath + validatedPath + search`, never
`new URL(req.url, base)`) and inbound/outbound header filtering.

## Alternatives considered
- **`@fastify/http-proxy`:** a layer on top of reply-from with a fixed prefix; we do not
  need it, since our route and hooks already define the flow.
- **undici directly:** more control, but we would reimplement streaming, error mapping and
  edge cases that reply-from already covers.
- **`http-proxy` / `node-http-proxy`:** not Fastify-native and less actively maintained.

## Consequences
- ✅ Small, well-maintained dependency aligned with the server framework.
- ✅ Security rules are explicit and unit-tested, independent of library behavior.
- ❌ We depend on reply-from options and hooks for header rewriting; a major version change
  may require adjustments (Dependabot + tests catch it).
- ❌ Streaming request bodies is out of scope; bodies are buffered up to `BODY_LIMIT_BYTES`.
