# ADR 0008: API key format and peppered HMAC storage

> Portuguese translation: [0008-api-key-format-and-hmac-pepper.pt-BR.md](0008-api-key-format-and-hmac-pepper.pt-BR.md).

- **Status:** Accepted
- **Date:** 2026-11-22

## Context
Keys must be high-entropy, carry an identifiable prefix, be stored only as an HMAC-SHA256
with a pepper from the environment, be compared in constant time, and be shown only once.
v1 used a base64url secret, which contains `_` and `-`, so parsing the key by `_` was
ambiguous.

## Decision
- **Format:** `rlg_{live|test}_<id>_<secret>`, validated by
  `^rlg_(live|test)_([0-9A-Za-z]{12})_([0-9A-Za-z]{43})$`. The fixed prefix allows a custom
  GitHub secret-scanning pattern.
- **Generation:** `id` = 12 base62 characters (~71 bits, public); `secret` = 43 base62
  characters (~256 bits). Both come from `crypto.randomBytes` with rejection sampling
  (bytes ≥ 248 are discarded) to avoid modulo bias.
- **Storage:** `HMAC-SHA256(API_KEY_PEPPER, secret)` in hex plus `pepperVersion: "v1"`.
  Lookup is by the public `id`.
- **Verification:** regex parse → lookup by `id` → HMAC → `crypto.timingSafeEqual` on
  equal-length buffers. Unknown ids are compared against a fixed value, so malformed,
  unknown and revoked keys produce the same response.
- **Display:** the full key appears only in the `201` creation response; listings show
  `keyPreview`.

**Note on the pepper:** because the `secret` is random with 256 bits, a plain SHA-256 would
already resist offline brute force. The peppered HMAC is **defense in depth**: a Redis dump
alone is not enough to validate any key.

## Alternatives considered
- **Slow password hashes (bcrypt, Argon2):** designed for low-entropy passwords; with 256-bit
  secrets they add CPU cost per request without a security gain.
- **Plain SHA-256:** sufficient for 256-bit secrets, but a database dump alone would allow
  offline verification of leaked keys.
- **Lookup by hash without a public id:** removes the need for an id, but the database
  lookup becomes the comparison (no explicit constant-time step), and listing, revocation
  and logging need a separate identifier anyway.

## Consequences
- ✅ Unambiguous parsing, cheap validation without Redis for malformed keys.
- ✅ Constant-time comparison and identical errors prevent enumeration.
- ❌ Pepper rotation requires a restart (out of scope); `pepperVersion` keeps the format ready.
- ❌ Losing the pepper invalidates every key.
