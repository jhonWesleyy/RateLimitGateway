# Security Policy

## Supported versions

This project is under active development. Security fixes are applied to the `main` branch
and, once releases exist, to the latest release only.

| Version | Supported |
|---|---|
| `main` (latest) | ✅ |
| Latest release | ✅ |
| Older releases | ❌ |

## Reporting a vulnerability

**Please do not open a public issue, discussion or pull request for security problems.**

Report privately through GitHub:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability** (GitHub private vulnerability reporting / Security
   Advisories).
3. Describe the issue, the affected version or commit, the steps to reproduce, and the
   impact you expect. A minimal proof of concept helps a lot.

Do not include real API keys, tokens or personal data in the report. Never test against
deployments you do not own.

## What to expect

- **Acknowledgement:** within 3 business days.
- **Initial assessment:** within 7 days, including whether the report is accepted and an
  estimated severity.
- **Fix:** depends on severity; critical and high issues are prioritized over feature work.
  You will be kept informed in the advisory.
- **Disclosure:** coordinated. A GitHub Security Advisory is published once a fix is
  available, crediting the reporter unless they prefer to stay anonymous.

## Out of scope

- Vulnerabilities in the upstream API that the gateway protects, or in third-party
  services.
- Volumetric denial of service (traffic floods) and attacks that require exhausting the
  host's resources.
- Issues that require prior access to the internal port, the Redis instance, the host or
  the environment secrets.
- Reports from automated scanners without a demonstrated impact or proof of concept.
- Risks already documented as accepted in the [threat model](docs/threat-model.md)
  (for example, the auth-cache TTL after revocation, or fail-open mode during a Redis
  outage).
- Missing hardening in local development setups that are not meant for production.
