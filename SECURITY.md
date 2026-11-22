# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability, please **do not open a public issue**.

Instead, use GitHub's private disclosure mechanism:

👉 [Report a vulnerability](https://github.com/nicolafilippetto/smtp-relay/security/advisories/new)

This keeps the details private until a fix is available.

There are no formal SLAs or response time guarantees — this is a personal open
source project maintained on a best-effort basis.

---

## Known Accepted Risks

The Docker image is based on `python:3.12-slim-bookworm` (Debian 12). Trivy
reports several OS-level CVEs that are **not fixable at this time** because
Debian has not yet released patches for them. These are tracked and will be
resolved automatically when upstream patches are available via periodic image
rebuilds.

| CVE | Package | Severity | Status |
|---|---|---|---|
| CVE-2025-69720 | ncurses | HIGH | No fix available |
| CVE-2025-7458 | libsqlite3 | CRITICAL | No fix available |
| CVE-2023-45853 | zlib | CRITICAL | `will_not_fix` — not exploitable in this context |

The only remaining Python findings are three advisories against setuptools
70.3.0 vendored inside pip (`pip/_vendor`, used for `pkg_resources`):
CVE-2025-47273 (HIGH, path traversal in `setuptools.package_index`, which pip
does not ship), CVE-2026-59890 (MEDIUM, sdist building) and
GHSA-xmj3-9gf7-h52w (LOW, legacy wheel installation on Windows). None of these
code paths runs in the Linux images; they clear once pip updates its vendored
copy. The image is rebuilt periodically to pick up OS-level
patches as they are released by Debian.

Last reviewed: 2026-11-22.

These accepted CVEs are also listed in [`.trivyignore`](.trivyignore) so that a
Trivy scan configured to fail on CRITICAL findings passes with the risk
acceptance recorded in version control. Keep the two lists in sync.

---

## Cache-Control on Static Assets

ZAP baseline scan reports a `Re-examine Cache-control Directives` warning on
`app.css` and `app.js`. This is a known accepted risk:

- Both files are small public assets (CSS ~12KB, JS ~600 bytes)
- Neither contains sensitive information
- Disabling caching would increase latency and bandwidth on every page load

---

## Disclaimer

This software is provided **as-is** under the MIT License, without warranty of
any kind. The author is not responsible for any damage or security incidents
arising from the use of this software. See [LICENSE](LICENSE) for full details.
