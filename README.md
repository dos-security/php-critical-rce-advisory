# PHP critical RCE update guidance

Maintained by **DOS Security** — Hawaii-based security research and defensive engineering.

This repository is a defender-facing companion to the PHP Project's October 2026 security release for [CVE-2026-109618](https://www.cve.org/CVERecord?id=CVE-2026-109618) and [CVE-2026-109619](https://www.cve.org/CVERecord?id=CVE-2026-109619).

## Purpose

The goal is practical remediation, not exploitation. This repository contains:

- an upstream-sourced remediation summary;
- a local, CLI-only runtime inventory aid and on-host PHP source audit;
- a non-operational technical note explaining the public-disclosure boundary; and
- a safe verification workflow for systems you administer.

It deliberately does **not** contain remote scanners, target enumeration, request payloads, exploit automation, captured session data, or a claim of an unacknowledged post-patch variant.

## Immediate action

Update the runtime serving traffic to an upstream fixed release (PHP 8.5.12, 8.4.27, 8.3.36, or 8.2.35) or obtain documented confirmation of an applicable vendor backport. Restart PHP workers and record the effective runtime version.

See [ADVISORY.md](ADVISORY.md) and the [PHP Project security advisory](https://www.php.net/).

## Local self-check

The bundled utility operates only on the PHP installation where it is run:

```sh
php tools/php-critical-rce-self-check.php
php tools/php-critical-rce-self-check.php --json
php tools/php-on-host-security-audit.php --path /srv/www/app
```

Both utilities send no network traffic, scan no remote hosts, and do not attempt reproduction or exploitation. The source audit identifies review candidates in PHP files you administer; it is not a vulnerability verdict. Read [SAFE_VERIFICATION.md](SAFE_VERIFICATION.md) before using either tool.

## Research and disclosure

[RESEARCH_NOTE.md](RESEARCH_NOTE.md) records the public-facing technical context without operational reproduction material. Supporting research, lab artifacts, and working notes are retained in a private archive pending independent validation and responsible-disclosure review.

## Reporting

For a potential issue in this repository, see [SECURITY.md](SECURITY.md). Do not send exploit payloads, credentials, or customer data.

## License

MIT — see [LICENSE](LICENSE).
