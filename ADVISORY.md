# Advisory: prioritize PHP updates for two critical RCE CVEs

**Severity:** Critical  
**Affected systems:** PHP deployments that serve web requests, including common PHP-FPM, Apache module, CGI, FrankenPHP, and LiteSpeed configurations

## Summary

The PHP Project’s 21 October 2026 security advisory covers two critical vulnerabilities:

- [CVE-2026-109618](https://www.cve.org/CVERecord?id=CVE-2026-109618): PHP identifies an out-of-memory handling issue involving partially initialized request data during cleanup.
- [CVE-2026-109619](https://www.cve.org/CVERecord?id=CVE-2026-109619): PHP identifies request-owned state that can outlive backing memory and later be used before normal initialization resets it.

The upstream fix levels are PHP 8.5.12, 8.4.27, 8.3.36, and 8.2.35. Update as soon as possible, restart all PHP workers, and verify the runtime actually serving traffic.

## Interim risk reduction is not remediation

The PHP Project states that updating is the complete solution. If a maintenance window cannot happen immediately, follow the temporary risk-reduction guidance in the upstream advisory. For the confirmed session-related path, that advisory identifies server-level disabling of `session.upload_progress.enabled` and a worker restart as an interim measure only.

Do not rely on application-level runtime configuration calls to make this change. Record the temporary control, its owner, and the scheduled patch date.

## Incident-response signal

Where exposure is suspected, preserve web-server and PHP worker logs, record the effective version and SAPI, and review for anomalous worker failures, unexpected child processes, modified files, credential changes, and unusual outbound connections. Do not run public exploit tests against production systems as a verification step.

## Sources

- [PHP Project security advisory](https://www.php.net/)
- [PHP 8.4.27 release announcement](https://www.php.net/releases/8_4_27.php)
- [PHP downloads](https://www.php.net/downloads.php)
