# Public technical note

## Evidence, not theater

The public record is intentionally specific about what has—and has not—been independently established.

| Evidence | Public source | Defender meaning |
| --- | --- | --- |
| CVE-2026-109618 | [PHP Project advisory](https://www.php.net/) | PHP reports an out-of-memory cleanup path involving partially initialized request data. |
| CVE-2026-109619 | [PHP Project advisory](https://www.php.net/) | PHP reports request-owned state surviving after backing memory is freed. |
| Fixed releases | PHP 8.5.12, 8.4.27, 8.3.36, and 8.2.35 | Update the runtime serving traffic, then restart its workers. |
| Session-ID handling review | [php/php-src PR #22113](https://github.com/php/php-src/pull/22113) | An open upstream change discusses guarding form-supplied session IDs when `session.use_only_cookies=1`. It is a code-review reference—not a separate CVE or a public claim that patched PHP remains vulnerable. |

### Source-oriented observation ledger

The public PHP source and its review history provide more useful evidence than dramatic payloads. The relevant names are deliberately included so an experienced reviewer can follow the upstream work:

```text
ext/session/session.c
php_session_rfc1867_callback
php_session_rfc1867_early_find_sid
MULTIPART_EVENT_FORMDATA
session.upload_progress.enabled
session.use_only_cookies
```

These identifiers describe a narrow session-upload-progress and session-ID handling area. DOS Security does **not** represent the open PR as a third confirmed RCE, a post-patch bypass, or an assigned CVE. That distinction matters: publication should make a reviewer more confident, not ask them to take a dramatic conclusion on faith.

### Local evidence artifact

The included checker produces a machine-readable, local-only inventory record. A representative result shape is:

```json
{
  "php_branch": "8.4",
  "minimum_fixed_version": "8.4.27",
  "status": "update_required",
  "network_requests_sent": 0
}
```

It reads the active local PHP runtime and one configuration value; it neither contacts a host nor constructs a request.

## Why this is not a full proof of concept

Publishing a reliable exploit chain before independent validation and coordinated disclosure creates a needless operational advantage for people who do not administer the affected systems. That is not useful research communication.

The public record already establishes the defender-relevant facts: a malformed or resource-constrained request can enter an affected PHP request lifecycle, leave internal state inconsistent, and later reach an unsafe use. The PHP Project has assigned CVEs, published fixes, and directs administrators to update immediately.

```text
untrusted web request
        ↓
affected request lifecycle / error handling
        ↓
inconsistent internal state
        ↓
unsafe downstream use
        ↓
potential remote code execution
```

The diagram is an explanatory model, not executable instructions. It intentionally omits request construction, trigger conditions, payload material, target discovery, paths, and reproduction automation.

## What DOS Security retains privately

The private research archive preserves the original laboratory notes, source-analysis references, test artifacts, and draft analysis. It is not a public distribution channel. Material may move to the public record only after accuracy, scope, remediation status, and disclosure timing are reviewed.

## What defenders can do now

1. Upgrade to the PHP Project's listed fixed release or verify a vendor backport.
2. Restart every serving PHP worker after the change.
3. Apply official interim controls only when an emergency patch window is not available.
4. Use the local-only self-check and normal operations telemetry to document remediation.

## References

- [PHP Project security advisory](https://www.php.net/)
- [CVE-2026-109618](https://www.cve.org/CVERecord?id=CVE-2026-109618)
- [CVE-2026-109619](https://www.cve.org/CVERecord?id=CVE-2026-109619)
