# Safe verification for systems you administer

This procedure is intentionally non-invasive. It does not send crafted uploads, enumerate routes, scan third-party services, replay requests, or attempt code execution.

## 1. Establish the active runtime

For every public-facing PHP service, record the asset identifier, active PHP version, execution model, package/vendor version, and PHP worker restart time. Confirm the runtime serving requests—not only the package-manager inventory.

## 2. Verify remediation

Confirm that the active runtime has the upstream fixed version for its release branch or a vendor-documented backport for both CVE-2026-109618 and CVE-2026-109619.

The included local self-check can help capture that inventory:

```text
php tools/php-critical-rce-self-check.php
```

For a controlled static review of PHP source you administer, run:

```text
php tools/php-on-host-security-audit.php --path /absolute/path/to/application
```

This is a local source review aid. Treat its output as review candidates, not findings, and do not point it at paths or code you are not authorized to assess.

## 3. Apply interim controls only if patching is delayed

Use the upstream PHP advisory for temporary exposure-reduction measures. For the confirmed session-related path, PHP calls out server-level disabling of `session.upload_progress.enabled` followed by a worker restart. This does not replace updating.

## 4. Review existing telemetry

Use logging and monitoring already approved for the environment. Look for unusual request-size patterns, upload failures, worker crashes or restarts, unexpected process trees, unplanned file changes, and unusual network activity. Preserve relevant evidence before broad remediation changes.

## 5. Close the change

Record the active version, vendor-backport evidence if applicable, restart time, verification time, and reviewing owner. Remove temporary mitigations only after the permanent update has been confirmed.
