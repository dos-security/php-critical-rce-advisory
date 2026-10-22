<?php
declare(strict_types=1);

/*
 * Local-only inventory aid for CVE-2026-109618 and CVE-2026-109619.
 * No network requests, file scanning, payload handling, or exploitation.
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    header('Content-Type: text/plain; charset=utf-8');
    echo "This self-check is intended for local CLI use only.\n";
    exit(64);
}

$fixedVersions = [
    '8.5' => '8.5.12',
    '8.4' => '8.4.27',
    '8.3' => '8.3.36',
    '8.2' => '8.2.35',
];

$asJson = in_array('--json', $argv, true);
$branch = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
$minimum = $fixedVersions[$branch] ?? null;
$uploadProgress = ini_get('session.upload_progress.enabled');

$report = [
    'tool' => 'PHP Critical RCE Self-Check',
    'php_version' => PHP_VERSION,
    'php_branch' => $branch,
    'cves' => ['CVE-2026-109618', 'CVE-2026-109619'],
    'session_upload_progress_enabled' => $uploadProgress,
    'network_requests_sent' => 0,
];

if ($minimum === null) {
    $report['status'] = 'manual_vendor_verification_required';
    $report['message'] = 'No upstream fixed-version threshold is listed for this branch. Verify a vendor backport or upgrade to a supported PHP branch.';
    $exitCode = 3;
} elseif (version_compare(PHP_VERSION, $minimum, '>=')) {
    $report['status'] = 'upstream_fixed_version_detected';
    $report['minimum_fixed_version'] = $minimum;
    $report['message'] = 'The active runtime meets the upstream fixed-version threshold. Continue normal patch and configuration management.';
    $exitCode = 0;
} else {
    $report['status'] = 'update_required';
    $report['minimum_fixed_version'] = $minimum;
    $report['message'] = 'The active runtime is below the upstream fixed-version threshold. Update immediately or verify an applicable vendor backport.';
    $exitCode = 2;
}

if ($asJson) {
    echo json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
} else {
    echo "PHP Critical RCE Self-Check\n";
    echo "===========================\n";
    echo "Active PHP version: " . $report['php_version'] . "\n";
    echo "Release branch: " . $report['php_branch'] . "\n";
    echo "CVE coverage: CVE-2026-109618, CVE-2026-109619\n";
    echo "session.upload_progress.enabled: " . var_export($uploadProgress, true) . "\n";
    echo "Status: " . $report['status'] . "\n";
    if (isset($report['minimum_fixed_version'])) {
        echo "Upstream minimum for this branch: " . $report['minimum_fixed_version'] . "\n";
    }
    echo "\n" . $report['message'] . "\n";
    echo "This tool made no network requests and does not prove that a host is uncompromised.\n";
}

exit($exitCode);
