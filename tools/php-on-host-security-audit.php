<?php
declare(strict_types=1);

/*
 * DOS Security PHP On-Host Security Audit
 *
 * A local static-review helper for PHP source you administer. It never makes
 * network requests, generates payloads, modifies files, or executes scanned code.
 * Results are review candidates, not proof of a vulnerability.
 *
 * Usage:
 *   php php-on-host-security-audit.php --path /absolute/path/to/application
 *   php php-on-host-security-audit.php --path /absolute/path/to/application --json
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    header('Content-Type: text/plain; charset=utf-8');
    echo "This utility is intended for local CLI use only.\n";
    exit(64);
}

$options = getopt('', ['path:', 'json', 'max-files::']);
$requestedPath = $options['path'] ?? '';
$target = is_string($requestedPath) ? realpath($requestedPath) : false;

if ($target === false || !is_dir($target)) {
    fwrite(STDERR, "Provide an existing application directory with --path.\n");
    exit(64);
}

$maxFiles = 5000;
if (isset($options['max-files']) && is_string($options['max-files']) && ctype_digit($options['max-files'])) {
    $maxFiles = max(1, min((int) $options['max-files'], 20000));
}

$maxBytesPerFile = 1_500_000;
$skipDirectories = ['.git', '.svn', '.hg', 'node_modules', 'vendor', 'cache', 'logs'];
$rules = [
    [
        'id' => 'PHP-INPUT-INCLUDE',
        'severity' => 'high',
        'title' => 'Direct include or require from an HTTP superglobal',
        'pattern' => '/\b(?:include|require)(?:_once)?\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/i',
    ],
    [
        'id' => 'PHP-INPUT-FILE-READ',
        'severity' => 'high',
        'title' => 'Direct file read from an HTTP superglobal',
        'pattern' => '/\b(?:file_get_contents|fopen|readfile|file)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/i',
    ],
    [
        'id' => 'PHP-INPUT-EVAL',
        'severity' => 'critical',
        'title' => 'eval called with an HTTP superglobal',
        'pattern' => '/\beval\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/i',
    ],
    [
        'id' => 'PHP-INPUT-COMMAND',
        'severity' => 'critical',
        'title' => 'Command-execution function called with an HTTP superglobal',
        'pattern' => '/\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/i',
    ],
    [
        'id' => 'PHP-INPUT-DESERIALIZE',
        'severity' => 'high',
        'title' => 'unserialize called with an HTTP superglobal',
        'pattern' => '/\bunserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/i',
    ],
    [
        'id' => 'PHP-DYNAMIC-INCLUDE',
        'severity' => 'medium',
        'title' => 'Dynamic include or require requires data-flow review',
        'pattern' => '/\b(?:include|require)(?:_once)?\s*\(\s*\$[A-Za-z_][A-Za-z0-9_]*\s*\)/',
    ],
];

function shouldSkip(string $path, array $skipDirectories): bool
{
    $segments = preg_split('#[\\/]#', $path) ?: [];
    return count(array_intersect($segments, $skipDirectories)) > 0;
}

function lineNumberForOffset(string $content, int $offset): int
{
    return substr_count(substr($content, 0, $offset), "\n") + 1;
}

$findings = [];
$filesScanned = 0;
$filesSkipped = 0;
$truncated = false;

try {
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($target, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::LEAVES_ONLY
    );

    foreach ($iterator as $file) {
        if (!$file instanceof SplFileInfo || !$file->isFile()) {
            continue;
        }

        $path = $file->getPathname();
        if (shouldSkip($path, $skipDirectories) || !preg_match('/\.php$/i', $path)) {
            $filesSkipped++;
            continue;
        }

        if ($filesScanned >= $maxFiles) {
            $truncated = true;
            break;
        }

        if ($file->getSize() > $maxBytesPerFile || !$file->isReadable()) {
            $filesSkipped++;
            continue;
        }

        $content = @file_get_contents($path);
        if (!is_string($content)) {
            $filesSkipped++;
            continue;
        }

        $filesScanned++;

        foreach ($rules as $rule) {
            $matchCount = preg_match_all($rule['pattern'], $content, $matches, PREG_OFFSET_CAPTURE);
            if ($matchCount === false || $matchCount === 0) {
                continue;
            }

            foreach ($matches[0] as $match) {
                $findings[] = [
                    'rule_id' => $rule['id'],
                    'severity' => $rule['severity'],
                    'title' => $rule['title'],
                    'file' => $path,
                    'line' => lineNumberForOffset($content, (int) $match[1]),
                ];
            }
        }
    }
} catch (UnexpectedValueException $exception) {
    fwrite(STDERR, "Unable to read the requested directory safely: " . $exception->getMessage() . "\n");
    exit(74);
}

$summary = [
    'tool' => 'DOS Security PHP On-Host Security Audit',
    'target' => $target,
    'files_scanned' => $filesScanned,
    'files_skipped' => $filesSkipped,
    'scan_truncated' => $truncated,
    'network_requests_sent' => 0,
    'files_modified' => 0,
    'findings' => $findings,
    'notice' => 'Findings are static-review candidates. Validate authorization, reachability, sanitization, and data flow before classifying any issue.',
];

if (array_key_exists('json', $options)) {
    echo json_encode($summary, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;
} else {
    echo "DOS Security PHP On-Host Security Audit\n";
    echo "========================================\n";
    echo "Target: " . $target . "\n";
    echo "PHP files scanned: " . $filesScanned . "\n";
    echo "Files skipped: " . $filesSkipped . "\n";
    echo "Network requests: 0\n";
    echo "Files modified: 0\n";
    if ($truncated) {
        echo "Warning: scan stopped at the configured file limit (" . $maxFiles . ").\n";
    }
    echo "\nReview candidates: " . count($findings) . "\n";
    foreach ($findings as $finding) {
        echo strtoupper($finding['severity']) . " " . $finding['rule_id'] . " " . $finding['file'] . ":" . $finding['line'] . "\n";
        echo "  " . $finding['title'] . "\n";
    }
    echo "\n" . $summary['notice'] . "\n";
}

exit(count($findings) > 0 ? 1 : 0);
