<?php
/**
 * dkim-lookup.php — DMARC Viewer DKIM selector checker
 * Security hardened: strict input validation, rate limiting, no SSRF.
 */

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Cache-Control: public, max-age=300');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header("Content-Security-Policy: default-src 'self'; script-src 'none'; style-src 'none'; object-src 'none'; frame-ancestors 'none'");
header("Content-Security-Policy: default-src 'self'; frame-ancestors 'none';");

// ── Rate limiting ──
$caller_ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
if (function_exists('apcu_fetch')) {
    $rate_key = 'dmarc_dkim_' . md5($caller_ip);
    $hits = apcu_fetch($rate_key) ?: 0;
    if ($hits > 30) {
        http_response_code(429);
        echo json_encode(['error' => 'Rate limit exceeded.']);
        exit;
    }
    apcu_store($rate_key, $hits + 1, 60);
}

// ── Input validation ──
$domain   = isset($_GET['domain'])   ? strtolower(trim($_GET['domain']))   : '';
$selector = isset($_GET['selector']) ? strtolower(trim($_GET['selector'])) : '';

// Strip to safe chars
$domain   = preg_replace('/[^a-z0-9.\-]/',  '', $domain);
$selector = preg_replace('/[^a-z0-9.\-_]/', '', $selector);

// Length and format checks
if (!$domain || strlen($domain) > 253 || !preg_match('/^[a-z0-9]([a-z0-9\-]*(\.[a-z0-9][a-z0-9\-]*)*)?$/', $domain)) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid domain']);
    exit;
}
if (!$selector || strlen($selector) > 63 || !preg_match('/^[a-z0-9][a-z0-9\-_.]*$/', $selector)) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid selector']);
    exit;
}

// Block private/reserved hostnames
if (preg_match('/^(localhost|local|internal|intranet)$/i', $domain) ||
    preg_match('/\.(local|internal|corp|lan|test|example|invalid)$/', $domain)) {
    http_response_code(400);
    echo json_encode(['error' => 'Private or reserved domain names are not supported']);
    exit;
}

// ── DNS lookup ──
$dkim_host = $selector . '._domainkey.' . $domain;

// Final safety check on the constructed hostname
if (strlen($dkim_host) > 253 || !preg_match('/^[a-z0-9][a-z0-9.\-_]+$/i', $dkim_host)) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid DKIM hostname constructed']);
    exit;
}

$records = @dns_get_record($dkim_host, DNS_TXT);

if (!$records || !is_array($records)) {
    echo json_encode([
        'domain'   => $domain,
        'selector' => $selector,
        'host'     => $dkim_host,
        'found'    => false,
        'error'    => 'No DKIM record found at ' . $dkim_host,
    ]);
    exit;
}

// ── Extract TXT value ──
$raw = '';
foreach ($records as $r) {
    $txt = $r['txt'] ?? (isset($r['entries']) ? implode('', $r['entries']) : '');
    if ($txt && stripos($txt, 'v=DKIM1') !== false) { $raw = $txt; break; }
    if ($txt && !$raw) $raw = $txt;
}

if (!$raw) {
    echo json_encode(['domain'=>$domain,'selector'=>$selector,'host'=>$dkim_host,'found'=>false,'error'=>'TXT record found but no DKIM data']);
    exit;
}

// Guard against unreasonably large records
if (strlen($raw) > 8192) {
    echo json_encode(['domain'=>$domain,'selector'=>$selector,'host'=>$dkim_host,'found'=>false,'error'=>'DKIM record exceeds maximum safe length']);
    exit;
}

// ── Parse DKIM tags (key=value; pairs) ──
$tags = [];
foreach (explode(';', $raw) as $part) {
    $part = trim($part);
    if (!$part) continue;
    $eq = strpos($part, '=');
    if ($eq === false) continue;
    $k = trim(substr($part, 0, $eq));
    $v = trim(substr($part, $eq + 1));
    // Only accept known DKIM tag names
    if (preg_match('/^[a-z]{1,10}$/', $k)) {
        $tags[$k] = $v;
    }
}

$key_data = $tags['p'] ?? '';
$revoked  = ($key_data === '');
$key_type = $tags['k'] ?? 'rsa';
$version  = $tags['v'] ?? 'DKIM1';
$hash_alg = $tags['h'] ?? 'sha256 (default)';
$service  = $tags['s'] ?? 'email (default)';
$notes    = $tags['n'] ?? '';
$flags    = $tags['t'] ?? '';

// Sanitise tag values before output (they come from DNS, could contain anything)
$key_type = preg_replace('/[^a-z0-9]/', '', strtolower($key_type));
$version  = preg_replace('/[^a-zA-Z0-9]/', '', $version);
$flags    = preg_replace('/[^a-z:,]/', '', strtolower($flags));

// ── Estimate key strength ──
$key_bits = null;
if ($key_data && !$revoked) {
    $decoded = base64_decode($key_data, true); // strict mode
    if ($decoded !== false) {
        $len = strlen($decoded);
        if ($len > 380)      $key_bits = 4096;
        elseif ($len > 250)  $key_bits = 2048;
        elseif ($len > 140)  $key_bits = 1024;
        elseif ($len > 60)   $key_bits = 512;
    }
}

// ── Warnings ──
$warnings = [];
if ($revoked)            $warnings[] = 'Key is revoked (p= is empty). DKIM signing with this selector will fail.';
if ($key_bits === 1024)  $warnings[] = '1024-bit RSA key is below modern recommendations. Consider upgrading to 2048-bit.';
if ($key_bits === 512)   $warnings[] = '512-bit key is dangerously weak and likely unsupported by many receivers.';
if (str_contains($flags, 'y')) $warnings[] = 'Testing mode (t=y) is set. Some receivers may not enforce DKIM.';

// ── Output — never include raw DNS data without going through json_encode ──
echo json_encode([
    'domain'   => $domain,
    'selector' => $selector,
    'host'     => $dkim_host,
    'found'    => true,
    'raw'      => $raw,
    'tags'     => $tags,
    'revoked'  => $revoked,
    'key_type' => $key_type,
    'key_bits' => $key_bits,
    'version'  => $version,
    'hash_alg' => $hash_alg,
    'service'  => $service,
    'notes'    => $notes,
    'flags'    => $flags,
    'warnings' => $warnings,
], JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT);
