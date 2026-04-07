<?php
/**
 * iplookup.php — DMARC Viewer IP lookup proxy
 * Security hardened: input validation, no SSRF, rate-limit headers, no redirect following.
 */

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Cache-Control: public, max-age=86400');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header("Content-Security-Policy: default-src 'self'; script-src 'none'; style-src 'none'; object-src 'none'; frame-ancestors 'none'");
header("Content-Security-Policy: default-src 'self'; frame-ancestors 'none';");

// ── Simple per-IP rate limiting using APCu (if available) ──
$caller_ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
if (function_exists('apcu_fetch')) {
    $rate_key = 'dmarc_iplookup_' . md5($caller_ip);
    $hits = apcu_fetch($rate_key) ?: 0;
    if ($hits > 60) { // 60 requests per minute
        http_response_code(429);
        echo json_encode(['error' => 'Rate limit exceeded. Please slow down.']);
        exit;
    }
    apcu_store($rate_key, $hits + 1, 60);
}

// ── Validate input ──
$ip = isset($_GET['ip']) ? trim($_GET['ip']) : '';
if (!filter_var($ip, FILTER_VALIDATE_IP)) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid IP address']);
    exit;
}

// ── Skip private / reserved ranges ──
if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
    echo json_encode(['org' => 'Internal network', 'country' => '', 'city' => '', 'isp' => '']);
    exit;
}

// ── Safe cURL helper — no redirect following, strict SSL, timeout ──
function safe_curl(string $url, int $timeout = 5): ?array {
    if (!function_exists('curl_init')) return null;

    // Only allow HTTPS (or the specific HTTP endpoint we control)
    if (!preg_match('#^https?://(?:ip-api\.com|ipinfo\.io)/#', $url)) return null;

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => $timeout,
        CURLOPT_CONNECTTIMEOUT => 3,
        CURLOPT_FOLLOWLOCATION => false,   // Never follow redirects (SSRF prevention)
        CURLOPT_SSL_VERIFYPEER => true,    // Always verify SSL
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_USERAGENT      => 'DMARC-Viewer/1.0',
        CURLOPT_PROTOCOLS      => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        CURLOPT_MAXREDIRS      => 0,
    ]);
    $body = curl_exec($ch);
    $err  = curl_error($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($err || $code !== 200 || !$body) return null;
    $data = json_decode($body, true);
    return is_array($data) ? $data : null;
}

// ── Primary: ip-api.com ──
$ip_encoded = urlencode($ip);
$data = safe_curl("http://ip-api.com/json/{$ip_encoded}?fields=status,org,isp,country,city,as");
if ($data && ($data['status'] ?? '') === 'success') {
    echo json_encode([
        'org'     => $data['org']     ?? $data['isp'] ?? '',
        'isp'     => $data['isp']     ?? '',
        'country' => $data['country'] ?? '',
        'city'    => $data['city']    ?? '',
        'as'      => $data['as']      ?? '',
    ]);
    exit;
}

// ── Fallback: ipinfo.io ──
$data2 = safe_curl("https://ipinfo.io/{$ip_encoded}/json");
if ($data2 && !isset($data2['error'])) {
    echo json_encode([
        'org'     => $data2['org']     ?? '',
        'isp'     => $data2['org']     ?? '',
        'country' => $data2['country'] ?? '',
        'city'    => $data2['city']    ?? '',
        'as'      => $data2['org']     ?? '',
    ]);
    exit;
}

echo json_encode(['error' => 'Lookup failed', 'org' => '', 'country' => '', 'city' => '']);
