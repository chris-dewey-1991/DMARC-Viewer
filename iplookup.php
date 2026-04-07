<?php
/**
 * iplookup.php — DMARC Viewer IP lookup proxy
 * Place alongside index.html on your web server.
 * Requires: PHP 7.4+, allow_url_fopen or curl enabled.
 */

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Cache-Control: public, max-age=86400'); // cache 24h per IP

// Validate input
$ip = isset($_GET['ip']) ? trim($_GET['ip']) : '';

if (!filter_var($ip, FILTER_VALIDATE_IP)) {
    echo json_encode(['error' => 'Invalid IP']);
    exit;
}

// Skip private/reserved ranges — return immediately
$private = filter_var($ip, FILTER_VALIDATE_IP,
    FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
if ($private === false) {
    echo json_encode(['org' => 'Internal network', 'country' => '', 'city' => '', 'isp' => '']);
    exit;
}

// Try ip-api.com (free, 45 req/min, works perfectly server-side)
$url = 'http://ip-api.com/json/' . urlencode($ip) . '?fields=status,org,isp,country,city,as';
$data = null;

if (function_exists('curl_init')) {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 5,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_USERAGENT      => 'DMARC-Viewer/1.0',
    ]);
    $body = curl_exec($ch);
    $err  = curl_error($ch);
    curl_close($ch);
    if (!$err && $body) $data = json_decode($body, true);
} elseif (ini_get('allow_url_fopen')) {
    $ctx  = stream_context_create(['http' => ['timeout' => 5]]);
    $body = @file_get_contents($url, false, $ctx);
    if ($body) $data = json_decode($body, true);
}

if ($data && isset($data['status']) && $data['status'] === 'success') {
    echo json_encode([
        'org'     => $data['org']  ?? $data['isp'] ?? '',
        'isp'     => $data['isp']  ?? '',
        'country' => $data['country'] ?? '',
        'city'    => $data['city']    ?? '',
        'as'      => $data['as']      ?? '',
    ]);
    exit;
}

// Fallback: ipinfo.io (also server-side friendly, 50k/month free)
$url2 = 'https://ipinfo.io/' . urlencode($ip) . '/json';
$data2 = null;
if (function_exists('curl_init')) {
    $ch = curl_init($url2);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 5,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_USERAGENT      => 'DMARC-Viewer/1.0',
    ]);
    $body2 = curl_exec($ch);
    curl_close($ch);
    if ($body2) $data2 = json_decode($body2, true);
}

if ($data2 && !isset($data2['error'])) {
    echo json_encode([
        'org'     => $data2['org']  ?? '',
        'isp'     => $data2['org']  ?? '',
        'country' => $data2['country'] ?? '',
        'city'    => $data2['city']    ?? '',
        'as'      => $data2['org']     ?? '',
    ]);
    exit;
}

// Nothing worked
echo json_encode(['error' => 'Lookup failed', 'org' => '', 'country' => '', 'city' => '']);
