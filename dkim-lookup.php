<?php
/**
 * dkim-lookup.php — DMARC Viewer DKIM selector checker
 * Looks up DKIM TXT records and parses key details.
 */
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Cache-Control: public, max-age=300');

$domain   = isset($_GET['domain'])   ? strtolower(trim($_GET['domain']))   : '';
$selector = isset($_GET['selector']) ? strtolower(trim($_GET['selector'])) : '';

$domain   = preg_replace('/[^a-z0-9.\-]/', '', $domain);
$selector = preg_replace('/[^a-z0-9.\-_]/', '', $selector);

if (!$domain || !$selector) {
    echo json_encode(['error' => 'Domain and selector are required']);
    exit;
}

$dkim_host = $selector . '._domainkey.' . $domain;
$records   = @dns_get_record($dkim_host, DNS_TXT);

if (!$records) {
    echo json_encode([
        'domain'    => $domain,
        'selector'  => $selector,
        'host'      => $dkim_host,
        'found'     => false,
        'error'     => 'No DKIM record found at ' . $dkim_host,
    ]);
    exit;
}

$raw = '';
foreach ($records as $r) {
    $txt = isset($r['txt']) ? $r['txt'] : (isset($r['entries']) ? implode('', $r['entries']) : '');
    if ($txt && stripos($txt, 'v=DKIM1') !== false) { $raw = $txt; break; }
    if ($txt && !$raw) $raw = $txt; // fallback to any TXT
}

if (!$raw) {
    echo json_encode(['domain'=>$domain,'selector'=>$selector,'host'=>$dkim_host,'found'=>false,'error'=>'TXT record exists but no DKIM data found']);
    exit;
}

// Parse DKIM tags
$tags = [];
foreach (explode(';', $raw) as $part) {
    $part = trim($part);
    if (strpos($part, '=') !== false) {
        list($k, $v) = explode('=', $part, 2);
        $tags[trim($k)] = trim($v);
    }
}

$key_data = isset($tags['p']) ? $tags['p'] : '';
$revoked  = ($key_data === '');
$key_type = isset($tags['k']) ? $tags['k'] : 'rsa';
$version  = isset($tags['v']) ? $tags['v'] : 'DKIM1';
$hash_alg = isset($tags['h']) ? $tags['h'] : 'sha256 (default)';
$service  = isset($tags['s']) ? $tags['s'] : 'email (default)';
$notes    = isset($tags['n']) ? $tags['n'] : '';
$flags    = isset($tags['t']) ? $tags['t'] : '';

// Estimate key length from base64 public key
$key_bits = null;
if ($key_data && !$revoked) {
    $decoded = base64_decode($key_data);
    if ($decoded) {
        // ASN.1 RSA key length heuristic
        $len = strlen($decoded);
        if ($len > 250)      $key_bits = 2048;
        elseif ($len > 140)  $key_bits = 1024;
        elseif ($len > 60)   $key_bits = 512;
    }
}

$warnings = [];
if ($revoked)              $warnings[] = 'Key is revoked (p= is empty). DKIM signing with this selector will fail.';
if ($key_bits === 1024)    $warnings[] = '1024-bit RSA key is below modern recommendations. Consider upgrading to 2048-bit.';
if ($key_bits === 512)     $warnings[] = '512-bit key is dangerously weak and likely unsupported by many receivers.';
if ($flags === 'y')        $warnings[] = 'Testing mode flag (t=y) is set. Some receivers may not enforce DKIM.';
if ($key_type === 'ed25519') {} // fine, no warning

echo json_encode([
    'domain'    => $domain,
    'selector'  => $selector,
    'host'      => $dkim_host,
    'found'     => true,
    'raw'       => $raw,
    'tags'      => $tags,
    'revoked'   => $revoked,
    'key_type'  => $key_type,
    'key_bits'  => $key_bits,
    'version'   => $version,
    'hash_alg'  => $hash_alg,
    'service'   => $service,
    'notes'     => $notes,
    'flags'     => $flags,
    'warnings'  => $warnings,
]);
