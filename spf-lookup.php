<?php
/**
 * spf-lookup.php — DMARC Viewer SPF record checker
 * Security hardened: input validation, DoS guards, rate limiting, no SSRF.
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
    $rate_key = 'dmarc_spf_' . md5($caller_ip);
    $hits = apcu_fetch($rate_key) ?: 0;
    if ($hits > 30) {
        http_response_code(429);
        echo json_encode(['error' => 'Rate limit exceeded.']);
        exit;
    }
    apcu_store($rate_key, $hits + 1, 60);
}

// ── Input validation ──
$domain = isset($_GET['domain']) ? strtolower(trim($_GET['domain'])) : '';

// Strip everything except valid hostname chars
$domain = preg_replace('/[^a-z0-9.\-]/', '', $domain);

// Enforce length and valid label structure
if (!$domain || strlen($domain) > 253 || !preg_match('/^[a-z0-9]([a-z0-9\-]*(\.[a-z0-9][a-z0-9\-]*)*)?$/', $domain)) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid domain']);
    exit;
}

// Block private hostnames and localhost
if (preg_match('/^(localhost|local|internal|intranet|corp|lan)$/i', $domain) ||
    preg_match('/\.(local|internal|corp|lan|test|example|invalid)$/', $domain)) {
    http_response_code(400);
    echo json_encode(['error' => 'Private or reserved domain names are not supported']);
    exit;
}

// ── DNS helper ──
function dns_txt(string $host): array {
    // Guard against overly long or invalid hostnames
    if (strlen($host) > 253 || !preg_match('/^[a-z0-9._\-]+$/i', $host)) return [];
    $records = @dns_get_record($host, DNS_TXT);
    if (!is_array($records)) return [];
    $txts = [];
    foreach ($records as $r) {
        $txt = $r['txt'] ?? (isset($r['entries']) ? implode('', $r['entries']) : '');
        if ($txt) $txts[] = $txt;
    }
    return $txts;
}

// ── SPF parser with strict DoS guards ──
function parse_spf(string $raw, string $domain, int &$lookup_count, int &$total_dns_calls, int $depth = 0): array {
    // Hard limits to prevent DoS via recursive SPF includes
    if ($depth > 4)            return [['type'=>'error', 'value'=>'Max recursion depth reached', 'qualifier'=>'+', 'raw'=>'']];
    if ($total_dns_calls > 20) return [['type'=>'error', 'value'=>'Too many total DNS lookups', 'qualifier'=>'+', 'raw'=>'']];

    $mechanisms = [];
    $parts = preg_split('/\s+/', trim($raw));

    foreach ($parts as $part) {
        if (!$part) continue;
        if (strtolower($part) === 'v=spf1') continue;

        $qualifier = '+';
        if (isset($part[0]) && in_array($part[0], ['+','-','~','?'])) {
            $qualifier = $part[0];
            $part = substr($part, 1);
        }

        $colon_pos = strpos($part, ':');
        $type  = strtolower($colon_pos !== false ? substr($part, 0, $colon_pos) : $part);
        $value = $colon_pos !== false ? substr($part, $colon_pos + 1) : '';

        // Sanitise type to known SPF mechanisms only
        $valid_types = ['all','include','a','mx','ptr','ip4','ip6','exists','redirect','exp','v'];
        if (!in_array($type, $valid_types)) continue;

        $mech = ['type'=>$type, 'value'=>$value, 'qualifier'=>$qualifier, 'raw'=>($qualifier!=='+'?$qualifier:'').$part];

        if (in_array($type, ['include','a','mx','ptr','exists','redirect'])) {
            $lookup_count++;
            if ($lookup_count > 10) $mech['warning'] = 'DNS lookup limit exceeded ('.$lookup_count.'/10)';
        }

        // Recursive include resolution with DoS protection
        if ($type === 'include' && $value && $depth < 3) {
            // Validate the include domain
            $inc_domain = preg_replace('/[^a-z0-9.\-]/i', '', strtolower($value));
            if ($inc_domain && strlen($inc_domain) <= 253) {
                $total_dns_calls++;
                $sub_txts = dns_txt($inc_domain);
                $sub_spf  = '';
                foreach ($sub_txts as $t) {
                    if (stripos($t, 'v=spf1') === 0) { $sub_spf = $t; break; }
                }
                if ($sub_spf) {
                    $mech['resolved']     = parse_spf($sub_spf, $inc_domain, $lookup_count, $total_dns_calls, $depth + 1);
                    $mech['resolved_raw'] = $sub_spf;
                } else {
                    $mech['warning'] = 'include domain has no SPF record';
                }
            }
        }

        $mechanisms[] = $mech;
    }
    return $mechanisms;
}

// ── Fetch SPF record ──
$txts    = dns_txt($domain);
$spf_raw = '';
foreach ($txts as $t) {
    if (stripos($t, 'v=spf1') === 0) { $spf_raw = $t; break; }
}

// Try _spf. prefix if not found
if (!$spf_raw) {
    $txts2 = dns_txt('_spf.' . $domain);
    foreach ($txts2 as $t) {
        if (stripos($t, 'v=spf1') === 0) { $spf_raw = $t; break; }
    }
}

if (!$spf_raw) {
    echo json_encode(['error' => 'No SPF record found for ' . $domain, 'domain' => $domain]);
    exit;
}

// Guard against absurdly large SPF records
if (strlen($spf_raw) > 4096) {
    echo json_encode(['error' => 'SPF record exceeds maximum safe length', 'domain' => $domain]);
    exit;
}

$lookup_count    = 0;
$total_dns_calls = 0;
$mechanisms      = parse_spf($spf_raw, $domain, $lookup_count, $total_dns_calls);

$warnings = [];
if ($lookup_count > 10) $warnings[] = 'SPF record exceeds 10 DNS lookup limit ('.$lookup_count.' lookups). Emails may fail SPF with permerror.';
if (strlen($spf_raw) > 450) $warnings[] = 'SPF record is very long ('.strlen($spf_raw).' chars). Some receivers truncate at 512 bytes.';
$has_all = false;
foreach ($mechanisms as $m) { if (($m['type'] ?? '') === 'all') $has_all = true; }
if (!$has_all) $warnings[] = 'SPF record has no ~all or -all terminator.';

echo json_encode([
    'domain'       => $domain,
    'raw'          => $spf_raw,
    'mechanisms'   => $mechanisms,
    'lookup_count' => $lookup_count,
    'warnings'     => $warnings,
    'char_count'   => strlen($spf_raw),
]);
