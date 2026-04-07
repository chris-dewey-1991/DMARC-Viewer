<?php
/**
 * spf-lookup.php — DMARC Viewer SPF record checker
 * Fetches and parses SPF TXT records for a domain.
 */
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Cache-Control: public, max-age=300');

$domain = isset($_GET['domain']) ? strtolower(trim($_GET['domain'])) : '';
$domain = preg_replace('/[^a-z0-9.\-]/', '', $domain);

if (!$domain || strlen($domain) > 253) {
    echo json_encode(['error' => 'Invalid domain']);
    exit;
}

function dns_txt($domain) {
    $records = @dns_get_record($domain, DNS_TXT);
    if (!$records) return [];
    $txts = [];
    foreach ($records as $r) {
        $txt = isset($r['txt']) ? $r['txt'] : (isset($r['entries']) ? implode('', $r['entries']) : '');
        if ($txt) $txts[] = $txt;
    }
    return $txts;
}

function parse_spf($raw, $domain, &$lookup_count, $depth = 0) {
    if ($depth > 5) return ['error' => 'Too many nested lookups'];
    $mechanisms = [];
    $parts = preg_split('/\s+/', trim($raw));
    foreach ($parts as $part) {
        if (strtolower($part) === 'v=spf1') continue;
        $qualifier = '+';
        if (in_array($part[0], ['+','-','~','?'])) {
            $qualifier = $part[0];
            $part = substr($part, 1);
        }
        $type = strtolower(explode(':', $part)[0]);
        $value = strpos($part, ':') !== false ? substr($part, strpos($part, ':') + 1) : '';

        $mech = ['type' => $type, 'value' => $value, 'qualifier' => $qualifier, 'raw' => ($qualifier !== '+' ? $qualifier : '') . $part];

        // Count DNS-lookup mechanisms
        if (in_array($type, ['include', 'a', 'mx', 'ptr', 'exists', 'redirect'])) {
            $lookup_count++;
            if ($lookup_count > 10) {
                $mech['warning'] = 'DNS lookup limit exceeded (>' . $lookup_count . '/10)';
            }
        }

        // Recursively resolve includes
        if ($type === 'include' && $value && $depth < 3) {
            $sub_txts = dns_txt($value);
            $sub_spf = '';
            foreach ($sub_txts as $t) {
                if (stripos($t, 'v=spf1') === 0) { $sub_spf = $t; break; }
            }
            if ($sub_spf) {
                $mech['resolved'] = parse_spf($sub_spf, $value, $lookup_count, $depth + 1);
                $mech['resolved_raw'] = $sub_spf;
            } else {
                $mech['warning'] = 'include domain has no SPF record';
            }
        }

        $mechanisms[] = $mech;
    }
    return $mechanisms;
}

// Fetch TXT records
$txts = dns_txt($domain);
$spf_raw = '';
foreach ($txts as $t) {
    if (stripos($t, 'v=spf1') === 0) { $spf_raw = $t; break; }
}

if (!$spf_raw) {
    // Try with leading underscore (some providers)
    $txts2 = dns_txt('_spf.' . $domain);
    foreach ($txts2 as $t) {
        if (stripos($t, 'v=spf1') === 0) { $spf_raw = $t; break; }
    }
}

if (!$spf_raw) {
    echo json_encode(['error' => 'No SPF record found for ' . $domain, 'domain' => $domain]);
    exit;
}

$lookup_count = 0;
$mechanisms = parse_spf($spf_raw, $domain, $lookup_count);

$warnings = [];
if ($lookup_count > 10) $warnings[] = 'SPF record exceeds 10 DNS lookup limit (' . $lookup_count . ' lookups). Emails may fail SPF with permerror.';
if (strlen($spf_raw) > 450) $warnings[] = 'SPF record is very long (' . strlen($spf_raw) . ' chars). Some receivers truncate at 512 bytes.';
$has_all = false;
foreach ($mechanisms as $m) { if ($m['type'] === 'all') $has_all = true; }
if (!$has_all) $warnings[] = 'SPF record has no ~all or -all terminator.';

echo json_encode([
    'domain'       => $domain,
    'raw'          => $spf_raw,
    'mechanisms'   => $mechanisms,
    'lookup_count' => $lookup_count,
    'warnings'     => $warnings,
    'char_count'   => strlen($spf_raw),
]);
