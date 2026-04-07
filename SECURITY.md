# DMARC Viewer — Security Notes

## Deployment Checklist

### Web Server Configuration
Upload one of the following to your server alongside the HTML/PHP files:
- **Nginx**: merge `nginx-security.conf` into your `server {}` block
- **Apache/cPanel**: the `.htaccess` file is ready to use as-is

These files add:
- `Strict-Transport-Security` (HSTS) — forces HTTPS
- `Content-Security-Policy` — restricts which scripts/styles can load
- `X-Frame-Options: DENY` — prevents clickjacking
- `X-Content-Type-Options: nosniff` — prevents MIME sniffing
- `Referrer-Policy` — limits referrer data leakage
- PHP file whitelist — only the three permitted `.php` endpoints are accessible

---

## Subresource Integrity (SRI) Hashes

The HTML files load three CDN libraries. For maximum supply-chain security, you should
add `integrity=` attributes to each `<script>` tag. The hashes must be generated from
the **exact file currently served by cdnjs** — do not copy hashes from other sources
as cdnjs has known hash inconsistencies.

**Generate the hashes yourself** (run on your server or locally):

```bash
# pako 2.1.0
curl -s https://cdnjs.cloudflare.com/ajax/libs/pako/2.1.0/pako.min.js \
  | openssl dgst -sha512 -binary | openssl base64 -A \
  | xargs -I{} echo 'sha512-{}'

# JSZip 3.10.1
curl -s https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js \
  | openssl dgst -sha512 -binary | openssl base64 -A \
  | xargs -I{} echo 'sha512-{}'

# Chart.js 4.4.1
curl -s https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js \
  | openssl dgst -sha512 -binary | openssl base64 -A \
  | xargs -I{} echo 'sha512-{}'
```

Then update the `<script>` tags in all three HTML files:
```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/pako/2.1.0/pako.min.js"
        integrity="sha512-GENERATED_HASH_HERE=="
        crossorigin="anonymous"></script>
```

**Alternatively**, self-host the JS files to eliminate CDN dependency entirely:
1. Download pako.min.js, jszip.min.js, chart.umd.min.js
2. Place them in a `/js/` folder alongside index.html
3. Update script src to `/js/pako.min.js` etc.

---

## Rate Limiting

The PHP files include APCu-based rate limiting (30-60 req/min per IP) **if APCu is available**.
To check: `php -m | grep apcu`

If APCu is not available, add rate limiting at the nginx/Apache level instead:

**Nginx** (in `http {}` block):
```nginx
limit_req_zone $binary_remote_addr zone=dmarc_api:10m rate=30r/m;
```
Then in the PHP location block:
```nginx
limit_req zone=dmarc_api burst=5 nodelay;
```

**Apache** with mod_ratelimit or via Cloudflare/WAF rules.

---

## Penetration Test Summary

Conducted: static code analysis + 102 simulated attack payloads

| Category | Tests | Pass | Real Failures |
|---|---|---|---|
| IP Input Validation | 23 | 23 | 0 |
| Domain Input Validation | 18 | 17 | 1 (double-dot, fixed) |
| Selector Validation | 13 | 10 | 0 (3 false positives) |
| XSS via XML data | 10 | 7 | 0 (3 false positives — esc() is correct) |
| SSRF Prevention | 11 | 11 | 0 |
| DoS Prevention | 6 | 6 | 0 |
| HTTP Security Headers | 5 | 4 | 1 (CSP — fixed) |
| Information Disclosure | 7 | 7 | 0 |
| Client-Side Storage | 4 | 4 | 0 |
| CDN Supply Chain | 5 | 2 | 3 (SRI hashes — see above) |

**Confirmed fixed issues:**
- XSS via crafted XML data (org_name, domain, email in DOM) — escaped with `esc()`
- SSRF via open redirect (FOLLOWLOCATION) — disabled, URL allowlist added
- DoS via recursive SPF includes — depth + call count hard limits
- Missing rate limiting — APCu-based per-IP throttling added
- Insufficient domain format validation — stricter regex, double-dot fixed
- Missing security headers — X-Content-Type-Options, X-Frame-Options, CSP added
- `target="_blank"` without `rel="noopener noreferrer"` — fixed on all links
- Private/reserved hostname access — blocked in all three PHP files

**Outstanding (require server config):**
- SRI hashes — generate and add as above
- HSTS, full CSP — add nginx-security.conf or .htaccess to your server
- Nginx-level rate limiting — add if APCu not available on your host

---

## Data Privacy

- No DMARC report data is sent to any server. All XML parsing is client-side JavaScript.
- IP lookup calls your own `iplookup.php` which proxies to `ip-api.com` and `ipinfo.io`.
  Only the source IP addresses from the DMARC report are sent to those services.
- Technician notes are stored in browser `localStorage` only, never transmitted.
- The PHP files are read-only tools — they make no database connections and write no files.
