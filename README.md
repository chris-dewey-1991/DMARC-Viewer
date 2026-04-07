# DMARC Viewer

A fast, privacy-first, open-source DMARC report analyzer with built-in DNS tools and client-friendly reporting.

Parse DMARC XML reports directly in your browser, investigate sending sources, and generate clean client summaries — all without sending data anywhere.

---

## Open Source & Free

This project is:

- 100% free to use
- Open source
- No usage limits
- No accounts required
- No tracking or analytics

You are free to:
- Use it commercially
- Modify it
- Host it yourself
- Integrate it into your own tools

---

## Features

### DMARC Report Viewer

- Upload .xml, .xml.gz, or .zip DMARC reports
- Drag & drop or paste raw XML
- Fully client-side processing (no data leaves your browser)
- Pass / fail breakdown
- DKIM / SPF alignment visibility
- Alerting for failing sources
- Trend chart across reports
- Export to CSV
- Print / PDF output

---

### DNS Tools

SPF Checker:
- Parses SPF records
- Resolves includes
- Detects lookup limits

DKIM Checker:
- Validates selectors
- Detects weak or revoked keys

IP Lookup:
- Identifies sending infrastructure
- Detects cloud / suspicious IPs

---

### Client Report

- Generates non-technical summaries
- Includes pass rate and actions
- Exportable as PDF

---

## Privacy

- No external uploads
- No tracking
- No stored data
- Runs locally in browser

---

## Project Structure

/index.html
/tools.html
/client.html

/spf-lookup.php
/dkim-lookup.php
/iplookup.php

---

## Getting Started

git clone https://github.com/chris-dewey-1991/dmarc-viewer.git
cd dmarc-viewer

Run locally:
open index.html

Optional PHP server:
php -S localhost:8000

Run Cloud

Download and Upload files to a Web server. Configure your domain to poin to the files and your good to go.

---

## License

MIT License
