# Roadmap

The roadmap favors reliable local operation and useful analysis over turning Nmap Studio into a remote scanning service.

## Shipped in 0.4

- Persistent asset/service inventory and security finding workflow
- Explicit CISA KEV, FIRST EPSS, and possible NVD CVE enrichment
- Scheduled Safe-mode rescans and drift alerts
- Project scope rules, authorization references, and hash-chained audit events
- SARIF, NDJSON, DefectDojo CSV, and workspace JSON exports
- Reproducible archives, SHA-256 checksums, and GitHub provenance attestations

## Shipped in 0.3

- Results search, filters, sorting, and JSON/CSV/HTML exports
- Scan comparison for new, changed, and removed services
- Named scans, projects, bounded queue, stages, and progress
- NSE category classification and guided script arguments
- Cross-platform Python and JavaScript tests
- Architecture documentation and product demo

## Next

- Optional encrypted-at-rest workspace storage and configurable retention
- Better progress estimation using Nmap XML progress events
- Report redaction before export
- Accessibility and keyboard-navigation audit
- Native ticket/webhook connectors with explicit per-destination configuration

## Later

- Optional multi-user architecture as a separate hardened service, with authentication, authorization, audit logging, target allowlists, rate limits, and isolated workers
- Plugin-style result enrichments that remain disabled until explicitly configured
- Broader import support for compatible inventory formats

Ideas and bug reports are welcome in GitHub Issues. Security reports should follow `SECURITY.md` and should not be filed publicly.
