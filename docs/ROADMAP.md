# Roadmap

The roadmap favors reliable local operation and useful analysis over turning Nmap Studio into a remote scanning service.

## Shipped in 0.3

- Results search, filters, sorting, and JSON/CSV/HTML exports
- Scan comparison for new, changed, and removed services
- Named scans, projects, bounded queue, stages, and progress
- NSE category classification and guided script arguments
- Cross-platform Python and JavaScript tests
- Architecture documentation and product demo

## Next

- Saved project workspaces and persistent, encrypted-at-rest report storage
- Better progress estimation using Nmap XML progress events
- Findings notes, tags, and explicit owner/authorization records
- Report redaction before export
- Accessibility and keyboard-navigation audit
- Signed release archives and automated release provenance

## Later

- Optional multi-user architecture as a separate hardened service, with authentication, authorization, audit logging, target allowlists, rate limits, and isolated workers
- Plugin-style result enrichments that remain disabled until explicitly configured
- Broader import support for compatible inventory formats

Ideas and bug reports are welcome in GitHub Issues. Security reports should follow `SECURITY.md` and should not be filed publicly.
