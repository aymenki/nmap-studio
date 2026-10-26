# Changelog

All notable changes are documented here.

## 0.3.0 — 2026-10-26

### Added

- Searchable, sortable results dashboard with JSON, CSV, and standalone HTML exports
- Scan-to-scan comparison for new, changed, and removed ports or services
- Named scans and projects with a two-worker queue, progress, stages, and elapsed time
- Scan manager for reviewing or cancelling queued and running work
- NSE safety library based on installed script categories, with guided key/value arguments
- Server-side Safe mode enforcement for script names, categories, and script arguments
- Architecture documentation, roadmap, screenshots, and animated product demo
- Framework-free frontend core module with Node-based behavior tests

### Changed

- Release archive now includes project documentation
- CI validates the frontend core and comparison/export behavior on every platform
- Navigation supports direct links to the main workspace views

## 0.2.0 — 2026-10-23

### Added

- Safe and explicitly confirmed Advanced execution modes
- Automatic Nmap XML capture and structured results
- Dynamic installed tool versions, paths, help, and NSE script discovery
- Settings for history privacy, profile import/export, diagnostics, and runner shutdown
- Rotating diagnostics and release packaging
- Security and lifecycle tests with cross-platform CI

### Changed

- Bounded job retention, output memory, request size, argument count, and XML imports
- Thread-safe job state and process-tree cancellation
- Strict security headers and mutation origin checks
- Browser history is disabled by default

### Fixed

- Website URLs are normalized to hostnames before scanning
- Launcher failures are written to a visible log instead of being discarded

## 0.1.0 — 2026-10-22

- Initial local Nmap Studio interface
