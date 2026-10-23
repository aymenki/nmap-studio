# Changelog

All notable changes are documented here.

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
