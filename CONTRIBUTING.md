# Contributing

Thank you for helping improve Nmap Studio.

1. Open an issue for larger changes so scope and security impact can be discussed.
2. Create a focused branch and keep dependencies at zero unless a dependency solves a clear maintenance or security problem.
3. Preserve loopback-only binding, origin and token checks, argument-array execution, and server-side limits.
4. Add or update tests for security boundaries, job lifecycle behavior, or XML parsing changes.
5. Run the commands in the README before opening a pull request.

Pull requests should explain the user-visible behavior, security impact, and validation performed. Never include real scan output, credentials, private addresses, or other sensitive network data in fixtures or screenshots.
