# Security policy

## Supported version

Security fixes are applied to the latest release.

## Report a vulnerability

Please do not open a public issue for a vulnerability that could expose a user's machine, command execution, or scan data. Use GitHub's **Security → Report a vulnerability** feature for this repository. Include the affected version, operating system, reproduction steps, impact, and any suggested mitigation.

You should receive an acknowledgement within seven days. Please allow time for a fix before publishing details.

## Security model

Nmap Studio is designed for a single user on one machine. The runner must remain bound to loopback and must not be placed behind a public web server or network proxy. Commands run with the permissions of the account that starts the runner.

Scheduled scans run only while the local runner is active. They are restricted to Safe mode and are rechecked against current target-scope rules before each run. The audit chain is tamper-evident rather than tamper-proof against a local administrator.

Normal scans do not send results to Nmap Studio or another hosted service. The optional intelligence refresh requires confirmation because it downloads CISA KEV and sends CVE identifiers or detected product/version keywords to FIRST and NVD. Treat those values as potentially sensitive inventory data.
