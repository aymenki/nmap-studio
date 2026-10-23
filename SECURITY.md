# Security policy

## Supported version

Security fixes are applied to the latest release.

## Report a vulnerability

Please do not open a public issue for a vulnerability that could expose a user's machine, command execution, or scan data. Use GitHub's **Security → Report a vulnerability** feature for this repository. Include the affected version, operating system, reproduction steps, impact, and any suggested mitigation.

You should receive an acknowledgement within seven days. Please allow time for a fix before publishing details.

## Security model

Nmap Studio is designed for a single user on one machine. The runner must remain bound to loopback and must not be placed behind a public web server or network proxy. Commands run with the permissions of the account that starts the runner.
