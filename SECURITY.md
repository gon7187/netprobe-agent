# Security policy

## Supported versions

Security fixes are provided for the latest release and the current `main` branch.

## Reporting a vulnerability

Please use GitHub's **Security → Report a vulnerability** flow. Do not open a
public issue for vulnerabilities, credential exposure, parser denial of service,
command injection, unsafe route-file writes, or TLS-probe privacy concerns.

When possible, include a minimal reproduction, affected platform, and the
relevant sanitized probe type. Do not attach unredacted diagnostic reports.

## Scope notes

`netprobe-agent` performs active network probes. Run it only against destinations
you are authorized to test. Its findings describe observed behavior and are not a
legal determination that a network operator is censoring traffic.
