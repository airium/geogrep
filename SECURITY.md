# Security Policy

## Reporting a vulnerability

If you find a security issue in geogrep, please report it privately to the maintainer before public disclosure.

Include:
- affected version or commit
- reproduction steps
- impact assessment
- suggested remediation (if available)

## Scope

This project is an offline lookup tool, but security issues can still exist in:
- parser logic for untrusted rule files
- dependency vulnerabilities
- malformed input handling

## Dependency hygiene

Before release, run:

```bash
go list -m -u all
go test ./...
```
