# Contributing

Thanks for contributing to geogrep.

## Development setup

1. Install Go 1.26+.
2. Clone the repository.
3. Run:

```bash
go mod tidy
go test ./...
```

## Local checks

Before opening a PR:

```bash
gofmt -w $(find cmd internal -name '*.go')
go test ./...
```

## Pull request guidelines

- Keep changes focused and small.
- Add tests for new behavior and regressions.
- Update related docs in the same PR when behavior changes. Check `README.md`,
  `FEATURES.md`, `CHANGELOG.md`, `AGENTS.md`, and `SECURITY.md` as applicable.
- Add a `CHANGELOG.md` entry for user-visible changes, supported-format changes,
  compatibility changes, migration notes, security hardening, and notable bug
  fixes.
- Include sample command output for user-facing behavior updates.

## Commit guidance

Recommended style:

```text
type(scope): summary
```

Examples:
- `feat(loader): add singgeo db parser`
- `fix(match): restrict keyword to rule-level hits`
- `docs(readme): add format matrix and examples`

## Reporting issues

When opening a bug report, include:
- command used
- sample input
- expected output
- actual output
- environment details (`go version`, OS)
