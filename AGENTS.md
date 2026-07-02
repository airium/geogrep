# AGENTS.md

Guidance for coding agents and maintainers working in this repository.

## Scope

This file applies to the `geogrep` repository. In the surrounding workspace,
other repositories and directories are reference material unless the user asks
otherwise. Keep changes scoped to `geogrep`.

## Project Overview

`geogrep` is a Go CLI and web service for searching geoip/geosite databases.

Important paths:

- `cmd/geogrep/main.go`: binary entrypoint.
- `internal/geogrep/cli.go`: CLI argument parsing.
- `internal/geogrep/discover.go`: database discovery.
- `internal/geogrep/input.go`: input classification.
- `internal/geogrep/loader.go`, `loader_srs.go`, `loader_mrs.go`: data loaders.
- `internal/geogrep/match.go`: query matching.
- `internal/geogrep/convert.go`: geodata conversion command and writers.
- `internal/geogrep/report.go`: stdout and JSON export formatting.
- `internal/geogrep/web.go`: HTTP API, embedded UI serving, web security.
- `internal/geogrep/webui/index.html`: embedded static UI.
- `VERSION`: release version used by build metadata.
- `Makefile`: build/test/release helpers.
- `DEVELOPMENT.md`: development workflow and commit-message guidance.

## Current Behavior to Preserve

- CLI subcommands are `find-rule` (`fr`), `list-rule` (`lr`),
  `find-category` (`fc`), `convert`, `web`, and `version`.
- `find-rule` supports `-db/--database`, `--json`, `-v|--verbose`, `-4`,
  `-6`, `-d`, and `-k`.
- `list-rule` supports `-db/--database`, `--include-mmdb`, `--json`, and one
  or more exact case-insensitive ruleset names. For grouped sparse files, the
  direct child directory is the database, each direct file is the ruleset, and
  each file line is a rule.
- `find-category` supports `-db/--database`, `--include-mmdb`, `--json`, and
  one or more case-insensitive regex patterns for category discovery.
- `convert` supports `-i/--input`, `-o/--output`, and `--to`.
- `web` defaults to `127.0.0.1:8080` for normal and production runs.
- `GEOGREP_ENV=development` or `GEOGREP_ENV=dev` changes the default web
  listen address to `0.0.0.0:8080`; `-l`/`--listen` overrides both defaults.
- API routes are stable:
  - `/health`
  - `/openapi.json`
  - `/api/find/auto/<value>`
  - `/api/find/ipv4/<value>`
  - `/api/find/ipv6/<value>`
  - `/api/find/domain/<value>`
  - `/api/find/keyword/<value>`
  - `/api/list/<ruleset>`
  - `/api/list-category/<pattern>`
- Share routes under `/find/<type>/<value>` redirect to
  `/?mode=find-rule&type=...&q=...`. `/find/list-rule/<ruleset>` redirects to
  `/?mode=list-rule&q=...`. `/find/find-category/<pattern>` redirects to
  `/?mode=find-category&q=...`. Legacy `/find/list/...` and
  `/find/list-category/...` routes redirect to the new UI mode names.
- API responses must not expose local database root paths or loader diagnostics.
- Web path traversal guards and security headers are intentional.
- The embedded UI is currently a single dependency-free static HTML file.

## Development Commands

Run from the repository root:

```bash
go test ./...
go build -o geogrep ./cmd/geogrep
make build
make all
make fmt
make version
```

Use `gofmt` for Go changes. Prefer `go test ./...` after code changes.

For web development with the workspace database directory:

```bash
GEOGREP_ENV=development go run ./cmd/geogrep web -db ./db -l 0.0.0.0:18080
```

If that workspace path is unavailable, use an explicit supported test database
directory rather than relying on implicit discovery.

## Documentation Expectations

Treat user-visible code changes and their related docs as one change. Before
finishing any feature, behavior change, CLI/API change, format support change,
web UI change, release workflow change, or security-sensitive fix, check the
related documentation files and update them in the same change when applicable.
If no documentation update is needed, mention that in the final summary.

- Keep `README.md` focused on user-facing setup, CLI/API usage, supported
  formats, output, examples, conversion behavior, and build instructions.
- Keep `FEATURES.md` as the detailed feature catalog and history summary.
- Keep `CHANGELOG.md` release-oriented. Add an entry for every user-visible
  change, supported-format change, compatibility change, migration note,
  security hardening, notable bug fix, and release-relevant documentation
  addition.
- Keep `CONTRIBUTING.md` aligned with development, testing, pull request, and
  release expectations.
- Keep this `AGENTS.md` aligned with repository structure, agent workflow,
  documentation policy, and safety-sensitive project rules.
- Check `SECURITY.md` when changing security posture, disclosure guidance,
  serving behavior, path handling, or data exposure.
- Update examples, compatibility matrices, and API route lists when changing
  CLI flags, API routes, output shape, supported formats, discovery behavior,
  conversion behavior, or web UI behavior.

## Testing Notes

Existing tests cover:

- CLI parsing.
- database discovery.
- input classification.
- loaders.
- ruleset listing.
- matching.
- conversion.
- report formatting.
- web API, redirects, path guards, and security-sensitive behavior.

When changing behavior, add or update focused tests near the affected package
file. Avoid broad snapshot tests for the whole embedded HTML unless the exact
markup becomes part of a contract.

## Web UI Notes

The current UI is Kumo-inspired but does not import Kumo or run a frontend build.
It intentionally uses static HTML, CSS, and JavaScript so it can stay embedded
with Go's `embed.FS`.

When editing `internal/geogrep/webui/index.html`:

- Preserve element IDs used by the script unless updating the script at the
  same time.
- Preserve API path construction and share URL behavior, including lookup,
  ruleset listing, and category discovery modes.
- Keep the UI usable on desktop and mobile.
- Keep result rendering safe by escaping API-provided text before injecting
  HTML.
- Do not add external scripts, fonts, or CDN dependencies without an explicit
  project decision; the CSP currently allows only self-hosted resources and
  inline static code.
- If adopting a real frontend build later, update `web.go`, `Makefile`,
  `README.md`, and this file together.

## Security Notes

Be cautious around:

- URL path unescaping.
- encoded slash or backslash handling.
- `..` traversal checks.
- API value length limits.
- local filesystem paths in API output.
- serving custom `--webui` directories.

Security hardening was added deliberately and should not be relaxed for
convenience without a replacement test.

## Release Notes

When bumping a release:

- Update `VERSION`.
- Update `internal/geogrep/version.go` if the project still keeps a static
  fallback version there.
- Add a `CHANGELOG.md` entry.
- Run `go test ./...`.
- Use `make build` or `make all` to embed version, commit, and build date.

## Commit Guidance

- Follow [DEVELOPMENT.md](DEVELOPMENT.md) for Conventional Commit formatting.
- Use signed commits with `git commit -S`.
- Keep one fix per commit when requested, including the code, focused tests, and
  related documentation or changelog entry for that fix.
- If GPG signing asks for a passphrase, stop and ask the user to unlock the key
  before retrying.

## Style

- Keep Go code small and direct.
- Prefer standard library behavior where practical.
- Preserve existing output shape unless the user explicitly requests a breaking
  change.
- Keep docs ASCII-only unless there is a clear reason otherwise.
