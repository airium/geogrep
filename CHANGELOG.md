# Changelog

All notable changes to this project will be documented in this file.

## [0.2.1] - 2026-04-17

### Changed

- Removed database root from responses for privacy consideration.

## [0.2.0] - 2026-04-17

### Added

- `web` subcommand with built-in HTTP API and bundled static UI.
- `GET /health` endpoint for lightweight service and database availability checks.
- `GET /openapi.json` endpoint exposing OpenAPI 3.0 schema for web API routes.
- API endpoints for type-specific lookup:
	- `/api/find/auto/<any>`
	- `/api/find/ipv4/<IP_or_CIDR>`
	- `/api/find/ipv6/<IP_or_CIDR>`
	- `/api/find/domain/<domain>`
	- `/api/find/keyword/<keyword>`
- Shareable URL redirects from `/find/<type>/<value>` to `/` with auto-run query params.

### Changed

- CLI flow now uses explicit subcommands: `find`, `web`, `version`.
- No-match detail output control moved to verbosity levels (`-v/--verbose`) with level >= 1.
- Database path flags are standardized as `-db` and `--database`.

## [Unreleased]

## [0.1.0] - 2026-04-15

### Added

- Initial geogrep release.
- Unified lookup across geodata formats including mmdb, dat, db, srs, mrs, json, yaml/yml, list, txt.
- Query type forcing flags: -4, -6, -d, -k.
- JSON export with --json and explicit no-match reporting with --report-empty.
- Embedded binary version metadata and --version/-v flag.
