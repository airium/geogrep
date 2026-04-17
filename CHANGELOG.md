# Changelog

All notable changes to this project will be documented in this file.

## [0.2.5] - 2026-04-17

### Changed

- Hardened web server security.

## [0.2.4] - 2026-04-17

### Changed

- Web UI match lines now show only `category | rule` (database name and data format columns are hidden in per-rule lines).

## [0.2.3] - 2026-04-17

### Changed

- Refined default web UI layout and result rendering:
	- Expanded content width to `1960px` max.
	- Updated lookup form row sizing so `lookup-value` absorbs remaining row width.
	- Search results now render with monospace typography.
	- Result card grid now uses a `720px` minimum card width with adaptive columns.
- Improved folded-match UX:
	- Moved fold toggle button to the top-right of each result card.
	- Toggle labels are now `Show more` and `Show less`.
	- Added bottom `+n more` hint for folded content that hides when expanded.
	- Fold controls and hints only render when folded items exist.

## [0.2.2] - 2026-04-17

### Changed

- Improved default web UI result cards:
	- Added clickable expansion for folded `+n more` match lines.
	- Adjusted default result grid to 2 columns.
- Updated lookup input row layout so the query input occupies remaining row width.
- Reworked share/API URL UX:
	- Removed inline share hint text.
	- Replaced visible URL links with copy buttons (`Copy Share URL`, `Copy API URL`).
	- Copy buttons only appear after successful lookup and are shown in the result header row.

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
