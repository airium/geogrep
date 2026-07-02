# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- `geogrep find-category|fc [--include-mmdb] [-db|--database DB_DIR|DB_FILE]
  CATEGORY_REGEX [...]` for finding databases and category names with
  case-insensitive regular expressions.
- `geogrep find-category --json RESULT_PATH`, `GET
  /api/list-category/<pattern>`, `include_mmdb=true`, share redirects, and
  embedded web UI category discovery mode.
- MMDB/MetaDB list caches now include `category_names` for category discovery,
  while remaining compatible with existing category-to-rule caches.

### Changed

- Renamed CLI subcommands from `find`, `list`, and `list-category` to
  `find-rule`, `list-rule`, and `find-category`, with shortcuts `fr`, `lr`,
  and `fc`.

## [0.4.1] - 2026-06-30

### Changed

- `geogrep web` now defaults to `127.0.0.1:8080` for normal and production
  runs, while `GEOGREP_ENV=development` or `GEOGREP_ENV=dev` defaults to
  `0.0.0.0:8080` for LAN-visible development.
- `geogrep list` now skips MMDB/MetaDB sources by default when other database
  types are loaded, prints a CLI hint for `--include-mmdb`, and auto-includes
  MMDB/MetaDB data when it is the only loaded database type.
- MMDB/MetaDB ruleset listing now uses a compact sibling
  `<filename-stem>.json` category cache with the source file SHA-256, and
  generated cache files are ignored during database discovery/loading.
- Web UI and `GET /api/list/<ruleset>` now support `include_mmdb=true` for
  opting into MMDB/MetaDB list output.

## [0.4.0] - 2026-06-29

### Added

- `geogrep list [-db|--database DB_DIR|DB_FILE] RULESET_NAME [...]` for listing
  all rules from exact ruleset/category names across loaded databases.
- `geogrep list --json RESULT_PATH` and `GET /api/list/<ruleset>` for
  structured ruleset listing output.
- Embedded web UI ruleset listing mode.
- Ruleset matching for `list` is case-insensitive, so `cn` matches GeoIP
  category `CN`.
- JSON/YAML sing-box string-list fields now accept either a string or string
  array for compatibility with common ruleset files.

## [0.3.1] - 2026-06-29

### Added

- `DEVELOPMENT.md` with Conventional Commit and signed-commit guidance.

### Changed

- Embedded web UI now displays the running geogrep version from `/health`.
- Binary rule loaders now reject oversized singgeo and SRS length fields before
  allocating memory.
- Loader failures no longer leave partially parsed rules active for lookup or
  `.db` compatibility fallback.
- `convert` now rejects output paths that overlap discovered input sources and
  writes output through temporary files before replacing the target.
- `.dat` loading now rejects protobuf payloads that contain entries but no
  usable GeoIP or GeoSite rules.
- Text, JSON, and YAML loaders now report invalid typed CIDR and regex rules,
  and `convert` rejects inputs that would otherwise produce partial output.
- AdGuard-style domain matching now uses the sing-domain matcher for supported
  rule syntax and ignores exception rules during positive match reporting.
- Agent and contributor guidance now points maintainers to the shared
  development workflow and one-fix-per-commit expectations.

## [0.3.0] - 2026-06-28

### Added

- `convert` subcommand for converting loaded geodata rule data to JSON, YAML,
  list/txt, V2Ray/Xray `.dat`, singgeo `.db`, sing-box `.srs`, mihomo `.mrs`,
  and GeoIP `.mmdb` outputs.
- `convert` accepts `-i/--input`, `-o/--output`, optional positional
  input/output paths, and `--to` for explicit output format selection.
- Output format inference for `convert` based on `.json`, `.yaml`, `.yml`,
  `.list`, `.txt`, `.dat`, `.db`, `.srs`, `.mrs`, `.mmdb`, and `.metadb`
  extensions.
- Generated GeoIP MMDB output for IP/CIDR rule sets, including category values
  in inserted records.
- Target-specific conversion validation so unsupported mixed payloads or rule
  kinds fail explicitly instead of producing partial output.
- Conversion tests covering text-to-JSON, JSON-to-DAT, JSON-to-SRS,
  JSON-to-MRS, JSON-to-singgeo, JSON-to-MMDB, and target rejection cases.
- `FEATURES.md` with the current feature catalog and history summary.
- `AGENTS.md` with maintainer and agent working guidance for this repository,
  including an explicit checklist for related documentation updates.

### Changed

- Embedded web UI was redesigned with a Kumo-inspired, dependency-free layout
  including sidebar navigation, compact lookup controls, endpoint and examples
  panels, lookup metrics, expandable match rows, copy actions, and raw JSON
  inspection.
- Web UI API behavior and share-link behavior remain compatible with the 0.2.x
  routes.
- README was expanded with quick-start examples, CLI reference, web/API usage,
  conversion documentation, supported format details, compatibility matrix, and
  build/test instructions.
- Contributor guidance now tells maintainers to update related docs, including
  `README.md`, `FEATURES.md`, `CHANGELOG.md`, `AGENTS.md`, and `SECURITY.md`,
  alongside behavior changes.
- JSON/YAML rule loading now preserves `category` fields and supports
  `domain_wildcard` and `adguard_domain` rule arrays.
- Converted JSON/YAML documents group rules by category and include exact,
  suffix, keyword, regex, wildcard, AdGuard domain, and IP CIDR rule arrays
  where representable.
- Converted rule output is sorted and deduplicated for stable generated files.

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

## [0.1.0] - 2026-04-15

### Added

- Initial geogrep release.
- Unified lookup across geodata formats including mmdb, dat, db, srs, mrs, json, yaml/yml, list, txt.
- Query type forcing flags: -4, -6, -d, -k.
- JSON export with --json and explicit no-match reporting with --report-empty.
- Embedded binary version metadata and --version/-v flag.
