# Features

This document summarizes the current `geogrep` feature set and the main
capabilities added through the repository history.

## Current Capabilities

### Rule Finding

- Searches multiple geoip and geosite database formats through one command.
- Handles IP, CIDR, domain, and keyword inputs.
- Preserves lookup order for batch requests.
- Reports provenance for every match: database, source, format, category, and
  matched rule or network.

### Rule Listing

- Lists all rules in loaded ruleset/category names with `geogrep list-rule`
  or `geogrep lr`.
- Ruleset matching is exact by name and case-insensitive.
- For grouped sparse files, the child directory is the database and each direct
  file is a ruleset; each file line is a rule.
- MMDB/MetaDB sources are skipped by default when mixed with other database
  types, can be included with `--include-mmdb`, and are auto-included when they
  are the only loaded database type. Included MMDB lists use a generated
  source-hash-checked cache with category names and category-to-rule data.
- Supports human-readable stdout, `--json`, `GET /api/list/<ruleset>`, the
  `include_mmdb=true` API toggle, and web UI list mode.

### Category Discovery

- Lists every category exposed by loaded databases with `geogrep list-category`
  or `geogrep lc`.
- Lists databases and category names matching case-insensitive regular
  expressions with `geogrep find-category` or `geogrep fc`.
- Supports `-db/--database` for explicit database root or single-file
  selection.
- Uses the same MMDB/MetaDB policy as ruleset listing: skipped by default when
  mixed with other database types, included with `--include-mmdb`, and
  auto-included when MMDB/MetaDB is the only loaded database type.
- Reads cached MMDB/MetaDB `category_names` when available and writes that
  cache after a full scan.
- Supports structured CLI export with `--json`.
- Reports `source | format | category` rows grouped by database.
- Uses the same meaningful category names as ruleset listing, including source
  filename stems for sparse files and opt-in categories derived from
  MMDB/MetaDB records.
- Category listing is CLI-only; regex category discovery is also exposed
  through the API and web UI.
- Exposes category discovery through `GET /api/list-category/<pattern>` and
  embedded web UI category mode.

### Input Modes

- `auto`: classify input as IP, CIDR, domain, then keyword fallback.
- `ipv4`: force IPv4 address or IPv4 CIDR.
- `ipv6`: force IPv6 address or IPv6 CIDR.
- `domain`: force strict domain matching.
- `keyword`: force text search over rule text/value.

CLI flags:

- `-4 VALUE`
- `-6 VALUE`
- `-d VALUE`
- `-k VALUE`

Web/API routes expose the same modes under `/api/find/<mode>/<value>`.

### Supported Database Formats

- MMDB-compatible `.mmdb`, `.metadb`, and compatible `.db` files.
- V2Ray/Xray `.dat` geoip and geosite protobuf databases.
- singgeo geosite `.db` databases.
- sing-box `.srs` binary rule sets.
- mihomo `.mrs` binary rule sets for supported domain and IP CIDR behavior.
- JSON and YAML rule sets:
  - sing-box-style `rules`
  - string or string-array values for known sing-box string-list fields
  - `payload` or `rules` lists
  - string arrays
- Plain `.list` and `.txt` rule files.

### Database Discovery

- A single `-db` file loads only that source.
- A `-db` directory loads supported top-level files as standalone databases.
- Direct child directories are treated as grouped databases.
- Direct files inside grouped directories are grouped sources and appear as
  `folder/file.ext` in output.
- In ruleset listing mode, grouped source filenames or filename stems are the
  ruleset names for uncategorized sparse files.
- If `-db` is omitted, discovery checks the current directory, then the
  executable directory.

### Matching Behavior

- IP queries match containing prefixes and MMDB networks.
- CIDR queries match overlapping prefixes and MMDB networks.
- Domain queries support exact, suffix, keyword, regex, wildcard, and
  AdGuard-like rule forms where the source format exposes them.
- Keyword queries search rule text and rule values, not category names alone.

### CLI Output and JSON Export

- Human-readable stdout is grouped by input and database.
- Match lines are consistently formatted as source, format, category, and rule.
- `geogrep list-rule|lr [--include-mmdb] [-db DB_DIR|DB_FILE] RULESET_NAME
  [...]` lists every rule from exact, case-insensitive ruleset/category names
  across loaded databases.
- `geogrep find-category|fc [--include-mmdb] [-db DB_DIR|DB_FILE]
  CATEGORY_REGEX [...]` lists which loaded databases contain category names
  matching case-insensitive regex patterns.
- `geogrep list-category|lc [--include-mmdb] [-db DB_DIR|DB_FILE]` lists all
  loaded category names.
- `geogrep list-rule --json PATH ...` writes structured list output for
  automation.
- Verbose mode (`-v` or `--verbose`) enables explicit no-match reporting.
- `--json PATH` writes structured metadata, query results, matches, optional
  no-match records, and loader diagnostics.

### Format Conversion

- `geogrep convert -i INPUT -o OUTPUT [--to FORMAT]` transforms loaded rule data
  between supported geodata formats.
- Output format can be inferred from the output extension or forced with
  `--to`.
- Supported output formats include JSON, YAML, list/txt, V2Ray/Xray `.dat`,
  singgeo geosite `.db`, sing-box `.srs`, mihomo `.mrs`, and GeoIP `.mmdb`.
- Conversion preserves categories where the target format has an equivalent
  category or code field.
- Target-specific constraints are explicit: `.dat` cannot mix GeoIP and
  GeoSite payloads, `.mrs` cannot mix domain and IP CIDR behaviors, singgeo is
  domain-only, and MMDB is IP/CIDR-only.

### Web Service

- `geogrep web` starts an HTTP server on `127.0.0.1:8080` by default.
- `GEOGREP_ENV=development` or `GEOGREP_ENV=dev` changes the default web
  listen address to `0.0.0.0:8080` for LAN-visible development.
- `-l`/`--listen` overrides either default listen address.
- API endpoints:
  - `GET /health`
  - `GET /openapi.json`
  - `GET /api/find/auto/<value>`
  - `GET /api/find/ipv4/<IP_or_CIDR>`
  - `GET /api/find/ipv6/<IP_or_CIDR>`
  - `GET /api/find/domain/<domain>`
  - `GET /api/find/keyword/<keyword>`
  - `GET /api/list/<ruleset>` with optional `include_mmdb=true`
  - `GET /api/list-category/<pattern>` with optional `include_mmdb=true`
- `--api-only` disables UI routes.
- `--webui PATH` serves custom static UI files.
- Share routes under `/find/<type>/<value>` redirect to the UI and auto-run
  find-rule mode; `/find/list-rule/<ruleset>` opens list-rule mode, and
  `/find/find-category/<pattern>` opens find-category mode. Legacy
  `/find/list/...` and `/find/list-category/...` routes remain accepted.

### Embedded Web UI

- Dependency-free static UI embedded into the Go binary.
- Kumo-inspired layout with sidebar navigation, page header, compact lookup
  controls, endpoint reference, examples panel, and metrics.
- Runtime version display loaded from the local `/health` endpoint.
- Results render as dense database match rows with badges, expandable overflow,
  copy buttons, and raw JSON inspection.
- List-rule mode uses the same result surface and raw JSON inspection,
  with an MMDB include toggle.
- Find-category mode lists matching database/category names and supports
  share/API URL copy plus raw JSON inspection.
- The UI preserves existing API and share-link behavior.

### Web Hardening and Privacy

- Static asset path traversal guards.
- Encoded slash/backslash and suspicious `..` path blocking.
- Method checks on API and UI routes.
- Request value length limit for API lookups and ruleset listing.
- Security headers including CSP, frame denial, no-sniff, and no-referrer.
- API responses avoid exposing database root paths and loader diagnostics.

### Build and Release Support

- `make build` embeds version, commit, and UTC build timestamp.
- `make all` builds native and Windows amd64 binaries.
- `go test ./...` covers CLI parsing, discovery, loaders, matching, reporting,
  conversion, web API behavior, redirects, and path guards.

## History Summary

The project history is compact and linear:

- `feat: initial geogrep`
  - Introduced the core multi-format lookup engine, CLI, database discovery,
    parsers/loaders, matching, JSON export, version metadata, tests, CI,
    release files, and documentation.
- `refactor: change CLI argument layout`
  - Moved to the current subcommand-oriented CLI shape and standardized
    database discovery behavior.
- `feat: add web subcommand complex and bump version to 0.2.0`
  - Added `geogrep web`, HTTP API, OpenAPI document, health endpoint, embedded
    static UI, API-only mode, share redirects, and the current `find`, `web`,
    `version` command model.
- `refactor: remove database root from responses`
  - Removed local database root paths from JSON/API responses for privacy.
- `refactor: improve webui style`
  - Improved the original embedded UI layout, result grid, expansion controls,
    and copy-link actions.
- `style: enhance web UI`
  - Expanded the UI result layout and folded-match experience.
- `fix: ensure matched lines formatted consistently`
  - Unified CLI and web match-line formatting, especially grouped source
    category handling.
- `chore: add Windows build target`
  - Added Windows amd64 release output to the Makefile.
- `feat: enhance web server security`
  - Hardened path handling, HTTP methods, security headers, cache behavior, and
    API validation.
- `webui: refactor embedded web UI with Kumo-inspired layout`
  - Replaced the older embedded interface with a Kumo-inspired static UI while
    preserving the existing API and share-link behavior.
- `feat: add geodata format conversion`
  - Added `geogrep convert` for transforming loaded rule data into JSON, YAML,
    list/txt, `.dat`, singgeo `.db`, `.srs`, `.mrs`, and `.mmdb` outputs.
- `feat: add ruleset listing`
  - Added `geogrep list`, list JSON export, `GET /api/list/<ruleset>`, web UI
    list mode, case-insensitive ruleset matching, and sparse-file ruleset
    listing semantics.
- `fix: skip MMDB list data by default`
  - Added explicit MMDB/MetaDB opt-in for list output, MMDB-only auto-inclusion,
    compact source-hash-checked list caches, discovery ignores for generated
    caches, and web/API include toggles.
- `feat: add category regex listing`
  - Added `geogrep list-category`, `--json` export, `GET
    /api/list-category/<pattern>`, share redirects, and web UI category mode
    for finding databases and category names by case-insensitive regex pattern.
- `build(release): bump version to 0.3.1`
  - Released loader validation hardening, atomic conversion output replacement,
    improved invalid-rule reporting, AdGuard domain matcher behavior, embedded
    web UI runtime version display, and shared development workflow guidance.

## Non-Goals and Limits

- `geogrep` does not try to exactly emulate every upstream runtime's complete
  rule evaluation model.
- Database discovery intentionally stays shallow and predictable.
- The embedded UI stays static and dependency-free unless the project
  intentionally adopts a frontend build pipeline later.
- Keyword searches can be large because they are designed for broad rule
  inspection.
- Conversion is best-effort across target format capabilities and rejects
  targets that cannot represent the loaded rule mix.
- AdGuard exception rules are not modeled as allow rules during positive match
  reporting.
