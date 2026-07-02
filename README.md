# geogrep

`geogrep` is a unified lookup and inspection tool for geodata databases. It
searches IP, CIDR, domain, and keyword queries across common geoip and geosite
formats, lists ruleset/category contents, then reports exactly which database,
source, category, and rule matched.

Use it when you need to answer questions such as:

- Which geoip or geosite datasets match this IP, CIDR, domain, or keyword?
- What country, category, ASN-like entry, or rule produced the match?
- Which rules are contained in this ruleset/category?
- Do different upstream geodata formats agree for the same lookup?
- Can I expose the same lookup engine through a browser or HTTP API?

## Highlights

- Unified CLI lookup across geoip and geosite-style databases.
- Automatic input classification for IP, CIDR, domain, and keyword values.
- Explicit type forcing with `-4`, `-6`, `-d`, and `-k`.
- Batch lookup while preserving input order.
- Ruleset/category listing through CLI, JSON output, HTTP API, and web UI.
- Regex category discovery through CLI.
- Structured JSON export for automation.
- `convert` subcommand for transforming loaded rule data between supported
  geodata formats.
- Directory-as-database grouping for fragmented rule collections.
- Built-in `web` service with HTTP API, OpenAPI document, share redirects, and
  embedded static UI.
- Kumo-inspired embedded web UI with compact controls, result metrics, match
  rows, copy actions, and raw JSON inspection.
- Security-hardened static file serving and API responses.
- Native Linux/macOS build plus Windows amd64 release target.

For a fuller feature map, see [FEATURES.md](FEATURES.md).

## Quick Start

Prepare a directory of geodata files, then run:

```bash
# Find matching rules in databases in the current directory.
./geogrep find-rule google.com

# Search a prepared database directory.
./geogrep fr -db <dir/to/db> google.com

# Search one database file only.
./geogrep find-rule -db <dir/to/db>/geosite.dat google.com

# Force query types.
./geogrep find-rule -db <dir/to/db> -4 1.1.1.1 -6 2606:4700:4700::1111 -d google.com -k ads

# Mix auto-detected positional inputs.
./geogrep fr -db <dir/to/db> 1.1.1.1 1.1.1.0/24 google.com google

# List every rule from exact ruleset names.
./geogrep list-rule -db <dir/to/db> lan private

# List every category exposed by loaded databases.
./geogrep list-category -db <dir/to/db>

# Find databases and category names matching a regex.
./geogrep find-category -db <dir/to/db> cn

# Include MMDB/MetaDB category names when listing all categories.
./geogrep lc -db <dir/to/db> --include-mmdb

# Include MMDB/MetaDB category names when finding categories.
./geogrep fc -db <dir/to/db> --include-mmdb cn

# Export all loaded categories.
./geogrep lc -db <dir/to/db> --json ./category-list.json

# Export category discovery.
./geogrep find-category -db <dir/to/db> '^cn$' --json ./categories.json

# Export a ruleset listing.
./geogrep lr -db <dir/to/db> cn --json ./list.json

# Export structured results.
./geogrep find-rule -db <dir/to/db> -v google.com --json ./result.json

# Convert a rule file to another supported format.
./geogrep convert -i ./rules.list -o ./rules.json

# Convert with an explicit output format.
./geogrep convert -i ./geosite.dat -o ./geosite.db --to singgeo

# Print binary version metadata.
./geogrep version
```

Start the web UI and API:

```bash
# Production default listens on loopback only.
./geogrep web -db <dir/to/db>

# Development default listens on all interfaces, useful for LAN testing.
GEOGREP_ENV=development ./geogrep web -db <dir/to/db>

# API-only mode disables UI routes.
./geogrep web -db <dir/to/db> --api-only

# Override the listen address explicitly.
./geogrep web -db <dir/to/db> -l 0.0.0.0:8080

# Use a custom static UI directory instead of the embedded UI.
./geogrep web -db <dir/to/db> --webui ./my-webui
```

## CLI Reference

```text
geogrep find-rule|fr [--json RESULT_PATH] [-v|--verbose[=N]] [-db|--database DB_DIR|DB_FILE] \
  [-4 IPv4_OR_CIDR] [-6 IPv6_OR_CIDR6] [-d DOMAIN] [-k KEYWORD] \
  [IP_OR_CIDR_OR_DOMAIN_OR_KEYWORD ...]

geogrep list-rule|lr [--include-mmdb] [--json RESULT_PATH] [-db|--database DB_DIR|DB_FILE] RULESET_NAME [...]

geogrep find-category|fc [--include-mmdb] [--json RESULT_PATH] [-db|--database DB_DIR|DB_FILE] CATEGORY_REGEX [...]

geogrep list-category|lc [--include-mmdb] [--json RESULT_PATH] [-db|--database DB_DIR|DB_FILE]

geogrep convert -i INPUT_PATH -o OUTPUT_PATH [--to FORMAT]

geogrep web [-db|--database DB_DIR|DB_FILE] [-l|--listen IP:PORT] [--webui PATH] \
  [--api-only] [-v|--verbose[=N]]

geogrep version
```

Options:

- `-db PATH`, `--database PATH`: database root directory or single database
  file.
  If omitted, `geogrep` scans the current directory. If that yields no
  supported files, it falls back to the executable directory.
- `--json PATH`: write structured JSON output for `find-rule`, `list-rule`,
  `find-category`, or `list-category`.
- `--include-mmdb`: include MMDB/MetaDB data in `list-rule`, `find-category`,
  or `list-category` output. This is enabled automatically when MMDB/MetaDB is
  the only loaded database type. When enabled, geogrep may create a sibling
  `<filename-stem>.json` category cache with the source file SHA-256, category
  names, and category-to-rule data, and silently skip cache writes on error.
- `-v`, `--verbose`, `--verbose=N`: increase verbosity. Level `>= 1` enables
  explicit per-database no-match records.
- `-4 VALUE`: force IPv4 or IPv4 CIDR parsing.
- `-6 VALUE`: force IPv6 or IPv6 CIDR parsing.
- `-d VALUE`: force domain parsing. Non-domain input is rejected; use `-k` for
  keyword searches.
- `-k VALUE`: force keyword parsing.
- `RULESET_NAME`: exact ruleset/category name to list with `geogrep list-rule`.
  Multiple names can be supplied.
- `CATEGORY_REGEX`: case-insensitive regular expression used by
  `geogrep find-category` to find matching category names. Multiple patterns
  can be supplied.
- `-i PATH`, `--input PATH`: input file or directory for `convert`.
- `-o PATH`, `--output PATH`: output file for `convert`.
- `--to FORMAT`: output format for `convert`. If omitted, the format is
  inferred from the output extension.
- `-l`, `--listen IP:PORT`: listen address for `web` (default
  `127.0.0.1:8080`, or `0.0.0.0:8080` when `GEOGREP_ENV=development` or
  `GEOGREP_ENV=dev`).
- `--webui PATH`: serve static UI files from a directory instead of the embedded
  UI.
- `--api-only`: serve only API endpoints.

## Web UI and API

`geogrep web` loads databases once at startup, then serves lookup and ruleset
listing over HTTP.

By default, `geogrep web` listens on `127.0.0.1:8080`. Set
`GEOGREP_ENV=development` or `GEOGREP_ENV=dev` to default to `0.0.0.0:8080`
for LAN-visible development, or pass `-l/--listen` to choose an explicit
address.

Routes:

- `GET /health`
- `GET /openapi.json`
- `GET /api/find/auto/<value>`
- `GET /api/find/ipv4/<IP_or_CIDR>`
- `GET /api/find/ipv6/<IP_or_CIDR>`
- `GET /api/find/domain/<domain>`
- `GET /api/find/keyword/<keyword>`
- `GET /api/list/<ruleset>`; add `?include_mmdb=true` to include MMDB/MetaDB
  list output when it is not auto-included.
- `GET /api/list-category/<pattern>`; add `?include_mmdb=true` to include
  MMDB/MetaDB category names when they are not auto-included.
- `GET /find/<type>/<value>` redirects to the UI with
  `?mode=find-rule&type=<type>&q=<value>`.
- `GET /find/list-rule/<ruleset>` redirects to the UI with
  `?mode=list-rule&q=<ruleset>`.
- `GET /find/find-category/<pattern>` redirects to the UI with
  `?mode=find-category&q=<pattern>`.
- Legacy share routes `/find/list/<ruleset>` and
  `/find/list-category/<pattern>` redirect to the new UI mode names.

Examples:

```bash
curl "http://127.0.0.1:8080/health"
curl "http://127.0.0.1:8080/openapi.json"
curl "http://127.0.0.1:8080/api/find/auto/1.1.1.1"
curl "http://127.0.0.1:8080/api/find/domain/google.com"
curl "http://127.0.0.1:8080/api/find/ipv4/1.1.1.0/24"
curl "http://127.0.0.1:8080/api/list/cn"
curl "http://127.0.0.1:8080/api/list/cn?include_mmdb=true"
curl "http://127.0.0.1:8080/api/list-category/%5Ecn%24"
curl "http://127.0.0.1:8080/api/list-category/%5Ecn%24?include_mmdb=true"
```

Built-in UI behavior:

- Root `/` serves the embedded static UI unless `--api-only` is set.
- The UI can find matching rules, list rulesets, find category names by regex,
  toggle MMDB output for list modes, copy share/API URLs,
  expand long result groups, and inspect the raw JSON response.
- The UI displays the running geogrep version reported by `/health`.
- Share redirects auto-run the selected find/list mode when opened in a
  browser.
- The embedded UI is dependency-free and lives in
  [internal/geogrep/webui/index.html](internal/geogrep/webui/index.html).

## Conversion

`geogrep convert` loads the same file and directory inputs as lookup, normalizes
their GeoIP and domain rules, and writes a new geodata file.

Output formats:

- `json`, `yaml`: geogrep/sing-box-style source rule sets with preserved
  `category` values.
- `list`, `txt`: plain rule lines.
- `dat`: V2Ray/Xray GeoIP or GeoSite protobuf. Mixed IP and domain output is
  rejected because the upstream schemas are separate.
- `singgeo`: singgeo geosite `.db` output for exact, suffix, keyword, and regex
  domain rules.
- `srs`: sing-box binary rule set output for IP CIDR plus exact, suffix,
  keyword, regex, and AdGuard domain rules.
- `mrs`: mihomo binary rule set output. Domain and IP CIDR behaviors must be
  written separately.
- `mmdb`, `metadb`: generated GeoIP MMDB output for IP/CIDR rules.

Targets reject rule kinds they cannot encode instead of silently writing partial
data.

Compatibility matrix:

| Input format | To JSON/YAML | To list/txt | To `.dat` | To singgeo `.db` | To `.srs` | To `.mrs` | To `.mmdb`/`.metadb` |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `.json`, `.yaml`, `.yml` | Yes | Yes | GeoIP-only or GeoSite-only; exact/suffix/keyword/regex domains | Domain-only; exact/suffix/keyword/regex domains | IP CIDR plus exact/suffix/keyword/regex/AdGuard domains | Domain-only exact/suffix/wildcard or IP CIDR-only | IP/CIDR-only |
| `.list`, `.txt` | Yes | Yes | GeoIP-only or GeoSite-only; exact/suffix/keyword/regex domains | Domain-only; exact/suffix/keyword/regex domains | IP CIDR plus exact/suffix/keyword/regex/AdGuard domains | Domain-only exact/suffix/wildcard or IP CIDR-only | IP/CIDR-only |
| `.dat` | Yes | Yes | Same payload family only; GeoIP and GeoSite stay separate | GeoSite/domain-only; exact/suffix/keyword/regex domains | GeoIP CIDR or GeoSite exact/suffix/keyword/regex domains | GeoIP CIDR-only or GeoSite exact/suffix domains | GeoIP/IP-CIDR-only |
| singgeo `.db` | Yes | Yes | GeoSite/domain-only; exact/suffix/keyword/regex domains | Yes | Exact/suffix/keyword/regex domains | Exact/suffix domains only | No |
| `.srs` | Yes | Yes | GeoIP-only or GeoSite-only; exact/suffix/keyword/regex domains | Domain-only; exact/suffix/keyword/regex domains | Yes | Domain-only exact/suffix or IP CIDR-only | IP/CIDR-only |
| `.mrs` | Yes | Yes | GeoIP-only or GeoSite-only; exact/suffix domains | Domain-only; exact/suffix domains | IP CIDR plus exact/suffix domains | Same behavior only; domain and IP CIDR stay separate | IP/CIDR-only |
| `.mmdb`, `.metadb` | Yes | Yes | GeoIP/IP-CIDR-only | No | IP CIDR only | IP CIDR only | Yes |

`Yes` means all rule kinds currently extracted by `geogrep` for that input are
representable in the target. Constrained cells list the rule families that can
be represented; other loaded rule kinds cause conversion to fail.

Examples:

```bash
./geogrep convert -i ./rules.yaml -o ./rules.srs
./geogrep convert -i ./geoip.dat -o ./geoip.mmdb
./geogrep convert -i ./geosite.dat -o ./geosite.db --to singgeo
```

## Supported Formats

Top-level files under `DB_DIR` and direct child files inside grouped database
folders are supported.

- `.mmdb`, `.metadb`: MMDB-compatible GeoIP lookups.
- `.dat`: V2Ray/Xray protobuf geoip/geosite data.
- `.db`: MMDB-compatible databases, singgeo geosite binary databases, and
  fallback attempts for `.dat`, `.srs`, and `.mrs` payloads.
- `.srs`: sing-box binary rule sets.
- `.mrs`: mihomo binary rule sets for supported domain and IP CIDR behavior.
- `.json`: sing-box-style rule sets, `payload`/`rules` lists, or string arrays.
  Known sing-box string-list fields can be encoded as a string or string array.
- `.yaml`, `.yml`: same supported shapes as JSON.
- `.list`, `.txt`: text rules such as `DOMAIN`, `DOMAIN-SUFFIX`,
  `DOMAIN-KEYWORD`, `DOMAIN-REGEX`, `DOMAIN-WILDCARD`, `IP-CIDR`, and plain
  domain/prefix/keyword lines.

## Input and Matching Semantics

Automatic classification order:

1. IP address
2. CIDR prefix
3. domain
4. keyword fallback

Matching behavior:

- IP queries match geoip prefixes or MMDB networks that contain the IP.
- CIDR queries match overlapping prefixes or networks.
- Domain queries match exact, suffix, keyword, regex, wildcard, and
  AdGuard-like domain rules where supported by the source format.
- Keyword queries match rule text or normalized rule value. They do not match
  solely by sub-entry/category name.

## Database Discovery

When `-db` points to a directory:

- Supported files directly under that directory become standalone databases.
- Each direct child directory becomes one grouped database.
- Supported files directly inside a child directory become grouped sources.
- Nested directories below a grouped database are not scanned.

When `-db` points to a file:

- Only that single supported file is loaded.

## Output

Stdout output includes, for each input:

- the normalized query kind
- each matched database and match count
- match lines formatted as `source | format | category | rule`
- optional no-match lines when verbosity is enabled

`geogrep list-rule` prints each requested ruleset, grouped by matching database.
Rulesets are matched by full loaded GeoIP/geosite category name,
case-insensitively, so `cn` matches `CN`. Uncategorized sparse files use the
source filename or filename stem as the ruleset name, while the containing
directory remains the database. MMDB/MetaDB sources are skipped unless
`--include-mmdb` is set or MMDB/MetaDB is the only loaded database type.

`geogrep list-category` prints all loaded category names, grouped by matching
database, then lists `source | format | category` rows. It supports automatic
database discovery, explicit `-db/--database` selection, `--include-mmdb`, and
`--json`. JSON export includes metadata and a top-level `categories` array.

`geogrep find-category` prints each requested regex pattern, grouped by
matching database, then lists `source | format | category` rows. Regex matching
is case-insensitive by default, so `cn` matches both `CN` and names such as
`apple-cn`. MMDB/MetaDB category names are skipped unless `--include-mmdb` is
set or MMDB/MetaDB is the only loaded database type. When a valid MMDB/MetaDB
list cache includes `category_names`, category discovery reads that compact key
directly instead of loading category-to-rule data or walking every MMDB network.
Find-category JSON export includes metadata and one result object per requested
pattern, with each category carrying database, source, format, and category
fields.

JSON export includes:

- metadata (`generated_at`, database count, query count, no-match reporting
  mode, executable-directory fallback flag)
- per-input results in original input order
- per-database matches and optional no-match records
- loader diagnostics from partial parse failures

List JSON export includes metadata and one result object per requested ruleset,
with each listed rule carrying database, source, format, ruleset, and rule
fields.

API responses use the same export document shape but intentionally omit database
root paths and loader diagnostics to avoid leaking local runtime details.

## Build and Test

```bash
# Build with default go build metadata.
go build -o geogrep ./cmd/geogrep

# Build with VERSION, git commit, and UTC build timestamp embedded.
make build

# Build native binary plus Windows amd64 binary.
make all

# Run tests.
go test ./...

# Format Go code.
make fmt

# Print the release version.
make version
```

## Project Layout

```text
.
├── cmd/geogrep/             # CLI entrypoint
├── internal/geogrep/        # Core implementation, parsers, matcher, reporting, web server
├── internal/geogrep/webui/  # Embedded static web UI
├── .github/workflows/       # CI workflow
├── VERSION                  # Current release version
├── CHANGELOG.md             # Release notes
├── FEATURES.md              # Feature catalog and history summary
├── AGENTS.md                # Contributor/agent working notes
├── DEVELOPMENT.md           # Development workflow and commit guidance
├── README.md
├── CONTRIBUTING.md
├── CONTRIBUTORS.md
├── SECURITY.md
└── Makefile
```

## Versioning

The release version is tracked in [VERSION](VERSION). Release builds embed:

- version
- short git commit
- UTC build timestamp

Inspect metadata with:

```bash
./geogrep version
```

## Known Limitations

- MRS classical behavior is not fully decoded.
- Rule behavior can vary across upstream runtimes and formats.
- AdGuard exception rules are ignored during positive match reporting.
- Large keyword searches may intentionally produce large outputs.
- Database discovery scans only the configured root and one grouped directory
  level.

## License

This repository is distributed under GNU GPL v3.0 or later. See
[LICENSE](LICENSE).

## Contributors

See [CONTRIBUTORS.md](CONTRIBUTORS.md).

Main implementation contributor: GitHub Copilot (GPT-5.3-Codex).
