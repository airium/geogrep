# geogrep

A unified lookup CLI for geodata ecosystem, supporting multiple geodata formats.

`geogrep` helps you quickly answer questions like:
- Which geoip/geosite datasets match this IP or CIDR?
- What is the geo country/category/ASN for this IP or CIDR?
- Which geosite entries exactly match this domain?
- Which geosite entries contain this domain keyword?

## Why geogrep

There are many geodata formats, but the lookup tooling is often format-specific.
`geogrep` scans all such datasets in one pass and reports exact match provenance:
- database file or grouped database folder
- matched sub-entry (country/category/ASN-like identity)
- exact rule or network CIDR that produced the match

## Features

- Unified lookup across geoip and geosite-style databases
- Input auto-detection for IP, CIDR, domain, and keyword
- Explicit type forcing with `-4`, `-6`, `-d`, `-k`
- Git-like subcommands: `find`, `web`, `version`
- Batch lookups in one command while preserving input order
- Concurrent processing for speed
- Structured JSON export via `--json`
- Verbose levels via `-v/--verbose` (`level >= 1` enables explicit no-match reporting)
- Directory-as-database mode for fragmented datasets
- Built-in web interface and HTTP API for browser and service use

## Usage examples

You should first prepare some databases at <dir/to/db> or just under the current directory. Then you can run commands like:

```bash
# Domain lookup (assume databases at the current directory)
./geogrep find google.com

# Keyword lookup (explicit)
./geogrep find -db <dir/to/db> -k google

# Lookup in only one specific database file
./geogrep find -db <dir/to/db>/geosite.dat google.com

# Mixed explicit inputs with JSON export
./geogrep find -db <dir/to/db> -v -4 1.1.1.1 -6 2404:6800:4008::200e -d google.com -k ads \
  --json ./result.json

# Auto detection for mixed positional inputs
./geogrep find -db <dir/to/db> 1.1.1.1 1.1.1.0/24 google.com google

# Print binary version information
./geogrep version

# Start web service with embedded UI
./geogrep web -db <dir/to/db> -l 0.0.0.0:8080

# API-only mode (no UI routes)
./geogrep web -db <dir/to/db> --api-only

# Override embedded UI with a custom static directory
./geogrep web -db <dir/to/db> --webui ./my-webui
```

## CLI

```text
geogrep find [--json RESULT_PATH] [-v|--verbose[=N]] [-db DB_DIR|DB_FILE] \
  [-4 IPv4/CIDR] [-6 IPv6/CIDR6] [-d DOMAIN] [-k KEYWORD] \
  IPv4/CIDR/IPv6/CIDR6/DOMAIN/KEYWORD [...]

geogrep web [-db DB_DIR|DB_FILE] [-l|--listen IP:PORT] [--webui PATH] [--api-only] \
  [-v|--verbose[=N]]

geogrep version
```

- `-db PATH`, `--database PATH`: Database root directory or single database file path.
  - If omitted, geogrep scans current directory.
  - If nothing supported is found, it falls back to executable directory.
- `--json PATH`: Export structured results to JSON.
- `-v`, `--verbose`, `--verbose=N`: Increase verbosity for `find`.
  - Verbose level `>= 1` enables explicit per-input x per-database no-match reporting.
- `-4 VALUE`: Force input to IPv4/CIDR4.
- `-6 VALUE`: Force input to IPv6/CIDR6.
- `-d VALUE`: Force input to domain. This is strict and rejects non-domain values.
- `-k VALUE`: Force input to keyword.
- `-l`, `--listen`: Listen address for `web` (default: `0.0.0.0:8080`).
- `--webui PATH`: Use custom static files directory instead of embedded UI.
- `--api-only`: Disable UI routes and serve only API endpoints.

## Web and API

`geogrep web` loads the databases once, then serves lookup APIs over HTTP.

API endpoints:
- `GET /health`
- `GET /openapi.json`
- `GET /api/find/auto/<any>`
- `GET /api/find/ipv4/<IP_or_CIDR>`
- `GET /api/find/ipv6/<IP_or_CIDR>`
- `GET /api/find/domain/<domain>`
- `GET /api/find/keyword/<keyword>`

Built-in UI behavior:
- Root `/` serves embedded static web UI (unless `--api-only` is used).
- Share links like `/find/auto/google.com` redirect to `/` with query parameters.
- The UI auto-runs lookup when opened from redirected share links.

Examples:

```bash
curl "http://127.0.0.1:8080/health"
curl "http://127.0.0.1:8080/openapi.json"
curl "http://127.0.0.1:8080/api/find/auto/1.1.1.1"
curl "http://127.0.0.1:8080/api/find/domain/google.com"
curl "http://127.0.0.1:8080/api/find/ipv4/1.1.1.0/24"
```

## Supported formats

Top-level files and direct child files under `DB_DIR` are supported.

- `mmdb` and `metadb` (GeoIP-like lookups)
- `dat` (V2Ray/Xray protobuf geoip/geosite)
- `db`
  - MMDB-compatible databases
  - singgeo geosite binary databases (for example `geosite.db`)
  - fallback attempts for `dat`, `srs`, `mrs`
- `srs` (sing-box ruleset binary)
- `mrs` (mihomo ruleset binary; domain and ipcidr behaviors)
- `json`
- `yaml` / `yml`
- `list` / `txt`


### Input behavior

Automatic classification order:
1. IP address
2. CIDR
3. domain
4. keyword fallback

Forced flags override auto-detection.

## Matching semantics

- IP query:
  - matches geoip prefixes containing the IP
  - matches MMDB network containing the IP
- CIDR query:
  - matches any overlapping (intersecting) prefix/network
- Domain query:
  - exact, suffix, keyword, regex, wildcard, adguard-like forms (format dependent)
- Keyword query:
  - matches only when the keyword appears in the rule text or rule value
  - does not match only by sub-entry name

## Database discovery model

Given `DB_DIR`:
- all supported files directly under `DB_DIR` are treated as standalone databases
- each direct child folder is treated as one grouped database
  - supported files directly inside the child folder are loaded as grouped sources
  - output source path appears as `folder/file.ext`

Given `DB_FILE` (when `-db` points to a file):
- only that single file is used as the lookup database source

## Output

### Stdout

For each input:
- matched databases and match counts
- each match line includes source, format, sub-entry, and matched rule
- optional no-match lines when verbose level is `>= 1`

### JSON export

When `--json <path/to/output.json>` is provided, geogrep writes:
- metadata block (time, db root, query count, and no-match reporting mode)
- per-input results in original input order
- per-database matches or no-match records
- loader diagnostics (for partial parse failures)

## Project layout

```text
.
├── cmd/geogrep/             # CLI entrypoint
├── internal/geogrep/        # Core implementation, parsers, matcher, reporting
├── .github/workflows/       # CI workflow
├── VERSION                  # Current release version
├── CHANGELOG.md             # Release notes
├── README.md
├── CONTRIBUTING.md
├── CONTRIBUTORS.md
├── SECURITY.md
└── Makefile
```

## Build and test

```bash
# Build
go build -o geogrep ./cmd/geogrep

# Build with embedded release metadata from VERSION
make build

# Test
go test ./...

# Print current release version from VERSION file
make version
```

## Versioning and release metadata

- The release version is tracked in [VERSION](VERSION).
- Build-time metadata is embedded into the binary:
  - version
  - commit
  - UTC build timestamp
- You can inspect binary metadata with:

```bash
./geogrep version
```

## Known limitations

- MRS classical behavior is not decoded yet.
- Rule semantics vary by upstream format and may not be perfectly identical to every runtime core.
- Very large keyword searches can produce large outputs by design.

## License

This repository is distributed under GNU GPL v3.0 or later.
See [LICENSE](LICENSE).

## Contributors

See [CONTRIBUTORS.md](CONTRIBUTORS.md).

Main implementation contributor: GitHub Copilot (GPT-5.3-Codex).
