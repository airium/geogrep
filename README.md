# geogrep

A unified geodata lookup CLI for proxy ecosystems.

`geogrep` helps you quickly answer questions like:
- Which geoip/geosite datasets match this IP or CIDR?
- Which rule entries match this domain?
- Which rule lines contain this keyword?

It supports mixed geodata formats used by Mihomo, sing-box, Xray, and V2Ray workflows.

## Why geogrep

Proxy cores rely on many geodata sources, but lookup tooling is often fragmented by format.
`geogrep` scans local datasets in one pass and reports exact match provenance:
- database file or grouped database folder
- matched sub-entry (country/category/ASN-like identity)
- exact rule or network that produced the match

## Features

- Unified lookup across geoip and geosite-style databases
- Input auto-detection for IP, CIDR, domain, and keyword
- Explicit type forcing with `-4`, `-6`, `-d`, `-k`
- Batch lookups in one command while preserving input order
- Concurrent processing for speed
- Structured JSON export via `--json`
- Explicit no-match reporting with `--report-empty`
- Directory-as-database mode for fragmented datasets

## Project layout

```text
.
├── cmd/geogrep/            # CLI entrypoint
├── internal/geogrep/       # Core implementation, parsers, matcher, reporting
├── .github/workflows/      # CI workflow
├── VERSION                  # Current release version
├── CHANGELOG.md             # Release notes
├── README.md
├── CONTRIBUTING.md
├── CONTRIBUTORS.md
├── SECURITY.md
└── Makefile
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
- `mrs` (Mihomo ruleset binary; domain and ipcidr behaviors)
- `json`
- `yaml` / `yml`
- `list` / `txt`

## CLI

```text
geogrep [--report-empty] [--json RESULT_PATH] [-db DB_DIR] \
  [-4 IPv4/CIDR] [-6 IPv6/CIDR6] [-d DOMAIN] [-k KEYWORD] \
  IPv4/CIDR/IPv6/CIDR6/DOMAIN/KEYWORD [...]

geogrep -v/--version
```

### Flags

- `-db PATH`: Database root directory.
  - If omitted, geogrep scans current directory.
  - If nothing supported is found, it falls back to executable directory.
- `--report-empty`: Include explicit per-input x per-database no-match records.
- `--json PATH`: Export structured results to JSON.
- `-4 VALUE`: Force input to IPv4/CIDR4.
- `-6 VALUE`: Force input to IPv6/CIDR6.
- `-d VALUE`: Force input to domain. This is strict and rejects non-domain values.
- `-k VALUE`: Force input to keyword.
- `--version`, `-v`: Print binary version, commit, and build timestamp.

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

## Output

### Stdout

For each input:
- matched databases and match counts
- each match line includes source, format, sub-entry, and matched rule
- optional no-match lines when `--report-empty` is enabled

### JSON export

When `--json` is provided, geogrep writes:
- metadata block (time, db root, query count, report-empty mode)
- per-input results in original input order
- per-database matches or no-match records
- loader diagnostics (for partial parse failures)

## Usage examples

You should first prepare some databases at <dir/to/db> or just under the current directory. Then you can run commands like:

```bash
# Domain lookup
./geogrep -db <dir/to/db> google.com

# Keyword lookup (explicit)
./geogrep -db <dir/to/db> -k google

# Mixed explicit inputs with JSON export
./geogrep -db <dir/to/db> -4 1.1.1.1 -6 2404:6800:4008::200e -d google.com -k ads \
  --report-empty --json ./result.json

# Auto detection for mixed positional inputs
./geogrep -db <dir/to/db> 1.1.1.1 1.1.1.0/24 google.com google
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
./geogrep --version
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
