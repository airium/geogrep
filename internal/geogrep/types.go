package geogrep

import (
	"net/netip"
	"regexp"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
)

type QueryKind string

const (
	QueryIP      QueryKind = "ip"
	QueryCIDR    QueryKind = "cidr"
	QueryDomain  QueryKind = "domain"
	QueryKeyword QueryKind = "keyword"
)

type ForceKind string

const (
	ForceAuto    ForceKind = "auto"
	ForceIPv4    ForceKind = "ipv4"
	ForceIPv6    ForceKind = "ipv6"
	ForceDomain  ForceKind = "domain"
	ForceKeyword ForceKind = "keyword"
)

type RawInput struct {
	Value string
	Force ForceKind
}

type Query struct {
	Index      int       `json:"index"`
	Raw        string    `json:"raw"`
	Normalized string    `json:"normalized"`
	Kind       QueryKind `json:"kind"`

	IP     netip.Addr   `json:"-"`
	Prefix netip.Prefix `json:"-"`
}

type CLIConfig struct {
	Command     string
	DBDir       string
	JSONPath    string
	ConvertIn   string
	ConvertOut  string
	ConvertTo   string
	Rulesets    []string
	ReportEmpty bool
	IncludeMMDB bool
	Verbose     int
	ListenAddr  string
	WebUIPath   string
	APIOnly     bool
	Inputs      []RawInput
}

type DiscoveryResult struct {
	RootDir    string
	Databases  []DiscoveredDatabase
	FromExeDir bool
}

type DiscoveredDatabase struct {
	Name    string
	Sources []DiscoveredSource
}

type DiscoveredSource struct {
	Display string
	Path    string
}

type LoadedDatabase struct {
	Name    string
	Sources []LoadedSource
}

type LoadedSource struct {
	Display    string
	Path       string
	Format     string
	GeoIPRules []GeoIPRule
	DomainRule []DomainRule
	MMDB       *MMDBSource

	Warnings []Diagnostic
}

type MMDBSource struct {
	Reader *maxminddb.Reader
}

type GeoIPRule struct {
	SubEntry string
	Rule     string
	Prefix   netip.Prefix
}

type DomainRuleKind string

const (
	DomainExact    DomainRuleKind = "exact"
	DomainSuffix   DomainRuleKind = "suffix"
	DomainKeyword  DomainRuleKind = "keyword"
	DomainRegex    DomainRuleKind = "regex"
	DomainWildcard DomainRuleKind = "wildcard"
	DomainAdGuard  DomainRuleKind = "adguard"
)

type DomainRule struct {
	SubEntry string
	Rule     string
	Kind     DomainRuleKind
	Value    string
	Regex    *regexp.Regexp
}

type Diagnostic struct {
	Level   string `json:"level"`
	Scope   string `json:"scope"`
	Message string `json:"message"`
}

type MatchRecord struct {
	Database string         `json:"database"`
	Source   string         `json:"source"`
	Format   string         `json:"format"`
	SubEntry string         `json:"sub_entry,omitempty"`
	Rule     string         `json:"rule"`
	Detail   map[string]any `json:"detail,omitempty"`
}

type DatabaseResult struct {
	Database string        `json:"database"`
	Matched  bool          `json:"matched"`
	Matches  []MatchRecord `json:"matches,omitempty"`
}

type QueryResult struct {
	Query          Query            `json:"query"`
	DatabaseResult []DatabaseResult `json:"database_results"`
}

type ExportMetadata struct {
	GeneratedAt    time.Time `json:"generated_at"`
	DatabaseCount  int       `json:"database_count"`
	QueryCount     int       `json:"query_count"`
	ReportEmpty    bool      `json:"report_empty"`
	UsedExecutable bool      `json:"used_executable_dir_fallback"`
}

type ExportDocument struct {
	Metadata    ExportMetadata `json:"metadata"`
	Results     []QueryResult  `json:"results"`
	Diagnostics []Diagnostic   `json:"diagnostics,omitempty"`
}
