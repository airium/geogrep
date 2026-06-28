package geogrep

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/metacubex/geo/encoding/v2raygeo"
	"github.com/oschwald/maxminddb-golang/v2"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"
)

type singRuleSet struct {
	Version int            `json:"version" yaml:"version"`
	Rules   []singRuleNode `json:"rules" yaml:"rules"`
}

type singRuleNode struct {
	Type           string         `json:"type" yaml:"type"`
	Category       string         `json:"category" yaml:"category"`
	Domain         []string       `json:"domain" yaml:"domain"`
	DomainSuf      []string       `json:"domain_suffix" yaml:"domain_suffix"`
	DomainKey      []string       `json:"domain_keyword" yaml:"domain_keyword"`
	DomainRegex    []string       `json:"domain_regex" yaml:"domain_regex"`
	DomainWildcard []string       `json:"domain_wildcard" yaml:"domain_wildcard"`
	AdGuardDomain  []string       `json:"adguard_domain" yaml:"adguard_domain"`
	IPCIDR         []string       `json:"ip_cidr" yaml:"ip_cidr"`
	SourceCIDR     []string       `json:"source_ip_cidr" yaml:"source_ip_cidr"`
	Rules          []singRuleNode `json:"rules" yaml:"rules"`
}

type listPayload struct {
	Payload []string `json:"payload" yaml:"payload"`
	Rules   []string `json:"rules" yaml:"rules"`
}

func loadDatabases(discovery DiscoveryResult) ([]LoadedDatabase, []Diagnostic) {
	loaded := make([]LoadedDatabase, 0, len(discovery.Databases))
	diagnostics := make([]Diagnostic, 0)

	for _, db := range discovery.Databases {
		ldb := LoadedDatabase{Name: db.Name}
		for _, src := range db.Sources {
			loadedSource, sourceDiagnostics := loadSource(src)
			if len(sourceDiagnostics) > 0 {
				diagnostics = append(diagnostics, sourceDiagnostics...)
			}
			ldb.Sources = append(ldb.Sources, loadedSource)
		}
		loaded = append(loaded, ldb)
	}

	return loaded, diagnostics
}

func closeDatabases(databases []LoadedDatabase) {
	for _, db := range databases {
		for _, src := range db.Sources {
			if src.MMDB != nil && src.MMDB.Reader != nil {
				_ = src.MMDB.Reader.Close()
			}
		}
	}
}

func loadSource(src DiscoveredSource) (LoadedSource, []Diagnostic) {
	loaded := LoadedSource{Display: src.Display, Path: src.Path}
	diagnostics := make([]Diagnostic, 0)

	ext := strings.ToLower(filepath.Ext(src.Path))
	switch ext {
	case ".mmdb", ".metadb":
		if err := loadMMDB(&loaded); err != nil {
			diagnostics = append(diagnostics, Diagnostic{Level: "error", Scope: src.Display, Message: err.Error()})
		}
	case ".dat":
		if err := loadDAT(&loaded); err != nil {
			diagnostics = append(diagnostics, Diagnostic{Level: "error", Scope: src.Display, Message: err.Error()})
		}
	case ".srs":
		if err := loadSRS(&loaded); err != nil {
			diagnostics = append(diagnostics, Diagnostic{Level: "error", Scope: src.Display, Message: err.Error()})
		}
	case ".mrs":
		if err := loadMRS(&loaded); err != nil {
			diagnostics = append(diagnostics, Diagnostic{Level: "error", Scope: src.Display, Message: err.Error()})
		}
	case ".json":
		if err := loadJSONRules(&loaded); err != nil {
			diagnostics = append(diagnostics, Diagnostic{Level: "error", Scope: src.Display, Message: err.Error()})
		}
	case ".yaml", ".yml":
		if err := loadYAMLRules(&loaded); err != nil {
			diagnostics = append(diagnostics, Diagnostic{Level: "error", Scope: src.Display, Message: err.Error()})
		}
	case ".list", ".txt":
		if err := loadTextRules(&loaded); err != nil {
			diagnostics = append(diagnostics, Diagnostic{Level: "error", Scope: src.Display, Message: err.Error()})
		}
	case ".db":
		if err := loadDBCompatibility(&loaded); err != nil {
			diagnostics = append(diagnostics, Diagnostic{Level: "error", Scope: src.Display, Message: err.Error()})
		}
	default:
		diagnostics = append(diagnostics, Diagnostic{Level: "warning", Scope: src.Display, Message: "unsupported file extension"})
	}

	return loaded, diagnostics
}

func loadDBCompatibility(source *LoadedSource) error {
	if err := loadMMDB(source); err == nil {
		return nil
	}
	if err := loadSingGeoSite(source); err == nil {
		return nil
	}
	if err := loadDAT(source); err == nil {
		return nil
	}
	if err := loadSRS(source); err == nil {
		return nil
	}
	if err := loadMRS(source); err == nil {
		return nil
	}
	return fmt.Errorf("failed to parse .db file as mmdb/singgeo/dat/srs/mrs")
}

type singGeoSiteIndex struct {
	code   string
	index  uint64
	length uint64
}

func loadSingGeoSite(source *LoadedSource) error {
	content, err := os.ReadFile(source.Path)
	if err != nil {
		return err
	}

	reader := bytes.NewReader(content)
	version, err := reader.ReadByte()
	if err != nil {
		return err
	}
	if version != 0 {
		return errors.New("invalid singgeo version")
	}

	entryLength, err := readUvarint(reader)
	if err != nil {
		return err
	}
	if entryLength == 0 {
		return errors.New("empty singgeo entries")
	}

	indices := make([]singGeoSiteIndex, 0, entryLength)
	for i := uint64(0); i < entryLength; i++ {
		code, err := readVString(reader)
		if err != nil {
			return err
		}
		index, err := readUvarint(reader)
		if err != nil {
			return err
		}
		length, err := readUvarint(reader)
		if err != nil {
			return err
		}
		indices = append(indices, singGeoSiteIndex{code: strings.ToLower(code), index: index, length: length})
	}

	metadataEnd, err := reader.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	if metadataEnd < 0 || metadataEnd > int64(len(content)) {
		return errors.New("invalid singgeo metadata offset")
	}

	loadedAny := false
	for _, idx := range indices {
		if idx.length == 0 {
			continue
		}
		start := metadataEnd + int64(idx.index)
		if start < metadataEnd || start >= int64(len(content)) {
			continue
		}
		entryReader := bytes.NewReader(content[start:])
		for i := uint64(0); i < idx.length; i++ {
			typeByte, err := entryReader.ReadByte()
			if err != nil {
				return err
			}
			value, err := readVString(entryReader)
			if err != nil {
				return err
			}
			value = strings.ToLower(strings.TrimSpace(value))
			if value == "" {
				continue
			}

			switch typeByte {
			case 0:
				appendDomainRule(source, idx.code, "exact:"+value, DomainExact, value)
				loadedAny = true
			case 1:
				suffix := strings.TrimPrefix(value, ".")
				appendDomainRule(source, idx.code, "suffix:"+suffix, DomainSuffix, suffix)
				loadedAny = true
			case 2:
				appendDomainRule(source, idx.code, "keyword:"+value, DomainKeyword, value)
				loadedAny = true
			case 3:
				appendDomainRule(source, idx.code, "regex:"+value, DomainRegex, value)
				loadedAny = true
			}
		}
	}

	if !loadedAny {
		return errors.New("not a valid singgeo geosite database")
	}

	source.Format = "singgeo"
	return nil
}

func readUvarint(reader *bytes.Reader) (uint64, error) {
	return binary.ReadUvarint(reader)
}

func readVString(reader *bytes.Reader) (string, error) {
	strLen, err := readUvarint(reader)
	if err != nil {
		return "", err
	}
	if strLen == 0 {
		return "", nil
	}
	buf := make([]byte, strLen)
	if _, err := io.ReadFull(reader, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

func loadMMDB(source *LoadedSource) error {
	reader, err := maxminddb.Open(source.Path)
	if err != nil {
		return err
	}
	source.MMDB = &MMDBSource{Reader: reader}
	source.Format = "mmdb"
	return nil
}

func loadDAT(source *LoadedSource) error {
	bytes, err := os.ReadFile(source.Path)
	if err != nil {
		return err
	}

	loadedAny := false

	var ipList v2raygeo.GeoIPList
	if err := proto.Unmarshal(bytes, &ipList); err == nil && len(ipList.GetEntry()) > 0 {
		for _, entry := range ipList.GetEntry() {
			sub := strings.ToUpper(strings.TrimSpace(entry.GetCountryCode()))
			for _, cidr := range entry.GetCidr() {
				prefix, ok := prefixFromV2RayCIDR(cidr)
				if !ok {
					continue
				}
				source.GeoIPRules = append(source.GeoIPRules, GeoIPRule{
					SubEntry: sub,
					Rule:     prefix.String(),
					Prefix:   prefix,
				})
			}
		}
		loadedAny = true
	}

	var siteList v2raygeo.GeoSiteList
	if err := proto.Unmarshal(bytes, &siteList); err == nil && len(siteList.GetEntry()) > 0 {
		for _, site := range siteList.GetEntry() {
			sub := strings.ToLower(strings.TrimSpace(site.GetCountryCode()))
			for _, domain := range site.GetDomain() {
				ruleKind, value := mapV2RayDomain(domain.GetType(), domain.GetValue())
				if ruleKind == "" || value == "" {
					continue
				}
				appendDomainRule(source, sub, fmt.Sprintf("%s:%s", ruleKind, value), ruleKind, value)
			}
		}
		loadedAny = true
	}

	if !loadedAny {
		return errors.New("not a valid geosite.dat/geoip.dat protobuf payload")
	}

	source.Format = "dat"
	return nil
}

func loadJSONRules(source *LoadedSource) error {
	bytes, err := os.ReadFile(source.Path)
	if err != nil {
		return err
	}

	var set singRuleSet
	if err := json.Unmarshal(bytes, &set); err == nil && len(set.Rules) > 0 {
		for i, rule := range set.Rules {
			extractSingRuleNode(source, rule, fmt.Sprintf("rule[%d]", i))
		}
		source.Format = "json"
		return nil
	}

	var payload listPayload
	if err := json.Unmarshal(bytes, &payload); err == nil && (len(payload.Payload) > 0 || len(payload.Rules) > 0) {
		for _, line := range append(payload.Payload, payload.Rules...) {
			parseTextLine(source, line, "")
		}
		source.Format = "json"
		return nil
	}

	var arr []string
	if err := json.Unmarshal(bytes, &arr); err == nil && len(arr) > 0 {
		for _, line := range arr {
			parseTextLine(source, line, "")
		}
		source.Format = "json"
		return nil
	}

	return errors.New("unsupported JSON ruleset shape")
}

func loadYAMLRules(source *LoadedSource) error {
	bytes, err := os.ReadFile(source.Path)
	if err != nil {
		return err
	}

	var set singRuleSet
	if err := yaml.Unmarshal(bytes, &set); err == nil && len(set.Rules) > 0 {
		for i, rule := range set.Rules {
			extractSingRuleNode(source, rule, fmt.Sprintf("rule[%d]", i))
		}
		source.Format = "yaml"
		return nil
	}

	var payload listPayload
	if err := yaml.Unmarshal(bytes, &payload); err == nil && (len(payload.Payload) > 0 || len(payload.Rules) > 0) {
		for _, line := range append(payload.Payload, payload.Rules...) {
			parseTextLine(source, line, "")
		}
		source.Format = "yaml"
		return nil
	}

	var arr []string
	if err := yaml.Unmarshal(bytes, &arr); err == nil && len(arr) > 0 {
		for _, line := range arr {
			parseTextLine(source, line, "")
		}
		source.Format = "yaml"
		return nil
	}

	return errors.New("unsupported YAML ruleset shape")
}

func loadTextRules(source *LoadedSource) error {
	bytes, err := os.ReadFile(source.Path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(bytes), "\n")
	for _, line := range lines {
		parseTextLine(source, line, "")
	}
	source.Format = strings.TrimPrefix(strings.ToLower(filepath.Ext(source.Path)), ".")
	return nil
}

func extractSingRuleNode(source *LoadedSource, node singRuleNode, sub string) {
	if category := strings.TrimSpace(node.Category); category != "" {
		sub = category
	}
	for _, domain := range node.Domain {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain != "" {
			appendDomainRule(source, sub, "domain:"+domain, DomainExact, domain)
		}
	}
	for _, suffix := range node.DomainSuf {
		suffix = strings.ToLower(strings.TrimSpace(suffix))
		if suffix != "" {
			appendDomainRule(source, sub, "domain_suffix:"+suffix, DomainSuffix, strings.TrimPrefix(suffix, "."))
		}
	}
	for _, keyword := range node.DomainKey {
		keyword = strings.ToLower(strings.TrimSpace(keyword))
		if keyword != "" {
			appendDomainRule(source, sub, "domain_keyword:"+keyword, DomainKeyword, keyword)
		}
	}
	for _, expr := range node.DomainRegex {
		expr = strings.TrimSpace(expr)
		if expr != "" {
			appendDomainRule(source, sub, "domain_regex:"+expr, DomainRegex, expr)
		}
	}
	for _, wildcard := range node.DomainWildcard {
		wildcard = strings.ToLower(strings.TrimSpace(wildcard))
		if wildcard != "" {
			appendDomainRule(source, sub, "domain_wildcard:"+wildcard, DomainWildcard, wildcard)
		}
	}
	for _, adguard := range node.AdGuardDomain {
		adguard = strings.TrimSpace(adguard)
		if adguard != "" {
			appendDomainRule(source, sub, "adguard:"+adguard, DomainAdGuard, adguard)
		}
	}
	for _, cidr := range append(node.IPCIDR, node.SourceCIDR...) {
		prefix, err := parseFlexiblePrefix(cidr)
		if err != nil {
			continue
		}
		source.GeoIPRules = append(source.GeoIPRules, GeoIPRule{SubEntry: sub, Rule: prefix.String(), Prefix: prefix})
	}
	for idx, child := range node.Rules {
		extractSingRuleNode(source, child, fmt.Sprintf("%s/rule[%d]", sub, idx))
	}
}

func parseTextLine(source *LoadedSource, line, subEntry string) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
		return
	}

	parts := splitRuleLine(line)
	if len(parts) >= 2 {
		ruleType := strings.ToUpper(strings.TrimSpace(parts[0]))
		payload := strings.TrimSpace(parts[1])
		if payload == "" {
			return
		}
		switch ruleType {
		case "DOMAIN":
			appendDomainRule(source, subEntry, line, DomainExact, strings.ToLower(payload))
			return
		case "DOMAIN-SUFFIX":
			appendDomainRule(source, subEntry, line, DomainSuffix, strings.TrimPrefix(strings.ToLower(payload), "."))
			return
		case "DOMAIN-KEYWORD":
			appendDomainRule(source, subEntry, line, DomainKeyword, strings.ToLower(payload))
			return
		case "DOMAIN-REGEX":
			appendDomainRule(source, subEntry, line, DomainRegex, payload)
			return
		case "DOMAIN-WILDCARD":
			appendDomainRule(source, subEntry, line, DomainWildcard, strings.ToLower(payload))
			return
		case "IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR", "SRC-IP-CIDR6":
			prefix, err := parseFlexiblePrefix(payload)
			if err == nil {
				source.GeoIPRules = append(source.GeoIPRules, GeoIPRule{SubEntry: subEntry, Rule: line, Prefix: prefix})
			}
			return
		}
	}

	if prefix, err := parseFlexiblePrefix(line); err == nil {
		source.GeoIPRules = append(source.GeoIPRules, GeoIPRule{SubEntry: subEntry, Rule: line, Prefix: prefix})
		return
	}

	lower := strings.ToLower(line)
	if strings.HasPrefix(lower, ".") {
		appendDomainRule(source, subEntry, line, DomainSuffix, strings.TrimPrefix(lower, "."))
		return
	}
	if strings.ContainsAny(lower, "*?") {
		appendDomainRule(source, subEntry, line, DomainWildcard, lower)
		return
	}
	if isLikelyDomain(lower) {
		appendDomainRule(source, subEntry, line, DomainExact, strings.TrimSuffix(lower, "."))
		return
	}
	appendDomainRule(source, subEntry, line, DomainKeyword, lower)
}

func splitRuleLine(line string) []string {
	parts := strings.Split(line, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func appendDomainRule(source *LoadedSource, subEntry, raw string, kind DomainRuleKind, value string) {
	r := DomainRule{
		SubEntry: strings.TrimSpace(subEntry),
		Rule:     strings.TrimSpace(raw),
		Kind:     kind,
		Value:    strings.TrimSpace(value),
	}
	if kind == DomainRegex {
		expr := strings.TrimSpace(value)
		compiled, err := regexp.Compile(expr)
		if err != nil {
			return
		}
		r.Regex = compiled
	}
	source.DomainRule = append(source.DomainRule, r)
}

func parseFlexiblePrefix(value string) (netip.Prefix, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return netip.Prefix{}, errors.New("empty prefix")
	}
	if strings.Contains(value, "/") {
		prefix, err := netip.ParsePrefix(stripIPv6Zone(value))
		if err != nil {
			return netip.Prefix{}, err
		}
		return prefix.Masked(), nil
	}
	addr, err := netip.ParseAddr(stripIPv6Zone(value))
	if err != nil {
		return netip.Prefix{}, err
	}
	if addr.Is4() {
		return netip.PrefixFrom(addr.Unmap(), 32), nil
	}
	return netip.PrefixFrom(addr, 128), nil
}

func prefixFromV2RayCIDR(cidr *v2raygeo.CIDR) (netip.Prefix, bool) {
	addr, ok := netip.AddrFromSlice(cidr.GetIp())
	if !ok {
		return netip.Prefix{}, false
	}
	addr = addr.Unmap()
	bits := int(cidr.GetPrefix())
	if addr.Is4() && (bits < 0 || bits > 32) {
		return netip.Prefix{}, false
	}
	if addr.Is6() && (bits < 0 || bits > 128) {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(addr, bits).Masked(), true
}

func mapV2RayDomain(t v2raygeo.Domain_Type, value string) (DomainRuleKind, string) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "", ""
	}
	switch t {
	case v2raygeo.Domain_Full:
		return DomainExact, value
	case v2raygeo.Domain_Domain:
		return DomainSuffix, strings.TrimPrefix(value, ".")
	case v2raygeo.Domain_Plain:
		return DomainKeyword, value
	case v2raygeo.Domain_Regex:
		return DomainRegex, strings.TrimSpace(value)
	default:
		return "", ""
	}
}
