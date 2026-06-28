package geogrep

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/inserter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
	"github.com/metacubex/geo/encoding/v2raygeo"
	"github.com/metacubex/mihomo/component/cidr"
	"github.com/metacubex/mihomo/component/trie"
	"github.com/sagernet/sing/common/domain"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"
)

type convertFormat string

const (
	convertFormatJSON    convertFormat = "json"
	convertFormatYAML    convertFormat = "yaml"
	convertFormatList    convertFormat = "list"
	convertFormatTXT     convertFormat = "txt"
	convertFormatDAT     convertFormat = "dat"
	convertFormatSingGeo convertFormat = "singgeo"
	convertFormatSRS     convertFormat = "srs"
	convertFormatMRS     convertFormat = "mrs"
	convertFormatMMDB    convertFormat = "mmdb"
)

type convertRuleSet struct {
	GeoIP   []GeoIPRule
	Domains []DomainRule
}

type convertSummary struct {
	Format      convertFormat
	OutputPath  string
	SourceCount int
	GeoIPCount  int
	DomainCount int
}

type convertDocument struct {
	Version int               `json:"version" yaml:"version"`
	Rules   []convertJSONRule `json:"rules" yaml:"rules"`
}

type convertJSONRule struct {
	Type           string   `json:"type,omitempty" yaml:"type,omitempty"`
	Category       string   `json:"category,omitempty" yaml:"category,omitempty"`
	Domain         []string `json:"domain,omitempty" yaml:"domain,omitempty"`
	DomainSuffix   []string `json:"domain_suffix,omitempty" yaml:"domain_suffix,omitempty"`
	DomainKeyword  []string `json:"domain_keyword,omitempty" yaml:"domain_keyword,omitempty"`
	DomainRegex    []string `json:"domain_regex,omitempty" yaml:"domain_regex,omitempty"`
	DomainWildcard []string `json:"domain_wildcard,omitempty" yaml:"domain_wildcard,omitempty"`
	AdGuardDomain  []string `json:"adguard_domain,omitempty" yaml:"adguard_domain,omitempty"`
	IPCIDR         []string `json:"ip_cidr,omitempty" yaml:"ip_cidr,omitempty"`
}

type srsWriteRule struct {
	Domain        []string
	DomainSuffix  []string
	DomainKeyword []string
	DomainRegex   []string
	AdGuardDomain []string
	IPCIDR        []netip.Prefix
}

type singGeoWriteItem struct {
	Type  byte
	Value string
}

func runConvert(cfg CLIConfig) int {
	summary, err := convertDatabases(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "convert error: %v\n", err)
		return 1
	}

	fmt.Printf("[geogrep] converted %d source(s): geoip_rules=%d domain_rules=%d format=%s output=%s\n",
		summary.SourceCount,
		summary.GeoIPCount,
		summary.DomainCount,
		summary.Format,
		summary.OutputPath,
	)
	return 0
}

func convertDatabases(cfg CLIConfig) (convertSummary, error) {
	discovery, err := resolveDiscovery(CLIConfig{DBDir: cfg.ConvertIn})
	if err != nil {
		return convertSummary{}, err
	}
	outputPath, err := filepath.Abs(cfg.ConvertOut)
	if err != nil {
		return convertSummary{}, fmt.Errorf("resolve output path: %w", err)
	}
	if err := validateConvertOutputPath(discovery, outputPath); err != nil {
		return convertSummary{}, err
	}

	databases, diagnostics := loadDatabases(discovery)
	defer closeDatabases(databases)

	errorDiagnostics := make([]string, 0)
	for _, diag := range diagnostics {
		if strings.EqualFold(diag.Level, "error") {
			errorDiagnostics = append(errorDiagnostics, fmt.Sprintf("%s: %s", diag.Scope, diag.Message))
		}
	}
	if len(errorDiagnostics) > 0 {
		return convertSummary{}, fmt.Errorf("failed to load input: %s", strings.Join(errorDiagnostics, "; "))
	}

	rules, sourceCount, err := collectConvertRules(databases)
	if err != nil {
		return convertSummary{}, err
	}
	if len(rules.GeoIP) == 0 && len(rules.Domains) == 0 {
		return convertSummary{}, errors.New("input contains no convertible geoip or domain rules")
	}

	targetFormat, err := resolveConvertFormat(cfg.ConvertTo, outputPath)
	if err != nil {
		return convertSummary{}, err
	}
	if err := writeConvertedRules(outputPath, targetFormat, rules); err != nil {
		return convertSummary{}, err
	}
	return convertSummary{
		Format:      targetFormat,
		OutputPath:  cfg.ConvertOut,
		SourceCount: sourceCount,
		GeoIPCount:  len(rules.GeoIP),
		DomainCount: len(rules.Domains),
	}, nil
}

func validateConvertOutputPath(discovery DiscoveryResult, outputPath string) error {
	outputClean := filepath.Clean(outputPath)
	for _, db := range discovery.Databases {
		for _, source := range db.Sources {
			sourcePath, err := filepath.Abs(source.Path)
			if err != nil {
				return fmt.Errorf("resolve input source path: %w", err)
			}
			if filepath.Clean(sourcePath) == outputClean {
				return fmt.Errorf("convert output path must not overwrite input source: %s", outputPath)
			}
		}
	}
	return nil
}

func collectConvertRules(databases []LoadedDatabase) (convertRuleSet, int, error) {
	var rules convertRuleSet
	sourceCount := 0
	for _, db := range databases {
		for _, source := range db.Sources {
			sourceCount++
			if source.MMDB != nil {
				mmdbRules, err := geoIPRulesFromMMDB(source)
				if err != nil {
					return convertRuleSet{}, sourceCount, err
				}
				rules.GeoIP = append(rules.GeoIP, mmdbRules...)
			}
			rules.GeoIP = append(rules.GeoIP, source.GeoIPRules...)
			rules.Domains = append(rules.Domains, source.DomainRule...)
		}
	}
	sortConvertRules(&rules)
	return rules, sourceCount, nil
}

func geoIPRulesFromMMDB(source LoadedSource) ([]GeoIPRule, error) {
	rules := make([]GeoIPRule, 0)
	for result := range source.MMDB.Reader.Networks() {
		if err := result.Err(); err != nil {
			return nil, fmt.Errorf("%s: %w", source.Display, err)
		}
		var payload any
		if err := result.Decode(&payload); err != nil || payload == nil {
			continue
		}
		prefix := result.Prefix().Masked()
		rules = append(rules, GeoIPRule{
			SubEntry: normalizeConvertCategory(deriveMMDBSubEntry(payload), "mmdb"),
			Rule:     prefix.String(),
			Prefix:   prefix,
		})
	}
	return rules, nil
}

func sortConvertRules(rules *convertRuleSet) {
	sort.SliceStable(rules.GeoIP, func(i, j int) bool {
		a, b := rules.GeoIP[i], rules.GeoIP[j]
		if a.SubEntry != b.SubEntry {
			return a.SubEntry < b.SubEntry
		}
		return a.Prefix.String() < b.Prefix.String()
	})
	sort.SliceStable(rules.Domains, func(i, j int) bool {
		a, b := rules.Domains[i], rules.Domains[j]
		if a.SubEntry != b.SubEntry {
			return a.SubEntry < b.SubEntry
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Value < b.Value
	})
}

func resolveConvertFormat(rawFormat, outputPath string) (convertFormat, error) {
	format := strings.ToLower(strings.TrimSpace(rawFormat))
	if format == "" {
		ext := strings.ToLower(filepath.Ext(outputPath))
		switch ext {
		case ".json":
			format = string(convertFormatJSON)
		case ".yaml", ".yml":
			format = string(convertFormatYAML)
		case ".list":
			format = string(convertFormatList)
		case ".txt":
			format = string(convertFormatTXT)
		case ".dat":
			format = string(convertFormatDAT)
		case ".srs":
			format = string(convertFormatSRS)
		case ".mrs":
			format = string(convertFormatMRS)
		case ".mmdb", ".metadb":
			format = string(convertFormatMMDB)
		case ".db":
			format = string(convertFormatSingGeo)
		default:
			return "", fmt.Errorf("cannot infer output format from %q; use --to", outputPath)
		}
	}

	switch strings.ReplaceAll(format, "-", "_") {
	case "json":
		return convertFormatJSON, nil
	case "yaml", "yml":
		return convertFormatYAML, nil
	case "list":
		return convertFormatList, nil
	case "txt", "text":
		return convertFormatTXT, nil
	case "dat", "v2ray", "xray":
		return convertFormatDAT, nil
	case "singgeo", "sing_geo", "sing-geosite", "sing_geosite", "db":
		return convertFormatSingGeo, nil
	case "srs", "sing_rule_set", "sing-ruleset":
		return convertFormatSRS, nil
	case "mrs", "mihomo_rule_set", "mihomo-ruleset":
		return convertFormatMRS, nil
	case "mmdb", "metadb":
		return convertFormatMMDB, nil
	default:
		return "", fmt.Errorf("unsupported output format %q", rawFormat)
	}
}

func writeConvertedRules(path string, format convertFormat, rules convertRuleSet) error {
	var err error
	switch format {
	case convertFormatJSON:
		err = writeConvertJSON(path, rules)
	case convertFormatYAML:
		err = writeConvertYAML(path, rules)
	case convertFormatList, convertFormatTXT:
		err = writeConvertText(path, rules)
	case convertFormatDAT:
		err = writeConvertDAT(path, rules)
	case convertFormatSingGeo:
		err = writeConvertSingGeo(path, rules)
	case convertFormatSRS:
		err = writeConvertSRS(path, rules)
	case convertFormatMRS:
		err = writeConvertMRS(path, rules)
	case convertFormatMMDB:
		err = writeConvertMMDB(path, rules)
	default:
		err = fmt.Errorf("unsupported output format %q", format)
	}
	return err
}

func writeConvertJSON(path string, rules convertRuleSet) error {
	data, err := json.MarshalIndent(buildConvertDocument(rules), "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writeConvertedFile(path, data, 0o644)
}

func writeConvertYAML(path string, rules convertRuleSet) error {
	data, err := yaml.Marshal(buildConvertDocument(rules))
	if err != nil {
		return err
	}
	return writeConvertedFile(path, data, 0o644)
}

func buildConvertDocument(rules convertRuleSet) convertDocument {
	grouped := make(map[string]*convertJSONRule)
	keys := make([]string, 0)
	getGroup := func(category string) *convertJSONRule {
		category = normalizeConvertCategory(category, "default")
		rule := grouped[category]
		if rule == nil {
			rule = &convertJSONRule{Type: "default", Category: category}
			grouped[category] = rule
			keys = append(keys, category)
		}
		return rule
	}

	for _, rule := range rules.GeoIP {
		group := getGroup(rule.SubEntry)
		group.IPCIDR = append(group.IPCIDR, rule.Prefix.String())
	}
	for _, rule := range rules.Domains {
		group := getGroup(rule.SubEntry)
		switch rule.Kind {
		case DomainExact:
			group.Domain = append(group.Domain, normalizeDomainInput(rule.Value))
		case DomainSuffix:
			group.DomainSuffix = append(group.DomainSuffix, strings.TrimPrefix(normalizeDomainInput(rule.Value), "."))
		case DomainKeyword:
			group.DomainKeyword = append(group.DomainKeyword, strings.ToLower(strings.TrimSpace(rule.Value)))
		case DomainRegex:
			group.DomainRegex = append(group.DomainRegex, strings.TrimSpace(rule.Value))
		case DomainWildcard:
			group.DomainWildcard = append(group.DomainWildcard, strings.ToLower(strings.TrimSpace(rule.Value)))
		case DomainAdGuard:
			group.AdGuardDomain = append(group.AdGuardDomain, strings.TrimSpace(rule.Value))
		}
	}

	sort.Strings(keys)
	out := convertDocument{Version: 1, Rules: make([]convertJSONRule, 0, len(keys))}
	for _, key := range keys {
		rule := *grouped[key]
		dedupAndSortConvertJSONRule(&rule)
		out.Rules = append(out.Rules, rule)
	}
	return out
}

func dedupAndSortConvertJSONRule(rule *convertJSONRule) {
	rule.Domain = dedupSortedStrings(rule.Domain)
	rule.DomainSuffix = dedupSortedStrings(rule.DomainSuffix)
	rule.DomainKeyword = dedupSortedStrings(rule.DomainKeyword)
	rule.DomainRegex = dedupSortedStrings(rule.DomainRegex)
	rule.DomainWildcard = dedupSortedStrings(rule.DomainWildcard)
	rule.AdGuardDomain = dedupSortedStrings(rule.AdGuardDomain)
	rule.IPCIDR = dedupSortedStrings(rule.IPCIDR)
}

func writeConvertText(path string, rules convertRuleSet) error {
	lines := make([]string, 0, len(rules.GeoIP)+len(rules.Domains))
	for _, rule := range rules.GeoIP {
		if rule.Prefix.Addr().Is6() {
			lines = append(lines, "IP-CIDR6,"+rule.Prefix.String())
		} else {
			lines = append(lines, "IP-CIDR,"+rule.Prefix.String())
		}
	}
	for _, rule := range rules.Domains {
		switch rule.Kind {
		case DomainExact:
			lines = append(lines, "DOMAIN,"+normalizeDomainInput(rule.Value))
		case DomainSuffix:
			lines = append(lines, "DOMAIN-SUFFIX,"+strings.TrimPrefix(normalizeDomainInput(rule.Value), "."))
		case DomainKeyword:
			lines = append(lines, "DOMAIN-KEYWORD,"+strings.ToLower(strings.TrimSpace(rule.Value)))
		case DomainRegex:
			lines = append(lines, "DOMAIN-REGEX,"+strings.TrimSpace(rule.Value))
		case DomainWildcard:
			lines = append(lines, "DOMAIN-WILDCARD,"+strings.ToLower(strings.TrimSpace(rule.Value)))
		case DomainAdGuard:
			lines = append(lines, strings.TrimSpace(rule.Value))
		}
	}
	lines = dedupSortedStrings(lines)
	content := strings.Join(lines, "\n")
	if content != "" {
		content += "\n"
	}
	return writeConvertedFile(path, []byte(content), 0o644)
}

func writeConvertDAT(path string, rules convertRuleSet) error {
	if len(rules.GeoIP) > 0 && len(rules.Domains) > 0 {
		return errors.New("dat output cannot contain both GeoIP and GeoSite records; convert IP and domain inputs separately")
	}
	if len(rules.GeoIP) > 0 {
		data, err := proto.Marshal(buildV2RayGeoIPList(rules.GeoIP))
		if err != nil {
			return err
		}
		return writeConvertedFile(path, data, 0o644)
	}
	if len(rules.Domains) > 0 {
		if err := validateConvertDomainKinds(rules.Domains, "dat", DomainExact, DomainSuffix, DomainKeyword, DomainRegex); err != nil {
			return err
		}
		siteList := buildV2RayGeoSiteList(rules.Domains)
		if len(siteList.Entry) == 0 {
			return errors.New("no dat-compatible domain rules to write")
		}
		data, err := proto.Marshal(siteList)
		if err != nil {
			return err
		}
		return writeConvertedFile(path, data, 0o644)
	}
	return errors.New("no rules to write")
}

func buildV2RayGeoIPList(rules []GeoIPRule) *v2raygeo.GeoIPList {
	grouped := make(map[string][]*v2raygeo.CIDR)
	keys := make([]string, 0)
	for _, rule := range rules {
		key := strings.ToUpper(normalizeConvertCategory(rule.SubEntry, "GEOIP"))
		if _, ok := grouped[key]; !ok {
			keys = append(keys, key)
		}
		grouped[key] = append(grouped[key], v2rayCIDRFromPrefix(rule.Prefix))
	}
	sort.Strings(keys)
	list := &v2raygeo.GeoIPList{Entry: make([]*v2raygeo.GeoIP, 0, len(keys))}
	for _, key := range keys {
		list.Entry = append(list.Entry, &v2raygeo.GeoIP{
			CountryCode: key,
			Cidr:        grouped[key],
		})
	}
	return list
}

func v2rayCIDRFromPrefix(prefix netip.Prefix) *v2raygeo.CIDR {
	addr := prefix.Addr().Unmap()
	if addr.Is4() {
		return &v2raygeo.CIDR{Ip: addr.AsSlice(), Prefix: uint32(prefix.Bits())}
	}
	return &v2raygeo.CIDR{Ip: addr.AsSlice(), Prefix: uint32(prefix.Bits())}
}

func buildV2RayGeoSiteList(rules []DomainRule) *v2raygeo.GeoSiteList {
	grouped := make(map[string][]*v2raygeo.Domain)
	keys := make([]string, 0)
	for _, rule := range rules {
		if rule.Kind == DomainWildcard || rule.Kind == DomainAdGuard {
			continue
		}
		key := strings.ToLower(normalizeConvertCategory(rule.SubEntry, "geosite"))
		if _, ok := grouped[key]; !ok {
			keys = append(keys, key)
		}
		grouped[key] = append(grouped[key], v2rayDomainFromRule(rule))
	}
	sort.Strings(keys)
	list := &v2raygeo.GeoSiteList{Entry: make([]*v2raygeo.GeoSite, 0, len(keys))}
	for _, key := range keys {
		list.Entry = append(list.Entry, &v2raygeo.GeoSite{
			CountryCode: key,
			Domain:      grouped[key],
		})
	}
	return list
}

func v2rayDomainFromRule(rule DomainRule) *v2raygeo.Domain {
	value := strings.TrimSpace(rule.Value)
	out := &v2raygeo.Domain{Value: value}
	switch rule.Kind {
	case DomainExact:
		out.Type = v2raygeo.Domain_Full
	case DomainSuffix:
		out.Type = v2raygeo.Domain_Domain
		out.Value = strings.TrimPrefix(normalizeDomainInput(value), ".")
	case DomainKeyword:
		out.Type = v2raygeo.Domain_Plain
	case DomainRegex:
		out.Type = v2raygeo.Domain_Regex
	default:
		out.Type = v2raygeo.Domain_Plain
	}
	return out
}

func writeConvertSingGeo(path string, rules convertRuleSet) error {
	if len(rules.GeoIP) > 0 {
		return errors.New("singgeo output supports domain rules only")
	}
	if err := validateConvertDomainKinds(rules.Domains, "singgeo", DomainExact, DomainSuffix, DomainKeyword, DomainRegex); err != nil {
		return err
	}
	return writeSingGeoFile(path, buildSingGeoDomainMap(rules.Domains))
}

func buildSingGeoDomainMap(rules []DomainRule) map[string][]singGeoWriteItem {
	grouped := make(map[string][]singGeoWriteItem)
	for _, rule := range rules {
		item, ok := singGeoItemFromRule(rule)
		if !ok {
			continue
		}
		key := strings.ToLower(normalizeConvertCategory(rule.SubEntry, "geosite"))
		grouped[key] = append(grouped[key], item)
	}
	for key, values := range grouped {
		sort.SliceStable(values, func(i, j int) bool {
			if values[i].Type != values[j].Type {
				return values[i].Type < values[j].Type
			}
			return values[i].Value < values[j].Value
		})
		grouped[key] = dedupSingGeoItems(values)
	}
	return grouped
}

func singGeoItemFromRule(rule DomainRule) (singGeoWriteItem, bool) {
	value := strings.TrimSpace(rule.Value)
	switch rule.Kind {
	case DomainExact:
		return singGeoWriteItem{Type: 0, Value: normalizeDomainInput(value)}, true
	case DomainSuffix:
		return singGeoWriteItem{Type: 1, Value: strings.TrimPrefix(normalizeDomainInput(value), ".")}, true
	case DomainKeyword:
		return singGeoWriteItem{Type: 2, Value: strings.ToLower(value)}, true
	case DomainRegex:
		return singGeoWriteItem{Type: 3, Value: value}, true
	default:
		return singGeoWriteItem{}, false
	}
}

func dedupSingGeoItems(values []singGeoWriteItem) []singGeoWriteItem {
	out := values[:0]
	var last string
	for _, value := range values {
		key := fmt.Sprintf("%d\x00%s", value.Type, value.Value)
		if key == last {
			continue
		}
		out = append(out, value)
		last = key
	}
	return out
}

func writeSingGeoFile(path string, grouped map[string][]singGeoWriteItem) error {
	var payload bytes.Buffer
	keys := make([]string, 0, len(grouped))
	index := make(map[string]int)
	for key, values := range grouped {
		if len(values) == 0 {
			continue
		}
		keys = append(keys, key)
		index[key] = payload.Len()
		for _, value := range values {
			if err := payload.WriteByte(value.Type); err != nil {
				return err
			}
			writeConvertUvarint(&payload, uint64(len(value.Value)))
			if _, err := payload.WriteString(value.Value); err != nil {
				return err
			}
		}
	}
	if len(keys) == 0 {
		return errors.New("no singgeo-compatible domain rules to write")
	}
	sort.Strings(keys)

	var metadata bytes.Buffer
	if err := metadata.WriteByte(0); err != nil {
		return err
	}
	writeConvertUvarint(&metadata, uint64(len(keys)))
	for _, key := range keys {
		writeConvertUvarint(&metadata, uint64(len(key)))
		if _, err := metadata.WriteString(key); err != nil {
			return err
		}
		writeConvertUvarint(&metadata, uint64(index[key]))
		writeConvertUvarint(&metadata, uint64(len(grouped[key])))
	}

	content := append(metadata.Bytes(), payload.Bytes()...)
	return writeConvertedFile(path, content, 0o644)
}

func writeConvertSRS(path string, rules convertRuleSet) error {
	if err := validateConvertDomainKinds(rules.Domains, "srs", DomainExact, DomainSuffix, DomainKeyword, DomainRegex, DomainAdGuard); err != nil {
		return err
	}
	rule := buildSRSWriteRule(rules)
	if !srsRuleHasItems(rule) {
		return errors.New("no SRS-compatible rules to write")
	}

	file, tmpPath, err := createConvertedTempFile(path)
	if err != nil {
		return err
	}
	committed := false
	defer cleanupConvertedTempFile(file, tmpPath, &committed)

	if _, err := file.Write(srsMagic[:]); err != nil {
		return err
	}
	if err := binary.Write(file, binary.BigEndian, uint8(3)); err != nil {
		return err
	}
	compressed, err := zlib.NewWriterLevel(file, zlib.BestCompression)
	if err != nil {
		return err
	}
	writer := bufio.NewWriter(compressed)
	writeConvertUvarint(writer, 1)
	if err := writeSRSDefaultRule(writer, rule); err != nil {
		_ = compressed.Close()
		return err
	}
	if err := writer.Flush(); err != nil {
		_ = compressed.Close()
		return err
	}
	if err := compressed.Close(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	committed = true
	return nil
}

func buildSRSWriteRule(rules convertRuleSet) srsWriteRule {
	var out srsWriteRule
	for _, rule := range rules.GeoIP {
		out.IPCIDR = append(out.IPCIDR, rule.Prefix)
	}
	for _, rule := range rules.Domains {
		value := strings.TrimSpace(rule.Value)
		switch rule.Kind {
		case DomainExact:
			out.Domain = append(out.Domain, normalizeDomainInput(value))
		case DomainSuffix:
			out.DomainSuffix = append(out.DomainSuffix, strings.TrimPrefix(normalizeDomainInput(value), "."))
		case DomainKeyword:
			out.DomainKeyword = append(out.DomainKeyword, strings.ToLower(value))
		case DomainRegex:
			out.DomainRegex = append(out.DomainRegex, value)
		case DomainAdGuard:
			out.AdGuardDomain = append(out.AdGuardDomain, value)
		}
	}
	out.Domain = dedupSortedStrings(out.Domain)
	out.DomainSuffix = dedupSortedStrings(out.DomainSuffix)
	out.DomainKeyword = dedupSortedStrings(out.DomainKeyword)
	out.DomainRegex = dedupSortedStrings(out.DomainRegex)
	out.AdGuardDomain = dedupSortedStrings(out.AdGuardDomain)
	out.IPCIDR = dedupSortedPrefixes(out.IPCIDR)
	return out
}

func srsRuleHasItems(rule srsWriteRule) bool {
	return len(rule.Domain) > 0 ||
		len(rule.DomainSuffix) > 0 ||
		len(rule.DomainKeyword) > 0 ||
		len(rule.DomainRegex) > 0 ||
		len(rule.AdGuardDomain) > 0 ||
		len(rule.IPCIDR) > 0
}

func writeSRSDefaultRule(writer *bufio.Writer, rule srsWriteRule) error {
	if err := writer.WriteByte(0); err != nil {
		return err
	}
	if len(rule.Domain) > 0 || len(rule.DomainSuffix) > 0 {
		if err := writer.WriteByte(srsRuleItemDomain); err != nil {
			return err
		}
		if err := domain.NewMatcher(rule.Domain, rule.DomainSuffix, false).Write(writer); err != nil {
			return err
		}
	}
	if err := writeSRSStringListItem(writer, srsRuleItemDomainKeyword, rule.DomainKeyword); err != nil {
		return err
	}
	if err := writeSRSStringListItem(writer, srsRuleItemDomainRegex, rule.DomainRegex); err != nil {
		return err
	}
	if len(rule.IPCIDR) > 0 {
		if err := writer.WriteByte(srsRuleItemIPCIDR); err != nil {
			return err
		}
		if err := writeSRSIPSet(writer, rule.IPCIDR); err != nil {
			return err
		}
	}
	if len(rule.AdGuardDomain) > 0 {
		if err := writer.WriteByte(srsRuleItemAdGuardDomain); err != nil {
			return err
		}
		if err := domain.NewAdGuardMatcher(rule.AdGuardDomain).Write(writer); err != nil {
			return err
		}
	}
	if err := writer.WriteByte(srsRuleItemFinal); err != nil {
		return err
	}
	return binary.Write(writer, binary.BigEndian, false)
}

func writeSRSStringListItem(writer *bufio.Writer, itemType uint8, values []string) error {
	if len(values) == 0 {
		return nil
	}
	if err := writer.WriteByte(itemType); err != nil {
		return err
	}
	writeConvertUvarint(writer, uint64(len(values)))
	for _, value := range values {
		writeConvertUvarint(writer, uint64(len(value)))
		if _, err := writer.WriteString(value); err != nil {
			return err
		}
	}
	return nil
}

func writeSRSIPSet(writer io.Writer, prefixes []netip.Prefix) error {
	if _, err := writer.Write([]byte{1}); err != nil {
		return err
	}
	if err := binary.Write(writer, binary.BigEndian, uint64(len(prefixes))); err != nil {
		return err
	}
	for _, prefix := range prefixes {
		rng := prefix.Masked()
		from := rng.Addr()
		to := prefixLastAddr(rng)
		if err := writeSRSAddr(writer, from); err != nil {
			return err
		}
		if err := writeSRSAddr(writer, to); err != nil {
			return err
		}
	}
	return nil
}

func writeSRSAddr(writer io.Writer, addr netip.Addr) error {
	addr = addr.Unmap()
	bytes := addr.AsSlice()
	writeConvertUvarint(writer, uint64(len(bytes)))
	_, err := writer.Write(bytes)
	return err
}

func writeConvertUvarint(writer io.Writer, value uint64) {
	var buf [10]byte
	n := binary.PutUvarint(buf[:], value)
	_, _ = writer.Write(buf[:n])
}

func writeConvertMRS(path string, rules convertRuleSet) error {
	hasIP := len(rules.GeoIP) > 0
	hasDomain := len(rules.Domains) > 0
	if hasIP && hasDomain {
		return errors.New("mrs output cannot contain both domain and IP CIDR behavior; convert them separately")
	}
	if hasDomain {
		return writeDomainMRS(path, rules.Domains)
	}
	if hasIP {
		return writeIPCIDRMRS(path, rules.GeoIP)
	}
	return errors.New("no rules to write")
}

func writeDomainMRS(path string, rules []DomainRule) error {
	if err := validateConvertDomainKinds(rules, "mrs", DomainExact, DomainSuffix, DomainWildcard); err != nil {
		return err
	}
	domainTrie := trie.New[struct{}]()
	count := int64(0)
	for _, rule := range rules {
		value, ok := mrsDomainValue(rule)
		if !ok {
			continue
		}
		if err := domainTrie.Insert(value, struct{}{}); err != nil {
			continue
		}
		count++
	}
	if count == 0 {
		return errors.New("no MRS-compatible domain rules to write")
	}
	domainSet := domainTrie.NewDomainSet()
	if domainSet == nil {
		return errors.New("no MRS-compatible domain rules to write")
	}
	return writeMRS(path, 0, count, domainSet.WriteBin)
}

func mrsDomainValue(rule DomainRule) (string, bool) {
	switch rule.Kind {
	case DomainExact:
		return normalizeDomainInput(rule.Value), true
	case DomainSuffix:
		return "+." + strings.TrimPrefix(normalizeDomainInput(rule.Value), "."), true
	case DomainWildcard:
		return strings.ToLower(strings.TrimSpace(rule.Value)), true
	default:
		return "", false
	}
}

func writeIPCIDRMRS(path string, rules []GeoIPRule) error {
	set := cidr.NewIpCidrSet()
	for _, rule := range rules {
		if err := set.AddIpCidr(rule.Prefix); err != nil {
			return err
		}
	}
	if err := set.Merge(); err != nil {
		return err
	}
	return writeMRS(path, 1, int64(len(rules)), set.WriteBin)
}

func writeMRS(path string, behavior byte, count int64, writePayload func(io.Writer) error) error {
	file, tmpPath, err := createConvertedTempFile(path)
	if err != nil {
		return err
	}
	committed := false
	defer cleanupConvertedTempFile(file, tmpPath, &committed)

	encoder, err := zstd.NewWriter(file)
	if err != nil {
		return err
	}

	if _, err := encoder.Write(mrsMagic[:]); err != nil {
		return err
	}
	if _, err := encoder.Write([]byte{behavior}); err != nil {
		return err
	}
	if err := binary.Write(encoder, binary.BigEndian, count); err != nil {
		return err
	}
	if err := binary.Write(encoder, binary.BigEndian, int64(0)); err != nil {
		return err
	}
	if err := writePayload(encoder); err != nil {
		return err
	}
	if err := encoder.Close(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	committed = true
	return nil
}

func writeConvertMMDB(path string, rules convertRuleSet) error {
	if len(rules.Domains) > 0 {
		return errors.New("mmdb output supports IP/CIDR rules only")
	}
	if len(rules.GeoIP) == 0 {
		return errors.New("no GeoIP rules to write")
	}
	writer, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType:            "geogrep-geoip",
		Description:             map[string]string{"en": "geogrep converted GeoIP database"},
		IPVersion:               6,
		Languages:               []string{"en"},
		RecordSize:              24,
		Inserter:                inserter.ReplaceWith,
		DisableIPv4Aliasing:     true,
		IncludeReservedNetworks: true,
	})
	if err != nil {
		return err
	}
	for _, rule := range rules.GeoIP {
		category := normalizeConvertCategory(rule.SubEntry, "geoip")
		if err := writer.Insert(prefixIPNet(rule.Prefix), mmdbtype.String(category)); err != nil {
			return err
		}
	}
	file, tmpPath, err := createConvertedTempFile(path)
	if err != nil {
		return err
	}
	committed := false
	defer cleanupConvertedTempFile(file, tmpPath, &committed)
	if _, err := writer.WriteTo(file); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	committed = true
	return nil
}

func writeConvertedFile(path string, data []byte, perm os.FileMode) error {
	file, tmpPath, err := createConvertedTempFile(path)
	if err != nil {
		return err
	}
	committed := false
	defer cleanupConvertedTempFile(file, tmpPath, &committed)
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Chmod(perm); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	committed = true
	return nil
}

func createConvertedTempFile(path string) (*os.File, string, error) {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	file, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return nil, "", err
	}
	return file, file.Name(), nil
}

func cleanupConvertedTempFile(file *os.File, tmpPath string, committed *bool) {
	if file != nil {
		_ = file.Close()
	}
	if committed == nil || !*committed {
		_ = os.Remove(tmpPath)
	}
}

func normalizeConvertCategory(category, fallback string) string {
	category = strings.TrimSpace(category)
	if category == "" {
		return fallback
	}
	category = strings.ReplaceAll(category, " ", "_")
	category = strings.ReplaceAll(category, "/", "_")
	return category
}

func validateConvertDomainKinds(rules []DomainRule, target string, allowed ...DomainRuleKind) error {
	allowedSet := make(map[DomainRuleKind]struct{}, len(allowed))
	for _, kind := range allowed {
		allowedSet[kind] = struct{}{}
	}
	unsupported := make(map[DomainRuleKind]int)
	for _, rule := range rules {
		if _, ok := allowedSet[rule.Kind]; ok {
			continue
		}
		unsupported[rule.Kind]++
	}
	if len(unsupported) == 0 {
		return nil
	}
	parts := make([]string, 0, len(unsupported))
	for kind, count := range unsupported {
		parts = append(parts, fmt.Sprintf("%s=%d", kind, count))
	}
	sort.Strings(parts)
	return fmt.Errorf("%s output does not support domain rule kind(s): %s", target, strings.Join(parts, ", "))
}

func dedupSortedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	sort.Strings(values)
	out := values[:0]
	var last string
	for _, value := range values {
		if value == "" || value == last {
			continue
		}
		out = append(out, value)
		last = value
	}
	return out
}

func dedupSortedPrefixes(values []netip.Prefix) []netip.Prefix {
	if len(values) == 0 {
		return nil
	}
	sort.Slice(values, func(i, j int) bool {
		return values[i].String() < values[j].String()
	})
	out := values[:0]
	var last string
	for _, value := range values {
		key := value.String()
		if key == last {
			continue
		}
		out = append(out, value)
		last = key
	}
	return out
}

func prefixLastAddr(prefix netip.Prefix) netip.Addr {
	prefix = prefix.Masked()
	addr := prefix.Addr().Unmap()
	bits := prefix.Bits()
	if addr.Is4() {
		raw := binary.BigEndian.Uint32(addr.AsSlice())
		hostBits := 32 - bits
		if hostBits > 0 {
			raw |= uint32(1<<hostBits) - 1
		}
		var out [4]byte
		binary.BigEndian.PutUint32(out[:], raw)
		return netip.AddrFrom4(out)
	}
	raw := addr.As16()
	hostBits := 128 - bits
	for bit := 0; bit < hostBits; bit++ {
		byteIndex := 15 - bit/8
		raw[byteIndex] |= 1 << uint(bit%8)
	}
	return netip.AddrFrom16(raw)
}

func prefixIPNet(prefix netip.Prefix) *net.IPNet {
	prefix = prefix.Masked()
	addr := prefix.Addr().Unmap()
	if addr.Is4() {
		return &net.IPNet{IP: addr.AsSlice(), Mask: net.CIDRMask(prefix.Bits(), 32)}
	}
	return &net.IPNet{IP: addr.AsSlice(), Mask: net.CIDRMask(prefix.Bits(), 128)}
}
