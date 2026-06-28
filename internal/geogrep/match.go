package geogrep

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	domainpkg "github.com/sagernet/sing/common/domain"
)

func runLookups(queries []Query, databases []LoadedDatabase, reportEmpty bool) []QueryResult {
	results := make([]QueryResult, len(queries))

	workerLimit := runtime.GOMAXPROCS(0)
	if workerLimit < 1 {
		workerLimit = 1
	}
	sem := make(chan struct{}, workerLimit)
	var wg sync.WaitGroup

	for i, query := range queries {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, q Query) {
			defer wg.Done()
			defer func() { <-sem }()
			results[idx] = evaluateQuery(q, databases, reportEmpty)
		}(i, query)
	}

	wg.Wait()
	return results
}

func evaluateQuery(query Query, databases []LoadedDatabase, reportEmpty bool) QueryResult {
	result := QueryResult{Query: query}
	for _, db := range databases {
		dbResult := DatabaseResult{Database: db.Name}
		matches := make([]MatchRecord, 0)
		for _, source := range db.Sources {
			sourceMatches := matchSource(query, db.Name, source)
			if len(sourceMatches) > 0 {
				matches = append(matches, sourceMatches...)
			}
		}

		if len(matches) > 0 {
			dbResult.Matched = true
			dbResult.Matches = matches
			result.DatabaseResult = append(result.DatabaseResult, dbResult)
			continue
		}

		if reportEmpty {
			result.DatabaseResult = append(result.DatabaseResult, dbResult)
		}
	}
	return result
}

func matchSource(query Query, dbName string, source LoadedSource) []MatchRecord {
	matches := make([]MatchRecord, 0)

	switch query.Kind {
	case QueryIP:
		for _, rule := range source.GeoIPRules {
			if rule.Prefix.Contains(query.IP) {
				matches = append(matches, newRuleMatch(dbName, source, rule.SubEntry, rule.Rule, nil))
			}
		}
		if source.MMDB != nil {
			matches = append(matches, matchMMDBIP(query, dbName, source)...)
		}
	case QueryCIDR:
		for _, rule := range source.GeoIPRules {
			if query.Prefix.Overlaps(rule.Prefix) {
				matches = append(matches, newRuleMatch(dbName, source, rule.SubEntry, rule.Rule, map[string]any{
					"query": query.Prefix.String(),
				}))
			}
		}
		if source.MMDB != nil {
			matches = append(matches, matchMMDBCIDR(query, dbName, source)...)
		}
	case QueryDomain:
		domain := normalizeDomainInput(query.Normalized)
		for _, rule := range source.DomainRule {
			if domainRuleMatches(rule, domain) {
				matches = append(matches, newRuleMatch(dbName, source, rule.SubEntry, rule.Rule, nil))
			}
		}
	case QueryKeyword:
		needle := strings.ToLower(strings.TrimSpace(query.Normalized))
		for _, rule := range source.DomainRule {
			if strings.Contains(strings.ToLower(rule.Rule), needle) ||
				strings.Contains(strings.ToLower(rule.Value), needle) {
				matches = append(matches, newRuleMatch(dbName, source, rule.SubEntry, rule.Rule, map[string]any{
					"keyword": needle,
				}))
			}
		}
	}

	return matches
}

func newRuleMatch(dbName string, source LoadedSource, subEntry, rule string, detail map[string]any) MatchRecord {
	record := MatchRecord{
		Database: dbName,
		Source:   filepath.ToSlash(source.Display),
		Format:   source.Format,
		SubEntry: strings.TrimSpace(subEntry),
		Rule:     rule,
	}
	if len(detail) > 0 {
		record.Detail = detail
	}
	return record
}

func normalizeDomainInput(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimSuffix(value, ".")
	return value
}

func domainRuleMatches(rule DomainRule, domain string) bool {
	switch rule.Kind {
	case DomainExact:
		return domain == normalizeDomainInput(rule.Value)
	case DomainSuffix:
		suffix := strings.TrimPrefix(normalizeDomainInput(rule.Value), ".")
		return domain == suffix || strings.HasSuffix(domain, "."+suffix)
	case DomainKeyword:
		return strings.Contains(domain, strings.ToLower(rule.Value))
	case DomainRegex:
		if rule.Regex == nil {
			return false
		}
		return rule.Regex.MatchString(domain)
	case DomainWildcard:
		matched, err := filepath.Match(strings.ToLower(rule.Value), domain)
		return err == nil && matched
	case DomainAdGuard:
		return adGuardRuleMatch(rule.Value, domain)
	default:
		return false
	}
}

func adGuardRuleMatch(rule, domain string) bool {
	rule = strings.TrimSpace(strings.ToLower(rule))
	domain = normalizeDomainInput(domain)
	if rule == "" || domain == "" {
		return false
	}
	if strings.HasPrefix(rule, "@@") {
		return false
	}
	if idx := strings.IndexByte(rule, '$'); idx >= 0 {
		rule = strings.TrimSpace(rule[:idx])
	}
	return domainpkg.NewAdGuardMatcher([]string{rule}).Match(domain)
}

func matchMMDBIP(query Query, dbName string, source LoadedSource) []MatchRecord {
	result := source.MMDB.Reader.Lookup(query.IP)
	if err := result.Err(); err != nil {
		return nil
	}

	var payload any
	if err := result.Decode(&payload); err != nil || payload == nil {
		return nil
	}

	detail := map[string]any{
		"record": payload,
	}
	sub := deriveMMDBSubEntry(payload)
	return []MatchRecord{
		newRuleMatch(dbName, source, sub, result.Prefix().String(), detail),
	}
}

func matchMMDBCIDR(query Query, dbName string, source LoadedSource) []MatchRecord {
	matches := make([]MatchRecord, 0)
	for result := range source.MMDB.Reader.Networks() {
		if err := result.Err(); err != nil {
			continue
		}
		prefix := result.Prefix()
		if !query.Prefix.Overlaps(prefix) {
			continue
		}
		var payload any
		if err := result.Decode(&payload); err != nil || payload == nil {
			continue
		}
		detail := map[string]any{
			"record": payload,
			"query":  query.Prefix.String(),
		}
		matches = append(matches, newRuleMatch(dbName, source, deriveMMDBSubEntry(payload), prefix.String(), detail))
	}
	return matches
}

func deriveMMDBSubEntry(record any) string {
	switch v := record.(type) {
	case map[string]any:
		return deriveMMDBSubEntryFromMap(v)
	case string:
		return v
	case []string:
		if len(v) == 0 {
			return ""
		}
		return strings.Join(v, ",")
	case []any:
		parts := make([]string, 0, len(v))
		for _, it := range v {
			if s, ok := it.(string); ok && s != "" {
				parts = append(parts, s)
			}
		}
		if len(parts) == 0 {
			return ""
		}
		return strings.Join(parts, ",")
	default:
		return ""
	}
}

func deriveMMDBSubEntryFromMap(record map[string]any) string {
	if country, ok := nestedString(record, "country", "iso_code"); ok {
		return country
	}
	if country, ok := nestedString(record, "registered_country", "iso_code"); ok {
		return country
	}
	asn, asnOK := nestedNumber(record, "autonomous_system_number")
	org, orgOK := nestedString(record, "autonomous_system_organization")
	if asnOK && orgOK {
		return fmt.Sprintf("AS%d %s", int(asn), org)
	}
	if asnOK {
		return fmt.Sprintf("AS%d", int(asn))
	}
	if continent, ok := nestedString(record, "continent", "code"); ok {
		return continent
	}
	return ""
}

func nestedString(record map[string]any, path ...string) (string, bool) {
	current := any(record)
	for _, key := range path {
		asMap, ok := current.(map[string]any)
		if !ok {
			return "", false
		}
		next, ok := asMap[key]
		if !ok {
			return "", false
		}
		current = next
	}
	value, ok := current.(string)
	return value, ok
}

func nestedNumber(record map[string]any, path ...string) (float64, bool) {
	current := any(record)
	for _, key := range path {
		asMap, ok := current.(map[string]any)
		if !ok {
			return 0, false
		}
		next, ok := asMap[key]
		if !ok {
			return 0, false
		}
		current = next
	}
	switch v := current.(type) {
	case float64:
		return v, true
	case uint32:
		return float64(v), true
	case uint64:
		return float64(v), true
	case int:
		return float64(v), true
	case int32:
		return float64(v), true
	case int64:
		return float64(v), true
	default:
		return 0, false
	}
}
