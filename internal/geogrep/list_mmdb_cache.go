package geogrep

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const mmdbListCacheSchema = "geogrep-mmdb-list-cache-v1"

type mmdbListCacheDocument struct {
	Schema     string              `json:"schema"`
	Source     string              `json:"source"`
	SourceSHA  string              `json:"source_sha256"`
	Categories map[string][]string `json:"categories"`
}

func listMMDBRulesCached(dbName string, source LoadedSource, requestedRuleset string) []listedRule {
	if source.MMDB == nil || source.MMDB.Reader == nil {
		return nil
	}

	sourceHash, ok := fileSHA256Hex(source.Path)
	if !ok {
		return listMMDBRulesFromReader(dbName, source, requestedRuleset)
	}

	if doc, ok := readValidMMDBListCache(source.Path, sourceHash); ok {
		return listedRulesFromMMDBCache(dbName, source, requestedRuleset, doc)
	}

	doc := buildMMDBListCache(source, sourceHash)
	if doc == nil {
		return nil
	}
	writeMMDBListCache(source.Path, doc)
	return listedRulesFromMMDBCache(dbName, source, requestedRuleset, *doc)
}

func buildMMDBListCache(source LoadedSource, sourceHash string) *mmdbListCacheDocument {
	categories := make(map[string][]string)
	for result := range source.MMDB.Reader.Networks() {
		if err := result.Err(); err != nil {
			continue
		}
		var payload any
		if err := result.Decode(&payload); err != nil || payload == nil {
			continue
		}
		category := strings.TrimSpace(deriveMMDBSubEntry(payload))
		if category == "" {
			continue
		}
		categories[category] = append(categories[category], result.Prefix().Masked().String())
	}
	if len(categories) == 0 {
		return &mmdbListCacheDocument{
			Schema:     mmdbListCacheSchema,
			Source:     filepath.Base(source.Path),
			SourceSHA:  sourceHash,
			Categories: map[string][]string{},
		}
	}
	for category := range categories {
		sort.Strings(categories[category])
	}
	return &mmdbListCacheDocument{
		Schema:     mmdbListCacheSchema,
		Source:     filepath.Base(source.Path),
		SourceSHA:  sourceHash,
		Categories: categories,
	}
}

func listedRulesFromMMDBCache(dbName string, source LoadedSource, requestedRuleset string, doc mmdbListCacheDocument) []listedRule {
	matchedCategory := ""
	for category := range doc.Categories {
		if sameRulesetName(category, requestedRuleset) {
			matchedCategory = category
			break
		}
	}
	if matchedCategory == "" {
		return nil
	}

	rules := doc.Categories[matchedCategory]
	listed := make([]listedRule, 0, len(rules))
	for _, rule := range rules {
		rule = strings.TrimSpace(rule)
		if rule == "" {
			continue
		}
		listed = append(listed, newListedRule(dbName, source, matchedCategory, rule))
	}
	return listed
}

func listMMDBRulesFromReader(dbName string, source LoadedSource, requestedRuleset string) []listedRule {
	listed := make([]listedRule, 0)
	for result := range source.MMDB.Reader.Networks() {
		if err := result.Err(); err != nil {
			continue
		}
		var payload any
		if err := result.Decode(&payload); err != nil || payload == nil {
			continue
		}
		category := strings.TrimSpace(deriveMMDBSubEntry(payload))
		if !sameRulesetName(category, requestedRuleset) {
			continue
		}
		listed = append(listed, newListedRule(dbName, source, category, result.Prefix().Masked().String()))
	}
	sort.SliceStable(listed, func(i, j int) bool {
		return listed[i].Rule < listed[j].Rule
	})
	return listed
}

func fileSHA256Hex(path string) (string, bool) {
	file, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", false
	}
	return hex.EncodeToString(hash.Sum(nil)), true
}

func mmdbListCachePath(sourcePath string) string {
	ext := filepath.Ext(sourcePath)
	return strings.TrimSuffix(sourcePath, ext) + ".json"
}

func readValidMMDBListCache(sourcePath, sourceHash string) (mmdbListCacheDocument, bool) {
	data, err := os.ReadFile(mmdbListCachePath(sourcePath))
	if err != nil {
		return mmdbListCacheDocument{}, false
	}
	var doc mmdbListCacheDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return mmdbListCacheDocument{}, false
	}
	if doc.Schema != mmdbListCacheSchema || doc.SourceSHA != sourceHash || doc.Categories == nil {
		return mmdbListCacheDocument{}, false
	}
	return doc, true
}

func writeMMDBListCache(sourcePath string, doc *mmdbListCacheDocument) {
	if doc == nil {
		return
	}
	if !canWriteMMDBListCache(sourcePath) {
		return
	}
	data, err := json.Marshal(doc)
	if err != nil {
		return
	}
	_ = os.WriteFile(mmdbListCachePath(sourcePath), data, 0o644)
}

func canWriteMMDBListCache(sourcePath string) bool {
	cachePath := mmdbListCachePath(sourcePath)
	data, err := os.ReadFile(cachePath)
	if os.IsNotExist(err) {
		return true
	}
	if err != nil {
		return false
	}
	var probe struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	return probe.Schema == mmdbListCacheSchema
}

func isMMDBListCacheFile(path string) bool {
	if strings.ToLower(filepath.Ext(path)) != ".json" {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var probe struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	return probe.Schema == mmdbListCacheSchema
}
