package geogrep

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var supportedExtensions = map[string]struct{}{
	".mmdb":   {},
	".dat":    {},
	".srs":    {},
	".json":   {},
	".mrs":    {},
	".yaml":   {},
	".yml":    {},
	".list":   {},
	".txt":    {},
	".db":     {},
	".metadb": {},
}

func resolveDiscovery(cfg CLIConfig) (DiscoveryResult, error) {
	if cfg.DBDir != "" {
		resolved, err := filepath.Abs(cfg.DBDir)
		if err != nil {
			return DiscoveryResult{}, fmt.Errorf("resolve -db path: %w", err)
		}

		info, err := os.Stat(resolved)
		if err != nil {
			return DiscoveryResult{}, fmt.Errorf("stat -db path: %w", err)
		}

		if !info.IsDir() {
			name := filepath.Base(resolved)
			if !isSupportedDataFile(name) {
				return DiscoveryResult{}, fmt.Errorf("unsupported database file: %s", resolved)
			}
			root := filepath.Dir(resolved)
			return DiscoveryResult{
				RootDir: root,
				Databases: []DiscoveredDatabase{
					{
						Name: name,
						Sources: []DiscoveredSource{
							{
								Display: name,
								Path:    resolved,
							},
						},
					},
				},
			}, nil
		}

		dbs, err := discoverDatabases(resolved)
		if err != nil {
			return DiscoveryResult{}, err
		}
		if len(dbs) == 0 {
			return DiscoveryResult{}, fmt.Errorf("no supported database files found in %s", resolved)
		}
		return DiscoveryResult{RootDir: resolved, Databases: dbs}, nil
	}

	cwd, err := os.Getwd()
	if err != nil {
		return DiscoveryResult{}, fmt.Errorf("read working directory: %w", err)
	}
	cwdDBs, err := discoverDatabases(cwd)
	if err != nil {
		return DiscoveryResult{}, err
	}
	if len(cwdDBs) > 0 {
		return DiscoveryResult{RootDir: cwd, Databases: cwdDBs}, nil
	}

	execPath, err := os.Executable()
	if err != nil {
		return DiscoveryResult{}, fmt.Errorf("resolve executable path: %w", err)
	}
	execDir := filepath.Dir(execPath)
	exeDBs, err := discoverDatabases(execDir)
	if err != nil {
		return DiscoveryResult{}, err
	}
	if len(exeDBs) == 0 {
		return DiscoveryResult{}, fmt.Errorf("no supported database files found in working directory (%s) or executable directory (%s)", cwd, execDir)
	}
	return DiscoveryResult{RootDir: execDir, Databases: exeDBs, FromExeDir: true}, nil
}

func discoverDatabases(root string) ([]DiscoveredDatabase, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("read directory %s: %w", root, err)
	}

	dbs := make([]DiscoveredDatabase, 0)

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() {
			if strings.HasPrefix(name, ".") {
				continue
			}
			sources, err := discoverDirectorySources(filepath.Join(root, name), name)
			if err != nil {
				return nil, err
			}
			if len(sources) > 0 {
				dbs = append(dbs, DiscoveredDatabase{Name: name, Sources: sources})
			}
			continue
		}

		if !isSupportedDataFile(name) {
			continue
		}
		dbs = append(dbs, DiscoveredDatabase{
			Name: name,
			Sources: []DiscoveredSource{{
				Display: name,
				Path:    filepath.Join(root, name),
			}},
		})
	}

	sort.Slice(dbs, func(i, j int) bool {
		return dbs[i].Name < dbs[j].Name
	})

	for i := range dbs {
		sort.Slice(dbs[i].Sources, func(a, b int) bool {
			return dbs[i].Sources[a].Display < dbs[i].Sources[b].Display
		})
	}

	return dbs, nil
}

func discoverDirectorySources(dirPath, dirName string) ([]DiscoveredSource, error) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("read directory %s: %w", dirPath, err)
	}

	sources := make([]DiscoveredSource, 0)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !isSupportedDataFile(entry.Name()) {
			continue
		}
		sources = append(sources, DiscoveredSource{
			Display: filepath.ToSlash(filepath.Join(dirName, entry.Name())),
			Path:    filepath.Join(dirPath, entry.Name()),
		})
	}
	return sources, nil
}

func isSupportedDataFile(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	_, ok := supportedExtensions[ext]
	return ok
}
