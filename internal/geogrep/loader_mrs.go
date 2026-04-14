package geogrep

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/metacubex/mihomo/component/cidr"
	"github.com/metacubex/mihomo/component/trie"
)

var mrsMagic = [4]byte{'M', 'R', 'S', 1}

func loadMRS(source *LoadedSource) error {
	content, err := os.ReadFile(source.Path)
	if err != nil {
		return err
	}

	reader, err := zstd.NewReader(bytes.NewReader(content))
	if err != nil {
		return err
	}
	defer reader.Close()

	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return err
	}
	if header != mrsMagic {
		return errors.New("invalid MRS header")
	}

	var behavior [1]byte
	if _, err := io.ReadFull(reader, behavior[:]); err != nil {
		return err
	}

	var count int64
	if err := binary.Read(reader, binary.BigEndian, &count); err != nil {
		return err
	}

	var extraLen int64
	if err := binary.Read(reader, binary.BigEndian, &extraLen); err != nil {
		return err
	}
	if extraLen < 0 {
		return errors.New("invalid MRS extra length")
	}
	if extraLen > 0 {
		if _, err := io.CopyN(io.Discard, reader, extraLen); err != nil {
			return err
		}
	}

	sub := fmt.Sprintf("behavior:%d count:%d", behavior[0], count)

	switch behavior[0] {
	case 0:
		domainSet, err := trie.ReadDomainSetBin(reader)
		if err != nil {
			return err
		}
		keys := make([]string, 0)
		domainSet.Foreach(func(key string) bool {
			keys = append(keys, key)
			return true
		})
		slices.Sort(keys)
		for _, key := range keys {
			if _, exists := slices.BinarySearch(keys, "+."+key); exists {
				continue
			}
			k := strings.ToLower(strings.TrimSpace(key))
			if k == "" {
				continue
			}
			switch {
			case strings.HasPrefix(k, "+."):
				appendDomainRule(source, sub, k, DomainSuffix, strings.TrimPrefix(k, "+."))
			case strings.HasPrefix(k, "*.") || strings.ContainsAny(k, "*?"):
				appendDomainRule(source, sub, k, DomainWildcard, k)
			case strings.HasPrefix(k, "."):
				appendDomainRule(source, sub, k, DomainSuffix, strings.TrimPrefix(k, "."))
			default:
				appendDomainRule(source, sub, k, DomainExact, k)
			}
		}
	case 1:
		cidrSet, err := cidr.ReadIpCidrSet(reader)
		if err != nil {
			return err
		}
		cidrSet.Foreach(func(prefixValue netip.Prefix) bool {
			source.GeoIPRules = append(source.GeoIPRules, GeoIPRule{
				SubEntry: sub,
				Rule:     prefixValue.String(),
				Prefix:   prefixValue,
			})
			return true
		})
	case 2:
		return errors.New("MRS classical behavior is not supported")
	default:
		return fmt.Errorf("unsupported MRS behavior byte %d", behavior[0])
	}

	source.Format = "mrs"
	return nil
}
