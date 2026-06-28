package geogrep

import (
	"bufio"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"

	"github.com/sagernet/sing/common/domain"
	"go4.org/netipx"
)

const (
	maxSRSListLength       = 1 << 20
	maxSRSStringLength     = 1 << 20
	maxSRSPrefixRangeCount = 1 << 20

	srsRuleItemQueryType uint8 = iota
	srsRuleItemNetwork
	srsRuleItemDomain
	srsRuleItemDomainKeyword
	srsRuleItemDomainRegex
	srsRuleItemSourceIPCIDR
	srsRuleItemIPCIDR
	srsRuleItemSourcePort
	srsRuleItemSourcePortRange
	srsRuleItemPort
	srsRuleItemPortRange
	srsRuleItemProcessName
	srsRuleItemProcessPath
	srsRuleItemPackageName
	srsRuleItemWIFISSID
	srsRuleItemWIFIBSSID
	srsRuleItemAdGuardDomain
	srsRuleItemProcessPathRegex
	srsRuleItemNetworkType
	srsRuleItemNetworkIsExpensive
	srsRuleItemNetworkIsConstrained
	srsRuleItemNetworkInterfaceAddress
	srsRuleItemDefaultInterfaceAddress
	srsRuleItemPackageNameRegex
	srsRuleItemFinal uint8 = 0xFF
)

var srsMagic = [3]byte{0x53, 0x52, 0x53}

func loadSRS(source *LoadedSource) error {
	file, err := os.Open(source.Path)
	if err != nil {
		return err
	}
	defer file.Close()

	var magic [3]byte
	if _, err := io.ReadFull(file, magic[:]); err != nil {
		return err
	}
	if magic != srsMagic {
		return errors.New("invalid SRS header")
	}

	if _, err := file.Read(make([]byte, 1)); err != nil {
		return err
	}

	compressed, err := zlib.NewReader(file)
	if err != nil {
		return err
	}
	defer compressed.Close()

	reader := bufio.NewReader(compressed)
	ruleCount, err := binary.ReadUvarint(reader)
	if err != nil {
		return err
	}

	for i := uint64(0); i < ruleCount; i++ {
		if err := readSRSRule(reader, source, fmt.Sprintf("rule[%d]", i)); err != nil {
			return err
		}
	}

	source.Format = "srs"
	return nil
}

func readSRSRule(reader *bufio.Reader, source *LoadedSource, sub string) error {
	ruleType, err := reader.ReadByte()
	if err != nil {
		return err
	}
	switch ruleType {
	case 0:
		return readSRSDefaultRule(reader, source, sub)
	case 1:
		return readSRSLogicalRule(reader, source, sub)
	default:
		return fmt.Errorf("unknown SRS rule type %d", ruleType)
	}
}

func readSRSLogicalRule(reader *bufio.Reader, source *LoadedSource, sub string) error {
	mode, err := reader.ReadByte()
	if err != nil {
		return err
	}
	modeName := "and"
	if mode == 1 {
		modeName = "or"
	}
	length, err := binary.ReadUvarint(reader)
	if err != nil {
		return err
	}
	for i := uint64(0); i < length; i++ {
		if err := readSRSRule(reader, source, fmt.Sprintf("%s/%s[%d]", sub, modeName, i)); err != nil {
			return err
		}
	}
	var invert bool
	return binary.Read(reader, binary.BigEndian, &invert)
}

func readSRSDefaultRule(reader *bufio.Reader, source *LoadedSource, sub string) error {
	for {
		itemType, err := reader.ReadByte()
		if err != nil {
			return err
		}
		switch itemType {
		case srsRuleItemQueryType:
			_, err = readSRSUint16List(reader)
		case srsRuleItemNetwork:
			_, err = readSRSStringList(reader)
		case srsRuleItemDomain:
			var matcher *domain.Matcher
			matcher, err = domain.ReadMatcher(reader)
			if err == nil {
				domains, suffixes := matcher.Dump()
				for _, value := range domains {
					value = strings.ToLower(strings.TrimSpace(value))
					if value != "" {
						appendDomainRule(source, sub, "domain:"+value, DomainExact, value)
					}
				}
				for _, value := range suffixes {
					value = strings.ToLower(strings.TrimSpace(value))
					if value != "" {
						appendDomainRule(source, sub, "domain_suffix:"+value, DomainSuffix, strings.TrimPrefix(value, "."))
					}
				}
			}
		case srsRuleItemDomainKeyword:
			var values []string
			values, err = readSRSStringList(reader)
			if err == nil {
				for _, value := range values {
					value = strings.ToLower(strings.TrimSpace(value))
					if value != "" {
						appendDomainRule(source, sub, "domain_keyword:"+value, DomainKeyword, value)
					}
				}
			}
		case srsRuleItemDomainRegex:
			var values []string
			values, err = readSRSStringList(reader)
			if err == nil {
				for _, value := range values {
					value = strings.TrimSpace(value)
					if value != "" {
						appendDomainRule(source, sub, "domain_regex:"+value, DomainRegex, value)
					}
				}
			}
		case srsRuleItemSourceIPCIDR, srsRuleItemIPCIDR:
			var prefixes []netip.Prefix
			prefixes, err = readSRSIPSet(reader)
			if err == nil {
				for _, prefix := range prefixes {
					source.GeoIPRules = append(source.GeoIPRules, GeoIPRule{SubEntry: sub, Rule: prefix.String(), Prefix: prefix})
				}
			}
		case srsRuleItemSourcePort, srsRuleItemPort:
			_, err = readSRSUint16List(reader)
		case srsRuleItemSourcePortRange, srsRuleItemPortRange,
			srsRuleItemProcessName, srsRuleItemProcessPath,
			srsRuleItemPackageName, srsRuleItemWIFISSID,
			srsRuleItemWIFIBSSID, srsRuleItemProcessPathRegex,
			srsRuleItemPackageNameRegex:
			_, err = readSRSStringList(reader)
		case srsRuleItemAdGuardDomain:
			var matcher *domain.AdGuardMatcher
			matcher, err = domain.ReadAdGuardMatcher(reader)
			if err == nil {
				for _, value := range matcher.Dump() {
					value = strings.TrimSpace(value)
					if value != "" {
						appendDomainRule(source, sub, "adguard:"+value, DomainAdGuard, value)
					}
				}
			}
		case srsRuleItemNetworkType:
			_, err = readSRSUint8List(reader)
		case srsRuleItemNetworkIsExpensive, srsRuleItemNetworkIsConstrained:
			// item itself is a boolean marker with no payload.
		case srsRuleItemNetworkInterfaceAddress:
			var size uint64
			size, err = binary.ReadUvarint(reader)
			if err == nil {
				for i := uint64(0); i < size; i++ {
					if _, err = reader.ReadByte(); err != nil {
						break
					}
					var count uint64
					count, err = binary.ReadUvarint(reader)
					if err != nil {
						break
					}
					for j := uint64(0); j < count; j++ {
						_, err = readSRSPrefix(reader)
						if err != nil {
							break
						}
					}
					if err != nil {
						break
					}
				}
			}
		case srsRuleItemDefaultInterfaceAddress:
			var count uint64
			count, err = binary.ReadUvarint(reader)
			if err == nil {
				for j := uint64(0); j < count; j++ {
					_, err = readSRSPrefix(reader)
					if err != nil {
						break
					}
				}
			}
		case srsRuleItemFinal:
			var invert bool
			return binary.Read(reader, binary.BigEndian, &invert)
		default:
			return fmt.Errorf("unknown SRS rule item type %d", itemType)
		}
		if err != nil {
			return err
		}
	}
}

func readSRSStringList(reader *bufio.Reader) ([]string, error) {
	length, err := readBoundedSRSUvarint(reader, maxSRSListLength, "SRS string list length")
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, length)
	for i := uint64(0); i < length; i++ {
		strLen, err := readBoundedSRSUvarint(reader, maxSRSStringLength, "SRS string length")
		if err != nil {
			return nil, err
		}
		buf := make([]byte, strLen)
		if _, err := io.ReadFull(reader, buf); err != nil {
			return nil, err
		}
		result = append(result, string(buf))
	}
	return result, nil
}

func readSRSUint16List(reader *bufio.Reader) ([]uint16, error) {
	length, err := readBoundedSRSUvarint(reader, maxSRSListLength, "SRS uint16 list length")
	if err != nil {
		return nil, err
	}
	result := make([]uint16, length)
	if err := binary.Read(reader, binary.BigEndian, result); err != nil {
		return nil, err
	}
	return result, nil
}

func readSRSUint8List(reader *bufio.Reader) ([]byte, error) {
	length, err := readBoundedSRSUvarint(reader, maxSRSListLength, "SRS uint8 list length")
	if err != nil {
		return nil, err
	}
	result := make([]byte, length)
	_, err = io.ReadFull(reader, result)
	return result, err
}

func readSRSIPSet(reader *bufio.Reader) ([]netip.Prefix, error) {
	version, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	if version != 1 {
		return nil, errors.New("unsupported SRS ipset version")
	}
	var length uint64
	if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	if length > maxSRSPrefixRangeCount {
		return nil, fmt.Errorf("SRS IP range count too large: %d > %d", length, maxSRSPrefixRangeCount)
	}

	prefixes := make([]netip.Prefix, 0)
	for i := uint64(0); i < length; i++ {
		fromLen, err := readBoundedSRSUvarint(reader, 16, "SRS IP range start length")
		if err != nil {
			return nil, err
		}
		fromBytes := make([]byte, fromLen)
		if _, err := io.ReadFull(reader, fromBytes); err != nil {
			return nil, err
		}

		toLen, err := readBoundedSRSUvarint(reader, 16, "SRS IP range end length")
		if err != nil {
			return nil, err
		}
		toBytes := make([]byte, toLen)
		if _, err := io.ReadFull(reader, toBytes); err != nil {
			return nil, err
		}

		from, ok := netip.AddrFromSlice(fromBytes)
		if !ok {
			return nil, errors.New("invalid SRS IP range start")
		}
		to, ok := netip.AddrFromSlice(toBytes)
		if !ok {
			return nil, errors.New("invalid SRS IP range end")
		}
		rng := netipx.IPRangeFrom(from.Unmap(), to.Unmap())
		if !rng.IsValid() {
			return nil, errors.New("invalid SRS IP range")
		}
		prefixes = append(prefixes, rng.Prefixes()...)
	}
	return prefixes, nil
}

func readSRSPrefix(reader *bufio.Reader) (netip.Prefix, error) {
	addrLen, err := readBoundedSRSUvarint(reader, 16, "SRS prefix address length")
	if err != nil {
		return netip.Prefix{}, err
	}
	addrBytes := make([]byte, addrLen)
	if _, err := io.ReadFull(reader, addrBytes); err != nil {
		return netip.Prefix{}, err
	}
	bits, err := reader.ReadByte()
	if err != nil {
		return netip.Prefix{}, err
	}
	addr, ok := netip.AddrFromSlice(addrBytes)
	if !ok {
		return netip.Prefix{}, errors.New("invalid SRS prefix address")
	}
	return netip.PrefixFrom(addr.Unmap(), int(bits)).Masked(), nil
}

func readBoundedSRSUvarint(reader *bufio.Reader, max uint64, label string) (uint64, error) {
	value, err := binary.ReadUvarint(reader)
	if err != nil {
		return 0, err
	}
	if value > max {
		return 0, fmt.Errorf("%s too large: %d > %d", label, value, max)
	}
	return value, nil
}
