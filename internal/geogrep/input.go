package geogrep

import (
	"fmt"
	"net/netip"
	"strings"
	"unicode"
)

func normalizeQueries(raw []RawInput) ([]Query, error) {
	queries := make([]Query, 0, len(raw))
	for i, in := range raw {
		q, err := classifyInput(i, in)
		if err != nil {
			return nil, err
		}
		queries = append(queries, q)
	}
	return queries, nil
}

func classifyInput(index int, in RawInput) (Query, error) {
	value := strings.TrimSpace(in.Value)
	if value == "" {
		return Query{}, fmt.Errorf("input %d is empty", index)
	}

	switch in.Force {
	case ForceIPv4:
		return classifyForcedIP(index, value, true)
	case ForceIPv6:
		return classifyForcedIP(index, value, false)
	case ForceDomain:
		return classifyForcedDomain(index, value)
	case ForceKeyword:
		return Query{
			Index:      index,
			Raw:        value,
			Normalized: strings.ToLower(value),
			Kind:       QueryKeyword,
		}, nil
	case ForceAuto:
		return classifyAuto(index, value), nil
	default:
		return Query{}, fmt.Errorf("unsupported force kind %q", in.Force)
	}
}

func classifyForcedIP(index int, value string, wantIPv4 bool) (Query, error) {
	if prefix, err := netip.ParsePrefix(stripIPv6Zone(value)); err == nil {
		addr := prefix.Addr().Unmap()
		if wantIPv4 && !addr.Is4() {
			return Query{}, fmt.Errorf("%q is not IPv4/CIDR4", value)
		}
		if !wantIPv4 && addr.Is4() {
			return Query{}, fmt.Errorf("%q is not IPv6/CIDR6", value)
		}
		return Query{
			Index:      index,
			Raw:        value,
			Normalized: prefix.Masked().String(),
			Kind:       QueryCIDR,
			Prefix:     prefix.Masked(),
		}, nil
	}

	if ip, err := netip.ParseAddr(stripIPv6Zone(value)); err == nil {
		ip = ip.Unmap()
		if wantIPv4 && !ip.Is4() {
			return Query{}, fmt.Errorf("%q is not IPv4/CIDR4", value)
		}
		if !wantIPv4 && ip.Is4() {
			return Query{}, fmt.Errorf("%q is not IPv6/CIDR6", value)
		}
		return Query{
			Index:      index,
			Raw:        value,
			Normalized: ip.String(),
			Kind:       QueryIP,
			IP:         ip,
		}, nil
	}

	if wantIPv4 {
		return Query{}, fmt.Errorf("%q is not valid IPv4/CIDR4", value)
	}
	return Query{}, fmt.Errorf("%q is not valid IPv6/CIDR6", value)
}

func classifyForcedDomain(index int, value string) (Query, error) {
	normalized := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if !isLikelyDomain(value) {
		return Query{}, fmt.Errorf("%q is not a valid domain for -d; use -k for keyword search", value)
	}
	return Query{
		Index:      index,
		Raw:        value,
		Normalized: normalized,
		Kind:       QueryDomain,
	}, nil
}

func classifyAuto(index int, value string) Query {
	if ip, err := netip.ParseAddr(stripIPv6Zone(value)); err == nil {
		ip = ip.Unmap()
		return Query{
			Index:      index,
			Raw:        value,
			Normalized: ip.String(),
			Kind:       QueryIP,
			IP:         ip,
		}
	}

	if prefix, err := netip.ParsePrefix(stripIPv6Zone(value)); err == nil {
		prefix = prefix.Masked()
		return Query{
			Index:      index,
			Raw:        value,
			Normalized: prefix.String(),
			Kind:       QueryCIDR,
			Prefix:     prefix,
		}
	}

	if isLikelyDomain(value) {
		cleaned := strings.TrimSuffix(strings.ToLower(value), ".")
		return Query{
			Index:      index,
			Raw:        value,
			Normalized: cleaned,
			Kind:       QueryDomain,
		}
	}

	return Query{
		Index:      index,
		Raw:        value,
		Normalized: strings.ToLower(value),
		Kind:       QueryKeyword,
	}
}

func stripIPv6Zone(s string) string {
	if i := strings.IndexByte(s, '%'); i >= 0 {
		return s[:i]
	}
	return s
}

func isLikelyDomain(value string) bool {
	s := strings.ToLower(strings.TrimSpace(value))
	if s == "" {
		return false
	}
	if strings.ContainsAny(s, " /@") {
		return false
	}
	if _, err := netip.ParseAddr(stripIPv6Zone(s)); err == nil {
		return false
	}
	if strings.Contains(s, ":") && !strings.Contains(s, ".") {
		return false
	}
	s = strings.TrimPrefix(s, "*.")
	s = strings.TrimPrefix(s, ".")
	if !strings.Contains(s, ".") {
		return false
	}

	parts := strings.Split(s, ".")
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, r := range part {
			if unicode.IsLetter(r) || unicode.IsDigit(r) {
				continue
			}
			switch r {
			case '-', '_', '*':
			default:
				return false
			}
		}
	}
	return true
}
