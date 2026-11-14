package users

import (
	"strconv"
	"strings"
)

// ValidateSID accepts only account SID shapes that can identify local, domain, or Entra users.
func ValidateSID(value string) (string, bool) {
	parts := strings.Split(value, "-")
	if len(parts) != 8 || !strings.EqualFold(parts[0], "S") {
		return "", false
	}

	values := make([]uint32, len(parts)-1)
	for i, part := range parts[1:] {
		parsed, ok := parseSIDNumber(part)
		if !ok {
			return "", false
		}
		values[i] = parsed
	}
	if values[0] != 1 {
		return "", false
	}

	switch {
	case values[1] == 5 && values[2] == 21:
		// Domain and local accounts have a domain identifier followed by a non-zero RID.
		if values[6] == 0 {
			return "", false
		}
	case values[1] == 12 && values[2] == 1:
		// Entra account SIDs contain four values after the S-1-12-1 prefix.
		if values[3]|values[4]|values[5]|values[6] == 0 {
			return "", false
		}
	default:
		return "", false
	}

	canonical := make([]string, 0, len(parts))
	canonical = append(canonical, "S")
	for _, part := range values {
		canonical = append(canonical, strconv.FormatUint(uint64(part), 10))
	}
	return strings.Join(canonical, "-"), true
}

func parseSIDNumber(value string) (uint32, bool) {
	if value == "" {
		return 0, false
	}
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return 0, false
		}
	}
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(parsed), true
}

// Contains reports whether sid is in the validated account list.
func Contains(sids []string, sid string) bool {
	want, ok := ValidateSID(sid)
	if !ok {
		return false
	}
	for _, candidate := range sids {
		if normalized, valid := ValidateSID(candidate); valid && normalized == want {
			return true
		}
	}
	return false
}

func normalizeList(sids []string) []string {
	normalized := make([]string, 0, len(sids))
	seen := make(map[string]struct{}, len(sids))
	for _, sid := range sids {
		canonical, ok := ValidateSID(sid)
		if !ok {
			continue
		}
		if _, exists := seen[canonical]; exists {
			continue
		}
		seen[canonical] = struct{}{}
		normalized = append(normalized, canonical)
	}
	return normalized
}
