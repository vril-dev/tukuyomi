package requestmeta

import (
	"bufio"
	"fmt"
	"sort"
	"strings"
)

const MaxGeoIPConfigBytes = 512 << 10

type GeoIPConfigSummary struct {
	EditionIDs              []string
	SupportedCountryEdition string
	HasAccountID            bool
	HasLicenseKey           bool
}

func ParseGeoIPConfig(raw []byte) (GeoIPConfigSummary, error) {
	var (
		out            GeoIPConfigSummary
		accountIDSeen  bool
		licenseKeySeen bool
		editions       []string
	)
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	scanner.Buffer(make([]byte, 0, 4096), MaxGeoIPConfigBytes)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(strings.Join(parts[1:], " "))
		switch key {
		case "accountid", "userid":
			accountIDSeen = value != ""
		case "licensekey":
			licenseKeySeen = value != ""
		case "editionids", "productids":
			for _, token := range strings.FieldsFunc(value, func(r rune) bool {
				return r == ' ' || r == ',' || r == '\t'
			}) {
				token = strings.TrimSpace(token)
				if token == "" {
					continue
				}
				editions = append(editions, token)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return out, fmt.Errorf("read GeoIP.conf: %w", err)
	}
	out.EditionIDs = uniqueSortedStrings(editions)
	out.HasAccountID = accountIDSeen
	out.HasLicenseKey = licenseKeySeen
	out.SupportedCountryEdition = SelectSupportedCountryEdition(out.EditionIDs)
	if !out.HasAccountID {
		return out, fmt.Errorf("GeoIP.conf must include AccountID")
	}
	if !out.HasLicenseKey {
		return out, fmt.Errorf("GeoIP.conf must include LicenseKey")
	}
	if len(out.EditionIDs) == 0 {
		return out, fmt.Errorf("GeoIP.conf must include EditionIDs")
	}
	if out.SupportedCountryEdition == "" {
		return out, fmt.Errorf("GeoIP.conf EditionIDs must include GeoLite2-Country or GeoIP2-Country")
	}
	return out, nil
}

func SelectSupportedCountryEdition(editionIDs []string) string {
	for _, id := range editionIDs {
		switch strings.TrimSpace(id) {
		case "GeoIP2-Country", "GeoLite2-Country":
			return strings.TrimSpace(id)
		}
	}
	return ""
}

func RenderGeoIPConfigForCountryEdition(raw []byte, edition string) ([]byte, error) {
	edition = SelectSupportedCountryEdition([]string{strings.TrimSpace(edition)})
	if edition == "" {
		return nil, fmt.Errorf("GeoIP.conf country edition is required")
	}
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	scanner.Buffer(make([]byte, 0, 4096), MaxGeoIPConfigBytes)
	var out strings.Builder
	editionWritten := false
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			parts := strings.Fields(trimmed)
			if len(parts) > 0 {
				switch strings.ToLower(strings.TrimSpace(parts[0])) {
				case "editionids", "productids":
					if !editionWritten {
						out.WriteString("EditionIDs ")
						out.WriteString(edition)
						out.WriteByte('\n')
						editionWritten = true
					}
					continue
				}
			}
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read GeoIP.conf: %w", err)
	}
	if !editionWritten {
		out.WriteString("EditionIDs ")
		out.WriteString(edition)
		out.WriteByte('\n')
	}
	return []byte(out.String()), nil
}

func uniqueSortedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
