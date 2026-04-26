package requestmeta

import (
	"bytes"
	"net"
	"testing"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

func testCountryMMDBBytes(t *testing.T) []byte {
	t.Helper()
	writer, err := mmdbwriter.New(mmdbwriter.Options{
		BuildEpoch:              1,
		DatabaseType:            "GeoIP2-Country",
		Description:             map[string]string{"en": "tukuyomi request country test database"},
		IncludeReservedNetworks: true,
		IPVersion:               4,
		RecordSize:              24,
	})
	if err != nil {
		t.Fatalf("create sample country mmdb writer: %v", err)
	}
	_, network, err := net.ParseCIDR("203.0.113.0/24")
	if err != nil {
		t.Fatalf("parse sample country network: %v", err)
	}
	record := mmdbtype.Map{
		"country": mmdbtype.Map{
			"iso_code": mmdbtype.String("JP"),
		},
		"registered_country": mmdbtype.Map{
			"iso_code": mmdbtype.String("JP"),
		},
	}
	if err := writer.Insert(network, record); err != nil {
		t.Fatalf("insert sample country network: %v", err)
	}
	var buf bytes.Buffer
	if _, err := writer.WriteTo(&buf); err != nil {
		t.Fatalf("write sample country mmdb: %v", err)
	}
	return buf.Bytes()
}
