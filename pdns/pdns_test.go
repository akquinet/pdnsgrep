package pdns

import (
	"testing"
)

func TestCheckStringOnlyHostname(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"ns1", true},
		{"server", true},
		{"ns1.example.com", false},
		{"ns1*", false},
		{"*ns1", false},
		{"ns1?", false},
		{"example.com.", false},
		{"", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := CheckStringOnlyHostname(tt.input)
			if result != tt.expected {
				t.Errorf("CheckStringOnlyHostname(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestFilterRecordsOnType(t *testing.T) {
	records := []PDNSSearchResponseItem{
		{Name: "a.example.com.", Type: "A", Content: "10.0.0.1"},
		{Name: "b.example.com.", Type: "AAAA", Content: "2001:db8::1"},
		{Name: "c.example.com.", Type: "A", Content: "10.0.0.2"},
		{Name: "d.example.com.", Type: "CNAME", Content: "target.example.com."},
		{Name: "e.example.com.", Type: "a", Content: "10.0.0.3"}, // lowercase
	}

	t.Run("filter A records", func(t *testing.T) {
		filtered := FilterRecordsOnType(records, "A")
		if len(filtered) != 3 {
			t.Errorf("expected 3 A records, got %d", len(filtered))
		}
		for _, r := range filtered {
			if r.Type != "A" && r.Type != "a" {
				t.Errorf("expected type A, got %s", r.Type)
			}
		}
	})

	t.Run("filter AAAA records", func(t *testing.T) {
		filtered := FilterRecordsOnType(records, "AAAA")
		if len(filtered) != 1 {
			t.Errorf("expected 1 AAAA record, got %d", len(filtered))
		}
		if filtered[0].Type != "AAAA" {
			t.Errorf("expected type AAAA, got %s", filtered[0].Type)
		}
	})

	t.Run("filter non-existent type", func(t *testing.T) {
		filtered := FilterRecordsOnType(records, "MX")
		if len(filtered) != 0 {
			t.Errorf("expected 0 MX records, got %d", len(filtered))
		}
	})

	t.Run("case insensitive", func(t *testing.T) {
		filtered := FilterRecordsOnType(records, "cname")
		if len(filtered) != 1 {
			t.Errorf("expected 1 CNAME record, got %d", len(filtered))
		}
	})
}
