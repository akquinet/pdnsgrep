package misc

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/akquinet/pdnsgrep/pdns"
)

func TestSortRecords(t *testing.T) {
	records := []pdns.PDNSSearchResponseItem{
		{Name: "c.example.com.", Type: "A", Zone: "example.com.", Ttl: 300},
		{Name: "a.example.com.", Type: "AAAA", Zone: "example.com.", Ttl: 3600},
		{Name: "b.test.com.", Type: "A", Zone: "test.com.", Ttl: 300},
	}

	t.Run("sort by name", func(t *testing.T) {
		r := make([]pdns.PDNSSearchResponseItem, len(records))
		copy(r, records)
		err := SortRecords(r, "name")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if r[0].Name != "a.example.com." || r[1].Name != "b.test.com." || r[2].Name != "c.example.com." {
			t.Errorf("expected sorted by name, got %v", r)
		}
	})

	t.Run("sort by zone", func(t *testing.T) {
		r := make([]pdns.PDNSSearchResponseItem, len(records))
		copy(r, records)
		err := SortRecords(r, "zone")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if r[0].Zone != "example.com." || r[2].Zone != "test.com." {
			t.Errorf("expected sorted by zone, got %v", r)
		}
	})

	t.Run("sort by ttl", func(t *testing.T) {
		r := make([]pdns.PDNSSearchResponseItem, len(records))
		copy(r, records)
		err := SortRecords(r, "ttl")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if r[0].Ttl != 300 || r[2].Ttl != 3600 {
			t.Errorf("expected sorted by ttl, got %v", r)
		}
	})

	t.Run("sort by type", func(t *testing.T) {
		r := make([]pdns.PDNSSearchResponseItem, len(records))
		copy(r, records)
		err := SortRecords(r, "type")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if r[0].Type != "A" || r[2].Type != "AAAA" {
			t.Errorf("expected sorted by type, got %v", r)
		}
	})

	t.Run("invalid sort field", func(t *testing.T) {
		r := make([]pdns.PDNSSearchResponseItem, len(records))
		copy(r, records)
		err := SortRecords(r, "invalid")
		if err == nil {
			t.Error("expected error for invalid sort field")
		}
	})
}

func TestRecordsEqual(t *testing.T) {
	r1 := []pdns.PDNSSearchResponseItem{
		{Name: "a.example.com.", Type: "A", Content: "10.0.0.1", Ttl: 300},
		{Name: "b.example.com.", Type: "AAAA", Content: "2001:db8::1", Ttl: 3600},
	}

	r2 := []pdns.PDNSSearchResponseItem{
		{Name: "a.example.com.", Type: "A", Content: "10.0.0.1", Ttl: 300},
		{Name: "b.example.com.", Type: "AAAA", Content: "2001:db8::1", Ttl: 3600},
	}

	r3 := []pdns.PDNSSearchResponseItem{
		{Name: "a.example.com.", Type: "A", Content: "10.0.0.2", Ttl: 300},
		{Name: "b.example.com.", Type: "AAAA", Content: "2001:db8::1", Ttl: 3600},
	}

	t.Run("equal records", func(t *testing.T) {
		if !RecordsEqual(r1, r2) {
			t.Error("expected records to be equal")
		}
	})

	t.Run("different content", func(t *testing.T) {
		if RecordsEqual(r1, r3) {
			t.Error("expected records to be different")
		}
	})

	t.Run("different length", func(t *testing.T) {
		if RecordsEqual(r1, r1[:1]) {
			t.Error("expected records to be different")
		}
	})

	t.Run("empty slices", func(t *testing.T) {
		if !RecordsEqual([]pdns.PDNSSearchResponseItem{}, []pdns.PDNSSearchResponseItem{}) {
			t.Error("expected empty slices to be equal")
		}
	})
}

func TestOutputStats(t *testing.T) {
	records := []pdns.PDNSSearchResponseItem{
		{Name: "a.example.com.", Type: "A", Zone: "example.com.", Ttl: 300},
		{Name: "b.example.com.", Type: "A", Zone: "example.com.", Ttl: 300},
		{Name: "c.example.com.", Type: "AAAA", Zone: "example.com.", Ttl: 3600},
		{Name: "d.test.com.", Type: "A", Zone: "test.com.", Ttl: 300},
	}

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	OutputStats(records)

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	t.Run("total count", func(t *testing.T) {
		if !strings.Contains(output, "Total Records: 4") {
			t.Errorf("expected total count, got: %s", output)
		}
	})

	t.Run("type breakdown", func(t *testing.T) {
		if !strings.Contains(output, "By Type:") {
			t.Error("expected type breakdown")
		}
		if !strings.Contains(output, "A") || !strings.Contains(output, "AAAA") {
			t.Error("expected A and AAAA types")
		}
	})

	t.Run("zone breakdown", func(t *testing.T) {
		if !strings.Contains(output, "By Zone:") {
			t.Error("expected zone breakdown")
		}
		if !strings.Contains(output, "example.com.") || !strings.Contains(output, "test.com.") {
			t.Error("expected example.com and test.com zones")
		}
	})
}
