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

func TestDiffRecords(t *testing.T) {
	base := []pdns.PDNSSearchResponseItem{
		{Zone: "example.com.", Name: "a.example.com.", Type: "A", Content: "10.0.0.1", Ttl: 300},
		{Zone: "example.com.", Name: "b.example.com.", Type: "AAAA", Content: "2001:db8::1", Ttl: 3600},
	}

	t.Run("no changes", func(t *testing.T) {
		added, removed := DiffRecords(base, base)
		if len(added) != 0 || len(removed) != 0 {
			t.Errorf("expected no diff, got added=%v removed=%v", added, removed)
		}
	})

	t.Run("record added", func(t *testing.T) {
		curr := append(base, pdns.PDNSSearchResponseItem{Zone: "example.com.", Name: "c.example.com.", Type: "A", Content: "10.0.0.3", Ttl: 300})
		added, removed := DiffRecords(base, curr)
		if len(added) != 1 || added[0].Name != "c.example.com." {
			t.Errorf("expected 1 added record, got %v", added)
		}
		if len(removed) != 0 {
			t.Errorf("expected no removed records, got %v", removed)
		}
	})

	t.Run("record removed", func(t *testing.T) {
		added, removed := DiffRecords(base, base[:1])
		if len(removed) != 1 || removed[0].Name != "b.example.com." {
			t.Errorf("expected 1 removed record, got %v", removed)
		}
		if len(added) != 0 {
			t.Errorf("expected no added records, got %v", added)
		}
	})

	t.Run("content changed appears as remove+add", func(t *testing.T) {
		curr := []pdns.PDNSSearchResponseItem{
			{Zone: "example.com.", Name: "a.example.com.", Type: "A", Content: "10.0.0.99", Ttl: 300},
			{Zone: "example.com.", Name: "b.example.com.", Type: "AAAA", Content: "2001:db8::1", Ttl: 3600},
		}
		added, removed := DiffRecords(base, curr)
		if len(added) != 1 || added[0].Content != "10.0.0.99" {
			t.Errorf("expected 1 added record with new IP, got %v", added)
		}
		if len(removed) != 1 || removed[0].Content != "10.0.0.1" {
			t.Errorf("expected 1 removed record with old IP, got %v", removed)
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
