package misc

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/akquinet/pdnsgrep/pdns"
	"github.com/fatih/color"
	"github.com/spf13/viper"
)

const (
	TabDelimiter     = "\t"
	SpaceDelimiter   = " "
	DefaultDelimiter = SpaceDelimiter
)

var headers = []string{"Zone", "Name", "Type", "Content", "TTL", "Object Type"}

// Color settings
var (
	headerColor  = color.New(color.FgHiWhite, color.Bold)
	zoneColor    = color.New(color.FgCyan)
	nameColor    = color.New(color.FgGreen)
	typeColor    = color.New(color.FgYellow)
	contentColor = color.New(color.FgWhite)
	ttlColor     = color.New(color.FgMagenta)
	objectColor  = color.New(color.FgBlue)
)

// Helper function to format record as string (for non-colored output)
func formatRecord(record pdns.PDNSSearchResponseItem, delimiter string) string {
	return fmt.Sprintf("%s%s%s%s%s%s%s%s%d%s%s", record.Zone, delimiter, record.Name, delimiter, record.Type, delimiter, record.Content, delimiter, record.Ttl, delimiter, record.ObjectType)
}

func generateOutput(records []pdns.PDNSSearchResponseItem, delimiter string) string {
	output := ""
	if !viper.GetBool("no-header") {
		output += strings.Join(headers, delimiter) + "\n"
	}
	for _, r := range records {
		output += formatRecord(r, delimiter) + "\n"
	}
	return output
}

func OutputToStdout(records []pdns.PDNSSearchResponseItem) {
	fmt.Print(generateOutput(records, DefaultDelimiter))
}

func OutputToTable(records []pdns.PDNSSearchResponseItem) {
	// Check if colors should be disabled
	if viper.GetBool("no-color") {
		// Use the original non-colored output with standard tabwriter
		writer := tabwriter.NewWriter(os.Stdout, 0, 8, 1, ' ', 0)
		defer writer.Flush()

		if !viper.GetBool("no-header") {
			fmt.Fprintln(writer, strings.Join(headers, TabDelimiter))
		}

		for _, r := range records {
			fmt.Fprintln(writer, formatRecord(r, TabDelimiter))
		}
		return
	}

	// For colored output, we'll use a different approach to ensure alignment
	// First, calculate the width needed for each column
	zoneWidth := len(headers[0])
	nameWidth := len(headers[1])
	typeWidth := len(headers[2])
	contentWidth := len(headers[3])
	ttlWidth := len(headers[4])

	for _, r := range records {
		if len(r.Zone) > zoneWidth {
			zoneWidth = len(r.Zone)
		}
		if len(r.Name) > nameWidth {
			nameWidth = len(r.Name)
		}
		if len(r.Type) > typeWidth {
			typeWidth = len(r.Type)
		}
		if len(r.Content) > contentWidth {
			contentWidth = len(r.Content)
		}
		ttlStr := strconv.Itoa(r.Ttl)
		if len(ttlStr) > ttlWidth {
			ttlWidth = len(ttlStr)
		}
	}

	// Add some padding
	zoneWidth += 2
	nameWidth += 2
	typeWidth += 2
	contentWidth += 2
	ttlWidth += 2

	// Print headers
	if !viper.GetBool("no-header") {
		fmt.Printf("%s%s%s%s%s%s\n",
			headerColor.Sprintf("%-*s", zoneWidth, headers[0]),
			headerColor.Sprintf("%-*s", nameWidth, headers[1]),
			headerColor.Sprintf("%-*s", typeWidth, headers[2]),
			headerColor.Sprintf("%-*s", contentWidth, headers[3]),
			headerColor.Sprintf("%-*s", ttlWidth, headers[4]),
			headerColor.Sprint(headers[5]))
	}

	// Print records with fixed width columns
	for _, r := range records {
		fmt.Printf("%s%s%s%s%s%s\n",
			zoneColor.Sprintf("%-*s", zoneWidth, r.Zone),
			nameColor.Sprintf("%-*s", nameWidth, r.Name),
			typeColor.Sprintf("%-*s", typeWidth, r.Type),
			contentColor.Sprintf("%-*s", contentWidth, r.Content),
			ttlColor.Sprintf("%-*d", ttlWidth, r.Ttl),
			objectColor.Sprint(r.ObjectType))
	}
}

func OutputToCSV(records []pdns.PDNSSearchResponseItem, delimiter string) {
	fmt.Print(generateOutput(records, delimiter))
}

// OutputToJSON outputs records in JSON format
func OutputToJSON(records []pdns.PDNSSearchResponseItem) {
	var output []byte
	var err error

	output, err = json.MarshalIndent(records, "", "  ")

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling to JSON: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(output))
}
