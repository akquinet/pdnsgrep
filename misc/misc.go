package misc

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/akquinet/pdnsgrep/pdns"
	"github.com/spf13/viper"
)

const (
	TabDelimiter     = "\t"
	SpaceDelimiter   = " "
	DefaultDelimiter = SpaceDelimiter
)

var headers = []string{"Zone", "Name", "Type", "Content", "TTL", "Object Type"}

// Helper function to format record as string
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
	writer := tabwriter.NewWriter(os.Stdout, 1, 1, 1, ' ', 0)
	defer writer.Flush()

	if !viper.GetBool("no-header") {
		fmt.Fprintln(writer, strings.Join(headers, TabDelimiter))
	}

	for _, r := range records {
		fmt.Fprintln(writer, formatRecord(r, TabDelimiter))
	}
}

func OutputToCSV(records []pdns.PDNSSearchResponseItem, delimiter string) {
	fmt.Print(generateOutput(records, delimiter))
}
