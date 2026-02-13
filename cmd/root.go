package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/akquinet/pdnsgrep/misc"
	"github.com/akquinet/pdnsgrep/pdns"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	log "github.com/sirupsen/logrus"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:                   "pdnsgrep SEARCH [SEARCH...]",
	Short:                 "Search blazingly fast trough PowerDNS Entries",
	Example:               "pdnsgrep \"*firewall*\"",
	DisableFlagsInUseLine: true,
	Args:                  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		completion := viper.GetString("show-completion")
		if completion != "" {
			ShowCompletions(cmd, completion)
			os.Exit(0)
		}

		initConfig()
		// We don't need to check for empty args anymore since we've set MinimumNArgs(1)

		client := createPDNSClient()

		objectType := "all"
		if viper.GetBool("zone") {
			objectType = "zone"
		} else if viper.GetBool("comment") {
			objectType = "comment"
		} else if viper.GetBool("record") {
			objectType = "record"
		}

		if viper.GetBool("watch") {
			watchMode(client, args, objectType)
			return
		}

		ctx := context.Background()
		found, err := fetchAndProcessRecords(ctx, client, args, objectType)
		if err != nil {
			log.Fatal(err)
		}

		if len(found) == 0 {
			fmt.Println("Nothing found")
			os.Exit(0)
		}

		if viper.GetBool("stats") {
			misc.OutputStats(found)
			return
		}

		outputResults(found)
	},
}

func outputResults(records []pdns.PDNSSearchResponseItem) {
	switch viper.GetString("output") {
	case "table":
		misc.OutputToTable(records)
	case "csv":
		misc.OutputToCSV(records, viper.GetString("delimiter"))
	case "raw":
		misc.OutputToStdout(records)
	case "json":
		misc.OutputToJSON(records)
	default:
		log.Errorf("Output format %s not known\n", viper.GetString("output"))
		log.Exit(1)
	}
}

func fetchAndProcessRecords(ctx context.Context, client *pdns.PDNSAPI, args []string, objectType string) ([]pdns.PDNSSearchResponseItem, error) {
	found, err := pdns.GetPDNSRecords(ctx, client, args, objectType)
	if err != nil {
		return nil, err
	}

	rType := viper.GetString("type")
	if rType != "" {
		found = pdns.FilterRecordsOnType(found, rType)
	}

	sortBy := viper.GetString("sort-by")
	if sortBy != "" {
		if err := misc.SortRecords(found, sortBy); err != nil {
			return nil, err
		}
	}

	return found, nil
}

func watchMode(client *pdns.PDNSAPI, args []string, objectType string) {
	interval := viper.GetInt("watch-interval")
	if interval < 1 {
		interval = 5
	}

	clearScreen := viper.GetBool("watch-clear")
	onlyChanged := viper.GetBool("watch-only-changed")
	var previous []pdns.PDNSSearchResponseItem
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	ctx := context.Background()

	fetchAndDisplay := func() ([]pdns.PDNSSearchResponseItem, bool) {
		found, err := fetchAndProcessRecords(ctx, client, args, objectType)
		if err != nil {
			log.Error(err)
			return previous, false
		}

		changed := !misc.RecordsEqual(previous, found)
		return found, changed
	}

	// Initial fetch
	found, _ := fetchAndDisplay()
	if clearScreen {
		fmt.Print("\033[2J\033[H")
	}
	fmt.Printf("=== %s ===\n", time.Now().Format("15:04:05"))
	outputResults(found)
	previous = found

	for range ticker.C {
		found, changed := fetchAndDisplay()

		if onlyChanged && !changed {
			continue
		}

		status := ""
		if changed {
			status = " (CHANGED)"
			previous = found
		}

		if clearScreen {
			fmt.Print("\033[2J\033[H")
			fmt.Printf("=== %s%s ===\n", time.Now().Format("15:04:05"), status)
		} else {
			fmt.Printf("\n=== %s%s ===\n", time.Now().Format("15:04:05"), status)
		}
		outputResults(found)
	}
}

func createPDNSClient() *pdns.PDNSAPI {
	client := pdns.NewPDNSAPI(viper.GetString("url"), viper.GetString("token"))

	// Set timeout if specified
	if viper.IsSet("timeout") {
		timeout := time.Duration(viper.GetInt("timeout")) * time.Second
		client.Timeout = timeout
		client.Client.Timeout = timeout
	}

	return client
}

func ShowCompletions(cmd *cobra.Command, shell string) {
	switch shell {
	case "bash":
		cmd.Root().GenBashCompletion(os.Stdout)
	case "zsh":
		cmd.Root().GenZshCompletion(os.Stdout)
	case "fish":
		cmd.Root().GenFishCompletion(os.Stdout, true)
	case "powershell":
		cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
	}
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func initLogLevel() {
	if viper.GetBool("debug") {
		log.SetLevel(log.DebugLevel)
	} else if viper.GetBool("verbose") {
		log.SetLevel(log.InfoLevel)
	} else {
		log.SetLevel(log.WarnLevel)
	}
}

func initConfig() {
	// set log level from cmd params
	initLogLevel()

	if viper.GetString("config") != "" {
		viper.SetConfigFile(viper.GetString("config"))
	} else {
		home, err := homedir.Dir()
		if err != nil {
			log.Fatal(err)
		}
		viper.AddConfigPath(home)
		viper.SetConfigName(".pdnsgrep.yaml")
		viper.SetConfigType("yaml")
	}

	// if a config file is found read it in
	if err := viper.ReadInConfig(); err == nil {
		log.Debug("Using config file:", viper.ConfigFileUsed())
	}

	// set log level in case config has different values
	initLogLevel()

	validateConfigValues()
}

func validateConfigValues() {
	log.Debug("validating config")
	if token := viper.GetString("token"); token == "" {
		log.Fatal("Token needs to be defined")
	}
}

func init() {
	rootCmd.Flags().BoolP("debug", "d", false, "enable debug logging")
	rootCmd.Flags().BoolP("verbose", "v", false, "enable verbose logging")
	rootCmd.Flags().StringP("config", "c", "", "path to a config file")
	rootCmd.Flags().String("token", "", "PowerDNS Token")
	rootCmd.Flags().StringP("url", "u", "", "PowerDNS API URL")
	rootCmd.Flags().StringP("output", "o", "table", "output (table|csv|raw|json)")
	rootCmd.Flags().String("delimiter", ";", "Delimiter when csv export is used")
	rootCmd.Flags().Bool("no-header", false, "do not show header in output")
	rootCmd.Flags().Bool("no-color", false, "disable colored output")
	rootCmd.Flags().Bool("zone", false, "search only for zones")
	rootCmd.Flags().Bool("record", false, "search only for records")
	rootCmd.Flags().Bool("comment", false, "search only for comments")
	rootCmd.Flags().StringP("type", "t", "", "filter type of record (A, AAAA, TXT ....)")
	rootCmd.Flags().IntP("timeout", "", 10, "timeout in seconds for API requests")
	rootCmd.Flags().String("show-completion", "", "show completion (bash, zsh, fish, powershell)")
	rootCmd.Flags().StringP("sort-by", "s", "", "sort results by field (name|zone|ttl|type)")
	rootCmd.Flags().Bool("stats", false, "show statistics instead of full output")
	rootCmd.Flags().BoolP("watch", "w", false, "continuously poll and show changes")
	rootCmd.Flags().Int("watch-interval", 5, "interval in seconds for watch mode")
	rootCmd.Flags().Bool("watch-clear", false, "clear screen on each watch update (default: continuous print)")
	rootCmd.Flags().Bool("watch-only-changed", false, "only show output when changes are detected")

	viper.AutomaticEnv()
	viper.SetEnvPrefix("PDNSGREP")

	// bind all cobra flags to viper
	viper.BindPFlags(rootCmd.Flags())
}
