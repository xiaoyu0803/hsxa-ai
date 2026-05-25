package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/hsxa-ai/net-probe/internal/config"
	"github.com/hsxa-ai/net-probe/internal/output"
	"github.com/hsxa-ai/net-probe/internal/scanner"
	"github.com/spf13/cobra"
)

var cfg = config.DefaultConfig()

// rootCmd is the main cobra command.
var rootCmd = &cobra.Command{
	Use:   "hsxa-ai",
	Short: "mDNS/DNS-SD network asset scanner",
	Long: `hsxa-ai probes IP ranges and port lists using mDNS/DNS-SD (unicast)
to discover and fingerprint network services and devices.`,
	RunE: runScan,
}

// Execute is the entry point called from main.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().StringVarP(&cfg.RawIPs, "ips", "i", "", "IP(s) to scan: single, CIDR, range, or comma-list (required)")
	rootCmd.Flags().StringVarP(&cfg.RawPorts, "ports", "p", "5353", "Port(s) to scan: single, range, or comma-list")
	rootCmd.Flags().StringVarP(&cfg.OutputFmt, "output", "o", "text", "Output format: text, json, yaml")
	rootCmd.Flags().StringVarP(&cfg.OutputFile, "file", "f", "", "Write output to file instead of stdout")
	rootCmd.Flags().DurationVar(&cfg.Timeout, "timeout", 5*time.Second, "Per-target timeout (e.g. 5s, 2s)")
	rootCmd.Flags().IntVar(&cfg.Concurrency, "concur", 200, "Maximum concurrent probes")
	rootCmd.Flags().BoolVarP(&cfg.Verbose, "verbose", "v", false, "Verbose output")

	_ = rootCmd.MarkFlagRequired("ips")
}

func runScan(_ *cobra.Command, _ []string) error {
	sr, err := scanner.Run(cfg)
	if err != nil {
		return fmt.Errorf("scan error: %w", err)
	}
	if err := output.Render(cfg.OutputFmt, cfg.OutputFile, sr); err != nil {
		return fmt.Errorf("output error: %w", err)
	}
	return nil
}
