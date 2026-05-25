package config

import "time"

// ScanConfig holds all user-supplied and default scan parameters.
type ScanConfig struct {
	RawIPs      string
	RawPorts    string
	OutputFmt   string        // "text" | "json" | "yaml"
	OutputFile  string
	Timeout     time.Duration // default 5s
	Concurrency int           // default 200
	Verbose     bool
}

// DefaultConfig returns a ScanConfig populated with sensible defaults.
func DefaultConfig() *ScanConfig {
	return &ScanConfig{
		OutputFmt:   "text",
		Timeout:     5 * time.Second,
		Concurrency: 200,
	}
}
