package output

import (
	"fmt"
	"io"
	"os"

	"github.com/hsxa-ai/net-probe/internal/result"
)

// Writer is the interface implemented by all output formatters.
type Writer interface {
	Write(w io.Writer, sr *result.ScanResult) error
}

// Render selects the correct formatter based on format name and writes to
// either a file (if outputFile is non-empty) or stdout.
func Render(format, outputFile string, sr *result.ScanResult) error {
	var w Writer
	switch format {
	case "json":
		w = &JSONWriter{}
	case "yaml":
		w = &YAMLWriter{}
	default:
		w = &TextWriter{}
	}

	dest := io.Writer(os.Stdout)
	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("cannot create output file %q: %w", outputFile, err)
		}
		defer f.Close()
		dest = f
	}

	return w.Write(dest, sr)
}
