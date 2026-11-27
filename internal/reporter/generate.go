package reporter

import (
	"io"
	"os"
	"strings"

	"core/internal/terminal"
	"core/pkg/models"
)

// GenerateReport writes the report to outputPath. When outputPath is empty
// the report is written to stdout.
func GenerateReport(outputPath string, format string, result *models.ScanResult) bool {
	var writer io.Writer = os.Stdout

	if strings.TrimSpace(outputPath) != "" {
		file, err := os.Create(outputPath)
		if err != nil {
			terminal.ColoredError("Failed to create report:", err)
			return false
		}
		defer file.Close()
		writer = file
	}

	var err error
	switch format {
	case "text":
		err = WriteText(writer, result)
	case "json":
		err = WriteJSON(writer, result)
	case "markdown", "md":
		err = WriteMarkdown(writer, result)
	default:
		terminal.ColoredError("Unsupported report format:", format)
		return false
	}

	if err != nil {
		terminal.ColoredError("Failed to generate "+format+" report:", err)
		return false
	}
	return true
}