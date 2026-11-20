package reporter

import (
	"core/internal/terminal"
	"core/pkg/models"
	"io"
	"os"
)

func GenerateReport(outputConfig string, formatConfig string, result models.ScanResult) bool {
	var output *os.File
	var writer io.Writer = os.Stdout

	if outputConfig != "" {
		file, err := os.Create(outputConfig)
		if err != nil {
			terminal.ColoredError("Failed to create report:", err)
			return false
		}

		output = file
		writer = file
	}

	if output != nil {
		defer output.Close()
	}

	switch formatConfig {
	case "text":
		if err := WriteText(writer, result); err != nil {
			terminal.ColoredError("Failed to generate text report:", err)
			return false
		}

	case "json":
		if outputConfig != "" {
			if err := WriteJSON(writer, result); err != nil {
				terminal.ColoredError("Failed to generate JSON report:", err)
				return false
			}
		} else {
			terminal.ColoredError(
				"JSON output requires an output file path.",
			)
			return false
		}
	}
	return true
}
