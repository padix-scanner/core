package reporter

import (
	"core/internal/terminal"
	"core/pkg/models"
	"io"
	"os"
)

func GenerateReport(outputConfig string, formatConfig string, result *models.ScanResult) bool {
	

	var output *os.File
	var writer io.Writer = os.Stdout

	file, err := os.Create(outputConfig)
	if err != nil {
		terminal.ColoredError("Failed to create report:", err)
		return false
	}

	output = file
	writer = file

	defer output.Close()

	switch formatConfig {
	case "text":
		if err := WriteText(writer, result); err != nil {
			terminal.ColoredError("Failed to generate text report:", err)
			return false
		}

	case "json":
		if err := WriteJSON(writer, result); err != nil {
			terminal.ColoredError("Failed to generate JSON report:", err)
			return false
		}

	case "markdown", "md":
		if err := WriteMarkdown(writer, result); err != nil {
			terminal.ColoredError("Failed to generate markdown report:", err)
			return false
		}
	}
	return true
}
