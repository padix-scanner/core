package reporter

import (
	"encoding/json"
	"fmt"
	"io"

	"core/pkg/models"
)

func WriteJSON(w io.Writer, result *models.ScanResult) error {
	if w == nil {
		return fmt.Errorf("report writer cannot be nil")
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}

	data = append(data, '\n')
	_, err = w.Write(data)
	return err
}
