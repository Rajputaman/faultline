package report

import (
	"encoding/json"
	"fmt"
	"os"
)

// WriteJSONFile writes deterministic, pretty JSON.
func WriteJSONFile(path string, rep *Report) error {
	data, err := MarshalJSON(rep)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write JSON report %s: %w", path, err)
	}
	return nil
}

// MarshalJSON returns indented report JSON.
func MarshalJSON(rep *Report) ([]byte, error) {
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal JSON report: %w", err)
	}
	data = append(data, '\n')
	return data, nil
}
