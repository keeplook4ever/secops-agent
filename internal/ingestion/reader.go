package ingestion

import (
	"encoding/json"
	"fmt"
	"os"

	"secops-agent/pkg/models"
)

// Reader reads and parses the raw JSON log file.
type Reader struct{}

// NewReader creates a Reader.
func NewReader() *Reader {
	return &Reader{}
}

// Read parses the JSON array at filePath into a slice of RawLog.
// Returns an error if the file cannot be opened or parsed.
func (r *Reader) Read(filePath string) ([]models.RawLog, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("ingestion: open %q: %w", filePath, err)
	}
	defer f.Close()

	var logs []models.RawLog
	if err := json.NewDecoder(f).Decode(&logs); err != nil {
		return nil, fmt.Errorf("ingestion: decode %q: %w", filePath, err)
	}
	return logs, nil
}
