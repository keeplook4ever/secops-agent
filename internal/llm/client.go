package llm

import (
	"context"

	"secops-agent/pkg/models"
)

// Client is the LLM provider interface. Implement this interface to add
// support for additional providers (OpenAI, Vertex AI, local models, etc.)
// without touching the analyzer pipeline.
type Client interface {
	// Analyze sends a sanitized batch to the LLM and returns the raw JSON
	// response body. The caller (validator) is responsible for parsing and
	// validating the response.
	Analyze(ctx context.Context, batch models.SanitizedBatch) ([]byte, error)
}
