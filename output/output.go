package output

import (
	"fmt"
	"os"
)

// WriteOutput writes data to the specified file path
func WriteOutput(data []byte, filePath string) error {
	err := os.WriteFile(filePath, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write output to file %q: %w", filePath, err)
	}
	return nil
}
