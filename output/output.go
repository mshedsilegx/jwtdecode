package output

import (
	"fmt"
	"os"
)

// WriteOutput writes data to the specified file path.
// It uses restricted permissions (0600) to ensure the output (e.g., JWT claims)
// is only readable/writable by the owner, mitigating CWE-276 (G306).
func WriteOutput(data []byte, filePath string) error {
	// 1. Write the data to the file with owner-only permissions.
	// 0600 = Read/Write for owner, no access for others.
	err := os.WriteFile(filePath, data, 0600)
	if err != nil {
		return fmt.Errorf("failed to write output to file %q: %w", filePath, err)
	}
	return nil
}
