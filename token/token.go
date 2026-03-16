package token

import (
	"fmt"
	"jwtdecode/utils"
	"os"
	"path/filepath"
	"strings"
)

// GetToken reads the JWT token based on the specified type and source value.
func GetToken(tokenType string, tokenSourceValue string) (string, error) {
	var jwtToken string
	var err error

	switch tokenType {
	case "string":
		// Direct token provided as a string
		jwtToken = tokenSourceValue
	case "file":
		// Sanitize the file path to prevent basic directory traversal
		tokenSourceValue, err = utils.SanitizeFilePath(tokenSourceValue)
		if err != nil {
			return "", fmt.Errorf("sanitizing token file path: %w", err)
		}

		// Use os.Root for secure file access (Go 1.24+) to mitigate G304 (CWE-22).
		// We get the absolute path, split it into directory and filename,
		// and then open the directory as a secure root.
		absPath, err := filepath.Abs(tokenSourceValue)
		if err != nil {
			return "", fmt.Errorf("getting absolute path for token file: %w", err)
		}
		dir := filepath.Dir(absPath)
		base := filepath.Base(absPath)

		root, err := os.OpenRoot(dir)
		if err != nil {
			return "", fmt.Errorf("opening root for token file: %w", err)
		}
		defer func() {
			// Explicitly ignore close error as we are only reading
			_ = root.Close()
		}()

		// Read the file content from the secure root
		fileContent, err := root.ReadFile(base)
		if err != nil {
			return "", fmt.Errorf("reading token file %q: %w", tokenSourceValue, err)
		}
		jwtToken = strings.TrimSpace(string(fileContent))
		if jwtToken == "" {
			return "", fmt.Errorf("token file %q is empty", tokenSourceValue)
		}
	case "environment":
		// Fetch token from an environment variable
		envVarName := tokenSourceValue
		if envVarName == "" {
			envVarName = "JWT_TOKEN" // Default environment variable name
		}
		jwtToken = os.Getenv(envVarName)
		if jwtToken == "" {
			return "", fmt.Errorf("environment variable %q is not set", envVarName)
		}
	default:
		return "", fmt.Errorf("unknown token type: %s", tokenType)
	}

	return jwtToken, nil
}
