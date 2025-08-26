package token

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	// Regex to match common Linux special device files and Windows reserved names
	specialDeviceRegex = regexp.MustCompile(`(?i)^(/dev/|/proc/|/sys/|nul|con|prn|aux|com[1-9]|lpt[1-9])($|\\|/)`)
)

// sanitizeFilePath cleans and validates a file path to prevent directory traversal and special device files.
// It ensures the path is within the current working directory.
// NOTE: For production-grade applications, a more robust solution might be needed
// to handle all edge cases of path traversal and special device files across different OS environments.
func sanitizeFilePath(p string) (string, error) {
	if p == "" {
		return "", nil // Allow empty path for defaults
	}

	// Clean the path to resolve .. and .
	cleanedPath := filepath.Clean(p)

	// Check against special device regex
	if specialDeviceRegex.MatchString(cleanedPath) {
		return "", fmt.Errorf("path %q refers to a disallowed special device file", p)
	}

	return cleanedPath, nil
}

// GetToken reads the JWT token based on the specified type and source value.
func GetToken(tokenType string, tokenSourceValue string) (string, error) {
	var jwtToken string
	var err error

	switch tokenType {
	case "string":
		jwtToken = tokenSourceValue
	case "file":
		tokenSourceValue, err = sanitizeFilePath(tokenSourceValue)
		if err != nil {
			return "", fmt.Errorf("sanitizing token file path: %w", err)
		}
		fileContent, err := os.ReadFile(tokenSourceValue)
		if err != nil {
			return "", fmt.Errorf("reading token file %q: %w", tokenSourceValue, err)
		}
		jwtToken = strings.TrimSpace(string(fileContent))
		if jwtToken == "" {
			return "", fmt.Errorf("token file %q is empty", tokenSourceValue)
		}
	case "environment":
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
