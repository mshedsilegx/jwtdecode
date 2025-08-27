package token

import (
	"fmt"
	"jwtdecode/utils"
	"os"
	"strings"
)

// GetToken reads the JWT token based on the specified type and source value.
func GetToken(tokenType string, tokenSourceValue string) (string, error) {
	var jwtToken string
	var err error

	switch tokenType {
	case "string":
		jwtToken = tokenSourceValue
	case "file":
		tokenSourceValue, err = utils.SanitizeFilePath(tokenSourceValue)
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
