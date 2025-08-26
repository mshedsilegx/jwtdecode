package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Constants for TokenType
const (
	TokenTypeString      = "string"
	TokenTypeFile        = "file"
	TokenTypeEnvironment = "environment"
)

// Constants for OutputFormat
const (
	OutputFormatJSON = "JSON"
	OutputFormatCSV  = "CSV"
	OutputFormatXML  = "XML"
)

// Config struct to hold configuration from file
type Config struct {
	JWTToken        string `json:"jwtToken"`
	TokenType       string `json:"tokenType"`
	OutputFormat    string `json:"outputFormat"`
	OutputFile      string `json:"outputFile"`
	ConvertEpoch    bool   `json:"convertEpoch"`
	SilentExec      bool   `json:"silentExec"`
	MaxTokenSizeMB  int    `json:"maxTokenSizeMB"`
	MaxOutputSizeMB int    `json:"maxOutputSizeMB"`
}

func ReadConfig(filePath string) (*Config, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	err = json.Unmarshal(data, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Validate config values
	// Validate tokenType and jwtToken based on tokenType
	config.TokenType = strings.ToLower(config.TokenType)
	if config.TokenType == "" {
		// Default to "string" if jwtToken is provided and tokenType is not specified
		if config.JWTToken != "" {
			config.TokenType = TokenTypeString
		} else {
			return nil, fmt.Errorf("token type must be specified if JWT token is empty")
		}
	}

	switch config.TokenType {
	case TokenTypeString:
		if config.JWTToken == "" {
			return nil, fmt.Errorf("JWT token cannot be empty when token type is '%s'", TokenTypeString)
		}
	case TokenTypeFile:
		if config.JWTToken == "" {
			return nil, fmt.Errorf("JWT token (file path) cannot be empty when token type is '%s'", TokenTypeFile)
		}
	case TokenTypeEnvironment:
		// jwtToken can be empty, defaults to JWT_TOKEN
	default:
		return nil, fmt.Errorf("invalid token type in config file; must be '%s', '%s', or '%s'", TokenTypeString, TokenTypeFile, TokenTypeEnvironment)
	}

	// OutputFormat and OutputFile are optional in config, defaults will be applied in main.go
	config.OutputFormat = strings.ToUpper(config.OutputFormat)
	if config.OutputFormat != "" && config.OutputFormat != OutputFormatJSON && config.OutputFormat != OutputFormatCSV && config.OutputFormat != OutputFormatXML {
		return nil, fmt.Errorf("invalid output format in config file; must be %s, %s, or %s (or empty for default)", OutputFormatJSON, OutputFormatCSV, OutputFormatXML)
	}

	return &config, nil
}
