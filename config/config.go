package config

import (
	"encoding/json"
	"flag"
	"fmt"
	"jwtdecode/token"
	"jwtdecode/utils"
	"os"
	"strings"
)

// Constants for TokenType and OutputFormat
const (
	TokenTypeString      = "string"
	TokenTypeFile        = "file"
	TokenTypeEnvironment = "environment"
	OutputFormatJSON     = "JSON"
	OutputFormatCSV      = "CSV"
	OutputFormatXML      = "XML"

	defaultMaxTokenSizeMB  = 1
	defaultMaxOutputSizeMB = 100
)

// FileConfig defines the structure for the JSON configuration file.
type FileConfig struct {
	JWTToken        string `json:"jwtToken"`
	TokenType       string `json:"tokenType"`
	OutputFormat    string `json:"outputFormat"`
	OutputFile      string `json:"outputFile"`
	ConvertEpoch    bool   `json:"convertEpoch"`
	EpochUnit       string `json:"epochUnit"` // Added for consistency
	SilentExec      bool   `json:"silentExec"`
	MaxTokenSizeMB  int    `json:"maxTokenSizeMB"`
	MaxOutputSizeMB int    `json:"maxOutputSizeMB"`
}

// AppConfig holds the final, validated application configuration from all sources.
type AppConfig struct {
	JWTToken      string
	OutputFormat  string
	OutputFile    string
	ConvertEpoch  bool
	EpochUnit     string
	IsSilent      bool
	MaxTokenSize  int
	MaxOutputSize int
	ShowVersion   bool // To handle the -version flag
}

// LoadConfig parses command-line flags, reads an optional config file,
// validates the configuration, and returns the final AppConfig.
func LoadConfig(version string) (*AppConfig, error) {
	// Define flags
	var (
		tokenString   = flag.String("token-string", "", "Access token passed as a string")
		tokenFile     = flag.String("token-file", "", "Access token passed as file")
		tokenEnv      = flag.Bool("token-env", false, "Get the token from the environment variable JWT_TOKEN")
		outputFormat  = flag.String("output-format", "", "Output format (JSON, CSV, or XML)")
		outputFile    = flag.String("output-file", "", "Full path of output file")
		configFile    = flag.String("config", "", "Full path of config.json")
		showVersion   = flag.Bool("version", false, "Display the current application version")
		convertEpoch  = flag.Bool("convert-epoch", false, "Convert epoch timestamps to human-readable format")
		epochUnit     = flag.String("epoch-unit", "", "Specify epoch unit (s, ms, us, ns). Defaults to heuristic.")
		silent        = flag.Bool("silent", false, "Suppress all output messages")
		maxTokenSize  = flag.Int("max-token-size", 0, "Maximum JWT token size in MB")
		maxOutputSize = flag.Int("max-output-size", 0, "Maximum formatted output size in MB")
	)
	flag.Parse()

	// Handle -version flag immediately
	if *showVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	appConfig := &AppConfig{}
	fileCfg := &FileConfig{}

	// Sanitize file paths from flags first
	sanitizedTokenFile, err := utils.SanitizeFilePath(*tokenFile)
	if err != nil {
		return nil, fmt.Errorf("sanitizing token file path: %w", err)
	}
	sanitizedOutputFile, err := utils.SanitizeFilePath(*outputFile)
	if err != nil {
		return nil, fmt.Errorf("sanitizing output file path: %w", err)
	}
	sanitizedConfigFile, err := utils.SanitizeFilePath(*configFile)
	if err != nil {
		return nil, fmt.Errorf("sanitizing config file path: %w", err)
	}

	// Load from config file if specified
	if sanitizedConfigFile != "" {
		if flag.NArg() > 0 || *tokenString != "" || *tokenFile != "" || *tokenEnv || *outputFormat != "" || *outputFile != "" || *convertEpoch || *silent || *maxTokenSize != 0 || *maxOutputSize != 0 || *epochUnit != "" {
			return nil, fmt.Errorf("if -config is used, it must be the sole argument")
		}
		fileCfg, err = readConfigFile(sanitizedConfigFile)
		if err != nil {
			return nil, err
		}
	}

	// Merge and override with flags (flags take precedence)
	appConfig.ConvertEpoch = *convertEpoch || fileCfg.ConvertEpoch
	appConfig.EpochUnit = valueOrDefault(*epochUnit, fileCfg.EpochUnit)
	appConfig.IsSilent = *silent || fileCfg.SilentExec
	appConfig.MaxTokenSize = intValueOrDefault(*maxTokenSize, fileCfg.MaxTokenSizeMB, defaultMaxTokenSizeMB)
	appConfig.MaxOutputSize = intValueOrDefault(*maxOutputSize, fileCfg.MaxOutputSizeMB, defaultMaxOutputSizeMB)
	appConfig.OutputFormat = valueOrDefault(strings.ToUpper(*outputFormat), strings.ToUpper(fileCfg.OutputFormat))
	appConfig.OutputFile = valueOrDefault(sanitizedOutputFile, fileCfg.OutputFile)

	// Determine token source
	tokenType, tokenValue, err := getTokenSource(tokenString, &sanitizedTokenFile, tokenEnv, fileCfg)
	if err != nil {
		return nil, err
	}
	appConfig.JWTToken, err = token.GetToken(tokenType, tokenValue)
	if err != nil {
		return nil, err
	}

	// Validate and set defaults for output format and file
	if appConfig.OutputFormat == "" {
		appConfig.OutputFormat = OutputFormatJSON
	}
	if appConfig.OutputFormat != OutputFormatJSON && appConfig.OutputFormat != OutputFormatCSV && appConfig.OutputFormat != OutputFormatXML {
		return nil, fmt.Errorf("invalid output format; must be JSON, CSV, or XML")
	}

	if appConfig.OutputFile == "" {
		appConfig.OutputFile = "claims." + strings.ToLower(appConfig.OutputFormat)
	}
	// Sanitize the final output file path (could come from config file)
	appConfig.OutputFile, err = utils.SanitizeFilePath(appConfig.OutputFile)
	if err != nil {
		return nil, fmt.Errorf("sanitizing final output file path: %w", err)
	}

	// Final validation on token and output size
	if len(appConfig.JWTToken) > appConfig.MaxTokenSize*1024*1024 {
		return nil, fmt.Errorf("JWT token size exceeds %dMB limit", appConfig.MaxTokenSize)
	}
	if strings.Count(appConfig.JWTToken, ".") != 2 {
		return nil, fmt.Errorf("invalid JWT token format; expected 2 dots")
	}

	return appConfig, nil
}

// readConfigFile reads and unmarshals the JSON configuration file.
func readConfigFile(filePath string) (*FileConfig, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %q: %w", filePath, err)
	}
	var cfg FileConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file %q: %w", filePath, err)
	}
	return &cfg, nil
}

// getTokenSource determines the token source from flags or config file.
func getTokenSource(tokenString *string, tokenFile *string, tokenEnv *bool, cfg *FileConfig) (string, string, error) {
	// From flags
	if *tokenString != "" || *tokenFile != "" || *tokenEnv {
		sources := 0
		var sourceType, sourceValue string
		if *tokenString != "" {
			sources++
			sourceType = TokenTypeString
			sourceValue = *tokenString
		}
		if *tokenFile != "" {
			sources++
			sourceType = TokenTypeFile
			sourceValue = *tokenFile
		}
		if *tokenEnv {
			sources++
			sourceType = TokenTypeEnvironment
			sourceValue = "" // Default to JWT_TOKEN
		}
		if sources > 1 {
			return "", "", fmt.Errorf("multiple token sources provided via flags; only one is allowed")
		}
		return sourceType, sourceValue, nil
	}

	// From config file
	if cfg.TokenType != "" {
		return cfg.TokenType, cfg.JWTToken, nil
	}

	// No token source found
	return "", "", fmt.Errorf("no token source provided")
}

// valueOrDefault returns the first non-empty string.
func valueOrDefault(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// intValueOrDefault returns the first non-zero integer, or the default if all are zero.
func intValueOrDefault(val, fileVal, defaultVal int) int {
	if val != 0 {
		return val
	}
	if fileVal != 0 {
		return fileVal
	}
	return defaultVal
}
