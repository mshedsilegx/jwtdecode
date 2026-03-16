package config

import (
	"encoding/json"
	"flag"
	"fmt"
	"jwtdecode/token"
	"jwtdecode/utils"
	"os"
	"path/filepath"
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
	EpochUnit       string `json:"epochUnit"` // Unit for epoch timestamps (s, ms, us, ns)
	SilentExec      bool   `json:"silentExec"`
	MaxTokenSizeMB  int    `json:"maxTokenSizeMB"`
	MaxOutputSizeMB int    `json:"maxOutputSizeMB"`
}

// AppConfig holds the final, validated application configuration from all sources.
type AppConfig struct {
	JWTToken      string // The actual JWT token string
	OutputFormat  string // JSON, CSV, or XML
	OutputFile    string // Full path to the output file
	ConvertEpoch  bool   // Whether to convert epoch timestamps
	EpochUnit     string // Unit for epoch timestamps
	IsSilent      bool   // Suppress non-error output
	MaxTokenSize  int    // Maximum allowed token size in MB
	MaxOutputSize int    // Maximum allowed output size in MB
	ShowVersion   bool   // Whether to display the version and exit
}

// LoadConfig parses command-line flags, reads an optional config file,
// validates the configuration, and returns the final AppConfig.
// It follows a hierarchy: flags override config file settings, which override defaults.
func LoadConfig(version string) (*AppConfig, error) {
	// 1. Define and parse command-line flags
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

	// 2. Handle immediate actions (like showing version)
	if *showVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	appConfig := &AppConfig{}
	fileCfg := &FileConfig{}

	// 3. Sanitize and validate file paths from flags
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

	// 4. Load from config file if provided.
	// Note: If -config is used, other flags are disallowed to maintain clarity.
	if sanitizedConfigFile != "" {
		if flag.NArg() > 0 || *tokenString != "" || *tokenFile != "" || *tokenEnv || *outputFormat != "" || *outputFile != "" || *convertEpoch || *silent || *maxTokenSize != 0 || *maxOutputSize != 0 || *epochUnit != "" {
			return nil, fmt.Errorf("if -config is used, it must be the sole argument")
		}
		fileCfg, err = readConfigFile(sanitizedConfigFile)
		if err != nil {
			return nil, err
		}
	}

	// 5. Merge configuration sources (Flags > Config File > Defaults)
	appConfig.ConvertEpoch = *convertEpoch || fileCfg.ConvertEpoch
	appConfig.EpochUnit = valueOrDefault(*epochUnit, fileCfg.EpochUnit)
	appConfig.IsSilent = *silent || fileCfg.SilentExec
	appConfig.MaxTokenSize = intValueOrDefault(*maxTokenSize, fileCfg.MaxTokenSizeMB, defaultMaxTokenSizeMB)
	appConfig.MaxOutputSize = intValueOrDefault(*maxOutputSize, fileCfg.MaxOutputSizeMB, defaultMaxOutputSizeMB)
	appConfig.OutputFormat = valueOrDefault(strings.ToUpper(*outputFormat), strings.ToUpper(fileCfg.OutputFormat))
	appConfig.OutputFile = valueOrDefault(sanitizedOutputFile, fileCfg.OutputFile)

	// 6. Determine token source and retrieve the token
	tokenType, tokenValue, err := getTokenSource(tokenString, &sanitizedTokenFile, tokenEnv, fileCfg)
	if err != nil {
		return nil, err
	}
	appConfig.JWTToken, err = token.GetToken(tokenType, tokenValue)
	if err != nil {
		return nil, err
	}

	// 7. Validate and set defaults for output format and file
	if appConfig.OutputFormat == "" {
		appConfig.OutputFormat = OutputFormatJSON
	}
	if appConfig.OutputFormat != OutputFormatJSON && appConfig.OutputFormat != OutputFormatCSV && appConfig.OutputFormat != OutputFormatXML {
		return nil, fmt.Errorf("invalid output format; must be JSON, CSV, or XML")
	}

	if appConfig.OutputFile == "" {
		appConfig.OutputFile = "claims." + strings.ToLower(appConfig.OutputFormat)
	}
	// Sanitize the final output file path
	appConfig.OutputFile, err = utils.SanitizeFilePath(appConfig.OutputFile)
	if err != nil {
		return nil, fmt.Errorf("sanitizing final output file path: %w", err)
	}

	// 8. Final security and integrity validation
	if len(appConfig.JWTToken) > appConfig.MaxTokenSize*1024*1024 {
		return nil, fmt.Errorf("JWT token size exceeds %dMB limit", appConfig.MaxTokenSize)
	}
	if strings.Count(appConfig.JWTToken, ".") != 2 {
		return nil, fmt.Errorf("invalid JWT token format; expected 2 dots")
	}

	return appConfig, nil
}

// readConfigFile reads and unmarshals the JSON configuration file using secure os.Root.
func readConfigFile(filePath string) (*FileConfig, error) {
	// Obtain absolute path to resolve the root directory safely
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return nil, fmt.Errorf("getting absolute path for config file: %w", err)
	}
	dir := filepath.Dir(absPath)
	base := filepath.Base(absPath)

	// Open the directory as a secure root to prevent directory traversal (G304)
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("opening root for config file: %w", err)
	}
	defer func() {
		_ = root.Close()
	}()

	// Read content from within the secure root
	data, err := root.ReadFile(base)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %q: %w", filePath, err)
	}
	var cfg FileConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file %q: %w", filePath, err)
	}
	return &cfg, nil
}

// getTokenSource determines the token source (type and value) from flags or config file.
// It enforces that only one token source is provided via flags.
func getTokenSource(tokenString *string, tokenFile *string, tokenEnv *bool, cfg *FileConfig) (string, string, error) {
	// 1. Check if any token source is provided via command-line flags
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
			sourceValue = "" // Default environment variable name is handled in token.GetToken
		}
		// Error if multiple sources are specified via flags
		if sources > 1 {
			return "", "", fmt.Errorf("multiple token sources provided via flags; only one is allowed")
		}
		return sourceType, sourceValue, nil
	}

	// 2. Fall back to configuration file settings if no flags were provided
	if cfg.TokenType != "" {
		return cfg.TokenType, cfg.JWTToken, nil
	}

	// 3. Error if no token source can be determined
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
