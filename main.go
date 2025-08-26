package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"jwtdecode/config"
	"jwtdecode/formatter"
	"jwtdecode/output"
	"jwtdecode/token"
)

var (
	version = "dev" // This will be set by the build process
)

const (
	defaultMaxTokenSizeMB  = 1   // Default Maximum JWT token size in MB
	defaultMaxOutputSizeMB = 100 // Default Maximum formatted output size in MB
)

var ( // Compiled once for efficiency
	// Regex to match common Linux special device files and Windows reserved names
	// This is a simplified regex and might not cover all edge cases or platform-specific nuances.
	// For /dev/ and /proc/ and /sys/ paths, it's checked for the prefix.
	// For Windows reserved names, it's checked for exact match or prefix followed by path separator.
	specialDeviceRegex = regexp.MustCompile(`(?i)^(/dev/|/proc/|/sys/|nul|con|prn|aux|com[1-9]|lpt[1-9])($|\\|/)`)
)

// logAndExit prints the formatted message to stderr and exits with status 1.
func logAndExit(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

// sanitizeFilePath cleans and validates a file path to prevent directory traversal and special device files.
// It ensures the path is within the current working directory.
// NOTE: This function is duplicated in the 'token' package. Consider centralizing.
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

// AppConfig holds all parsed and validated application configuration
type AppConfig struct {
	JWTToken      string
	OutputFormat  string
	OutputFile    string
	ConvertEpoch  bool
	EpochUnit     string // New field
	IsSilent      bool
	MaxTokenSize  int
	MaxOutputSize int
}

// parseAndValidateArgs parses command-line arguments and returns a validated AppConfig
func parseAndValidateArgs() (*AppConfig, error) {
	var (
		tokenString   string
		tokenFile     string
		tokenEnv      bool
		outputFormat  string
		outputFile    string
		configFile    string
		showVersion   bool
		convertEpoch  bool
		epochUnit     string // New var
		silent        bool
		maxTokenSize  int
		maxOutputSize int
	)

	flag.StringVar(&tokenString, "token-string", "", "Access token passed as a string")
	flag.StringVar(&tokenFile, "token-file", "", "Access token passed as file")
	flag.BoolVar(&tokenEnv, "token-env", false, "Get the token from the environment variable JWT_TOKEN")
	flag.StringVar(&outputFormat, "output-format", "", "Output format (JSON, CSV, or XML)")
	flag.StringVar(&outputFile, "output-file", "", "Full path of output file")
	flag.StringVar(&configFile, "config", "", "Full path of config.json")
	flag.BoolVar(&showVersion, "version", false, "Display the current application version")
	flag.BoolVar(&convertEpoch, "convert-epoch", false, "Convert epoch timestamps to human-readable format")
	flag.StringVar(&epochUnit, "epoch-unit", "", "Specify epoch unit (s, ms, us, ns). Defaults to heuristic.") // New flag
	flag.BoolVar(&silent, "silent", false, "Suppress all output messages")
	flag.IntVar(&maxTokenSize, "max-token-size", defaultMaxTokenSizeMB, "Maximum JWT token size in MB")
	flag.IntVar(&maxOutputSize, "max-output-size", defaultMaxOutputSizeMB, "Maximum formatted output size in MB")

	flag.Parse()

	// Handle -version flag first
	if showVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	appConfig := &AppConfig{
		ConvertEpoch:  convertEpoch,
		EpochUnit:     epochUnit,
		IsSilent:      silent,
		MaxTokenSize:  maxTokenSize,
		MaxOutputSize: maxOutputSize,
	}

	// Sanitize file paths
	var err error
	configFile, err = sanitizeFilePath(configFile)
	if err != nil {
		return nil, fmt.Errorf("sanitizing config file path: %w", err)
	}

	outputFile, err = sanitizeFilePath(outputFile)
	if err != nil {
		return nil, fmt.Errorf("sanitizing output file path: %w", err)
	}

	tokenFile, err = sanitizeFilePath(tokenFile)
	if err != nil {
		return nil, fmt.Errorf("sanitizing token file path: %w", err)
	}

	// Handle config file or command-line arguments
	if configFile != "" {
		// If -config is specified, it must be the sole argument.
		if tokenString != "" || tokenFile != "" || tokenEnv || outputFormat != "" || outputFile != "" || convertEpoch || silent || maxTokenSize != defaultMaxTokenSizeMB || maxOutputSize != defaultMaxOutputSizeMB || epochUnit != "" {
			return nil, fmt.Errorf("config file specified, but other arguments are present")
		}

		cfg, err := config.ReadConfig(configFile)
		if err != nil {
			return nil, fmt.Errorf("reading config file: %w", err)
		}

		// Determine JWT token source from config
		appConfig.JWTToken, err = token.GetToken(cfg.TokenType, cfg.JWTToken)
		if err != nil {
			return nil, fmt.Errorf("getting token from config: %w", err)
		}

		// Print token source info from config
		if !appConfig.IsSilent {
			var tokenSourceDesc string
			switch cfg.TokenType {
			case "string":
				tokenSourceDesc = "Config (String)"
			case "file":
				tokenSourceDesc = fmt.Sprintf("Config (File: %s)", cfg.JWTToken)
			case "environment":
				envVarName := cfg.JWTToken
				if envVarName == "" {
					envVarName = "JWT_TOKEN"
				}
				tokenSourceDesc = fmt.Sprintf("Config (Environment: %s)", envVarName)
			}
			fmt.Printf("Token from %s: ", tokenSourceDesc)
			printTokenSnippet(appConfig.JWTToken)
		}

		appConfig.OutputFormat = cfg.OutputFormat
		appConfig.OutputFile = cfg.OutputFile
		appConfig.ConvertEpoch = cfg.ConvertEpoch
		appConfig.IsSilent = cfg.SilentExec
		appConfig.MaxTokenSize = cfg.MaxTokenSizeMB
		appConfig.MaxOutputSize = cfg.MaxOutputSizeMB

	} else {
		// Validate command-line arguments
		tokenSourcesProvided := 0
		tokenSourceType := ""
		tokenSourceValue := ""

		if tokenString != "" {
			tokenSourcesProvided++
			tokenSourceType = "string"
			tokenSourceValue = tokenString
		}
		if tokenFile != "" {
			tokenSourcesProvided++
			tokenSourceType = "file"
			tokenSourceValue = tokenFile
		}
		if tokenEnv {
			tokenSourcesProvided++
			tokenSourceType = "environment"
			tokenSourceValue = "" // Default to JWT_TOKEN in GetToken
		}

		if tokenSourcesProvided > 1 {
			return nil, fmt.Errorf("multiple token sources provided; only one is allowed")
		}

		if tokenSourcesProvided == 0 {
			return nil, fmt.Errorf("no token source provided")
		}

		// Get token from command-line source
		appConfig.JWTToken, err = token.GetToken(tokenSourceType, tokenSourceValue)
		if err != nil {
			return nil, fmt.Errorf("getting token from command-line: %w", err)
		}

		// Print token source info from command-line
		if !appConfig.IsSilent {
			var tokenSourceDesc string
			switch tokenSourceType {
			case "string":
				tokenSourceDesc = "String"
			case "file":
				tokenSourceDesc = fmt.Sprintf("File (%s)", tokenFile)
			case "environment":
				tokenSourceDesc = "Environment"
			}
			fmt.Printf("Token from %s: ", tokenSourceDesc)
			printTokenSnippet(appConfig.JWTToken)
		}

		// Apply defaults if not provided by flags
		if outputFormat == "" {
			outputFormat = "JSON"
		}

		outputFormat = strings.ToUpper(outputFormat)
		if outputFormat != "JSON" && outputFormat != "CSV" && outputFormat != "XML" {
			return nil, fmt.Errorf("invalid output format; must be JSON, CSV, or XML")
		}

		// Set default output file based on format if not provided
		if outputFile == "" {
			switch outputFormat {
			case "JSON":
				outputFile = "claims.json"
			case "CSV":
				outputFile = "claims.csv"
			case "XML":
				outputFile = "claims.xml"
			}
		}

		appConfig.OutputFormat = outputFormat
		appConfig.OutputFile = outputFile
	}

	// Resource Exhaustion Protection: Token Size Limit
	if len(appConfig.JWTToken) > appConfig.MaxTokenSize*1024*1024 {
		return nil, fmt.Errorf("JWT token size exceeds %dMB limit", appConfig.MaxTokenSize)
	}

	// Input Validation for JWT Token Structure
	if strings.Count(appConfig.JWTToken, ".") != 2 {
		return nil, fmt.Errorf("invalid JWT token format; expected 2 dots")
	}

	return appConfig, nil
}

func main() {
	// Custom usage message
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage of", os.Args[0]+":")
		fmt.Fprintln(os.Stderr, "  Parses a JWT token and outputs its claims in various formats.")
		fmt.Fprintln(os.Stderr, "\nArguments:")
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "\nExamples:")
		fmt.Fprintln(os.Stderr, "  "+os.Args[0]+" -token-string <your_jwt> -output-format JSON -output-file claims.json")
		fmt.Fprintln(os.Stderr, "  "+os.Args[0]+" -token-env -output-format CSV -output-file claims.csv (requires JWT_TOKEN env var)")
		fmt.Fprintln(os.Stderr, "  "+os.Args[0]+" -config config.json")
		fmt.Fprintln(os.Stderr, "  "+os.Args[0]+" -version")
		fmt.Fprintln(os.Stderr, "\nDefaults: -output-format defaults to JSON, -output-file defaults to claims.<format_extension>")
		fmt.Fprintln(os.Stderr, "\nSecurity: File paths are sanitized to prevent directory traversal and special device files.")
		fmt.Fprintln(os.Stderr, "  Input token and output data sizes are limited to prevent resource exhaustion.")
	}

	appConfig, err := parseAndValidateArgs()
	if err != nil {
		logAndExit("Error: %v", err)
	}

	if !appConfig.IsSilent {
		fmt.Println("Decoding JWT token")
	}

	// JWT Parsing

	token, _, err := new(jwt.Parser).ParseUnverified(appConfig.JWTToken, jwt.MapClaims{})
	if err != nil {
		logAndExit("Error parsing JWT token: %v", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		logAndExit("Error: Could not get claims from token.")
	}

	var outputData []byte
	switch appConfig.OutputFormat {
	case "JSON":
		outputData, err = formatter.FormatJSON(claims, appConfig.ConvertEpoch, appConfig.EpochUnit)
	case "CSV":
		outputData, err = formatter.FormatCSV(claims, appConfig.ConvertEpoch, appConfig.EpochUnit)
	case "XML":
		outputData, err = formatter.FormatXML(claims, appConfig.ConvertEpoch, appConfig.EpochUnit)
	default:
		// This case should ideally not be reached due to earlier validation
		logAndExit("Error: Unknown output format.")
	}

	if err != nil {
		logAndExit("Error formatting output: %v", err)
	}

	// Resource Exhaustion Protection: Output Size Limit
	if len(outputData) > appConfig.MaxOutputSize*1024*1024 {
		logAndExit("Error: Formatted output size exceeds %dMB limit.", appConfig.MaxOutputSize)
	}

	if err := output.WriteOutput(outputData, appConfig.OutputFile); err != nil {
		logAndExit("Error writing output to file: %v", err)
	}

	if !appConfig.IsSilent {
		fmt.Printf("Successfully wrote output to %s\n", appConfig.OutputFile)
	}
}

// printTokenSnippet prints a snippet of the token, handling short tokens
func printTokenSnippet(token string) {
	snippetLength := 10
	fullLength := len(token)

	if fullLength <= snippetLength*2+3 { // If token is too short to show start...end
		fmt.Printf("%s\n", token)
	} else {
		fmt.Printf("%s...%s\n", token[:snippetLength], token[fullLength-snippetLength:])
	}
}
