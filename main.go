package main

import (
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v5"

	"jwtdecode/config"
	"jwtdecode/formatter"
	"jwtdecode/output"
)

var (
	// version is set by the build process
	version = "dev"
)

// main is the entry point of the jwtdecode application.
// It orchestrates the configuration loading, token parsing, claims preprocessing,
// formatting, and final output writing.
func main() {
	// 1. Load configuration (flags, config file, or environment)
	appConfig, err := config.LoadConfig(version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	// 2. Execution logic start
	if !appConfig.IsSilent {
		fmt.Println("Decoding JWT token...")
		// Print a snippet of the token for immediate user confirmation
		printTokenSnippet(appConfig.JWTToken)
	}

	// 3. Parse the JWT token (unverified as we are only decoding claims)
	token, _, err := new(jwt.Parser).ParseUnverified(appConfig.JWTToken, jwt.MapClaims{})
	if err != nil {
		logAndExit("Error parsing JWT token: %v", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		logAndExit("Error: Could not extract claims from token.")
	}

	// 4. Pre-process claims (e.g., handle epoch-to-human-readable conversion)
	processedClaims := formatter.PreprocessClaims(claims, appConfig.ConvertEpoch, appConfig.EpochUnit)

	// 5. Format the claims into the requested output format (JSON, CSV, or XML)
	var outputData []byte
	switch appConfig.OutputFormat {
	case config.OutputFormatJSON:
		outputData, err = formatter.FormatJSON(processedClaims)
	case config.OutputFormatCSV:
		outputData, err = formatter.FormatCSV(processedClaims)
	case config.OutputFormatXML:
		outputData, err = formatter.FormatXML(processedClaims)
	default:
		logAndExit("Error: Unknown output format %q.", appConfig.OutputFormat)
	}

	if err != nil {
		logAndExit("Error formatting output: %v", err)
	}

	// 6. Security Check: Prevent Resource Exhaustion (Output Size)
	if len(outputData) > appConfig.MaxOutputSize*1024*1024 {
		logAndExit("Error: Formatted output size exceeds %dMB limit.", appConfig.MaxOutputSize)
	}

	// 7. Persist the output to the specified file
	if err := output.WriteOutput(outputData, appConfig.OutputFile); err != nil {
		logAndExit("Error writing output to file: %v", err)
	}

	if !appConfig.IsSilent {
		fmt.Printf("Successfully wrote output to %s\n", appConfig.OutputFile)
	}
}

// logAndExit prints a formatted message to stderr and exits with status 1.
func logAndExit(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

// printTokenSnippet prints a snippet of the token for user feedback.
func printTokenSnippet(token string) {
	snippetLength := 15
	if len(token) > snippetLength*2+3 {
		fmt.Printf("Token: %s...%s\n", token[:snippetLength], token[len(token)-snippetLength:])
	} else {
		fmt.Printf("Token: %s\n", token)
	}
}
