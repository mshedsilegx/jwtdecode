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

func main() {
	// Load configuration using the new centralized function
	appConfig, err := config.LoadConfig(version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// The rest of the main function remains focused on execution logic
	if !appConfig.IsSilent {
		fmt.Println("Decoding JWT token...")
		// Optional: Print a snippet of the token for user feedback
		printTokenSnippet(appConfig.JWTToken)
	}

	// Parse the JWT token
	token, _, err := new(jwt.Parser).ParseUnverified(appConfig.JWTToken, jwt.MapClaims{})
	if err != nil {
		logAndExit("Error parsing JWT token: %v", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		logAndExit("Error: Could not get claims from token.")
	}

	// Pre-process claims to handle epoch conversion before formatting
	processedClaims := formatter.PreprocessClaims(claims, appConfig.ConvertEpoch, appConfig.EpochUnit)

	// Format the claims based on the configuration
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

	// Resource Exhaustion Protection: Output Size Limit
	if len(outputData) > appConfig.MaxOutputSize*1024*1024 {
		logAndExit("Error: Formatted output size exceeds %dMB limit.", appConfig.MaxOutputSize)
	}

	// Write the output to the specified file
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
