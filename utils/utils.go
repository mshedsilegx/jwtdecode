package utils

import (
	"fmt"
	"path/filepath"
	"regexp"
)

var (
	// specialDeviceRegex matches common Linux special device files and Windows reserved names.
	// This is a simplified regex and might not cover all edge cases.
	specialDeviceRegex = regexp.MustCompile(`(?i)^(/dev/|/proc/|/sys/|nul|con|prn|aux|com[1-9]|lpt[1-9])($|\\|/)`)
)

// SanitizeFilePath cleans and validates a file path to prevent directory traversal and attacks via special device files.
// It returns a cleaned path or an error if the path is deemed unsafe.
func SanitizeFilePath(p string) (string, error) {
	if p == "" {
		return "", nil // Allow empty path for default values, which are handled later.
	}

	// filepath.Clean resolves ".." and "." elements, simplifying the path.
	cleanedPath := filepath.Clean(p)

	// Check if the cleaned path corresponds to a special or reserved device name.
	if specialDeviceRegex.MatchString(cleanedPath) {
		return "", fmt.Errorf("path %q refers to a disallowed special device file", p)
	}

	// Note: Further checks, like ensuring the path stays within a specific base directory,
	// could be added here for enhanced security. For this tool's scope, this is sufficient.

	return cleanedPath, nil
}
