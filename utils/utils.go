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

// SanitizeFilePath cleans and validates a file path to prevent directory traversal
// and attacks via special device files (e.g., /dev/ or Windows reserved names).
// It returns a cleaned path or an error if the path is deemed unsafe.
func SanitizeFilePath(p string) (string, error) {
	if p == "" {
		// Allow empty path for default values, which are handled by the caller.
		return "", nil
	}

	// 1. Clean the path to resolve ".." and "." elements.
	// This mitigates basic directory traversal.
	cleanedPath := filepath.Clean(p)

	// 2. Check if the cleaned path corresponds to a special or reserved device name.
	// This prevents reading from hardware devices or special system interfaces.
	if specialDeviceRegex.MatchString(cleanedPath) {
		return "", fmt.Errorf("path %q refers to a disallowed special device file", p)
	}

	return cleanedPath, nil
}
