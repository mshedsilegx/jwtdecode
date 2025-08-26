package formatter

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	ClaimIAT      = "iat"
	ClaimEXP      = "exp"
	ClaimNBF      = "nbf"
	ClaimAuthTime = "auth_time"
)

// FormatJSON formats claims into a JSON string
func FormatJSON(claims jwt.MapClaims, convertEpoch bool, epochUnit string) ([]byte, error) {
	// Create a new map to add human-readable timestamps
	extendedClaims := make(jwt.MapClaims)
	for key, value := range claims {
		extendedClaims[key] = value

		if convertEpoch {
			if datestamp, ok := convertEpochToHumanReadable(key, value, epochUnit); ok {
				extendedClaims[key+"_datestamp"] = datestamp
			}
		}
	}
	return json.MarshalIndent(extendedClaims, "", "  ")
}

// convertEpochToHumanReadable attempts to convert a value to a human-readable date string if it's a valid epoch.
// It checks for common epoch claim names (iat, exp, nbf, auth_time).
// epochUnit can be "s" (seconds), "ms" (milliseconds), "us" (microseconds), or "ns" (nanoseconds).
// If empty or invalid, it falls back to a heuristic.
func convertEpochToHumanReadable(key string, value interface{}, epochUnit string) (string, bool) {
	switch key {
	case ClaimIAT, ClaimEXP, ClaimNBF, ClaimAuthTime:
		var timestamp int64
		switch v := value.(type) {
		case float64:
			timestamp = int64(v)
		case json.Number:
			i, err := v.Int64()
			if err != nil {
				return "", false
			}
			timestamp = i
		default:
			return "", false
		}

		var tm time.Time
		switch strings.ToLower(epochUnit) {
		case "s", "seconds":
			tm = time.Unix(timestamp, 0)
		case "ms", "milliseconds":
			tm = time.Unix(0, timestamp*int64(time.Millisecond))
		case "us", "microseconds":
			tm = time.Unix(0, timestamp*int64(time.Microsecond))
		case "ns", "nanoseconds":
			tm = time.Unix(0, timestamp)
		default:
			// Fallback to heuristic if unit is not specified or invalid
			if timestamp > 1e10 { // Heuristic: if timestamp is very large, assume milliseconds
				tm = time.Unix(0, timestamp*int64(time.Millisecond))
			} else { // Assume seconds
				tm = time.Unix(timestamp, 0)
			}
		}
		return tm.UTC().Format("2006-01-02 15:04:05 UTC"), true
	}
	return "", false
}

// flattenClaims recursively flattens nested map claims for CSV output
// Complex types (maps and arrays) are JSON stringified to prevent data loss.
func flattenClaims(claims jwt.MapClaims, prefix string, convertEpoch bool, epochUnit string) map[string]interface{} {
	flattened := make(map[string]interface{})
	for key, value := range claims {
		newKey := key
		if prefix != "" {
			newKey = prefix + "." + key
		}

		switch v := value.(type) {
		case map[string]interface{}:
			// JSON stringify nested maps to preserve structure
			jsonBytes, err := json.Marshal(v)
			if err != nil {
				flattened[newKey] = "" // Error marshaling to JSON
			} else {
				flattened[newKey] = string(jsonBytes)
			}
		case []interface{}:
			// JSON stringify arrays to preserve structure
			jsonBytes, err := json.Marshal(v)
			if err != nil {
				flattened[newKey] = "" // Error marshaling to JSON
			} else {
				flattened[newKey] = string(jsonBytes)
			}
		default:
			flattened[newKey] = value
		}

		// Add human-readable timestamp for CSV
		if convertEpoch {
			if datestamp, ok := convertEpochToHumanReadable(key, value, epochUnit); ok {
				flattened[newKey+"_datestamp"] = datestamp
			}
		}
	}
	return flattened
}

// escapeCSVValue prepends a single quote to values that could cause CSV injection.
func escapeCSVValue(value string) string {
	if len(value) > 0 && (value[0] == '=' || value[0] == '+' || value[0] == '-' || value[0] == '@') {
		return "'" + value
	}
	return value
}

// FormatCSV formats claims into a CSV string
// Note: This implementation flattens nested claims and JSON stringifies complex types (maps and arrays).
// This approach aims to prevent data loss for complex JWT claims, but the resulting CSV cells
// containing JSON strings will require further parsing if direct access to nested data is needed.
// It also escapes values to prevent CSV injection.
func FormatCSV(claims jwt.MapClaims, convertEpoch bool, epochUnit string) ([]byte, error) {
	flattened := flattenClaims(claims, "", convertEpoch, epochUnit)

	var headers []string
	for key := range flattened {
		headers = append(headers, key)
	}
	sort.Strings(headers) // Sort headers for consistent output

	buf := new(bytes.Buffer)
	writer := csv.NewWriter(buf)

	// Write header row
	if err := writer.Write(headers); err != nil {
		return nil, fmt.Errorf("failed to write CSV header: %w", err)
	}

	// Write data row
	var row []string
	for _, header := range headers {
		row = append(row, escapeCSVValue(fmt.Sprintf("%v", flattened[header])))
	}
	if err := writer.Write(row); err != nil {
		return nil, fmt.Errorf("failed to write CSV row: %w", err)
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, fmt.Errorf("CSV writer error: %w", err)
	}

	return buf.Bytes(), nil
}

// XMLNode represents a generic XML element for marshaling
type XMLNode struct {
	XMLName xml.Name
	Attrs   []xml.Attr `xml:"-"`
	Content string     `xml:",chardata"`
	Nodes   []XMLNode  `xml:",any"`
}

// mapClaimsToXMLNode converts jwt.MapClaims to XMLNode structure
func mapClaimsToXMLNode(claims jwt.MapClaims, convertEpoch bool, epochUnit string) []XMLNode {
	var nodes []XMLNode
	for key, value := range claims {
		// Add human-readable timestamp for XML as an attribute or child element
		if convertEpoch {
			if datestamp, ok := convertEpochToHumanReadable(key, value, epochUnit); ok {
				nodes = append(nodes, XMLNode{
					XMLName: xml.Name{Local: key},
					Content: fmt.Sprintf("%v", value),
					Attrs:   []xml.Attr{{Name: xml.Name{Local: "datestamp"}, Value: datestamp}},
				})
				continue // Skip default handling for this claim as it's already processed
			}
		}

		switch v := value.(type) {
		case map[string]interface{}:
			nodes = append(nodes, XMLNode{
				XMLName: xml.Name{Local: key},
				Nodes:   mapClaimsToXMLNode(v, convertEpoch, epochUnit),
			})
		case []interface{}:
			arrayNode := XMLNode{XMLName: xml.Name{Local: key}}
			for _, item := range v {
				arrayNode.Nodes = append(arrayNode.Nodes, XMLNode{
					XMLName: xml.Name{Local: "item"},
					Content: fmt.Sprintf("%v", item),
				})
			}
			nodes = append(nodes, arrayNode)
		default:
			nodes = append(nodes, XMLNode{
				XMLName: xml.Name{Local: key},
				Content: fmt.Sprintf("%v", value),
			})
		}
	}
	return nodes
}

// FormatXML formats claims into an XML string
func FormatXML(claims jwt.MapClaims, convertEpoch bool, epochUnit string) ([]byte, error) {
	root := XMLNode{
		XMLName: xml.Name{Local: "JWTClaims"},
		Nodes:   mapClaimsToXMLNode(claims, convertEpoch, epochUnit),
	}

	// Add XML declaration and indent
	output, err := xml.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal XML: %w", err)
	}

	return append([]byte(xml.Header), output...), nil
}
