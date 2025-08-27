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

// PreprocessClaims iterates through the claims and, if enabled, adds human-readable
// datestamps for any epoch values it finds. This should be called once after parsing.
func PreprocessClaims(claims jwt.MapClaims, convertEpoch bool, epochUnit string) jwt.MapClaims {
	if !convertEpoch {
		return claims
	}

	processedClaims := make(jwt.MapClaims, len(claims))
	for key, value := range claims {
		processedClaims[key] = value
		// Check and add datestamp if applicable
		if datestamp, ok := convertEpochToHumanReadable(key, value, epochUnit); ok {
			processedClaims[key+"_datestamp"] = datestamp
		}
	}
	return processedClaims
}

// convertEpochToHumanReadable attempts to convert a value to a human-readable date string.
func convertEpochToHumanReadable(key string, value interface{}, epochUnit string) (string, bool) {
	// Only convert claims that are commonly epoch timestamps
	isEpochKey := false
	switch key {
	case ClaimIAT, ClaimEXP, ClaimNBF, ClaimAuthTime:
		isEpochKey = true
	}
	if !isEpochKey {
		return "", false
	}

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
		if timestamp > 1e11 { // Heuristic: very large numbers are likely ms/us/ns
			tm = time.Unix(0, timestamp*int64(time.Millisecond))
		} else { // Assume seconds
			tm = time.Unix(timestamp, 0)
		}
	}
	return tm.UTC().Format("2006-01-02 15:04:05 UTC"), true
}

// FormatJSON formats claims into a JSON string.
func FormatJSON(claims jwt.MapClaims) ([]byte, error) {
	return json.MarshalIndent(claims, "", "  ")
}

// FormatCSV formats claims into a CSV string.
func FormatCSV(claims jwt.MapClaims) ([]byte, error) {
	// CSV still requires flattening, but the epoch conversion is already done.
	flattened := flattenClaimsForCSV(claims)

	var headers []string
	for key := range flattened {
		headers = append(headers, key)
	}
	sort.Strings(headers)

	buf := new(bytes.Buffer)
	writer := csv.NewWriter(buf)

	if err := writer.Write(headers); err != nil {
		return nil, fmt.Errorf("failed to write CSV header: %w", err)
	}

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

// flattenClaimsForCSV recursively flattens claims for CSV output.
func flattenClaimsForCSV(claims jwt.MapClaims) map[string]interface{} {
	flattened := make(map[string]interface{})
	for key, value := range claims {
		switch v := value.(type) {
		case map[string]interface{}:
			jsonBytes, _ := json.Marshal(v)
			flattened[key] = string(jsonBytes)
		case []interface{}:
			jsonBytes, _ := json.Marshal(v)
			flattened[key] = string(jsonBytes)
		default:
			flattened[key] = value
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

// FormatXML formats claims into an XML string.
func FormatXML(claims jwt.MapClaims) ([]byte, error) {
	root := XMLNode{
		XMLName: xml.Name{Local: "JWTClaims"},
		Nodes:   mapClaimsToXMLNodes(claims),
	}
	output, err := xml.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal XML: %w", err)
	}
	return append([]byte(xml.Header), output...), nil
}

// XMLNode represents a generic XML element.
type XMLNode struct {
	XMLName xml.Name
	Content string    `xml:",chardata"`
	Nodes   []XMLNode `xml:",any"`
}

// mapClaimsToXMLNodes converts map claims to a slice of XMLNode.
func mapClaimsToXMLNodes(claims jwt.MapClaims) []XMLNode {
	var nodes []XMLNode
	// Sort keys for consistent XML output
	keys := make([]string, 0, len(claims))
	for k := range claims {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		value := claims[key]
		switch v := value.(type) {
		case map[string]interface{}:
			nodes = append(nodes, XMLNode{
				XMLName: xml.Name{Local: key},
				Nodes:   mapClaimsToXMLNodes(v),
			})
		case []interface{}:
			arrayNode := XMLNode{XMLName: xml.Name{Local: key}}
			for i, item := range v {
				arrayNode.Nodes = append(arrayNode.Nodes, XMLNode{
					XMLName: xml.Name{Local: fmt.Sprintf("item_%d", i+1)},
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
