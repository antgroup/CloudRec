package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	BASE_URL   = "http://localhost:8080"
	ACCESS_KEY = "your-access-key"
	SECRET_KEY = "your-secret-key"
)

// OpenApiClient represents the API client for CloudRec Open API
type OpenApiClient struct {
	baseURL   string
	accessKey string
	secretKey string
	client    *http.Client
}

// NewOpenApiClient creates a new instance of OpenApiClient
func NewOpenApiClient() *OpenApiClient {
	return &OpenApiClient{
		baseURL:   BASE_URL,
		accessKey: ACCESS_KEY,
		secretKey: SECRET_KEY,
		client:    &http.Client{Timeout: 30 * time.Second},
	}
}

// generateSignature generates SHA-256 signature for API authentication
func (c *OpenApiClient) generateSignature(accessKey, timestamp, sortedParams, secretKey string) string {
	data := fmt.Sprintf("%s|%s|%s|%s", accessKey, timestamp, sortedParams, secretKey)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash)
}

// buildSortedParamString builds sorted parameter string with enhanced processing
// Handles complex nested objects and arrays through recursive flattening
func (c *OpenApiClient) buildSortedParamString(params interface{}) string {
	if params == nil {
		return ""
	}

	flattenedParams := make(map[string]string)

	// Handle different parameter types
	switch p := params.(type) {
	case string:
		// If it's a JSON string, parse it first
		var jsonData interface{}
		if err := json.Unmarshal([]byte(p), &jsonData); err == nil {
			c.processObject(flattenedParams, "", jsonData)
		} else {
			// If not valid JSON, treat as simple string parameter
			flattenedParams["data"] = p
		}
	case map[string]interface{}:
		// Handle map[string]interface{}
		for key, value := range p {
			c.processObject(flattenedParams, key, value)
		}
	case map[string]string:
		// Handle simple string map
		for key, value := range p {
			flattenedParams[key] = value
		}
	default:
		// For other types, convert to JSON and process
		jsonBytes, err := json.Marshal(params)
		if err == nil {
			var jsonData interface{}
			if json.Unmarshal(jsonBytes, &jsonData) == nil {
				c.processObject(flattenedParams, "", jsonData)
			}
		}
	}

	// Sort parameters by key and build parameter string
	keys := make([]string, 0, len(flattenedParams))
	for k := range flattenedParams {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var parts []string
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", key, flattenedParams[key]))
	}

	return strings.Join(parts, "&")
}

// processObject recursively processes object to flatten complex objects (Map and List) into flat key-value pairs
// This approach provides better handling of nested structures
func (c *OpenApiClient) processObject(resultMap map[string]string, key string, value interface{}) {
	if value == nil {
		return
	}

	// Handle different value types using reflection
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Slice, reflect.Array:
		// Handle arrays/slices
		for i := 0; i < v.Len(); i++ {
			newKey := fmt.Sprintf("%s.%d", key, i+1)
			c.processObject(resultMap, newKey, v.Index(i).Interface())
		}
	case reflect.Map:
		// Handle maps
		for _, mapKey := range v.MapKeys() {
			mapValue := v.MapIndex(mapKey)
			newKey := fmt.Sprintf("%s.%s", key, mapKey.String())
			c.processObject(resultMap, newKey, mapValue.Interface())
		}
	default:
		// Handle primitive types
		if strings.HasPrefix(key, ".") {
			key = key[1:] // Remove leading dot
		}

		// Convert boolean values to lowercase strings (Java style)
		if b, ok := value.(bool); ok {
			resultMap[key] = strings.ToLower(strconv.FormatBool(b))
		} else {
			resultMap[key] = fmt.Sprintf("%v", value)
		}
	}
}

// toJSONString converts parameters to JSON string for request body
func (c *OpenApiClient) toJSONString(params interface{}) (string, error) {
	if params == nil {
		return "{}", nil
	}

	// If it's already a JSON string, validate and return
	if str, ok := params.(string); ok {
		var temp interface{}
		if json.Unmarshal([]byte(str), &temp) == nil {
			return str, nil
		}
		// If not valid JSON, marshal it as a string
		jsonBytes, err := json.Marshal(str)
		return string(jsonBytes), err
	}

	// For other types, marshal to JSON
	jsonBytes, err := json.Marshal(params)
	if err != nil {
		return "", err
	}

	return string(jsonBytes), nil
}

// QueryScanResult queries scan result from Open API with enhanced parameter processing
func (c *OpenApiClient) QueryScanResult(params interface{}) (string, error) {
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	// Build sorted parameter string using enhanced processing
	sortedParams := c.buildSortedParamString(params)
	signature := c.generateSignature(c.accessKey, timestamp, sortedParams, c.secretKey)

	// Convert parameters to JSON for request body
	jsonBody, err := c.toJSONString(params)
	if err != nil {
		return "", fmt.Errorf("failed to convert params to JSON: %w", err)
	}

	url := c.baseURL + "/api/open/v1/queryScanResult"

	// Create HTTP request
	req, err := http.NewRequest("POST", url, bytes.NewBufferString(jsonBody))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("access-key", c.accessKey)
	req.Header.Set("timestamp", timestamp)
	req.Header.Set("sign", signature)
	req.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	return string(body), nil
}

func main() {
	// Create API client
	client := NewOpenApiClient()

	// Example 1: Simple parameters (backward compatible)
	fmt.Println("=== Example 1: Simple Parameters ===")
	simpleParams := map[string]string{
		"tenantId": "1",
		"limit":    "10",
		"scrollId": "0",
	}

	result1, err := client.QueryScanResult(simpleParams)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("API Response: %s\n", result1)
	}

	// Example 2: Complex nested object
	fmt.Println("\n=== Example 2: Complex Nested Object ===")
	complexParams := map[string]interface{}{
		"tenantId": "1",
		"limit":    "10",
		"filter": map[string]interface{}{
			"status": "active",
			"type":   "security",
			"tags":   []string{"critical", "high-priority", "urgent"},
			"dateRange": map[string]interface{}{
				"start": "2024-01-01",
				"end":   "2024-12-31",
			},
		},
	}

	result2, err := client.QueryScanResult(complexParams)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("API Response: %s\n", result2)
	}

	// Example 3: Direct JSON object
	fmt.Println("\n=== Example 3: Direct JSON Object ===")
	jsonParams := `{"tenantId":"1","settings":{"maxResults":100,"includeMetadata":true,"filters":["type1","type2"]}}`

	result3, err := client.QueryScanResult(jsonParams)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("API Response: %s\n", result3)
	}

	// Example 4: Empty parameters
	fmt.Println("\n=== Example 4: Empty Parameters ===")
	emptyParams := map[string]interface{}{}
	result4, err := client.QueryScanResult(emptyParams)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("API Response: %s\n", result4)
	}

	// Example 5: Null values handling
	fmt.Println("\n=== Example 5: Null Values Handling ===")
	nullParams := map[string]interface{}{
		"tenantId":    "1",
		"nullField":   nil,
		"emptyString": "",
	}
	result5, err := client.QueryScanResult(nullParams)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("API Response: %s\n", result5)
	}

	// Example 6: Mixed data types
	fmt.Println("\n=== Example 6: Mixed Data Types ===")
	mixedParams := map[string]interface{}{
		"tenantId":    "1",
		"intValue":    42,
		"longValue":   int64(9876543210),
		"doubleValue": 3.14,
		"boolValue":   true,
	}
	result6, err := client.QueryScanResult(mixedParams)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("API Response: %s\n", result6)
	}

	// Example 7: Deeply nested structure
	fmt.Println("\n=== Example 7: Deeply Nested Structure ===")
	deepParams := map[string]interface{}{
		"tenantId": "1",
		"nested": map[string]interface{}{
			"level1Value": "top",
			"level2": map[string]interface{}{
				"level2Value": "middle",
				"level3": map[string]interface{}{
					"deepValue": "found",
					"deepArray": []string{"a", "b", "c"},
				},
			},
		},
	}
	result7, err := client.QueryScanResult(deepParams)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("API Response: %s\n", result7)
	}

	// Example 8: Array of objects
	fmt.Println("\n=== Example 8: Array of Objects ===")
	arrayParams := map[string]interface{}{
		"tenantId": "1",
		"objects": []map[string]interface{}{
			{
				"id":   "1",
				"name": "Object1",
				"tags": []string{"tag1", "tag2"},
			},
			{
				"id":     "2",
				"name":   "Object2",
				"active": true,
			},
		},
	}
	result8, err := client.QueryScanResult(arrayParams)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("API Response: %s\n", result8)
	}

	// Example 9: Special characters
	fmt.Println("\n=== Example 9: Special Characters ===")
	specialParams := map[string]interface{}{
		"tenantId": "1",
		"query":    "test@example.com",
		"path":     "/api/v1/test",
		"encoded":  "hello%20world",
	}
	result9, err := client.QueryScanResult(specialParams)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("API Response: %s\n", result9)
	}

	// Example 10: Large parameter set
	fmt.Println("\n=== Example 10: Large Parameter Set ===")
	largeParams := map[string]interface{}{
		"tenantId": "1",
	}
	for i := 1; i <= 20; i++ {
		largeParams[fmt.Sprintf("param%d", i)] = fmt.Sprintf("value%d", i)
	}
	result10, err := client.QueryScanResult(largeParams)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("API Response: %s\n", result10)
	}

	// Debug: Parameter Flattening Examples
	fmt.Println("\n=== Debug: Parameter Flattening Examples ===")
	fmt.Println("Complex nested flattening:")
	fmt.Println(client.buildSortedParamString(complexParams))

	fmt.Println("\nDeep nested flattening:")
	fmt.Println(client.buildSortedParamString(deepParams))

	fmt.Println("\nArray of objects flattening:")
	fmt.Println(client.buildSortedParamString(arrayParams))
}
