package com.alipay.application.service.system.utils;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Enhanced OpenAPI Client with improved parameter processing and signature generation
 * Supports complex nested objects and arrays with recursive flattening
 */
public class OpenApiClientJavaDemo {

    private static final String BASE_URL = "http://localhost:8080";
    private static final String ACCESS_KEY = "your-access-key";
    private static final String SECRET_KEY = "your-secret-key";
    private static final String DELIMITER = "|";

    /**
     * Generate SHA-256 signature for API authentication with enhanced parameter processing
     *
     * @param timestamp    Current timestamp in seconds
     * @param sortedParams Sorted query parameters string
     * @return SHA-256 signature in hex format
     */
    private static String generateSignature(String timestamp,
                                            String sortedParams)
            throws NoSuchAlgorithmException {
        // Use secure string concatenation with delimiter: accessKey|timestamp|sortedParams|secretKey
        String data = OpenApiClientJavaDemo.ACCESS_KEY + DELIMITER + timestamp + DELIMITER + sortedParams + DELIMITER + OpenApiClientJavaDemo.SECRET_KEY;
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(data.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(hash);
    }

    /**
     * Convert byte array to lowercase hexadecimal string
     * @param bytes byte array to convert
     * @return lowercase hexadecimal string
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * Build sorted parameter string from parameters map with enhanced processing
     * Handles complex nested objects and arrays through recursive flattening
     *
     * @param params Parameters object (can be Map, List, or simple values)
     * @return Sorted parameter string
     */
    private static String buildSortedParamString(Object params) {
        if (params == null) {
            return "";
        }

        Map<String, String> flattenedParams = new LinkedHashMap<>();

        // If params is already a Map<String, String>, use it directly
        if (params instanceof Map) {
            Map<?, ?> paramMap = (Map<?, ?>) params;
            for (Map.Entry<?, ?> entry : paramMap.entrySet()) {
                if (entry.getValue() instanceof String) {
                    flattenedParams.put(entry.getKey().toString(), (String) entry.getValue());
                } else {
                    // For complex values, use recursive processing
                    Map<String, Object> tempMap = new HashMap<>();
                    processObject(tempMap, entry.getKey().toString(), entry.getValue());
                    for (Map.Entry<String, Object> flatEntry : tempMap.entrySet()) {
                        flattenedParams.put(flatEntry.getKey(), flatEntry.getValue().toString());
                    }
                }
            }
        } else {
            // For other types, convert to JSON and then process
//            String jsonString = JSON.toJSONString(params);
            JSONObject jsonObject = JSON.parseObject(params.toString());
            Map<String, Object> tempMap = new HashMap<>();
            for (String key : jsonObject.keySet()) {
                processObject(tempMap, key, jsonObject.get(key));
            }
            for (Map.Entry<String, Object> entry : tempMap.entrySet()) {
                flattenedParams.put(entry.getKey(), entry.getValue().toString());
            }
        }

        // Sort parameters by key and build parameter string
        return flattenedParams.entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .map(entry -> entry.getKey() + "=" + entry.getValue())
                .collect(Collectors.joining("&"));
    }

    /**
     * Recursively process object to flatten complex objects (Map and List) into flat key-value pairs
     * This approach provides better handling of nested structures
     *
     * @param map   the original key-value collection that will be recursively updated
     * @param key   the current processing key, which will contain nested path information as recursion deepens
     * @param value the value corresponding to the key, can be nested Map, List or other types
     */
    private static void processObject(Map<String, Object> map, String key, Object value) {
        // If value is null, no further processing needed
        if (value == null) {
            return;
        }

        if (key == null) {
            key = "";
        }

        // When value is List type, iterate through each element in the List and process recursively
        if (value instanceof List<?>) {
            List<?> list = (List<?>) value;
            for (int i = 0; i < list.size(); ++i) {
                processObject(map, key + "." + (i + 1), list.get(i));
            }
        } else if (value instanceof Map<?, ?>) {
            // When value is Map type, iterate through each key-value pair in the Map and process recursively
            Map<?, ?> subMap = (Map<?, ?>) value;
            for (Map.Entry<?, ?> entry : subMap.entrySet()) {
                processObject(map, key + "." + entry.getKey().toString(), entry.getValue());
            }
        } else if (value instanceof JSONArray) {
            // Handle JSONArray from fastjson
            JSONArray array = (JSONArray) value;
            for (int i = 0; i < array.size(); i++) {
                processObject(map, key + "." + (i + 1), array.get(i));
            }
        } else if (value instanceof JSONObject) {
            // Handle JSONObject from fastjson
            JSONObject obj = (JSONObject) value;
            for (String objKey : obj.keySet()) {
                processObject(map, key + "." + objKey, obj.get(objKey));
            }
        } else {
            // For keys starting with ".", remove the leading "." to maintain key continuity
            if (key.startsWith(".")) {
                key = key.substring(1);
            }

            // For byte[] type values, convert them to UTF-8 encoded strings
            if (value instanceof byte[]) {
                map.put(key, new String((byte[]) value, StandardCharsets.UTF_8));
            } else {
                // For other types of values, convert directly to string
                map.put(key, String.valueOf(value));
            }
        }
    }

    /**
     * Convert parameters to JSON string for request body
     * @param params Parameters object
     * @return JSON string
     */
    private static String toJsonString(Object params) {
        if (params == null) {
            return "{}";
        }

        // If it's already a JSON string, return as is
        if (params instanceof String) {
            try {
                // Validate if it's valid JSON
                JSON.parse((String) params);
                return (String) params;
            } catch (Exception e) {
                // If not valid JSON, wrap in quotes
                return JSON.toJSONString(params);
            }
        }

        return JSON.toJSONString(params);
    }

    /**
     * Query scan result from Open API with enhanced parameter processing
     * @param params Request parameters (can be Map, complex object, etc.)
     * @return API response
     */
    public static String queryScanResult(Object params)
            throws IOException, InterruptedException,
            NoSuchAlgorithmException {
        String timestamp = String.valueOf(Instant.now().getEpochSecond());

        // Build sorted parameter string using enhanced processing
        String sortedParams = buildSortedParamString(params);
        String signature = generateSignature(timestamp, sortedParams);

        // Convert parameters to JSON for request body
        String jsonBody = toJsonString(params);

        String url = BASE_URL + "/api/open/v1/queryScanResult";

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("version", "v2")
                .header("access-key", ACCESS_KEY)
                .header("timestamp", timestamp)
                .header("sign", signature)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                .build();

        HttpResponse<String> response = client.send(request,
                HttpResponse.BodyHandlers.ofString());
        return response.body();
    }

    public static void main(String[] args) {
        try {
            // Example 1: Simple parameters (backward compatible)
            System.out.println("=== Example 1: Simple Parameters ===");
            LinkedHashMap<String, String> simpleParams = new LinkedHashMap<>();
            simpleParams.put("tenantId", "1");
            simpleParams.put("limit", "10");
            simpleParams.put("scrollId", "0");

            String result1 = queryScanResult(simpleParams);
            System.out.println("API Response: " + result1);

            // Example 2: Complex nested object
            System.out.println("\n=== Example 2: Complex Nested Object ===");
            Map<String, Object> complexParams = new LinkedHashMap<>();
            complexParams.put("tenantId", "1");
            complexParams.put("limit", "10");

            // Nested filter object
            Map<String, Object> filter = new LinkedHashMap<>();
            filter.put("status", "active");
            filter.put("type", "security");

            // Nested array
            List<String> tags = Arrays.asList("critical", "high-priority", "urgent");
            filter.put("tags", tags);

            // Nested object within filter
            Map<String, Object> dateRange = new LinkedHashMap<>();
            dateRange.put("start", "2024-01-01");
            dateRange.put("end", "2024-12-31");
            filter.put("dateRange", dateRange);

            complexParams.put("filter", filter);

            String result2 = queryScanResult(complexParams);
            System.out.println("API Response: " + result2);

            // Example 3: Direct JSON object
            System.out.println("\n=== Example 3: Direct JSON Object ===");
            String jsonParams = "{\"tenantId\":\"1\",\"settings\":{\"maxResults\":100,\"includeMetadata\":true,\"filters\":[\"type1\",\"type2\"]}}";

            String result3 = queryScanResult(jsonParams);
            System.out.println("API Response: " + result3);

            // Debug: Show how parameters are flattened
            System.out.println("\n=== Debug: Parameter Flattening ===");
            String sortedParams = buildSortedParamString(complexParams);
            System.out.println("Flattened and sorted parameters: " + sortedParams);


           // Nested filter object

            // Example 4: Empty parameters
            System.out.println("\n=== Example 4: Empty Parameters ===");
            Map<String, Object> emptyParams = new LinkedHashMap<>();
            String result4 = queryScanResult(emptyParams);
            System.out.println("API Response: " + result4);

            // Example 5: Null values handling
            System.out.println("\n=== Example 5: Null Values Handling ===");
            Map<String, Object> nullParams = new LinkedHashMap<>();
            nullParams.put("tenantId", "1");
            nullParams.put("nullField", null);
            nullParams.put("emptyString", "");
            String result5 = queryScanResult(nullParams);
            System.out.println("API Response: " + result5);

            // Example 6: Mixed data types
            System.out.println("\n=== Example 6: Mixed Data Types ===");
            Map<String, Object> mixedParams = new LinkedHashMap<>();
            mixedParams.put("tenantId", "1");
            mixedParams.put("intValue", 42);
            mixedParams.put("boolValue", true);
            mixedParams.put("doubleValue", 3.14);
            mixedParams.put("longValue", 9876543210L);
            String result6 = queryScanResult(mixedParams);
            System.out.println("API Response: " + result6);

            // Example 7: Deeply nested structure
            System.out.println("\n=== Example 7: Deeply Nested Structure ===");
            Map<String, Object> deepParams = new LinkedHashMap<>();
            deepParams.put("tenantId", "1");

            Map<String, Object> level1 = new LinkedHashMap<>();
            Map<String, Object> level2 = new LinkedHashMap<>();
            Map<String, Object> level3 = new LinkedHashMap<>();

            level3.put("deepValue", "found");
            level3.put("deepArray", Arrays.asList("a", "b", "c"));
            level2.put("level3", level3);
            level2.put("level2Value", "middle");
            level1.put("level2", level2);
            level1.put("level1Value", "top");
            deepParams.put("nested", level1);

            String result7 = queryScanResult(deepParams);
            System.out.println("API Response: " + result7);

            // Example 8: Array of objects
            System.out.println("\n=== Example 8: Array of Objects ===");
            Map<String, Object> arrayParams = new LinkedHashMap<>();
            arrayParams.put("tenantId", "1");

            List<Map<String, Object>> objectArray = new ArrayList<>();
            Map<String, Object> obj1 = new LinkedHashMap<>();
            obj1.put("id", "1");
            obj1.put("name", "Object1");
            obj1.put("tags", Arrays.asList("tag1", "tag2"));

            Map<String, Object> obj2 = new LinkedHashMap<>();
            obj2.put("id", "2");
            obj2.put("name", "Object2");
            obj2.put("active", true);

            objectArray.add(obj1);
            objectArray.add(obj2);
            arrayParams.put("objects", objectArray);

            String result8 = queryScanResult(arrayParams);
            System.out.println("API Response: " + result8);

            // Example 9: Special characters in values
            System.out.println("\n=== Example 9: Special Characters ===");
            Map<String, Object> specialParams = new LinkedHashMap<>();
            specialParams.put("tenantId", "1");
            specialParams.put("specialChars", "Hello & World! @#$%^&*()_+-={}[]|\\:;\"'<>?,./");
            specialParams.put("unicode", "测试中文字符 🚀 emoji");
            specialParams.put("urlEncoded", "param=value&other=test");
            String result9 = queryScanResult(specialParams);
            System.out.println("API Response: " + result9);

            // Example 10: Large parameter set
            System.out.println("\n=== Example 10: Large Parameter Set ===");
            Map<String, Object> largeParams = new LinkedHashMap<>();
            largeParams.put("tenantId", "1");

            // Add many parameters to test sorting and performance
            for (int i = 1; i <= 20; i++) {
                largeParams.put("param" + String.format("%02d", i), "value" + i);
            }

            // Add nested structure within large set
            Map<String, Object> largeNested = new LinkedHashMap<>();
            for (int i = 1; i <= 10; i++) {
                largeNested.put("nested" + i, "nestedValue" + i);
            }
            largeParams.put("nestedParams", largeNested);

            String result10 = queryScanResult(largeParams);
            System.out.println("API Response: " + result10);

            // Debug: Show how parameters are flattened for different examples
            System.out.println("\n=== Debug: Parameter Flattening Examples ===");

            System.out.println("Complex nested flattening:");
            String sortedParams1 = buildSortedParamString(complexParams);
            System.out.println(sortedParams1);

            System.out.println("\nDeep nested flattening:");
            String sortedParams2 = buildSortedParamString(deepParams);
            System.out.println(sortedParams2);

            System.out.println("\nArray of objects flattening:");
            String sortedParams3 = buildSortedParamString(arrayParams);
            System.out.println(sortedParams3);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}