#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
import hmac
import json
import time
import requests
from typing import Dict, Any, Union, List
from collections import OrderedDict

# Constants
BASE_URL = "http://localhost:8080"
ACCESS_KEY = "your-access-key"
SECRET_KEY = "your-secret-key"


class OpenApiClient:
    """API client for CloudRec Open API"""

    def __init__(self, base_url: str = BASE_URL, access_key: str = ACCESS_KEY, secret_key: str = SECRET_KEY):
        """
        Initialize OpenApiClient

        Args:
            base_url: Base URL of the API server
            access_key: Access key for authentication
            secret_key: Secret key for signature generation
        """
        self.base_url = base_url
        self.access_key = access_key
        self.secret_key = secret_key
        self.session = requests.Session()
        self.session.timeout = 30

    def _generate_signature(self, access_key: str, timestamp: str, sorted_params: str, secret_key: str) -> str:
        """
        Generate SHA-256 signature for API authentication with enhanced parameter processing

        Args:
            access_key: Access key
            timestamp: Current timestamp in seconds
            sorted_params: Sorted query parameters string
            secret_key: Secret key

        Returns:
            SHA-256 signature in hex format
        """
        # Use secure string concatenation with delimiter to match Java version: accessKey|timestamp|sortedParams|secretKey
        delimiter = "|"
        data = f"{access_key}{delimiter}{timestamp}{delimiter}{sorted_params}{delimiter}{secret_key}"
        hash_obj = hashlib.sha256(data.encode('utf-8'))
        return hash_obj.hexdigest()

    def _process_object(self, result_map: Dict[str, str], key: str, value: Any) -> None:
        """
        Recursively process object to flatten complex objects (dict and list) into flat key-value pairs
        This approach provides better handling of nested structures

        Args:
            result_map: the original key-value collection that will be recursively updated
            key: the current processing key, which will contain nested path information as recursion deepens
            value: the value corresponding to the key, can be nested dict, list or other types
        """
        # If value is None, no further processing needed
        if value is None:
            return

        if key is None:
            key = ""

        # When value is list type, iterate through each element in the list and process recursively
        if isinstance(value, list):
            for i, item in enumerate(value):
                self._process_object(result_map, f"{key}.{i + 1}", item)
        elif isinstance(value, dict):
            # When value is dict type, iterate through each key-value pair in the dict and process recursively
            for sub_key, sub_value in value.items():
                self._process_object(result_map, f"{key}.{sub_key}", sub_value)
        else:
            # For keys starting with ".", remove the leading "." to maintain key continuity
            if key.startswith("."):
                key = key[1:]

            # For other types of values, convert to string with proper formatting
            if isinstance(value, bool):
                # Convert Python boolean to lowercase string (Java style)
                result_map[key] = str(value).lower()
            else:
                # For other types of values, convert directly to string
                result_map[key] = str(value)

    def _build_sorted_param_string(self, params: Union[Dict[str, Any], str, None]) -> str:
        """
        Build sorted parameter string from parameters with enhanced processing
        Handles complex nested objects and arrays through recursive flattening

        Args:
            params: Parameters object (can be dict, str, or simple values)

        Returns:
            Sorted parameter string
        """
        if params is None:
            return ""

        flattened_params = {}

        # If params is a string, try to parse as JSON
        if isinstance(params, str):
            try:
                # Validate if it's valid JSON
                parsed_params = json.loads(params)
                for key, value in parsed_params.items():
                    self._process_object(flattened_params, key, value)
            except json.JSONDecodeError:
                # If not valid JSON, treat as simple string parameter
                flattened_params["data"] = params
        elif isinstance(params, dict):
            # For dict type, process each key-value pair
            for key, value in params.items():
                if isinstance(value, str) and not any(c in value for c in ['{', '[', '"']):
                    # Simple string value
                    flattened_params[key] = value
                else:
                    # Complex value, use recursive processing
                    self._process_object(flattened_params, key, value)
        else:
            # For other types, convert to string
            flattened_params["data"] = str(params)

        # Sort parameters by key and build parameter string
        sorted_items = sorted(flattened_params.items())
        parts = [f"{key}={value}" for key, value in sorted_items]
        return "&".join(parts)

    def _to_json_string(self, params: Union[Dict[str, Any], str, None]) -> str:
        """
        Convert parameters to JSON string for request body

        Args:
            params: Parameters object

        Returns:
            JSON string
        """
        if params is None:
            return "{}"

        # If it's already a JSON string, return as is
        if isinstance(params, str):
            try:
                # Validate if it's valid JSON
                json.loads(params)
                return params
            except json.JSONDecodeError:
                # If not valid JSON, wrap in quotes
                return json.dumps(params)

        return json.dumps(params, ensure_ascii=False)

    def query_scan_result(self, params: Union[Dict[str, Any], str, None]) -> str:
        """
        Query scan result from Open API with enhanced parameter processing

        Args:
            params: Request parameters (can be dict, complex object, etc.)

        Returns:
            API response as string

        Raises:
            requests.RequestException: If request fails
        """
        try:
            timestamp = str(int(time.time()))

            # Build sorted parameter string using enhanced processing
            sorted_params = self._build_sorted_param_string(params)
            signature = self._generate_signature(self.access_key, timestamp, sorted_params, self.secret_key)

            # Convert parameters to JSON for request body
            json_body = self._to_json_string(params)

            url = f"{self.base_url}/api/open/v1/queryScanResult"

            # Prepare headers
            headers = {
                'access-key': self.access_key,
                'timestamp': timestamp,
                'sign': signature,
                'Content-Type': 'application/json'
            }

            # Send POST request
            response = self.session.post(url, data=json_body, headers=headers)

            # Return response body
            return response.text

        except requests.RequestException as e:
            raise Exception(f"HTTP request failed: {e}")
        except Exception as e:
            raise Exception(f"Failed to query scan result: {e}")

    def close(self):
        """
        Close the HTTP session
        """
        self.session.close()


def main():
    """Main function to demonstrate API usage with comprehensive test cases"""
    # Create API client
    client = OpenApiClient()

    try:
        # Example 1: Simple parameters (backward compatible)
        print("=== Example 1: Simple Parameters ===")
        simple_params = OrderedDict([
            ("tenantId", "1"),
            ("limit", "10"),
            ("scrollId", "0")
        ])

        result1 = client.query_scan_result(simple_params)
        print(f"API Response: {result1}")

        # Example 2: Complex nested object
        print("\n=== Example 2: Complex Nested Object ===")
        complex_params = {
            "tenantId": "1",
            "limit": "10",
            "filter": {
                "status": "active",
                "type": "security",
                "tags": ["critical", "high-priority", "urgent"],
                "dateRange": {
                    "start": "2024-01-01",
                    "end": "2024-12-31"
                }
            }
        }

        result2 = client.query_scan_result(complex_params)
        print(f"API Response: {result2}")

        # Example 3: Direct JSON object
        print("\n=== Example 3: Direct JSON Object ===")
        json_params = '{"tenantId":"1","settings":{"maxResults":100,"includeMetadata":true,"filters":["type1","type2"]}}'

        result3 = client.query_scan_result(json_params)
        print(f"API Response: {result3}")

        # Example 4: Empty parameters
        print("\n=== Example 4: Empty Parameters ===")
        empty_params = {}
        result4 = client.query_scan_result(empty_params)
        print(f"API Response: {result4}")

        # Example 5: Null values handling
        print("\n=== Example 5: Null Values Handling ===")
        null_params = {
            "tenantId": "1",
            "nullField": None,
            "emptyString": ""
        }
        result5 = client.query_scan_result(null_params)
        print(f"API Response: {result5}")

        # Example 6: Mixed data types
        print("\n=== Example 6: Mixed Data Types ===")
        mixed_params = {
            "tenantId": "1",
            "intValue": 42,
            "longValue": 9876543210,
            "doubleValue": 3.14,
            "boolValue": True
        }
        result6 = client.query_scan_result(mixed_params)
        print(f"API Response: {result6}")

        # Example 7: Deeply nested structure
        print("\n=== Example 7: Deeply Nested Structure ===")
        deep_params = {
            "tenantId": "1",
            "nested": {
                "level1Value": "top",
                "level2": {
                    "level2Value": "middle",
                    "level3": {
                        "deepValue": "found",
                        "deepArray": ["a", "b", "c"]
                    }
                }
            }
        }
        result7 = client.query_scan_result(deep_params)
        print(f"API Response: {result7}")

        # Example 8: Array of objects
        print("\n=== Example 8: Array of Objects ===")
        array_params = {
            "tenantId": "1",
            "objects": [
                {
                    "id": "1",
                    "name": "Object1",
                    "tags": ["tag1", "tag2"]
                },
                {
                    "id": "2",
                    "name": "Object2",
                    "active": True
                }
            ]
        }
        result8 = client.query_scan_result(array_params)
        print(f"API Response: {result8}")

        # Example 9: Special characters in values
        print("\n=== Example 9: Special Characters ===")
        special_params = {
            "tenantId": "1",
            "specialChars": "Hello & World! @#$%^&*()_+-={}[]|\\:;\"'<>?,./",
            "unicode": "测试中文字符 🚀 emoji",
            "urlEncoded": "param=value&other=test"
        }
        result9 = client.query_scan_result(special_params)
        print(f"API Response: {result9}")

        # Example 10: Large parameter set
        print("\n=== Example 10: Large Parameter Set ===")
        large_params = {"tenantId": "1"}

        # Add many parameters to test sorting and performance
        for i in range(1, 21):
            large_params[f"param{i:02d}"] = f"value{i}"

        # Add nested structure within large set
        large_nested = {}
        for i in range(1, 11):
            large_nested[f"nested{i}"] = f"nestedValue{i}"
        large_params["nestedParams"] = large_nested

        result10 = client.query_scan_result(large_params)
        print(f"API Response: {result10}")

        # Debug: Show how parameters are flattened for different examples
        print("\n=== Debug: Parameter Flattening Examples ===")

        print("Complex nested flattening:")
        sorted_params1 = client._build_sorted_param_string(complex_params)
        print(sorted_params1)

        print("\nDeep nested flattening:")
        sorted_params2 = client._build_sorted_param_string(deep_params)
        print(sorted_params2)

        print("\nArray of objects flattening:")
        sorted_params3 = client._build_sorted_param_string(array_params)
        print(sorted_params3)

    except Exception as e:
        print(f"Error: {e}")
    finally:
        # Clean up
        client.close()


if __name__ == "__main__":
    main()