// Package config provides configuration management for the API gateway.
//
// This package handles loading, parsing, and validating configuration from
// multiple sources including files (JSON/YAML) and environment variables.
// It supports a hierarchical configuration approach where environment
// variables can override file-based settings.
//
// Configuration Sources (in order of precedence):
//
//  1. Environment variables (highest priority)
//  2. Configuration files (JSON or YAML)
//  3. Default values (lowest priority)
//
// Supported Configuration Formats:
//
//   - JSON (.json)
//   - YAML (.yaml, .yml)
//
// Environment Variable Mapping:
//
// All configuration values can be overridden using environment variables
// with the GATEWAY_ prefix. Nested structures use underscore separation.
//
// Examples:
//
//	GATEWAY_SERVER_PORT=8080
//	GATEWAY_SERVER_HOST=localhost
//	GATEWAY_SERVER_READ_TIMEOUT=30s
//
// Configuration Structure:
//
// The main configuration consists of server settings and routing rules.
// Server settings control HTTP server behavior including timeouts and
// bind address. Routes define how incoming requests are proxied to
// backend services.
//
// Example configuration:
//
//	{
//	  "server": {
//	    "port": 8080,
//	    "host": "0.0.0.0",
//	    "read_timeout": "30s"
//	  },
//	  "routes": [
//	    {
//	      "id": "users-api",
//	      "path": "/api/users",
//	      "target": "http://localhost:3001"
//	    }
//	  ]
//	}
//
// Validation:
//
// All configuration is validated on load to ensure required fields are
// present and values are within acceptable ranges. Invalid configuration
// will cause the application to fail fast during startup.
package config
