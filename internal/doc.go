// Package internal contains private application packages that cannot be
// imported by external projects.
//
// This package follows Go's internal package convention to enforce
// architectural boundaries and prevent external dependencies on
// implementation details.
//
// Subpackages:
//
//	config   - Configuration management and validation
//	gateway  - Core gateway orchestration and HTTP server setup
//	router   - HTTP request routing and route management
//	proxy    - Reverse proxy implementation and request forwarding
//
// The internal packages implement the core business logic of the API gateway
// using clean architecture principles with clear separation of concerns.
package internal
