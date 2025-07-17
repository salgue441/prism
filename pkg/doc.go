// Package pkg contains reusable packages that can be imported by external
// projects.
//
// This package follows Go's convention for shareable library code that provides
// utility functions and common patterns used across the API gateway and
// potentially other applications.
//
// The pkg directory contains packages that:
//
//   - Have stable, well-defined APIs
//   - Provide general-purpose functionality
//   - Can be safely imported by external projects
//   - Follow semantic versioning for compatibility
//
// Subpackages:
//
//	logger - Structured logging utilities and configuration
//	utils  - Common HTTP utilities and helper functions
//
// Design Principles:
//
// All packages in pkg/ are designed with the following principles:
//
//   - Minimal dependencies to reduce coupling
//   - Clear, documented APIs with examples
//   - Comprehensive test coverage
//   - Backward compatibility guarantees
//   - Thread-safe operations where applicable
//
// Import Path:
//
// External projects can import these packages using:
//
//	import "github.com/salgue441/api-gateway/pkg/logger"
//	import "github.com/salgue441/api-gateway/pkg/utils"
//
// Stability:
//
// Packages in pkg/ are considered stable and follow semantic versioning.
// Breaking changes will only be introduced in major version updates with
// proper deprecation notices and migration guides.
package pkg
