//go:build mage
// +build mage

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/magefile/mage/sh"
)

// Variables
const (
	binaryDir  = "bin"
	protoDir   = "services/shared/proto"
	protoOut   = "services/shared/proto/gen"
	goFlags    = "-v"
	ldFlags    = "-s -w"
)

// All builds everything.
func All() error {
	if err := Proto(); err != nil {
		return err
	}
	return Build()
}

// ============================================================================
// Build targets
// ============================================================================

// Build builds all services.
func Build() error {
	if err := BuildGateway(); err != nil {
		return err
	}
	if err := BuildAuth(); err != nil {
		return err
	}
	return BuildConfig()
}

// BuildGateway builds the gateway service.
func BuildGateway() error {
	fmt.Println("Building gateway...")
	if err := os.MkdirAll(binaryDir, 0755); err != nil {
		return err
	}
	return sh.Run("go", "build", goFlags, "-ldflags", ldFlags, "-o", filepath.Join(binaryDir, "gateway"), "./services/gateway/cmd")
}

// BuildAuth builds the auth service.
func BuildAuth() error {
	fmt.Println("Building auth service...")
	if err := os.MkdirAll(binaryDir, 0755); err != nil {
		return err
	}
	return sh.Run("go", "build", goFlags, "-ldflags", ldFlags, "-o", filepath.Join(binaryDir, "auth"), "./services/auth/cmd")
}

// BuildConfig builds the config service.
func BuildConfig() error {
	fmt.Println("Building config service...")
	if err := os.MkdirAll(binaryDir, 0755); err != nil {
		return err
	}
	return sh.Run("go", "build", goFlags, "-ldflags", ldFlags, "-o", filepath.Join(binaryDir, "config"), "./services/config/cmd")
}

// ============================================================================
// Development targets
// ============================================================================

// RunGateway runs the gateway service locally.
func RunGateway() error {
	return sh.Run("go", "run", "./services/gateway/cmd")
}

// RunAuth runs the auth service locally.
func RunAuth() error {
	return sh.Run("go", "run", "./services/auth/cmd")
}

// RunConfig runs the config service locally.
func RunConfig() error {
	return sh.Run("go", "run", "./services/config/cmd")
}

// ============================================================================
// Protocol Buffers
// ============================================================================

// Proto generates protobuf code.
func Proto() error {
	fmt.Println("Generating protobuf code...")
	if err := os.MkdirAll(protoOut, 0755); err != nil {
		return err
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	return sh.Run("protoc",
		"--go_out="+protoOut,
		"--go_opt=paths=source_relative",
		"--go-grpc_out="+protoOut,
		"--go-grpc_opt=paths=source_relative",
		"-I", protoDir,
		"-I", filepath.Join(home, ".local/include"),
		filepath.Join(protoDir, "*.proto"),
	)
}

// ProtoClean cleans generated protobuf files.
func ProtoClean() error {
	return os.RemoveAll(protoOut)
}

// ============================================================================
// Testing
// ============================================================================

// Test runs all tests.
func Test() error {
	return sh.Run("go", "test", "-v", "-race", "-cover", "./...")
}

// TestUnit runs unit tests only.
func TestUnit() error {
	return sh.Run("go", "test", "-v", "-race", "-cover", "-short", "./...")
}

// TestIntegration runs integration tests.
func TestIntegration() error {
	return sh.Run("go", "test", "-v", "-race", "-cover", "-run", "Integration", "./...")
}

// TestCoverage generates test coverage report.
func TestCoverage() error {
	if err := sh.Run("go", "test", "-v", "-race", "-coverprofile=coverage.out", "./..."); err != nil {
		return err
	}
	if err := sh.Run("go", "tool", "cover", "-html=coverage.out", "-o", "coverage.html"); err != nil {
		return err
	}
	fmt.Println("Coverage report generated: coverage.html")
	return nil
}

// Bench runs benchmarks.
func Bench() error {
	return sh.Run("go", "test", "-bench=.", "-benchmem", "./...")
}

// ============================================================================
// Code quality
// ============================================================================

// Lint runs the linter.
func Lint() error {
	return sh.Run("golangci-lint", "run", "./...")
}

// Fmt formats code.
func Fmt() error {
	if err := sh.Run("go", "fmt", "./..."); err != nil {
		return err
	}
	return sh.Run("gofumpt", "-l", "-w", ".")
}

// Vet runs go vet.
func Vet() error {
	return sh.Run("go", "vet", "./...")
}

// Tidy tidies and verifies go modules.
func Tidy() error {
	if err := sh.Run("go", "mod", "tidy"); err != nil {
		return err
	}
	return sh.Run("go", "mod", "verify")
}

// ============================================================================
// Docker
// ============================================================================

// DockerBuild builds all Docker images.
func DockerBuild() error {
	return sh.Run("docker", "compose", "-f", "deploy/docker-compose/docker-compose.yml", "build")
}

// DockerUp starts all services with Docker Compose.
func DockerUp() error {
	return sh.Run("docker", "compose", "-f", "deploy/docker-compose/docker-compose.yml", "up", "-d")
}

// DockerDown stops all Docker Compose services.
func DockerDown() error {
	return sh.Run("docker", "compose", "-f", "deploy/docker-compose/docker-compose.yml", "down")
}

// DockerLogs views Docker Compose logs.
func DockerLogs() error {
	return sh.Run("docker", "compose", "-f", "deploy/docker-compose/docker-compose.yml", "logs", "-f")
}

// DockerPs lists running containers.
func DockerPs() error {
	return sh.Run("docker", "compose", "-f", "deploy/docker-compose/docker-compose.yml", "ps")
}

// ============================================================================
// Database
// ============================================================================

// MigrateUp runs database migrations.
func MigrateUp() error {
	fmt.Println("Running migrations...")
	return sh.Run("go", "run", "./cmd/migrate", "up")
}

// MigrateDown rolls back database migrations.
func MigrateDown() error {
	fmt.Println("Rolling back migrations...")
	return sh.Run("go", "run", "./cmd/migrate", "down")
}

// MigrateCreate creates a new migration (usage: mage migrateCreate name=migration_name).
func MigrateCreate() error {
	name := os.Getenv("name")
	if name == "" {
		return fmt.Errorf("name parameter is required (usage: mage migrateCreate name=migration_name)")
	}
	fmt.Printf("Creating migration: %s\n", name)
	return sh.Run("migrate", "create", "-ext", "sql", "-dir", "migrations", "-seq", name)
}

// ============================================================================
// Security
// ============================================================================

// GenerateKeys generates RSA key pair for JWT signing.
func GenerateKeys() error {
	fmt.Println("Generating RSA key pair...")
	if err := os.MkdirAll("keys", 0755); err != nil {
		return err
	}
	if err := sh.Run("openssl", "genrsa", "-out", "keys/private.pem", "4096"); err != nil {
		return err
	}
	if err := sh.Run("openssl", "rsa", "-in", "keys/private.pem", "-pubout", "-out", "keys/public.pem"); err != nil {
		return err
	}
	if err := os.Chmod("keys/private.pem", 0600); err != nil {
		return err
	}
	fmt.Println("Keys generated in ./keys directory")
	return nil
}

// SecurityScan runs security scanner.
func SecurityScan() error {
	return sh.Run("gosec", "./...")
}

// ============================================================================
// Cleanup
// ============================================================================

// Clean cleans build artifacts.
func Clean() error {
	if err := os.RemoveAll(binaryDir); err != nil {
		return err
	}
	_ = os.Remove("coverage.out")
	_ = os.Remove("coverage.html")
	return sh.Run("go", "clean", "-cache")
}

// CleanAll cleans everything including generated files.
func CleanAll() error {
	if err := Clean(); err != nil {
		return err
	}
	if err := ProtoClean(); err != nil {
		return err
	}
	return os.RemoveAll("vendor")
}

// ============================================================================
// Installation
// ============================================================================

// InstallTools installs development tools.
func InstallTools() error {
	fmt.Println("Installing development tools...")
	tools := []struct {
		name   string
		module string
	}{
		{"protoc-gen-go", "google.golang.org/protobuf/cmd/protoc-gen-go@latest"},
		{"protoc-gen-go-grpc", "google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest"},
		{"golangci-lint", "github.com/golangci/golangci-lint/cmd/golangci-lint@latest"},
		{"gofumpt", "mvdan.cc/gofumpt@latest"},
		{"gosec", "github.com/securego/gosec/v2/cmd/gosec@latest"},
		{"migrate", "github.com/golang-migrate/migrate/v4/cmd/migrate@latest"},
	}

	for _, tool := range tools {
		args := []string{"install"}
		if tool.name == "migrate" {
			args = append(args, "-tags", "postgres")
		}
		args = append(args, tool.module)
		if err := sh.Run("go", args...); err != nil {
			return err
		}
	}
	return nil
}

// Deps downloads dependencies.
func Deps() error {
	return sh.Run("go", "mod", "download")
}

// Vendor vendors dependencies.
func Vendor() error {
	return sh.Run("go", "mod", "vendor")
}
