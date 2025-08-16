// Package main is a placeholder to satisfy build requirements.
// The actual CLI tool is in cmd/threshold-cli/
package main

import (
	"fmt"
	"os"
)

func main() {
	// This is a library package, not a standalone executable.
	// For the CLI tool, use: go run ./cmd/threshold-cli/
	fmt.Fprintln(os.Stderr, "This is a library package. Use cmd/threshold-cli for the CLI tool.")
	os.Exit(1)
}