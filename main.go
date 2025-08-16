// Command threshold provides a CLI for threshold signature operations
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println("Threshold Signature Library")
	fmt.Println("Version: 1.0.0")
	fmt.Println()
	fmt.Println("This is a library package. Use the following:")
	fmt.Println("  - Import packages from github.com/luxfi/threshold/pkg/...")
	fmt.Println("  - Import protocols from github.com/luxfi/threshold/protocols/...")
	fmt.Println()
	fmt.Println("For CLI tools, see cmd/threshold-cli/")
	os.Exit(0)
}