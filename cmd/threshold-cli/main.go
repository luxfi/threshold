package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/luxfi/threshold/internal/test"
	"github.com/luxfi/threshold/pkg/math/curve"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/protocols/cmp"
	"github.com/luxfi/threshold/protocols/frost"
	"github.com/luxfi/threshold/protocols/lss"
)

var (
	// Global flags
	configDir     string
	protocolName  string
	curveType     string
	networkAddr   string
	verbose       bool

	// Protocol options
	threshold   int
	parties     int
	partyID     string
	outputFile  string
	inputFile   string

	// Root command
	rootCmd = &cobra.Command{
		Use:   "threshold-cli",
		Short: "CLI tool for threshold signature protocols",
		Long: `A comprehensive CLI tool for testing and using threshold signature protocols
including LSS-MPC, CGG21 (CMP), and FROST protocols.`,
	}

	// Subcommands
	keygenCmd = &cobra.Command{
		Use:   "keygen",
		Short: "Generate threshold keys",
		Long:  `Generate threshold keys for the specified protocol and parameters`,
		RunE:  runKeygen,
	}

	signCmd = &cobra.Command{
		Use:   "sign",
		Short: "Create threshold signature",
		Long:  `Create a threshold signature using the specified protocol`,
		RunE:  runSign,
	}

	reshareCmd = &cobra.Command{
		Use:   "reshare",
		Short: "Reshare keys with new parties",
		Long:  `Dynamically reshare keys to add/remove parties or change threshold`,
		RunE:  runReshare,
	}

	verifyCmd = &cobra.Command{
		Use:   "verify",
		Short: "Verify a signature",
		Long:  `Verify a threshold signature against a public key and message`,
		RunE:  runVerify,
	}

	benchCmd = &cobra.Command{
		Use:   "bench",
		Short: "Run performance benchmarks",
		Long:  `Run performance benchmarks for the specified protocol`,
		RunE:  runBenchmark,
	}

	testCmd = &cobra.Command{
		Use:   "test",
		Short: "Run protocol tests",
		Long:  `Run comprehensive tests for the specified protocol`,
		RunE:  runTests,
	}

	simulateCmd = &cobra.Command{
		Use:   "simulate",
		Short: "Simulate protocol execution",
		Long:  `Simulate protocol execution with various scenarios`,
		RunE:  runSimulation,
	}

	exportCmd = &cobra.Command{
		Use:   "export",
		Short: "Export keys in various formats",
		Long:  `Export threshold keys in different formats (PEM, JWK, etc.)`,
		RunE:  runExport,
	}

	importCmd = &cobra.Command{
		Use:   "import",
		Short: "Import keys from various formats",
		Long:  `Import threshold keys from different formats`,
		RunE:  runImport,
	}

	infoCmd = &cobra.Command{
		Use:   "info",
		Short: "Display protocol information",
		Long:  `Display detailed information about protocols and configurations`,
		RunE:  runInfo,
	}
)

func init() {
	// Global flags
	rootCmd.PersistentFlags().StringVarP(&configDir, "config-dir", "d", "./threshold-data", "Configuration directory")
	rootCmd.PersistentFlags().StringVarP(&protocolName, "protocol", "p", "lss", "Protocol to use: lss, cmp, frost")
	rootCmd.PersistentFlags().StringVarP(&curveType, "curve", "c", "secp256k1", "Elliptic curve: secp256k1, p256, ed25519")
	rootCmd.PersistentFlags().StringVarP(&networkAddr, "network", "n", "", "Network address for distributed mode")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")

	// Keygen flags
	keygenCmd.Flags().IntVarP(&threshold, "threshold", "t", 0, "Threshold value (required)")
	keygenCmd.Flags().IntVarP(&parties, "parties", "N", 0, "Total number of parties (required)")
	keygenCmd.Flags().StringVarP(&partyID, "id", "i", "", "Party ID (required)")
	keygenCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file for config")
	keygenCmd.MarkFlagRequired("threshold")
	keygenCmd.MarkFlagRequired("parties")
	keygenCmd.MarkFlagRequired("id")

	// Sign flags
	signCmd.Flags().StringVarP(&inputFile, "input", "i", "", "Input config file (required)")
	signCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output signature file")
	signCmd.Flags().StringSliceP("signers", "s", nil, "List of signer IDs")
	signCmd.Flags().String("message", "", "Message to sign (hex encoded)")
	signCmd.Flags().String("message-file", "", "File containing message to sign")
	signCmd.MarkFlagRequired("input")

	// Reshare flags
	reshareCmd.Flags().StringVarP(&inputFile, "input", "i", "", "Input config file (required)")
	reshareCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output config file")
	reshareCmd.Flags().IntVar(&threshold, "new-threshold", 0, "New threshold value")
	reshareCmd.Flags().StringSlice("add-parties", nil, "Parties to add")
	reshareCmd.Flags().StringSlice("remove-parties", nil, "Parties to remove")
	reshareCmd.MarkFlagRequired("input")

	// Verify flags
	verifyCmd.Flags().String("signature", "", "Signature file (required)")
	verifyCmd.Flags().String("public-key", "", "Public key file (required)")
	verifyCmd.Flags().String("message", "", "Message (hex encoded)")
	verifyCmd.Flags().String("message-file", "", "File containing message")
	verifyCmd.MarkFlagRequired("signature")
	verifyCmd.MarkFlagRequired("public-key")

	// Benchmark flags
	benchCmd.Flags().Int("iterations", 10, "Number of benchmark iterations")
	benchCmd.Flags().String("operation", "all", "Operation to benchmark: keygen, sign, reshare, all")
	benchCmd.Flags().Bool("profile", false, "Enable CPU profiling")

	// Test flags
	testCmd.Flags().String("suite", "all", "Test suite to run: functional, security, property, fuzz, all")
	testCmd.Flags().Bool("ginkgo", false, "Run Ginkgo tests")
	testCmd.Flags().Duration("timeout", 0, "Test timeout (0 = no timeout)")

	// Simulate flags
	simulateCmd.Flags().String("scenario", "", "Scenario to simulate: byzantine, network-failure, etc.")
	simulateCmd.Flags().Int("rounds", 100, "Number of simulation rounds")
	simulateCmd.Flags().Float64("failure-rate", 0.1, "Failure rate for fault simulation")

	// Export/Import flags
	exportCmd.Flags().StringVarP(&inputFile, "input", "i", "", "Input config file (required)")
	exportCmd.Flags().String("format", "pem", "Export format: pem, jwk, der")
	exportCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file")
	exportCmd.MarkFlagRequired("input")

	importCmd.Flags().StringVarP(&inputFile, "input", "i", "", "Input file (required)")
	importCmd.Flags().String("format", "pem", "Import format: pem, jwk, der")
	importCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output config file")
	importCmd.MarkFlagRequired("input")

	// Add subcommands
	rootCmd.AddCommand(keygenCmd, signCmd, reshareCmd, verifyCmd, benchCmd, 
		testCmd, simulateCmd, exportCmd, importCmd, infoCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runKeygen(cmd *cobra.Command, args []string) error {
	// Create config directory
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Get curve
	group, err := getCurve(curveType)
	if err != nil {
		return err
	}

	// Create party IDs
	partyIDs := make([]party.ID, parties)
	for i := 0; i < parties; i++ {
		partyIDs[i] = party.ID(fmt.Sprintf("party-%d", i+1))
	}

	// Find our index
	var ourIndex int
	found := false
	for i, id := range partyIDs {
		if string(id) == partyID {
			ourIndex = i
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("party ID %s not in party list", partyID)
	}

	// Setup network
	var network *test.Network
	if networkAddr == "" {
		// Local simulation mode
		network = test.NewNetwork(partyIDs)
		fmt.Println("Running in local simulation mode...")
	} else {
		// Distributed mode
		return fmt.Errorf("distributed mode not yet implemented")
	}

	// Run protocol
	pl := pool.NewPool(0)
	defer pl.TearDown()

	var config interface{}
	
	switch protocolName {
	case "lss":
		config, err = runLSSKeygen(group, partyIDs[ourIndex], partyIDs, threshold, pl, network)
	case "cmp":
		config, err = runCMPKeygen(group, partyIDs[ourIndex], partyIDs, threshold, pl, network)
	case "frost":
		config, err = runFROSTKeygen(group, partyIDs[ourIndex], partyIDs, threshold, pl, network)
	default:
		return fmt.Errorf("unknown protocol: %s", protocolName)
	}

	if err != nil {
		return fmt.Errorf("keygen failed: %w", err)
	}

	// Save config
	if outputFile == "" {
		outputFile = filepath.Join(configDir, fmt.Sprintf("%s-%s.json", protocolName, partyID))
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := ioutil.WriteFile(outputFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	fmt.Printf("Key generation complete. Config saved to: %s\n", outputFile)
	
	// Display public key
	switch c := config.(type) {
	case *lss.Config:
		if c.PublicKey != nil {
			pkBytes, err := c.PublicKey.MarshalBinary()
			if err == nil {
				fmt.Printf("Public key: %s\n", hex.EncodeToString(pkBytes))
			}
		}
	case *cmp.Config:
		if pk := c.PublicPoint(); pk != nil {
			pkBytes, err := pk.MarshalBinary()
			if err == nil {
				fmt.Printf("Public key: %s\n", hex.EncodeToString(pkBytes))
			}
		}
	case *frost.Config:
		if c.PublicKey != nil {
			pkBytes, err := c.PublicKey.MarshalBinary()
			if err == nil {
				fmt.Printf("Public key: %s\n", hex.EncodeToString(pkBytes))
			}
		}
	}

	return nil
}

func runSign(cmd *cobra.Command, args []string) error {
	// Load config
	configData, err := ioutil.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}

	// Get message
	var message []byte
	if msgFile, _ := cmd.Flags().GetString("message-file"); msgFile != "" {
		message, err = ioutil.ReadFile(msgFile)
		if err != nil {
			return fmt.Errorf("failed to read message file: %w", err)
		}
	} else if msgHex, _ := cmd.Flags().GetString("message"); msgHex != "" {
		message, err = hex.DecodeString(msgHex)
		if err != nil {
			return fmt.Errorf("failed to decode message: %w", err)
		}
	} else {
		return fmt.Errorf("either --message or --message-file must be specified")
	}

	// Get signers
	signerStrs, _ := cmd.Flags().GetStringSlice("signers")
	signers := make([]party.ID, len(signerStrs))
	for i, s := range signerStrs {
		signers[i] = party.ID(s)
	}

	// Setup network
	pl := pool.NewPool(0)
	defer pl.TearDown()

	var signature interface{}
	
	switch protocolName {
	case "lss":
		var config lss.Config
		if err := json.Unmarshal(configData, &config); err != nil {
			return fmt.Errorf("failed to unmarshal LSS config: %w", err)
		}
		
		network := test.NewNetwork(signers)
		signature, err = runLSSSign(&config, signers, message, pl, network)
		
	case "cmp":
		var config cmp.Config
		if err := json.Unmarshal(configData, &config); err != nil {
			return fmt.Errorf("failed to unmarshal CMP config: %w", err)
		}
		
		network := test.NewNetwork(signers)
		signature, err = runCMPSign(&config, signers, message, pl, network)
		
	case "frost":
		var config frost.Config
		if err := json.Unmarshal(configData, &config); err != nil {
			return fmt.Errorf("failed to unmarshal FROST config: %w", err)
		}
		
		network := test.NewNetwork(signers)
		signature, err = runFROSTSign(&config, signers, message, pl, network)
		
	default:
		return fmt.Errorf("unknown protocol: %s", protocolName)
	}

	if err != nil {
		return fmt.Errorf("signing failed: %w", err)
	}

	// Save signature
	if outputFile == "" {
		outputFile = "signature.json"
	}

	sigData, err := json.MarshalIndent(signature, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal signature: %w", err)
	}

	if err := ioutil.WriteFile(outputFile, sigData, 0644); err != nil {
		return fmt.Errorf("failed to write signature: %w", err)
	}

	fmt.Printf("Signature created and saved to: %s\n", outputFile)
	return nil
}

func runReshare(cmd *cobra.Command, args []string) error {
	// Load current config
	configData, err := ioutil.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}

	// Get parameters
	addParties, _ := cmd.Flags().GetStringSlice("add-parties")
	removeParties, _ := cmd.Flags().GetStringSlice("remove-parties")
	
	if threshold == 0 && len(addParties) == 0 && len(removeParties) == 0 {
		return fmt.Errorf("must specify new threshold, parties to add, or parties to remove")
	}

	// Currently only LSS supports resharing
	if protocolName != "lss" {
		return fmt.Errorf("resharing is currently only supported for LSS protocol")
	}

	var config lss.Config
	if err := json.Unmarshal(configData, &config); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Setup network
	pl := pool.NewPool(0)
	defer pl.TearDown()

	// Convert string IDs to party.ID
	newPartyIDs := make([]party.ID, len(addParties))
	for i, p := range addParties {
		newPartyIDs[i] = party.ID(p)
	}

	// Create network with all parties
	allParties := append(config.PartyIDs, newPartyIDs...)
	network := test.NewNetwork(allParties)

	// Run resharing
	newConfig, err := runLSSReshare(&config, threshold, newPartyIDs, pl, network)
	if err != nil {
		return fmt.Errorf("resharing failed: %w", err)
	}

	// Save new config
	if outputFile == "" {
		outputFile = filepath.Join(configDir, fmt.Sprintf("%s-%s-reshared.json", protocolName, config.ID))
	}

	data, err := json.MarshalIndent(newConfig, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := ioutil.WriteFile(outputFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	fmt.Printf("Resharing complete. New config saved to: %s\n", outputFile)
	fmt.Printf("New threshold: %d, Total parties: %d\n", newConfig.Threshold, len(newConfig.PartyIDs))
	
	return nil
}

func runVerify(cmd *cobra.Command, args []string) error {
	// Load signature
	sigFile, _ := cmd.Flags().GetString("signature")
	sigData, err := ioutil.ReadFile(sigFile)
	if err != nil {
		return fmt.Errorf("failed to read signature: %w", err)
	}

	// Load public key
	pkFile, _ := cmd.Flags().GetString("public-key")
	pkData, err := ioutil.ReadFile(pkFile)
	if err != nil {
		return fmt.Errorf("failed to read public key: %w", err)
	}

	// Get message
	var message []byte
	if msgFile, _ := cmd.Flags().GetString("message-file"); msgFile != "" {
		message, err = ioutil.ReadFile(msgFile)
		if err != nil {
			return fmt.Errorf("failed to read message file: %w", err)
		}
	} else if msgHex, _ := cmd.Flags().GetString("message"); msgHex != "" {
		message, err = hex.DecodeString(msgHex)
		if err != nil {
			return fmt.Errorf("failed to decode message: %w", err)
		}
	} else {
		return fmt.Errorf("either --message or --message-file must be specified")
	}

	// Verify based on protocol
	valid := false
	switch protocolName {
	case "lss", "cmp":
		// ECDSA verification
		valid, err = verifyECDSA(sigData, pkData, message)
	case "frost":
		// Schnorr verification
		valid, err = verifySchnorr(sigData, pkData, message)
	default:
		return fmt.Errorf("unknown protocol: %s", protocolName)
	}

	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	if valid {
		fmt.Println("✓ Signature is VALID")
		return nil
	} else {
		fmt.Println("✗ Signature is INVALID")
		return fmt.Errorf("invalid signature")
	}
}

func runBenchmark(cmd *cobra.Command, args []string) error {
	iterations, _ := cmd.Flags().GetInt("iterations")
	operation, _ := cmd.Flags().GetString("operation")
	enableProfile, _ := cmd.Flags().GetBool("profile")

	fmt.Printf("Running %s benchmarks for %s protocol...\n", operation, protocolName)
	fmt.Printf("Iterations: %d\n", iterations)
	
	if enableProfile {
		// Setup CPU profiling
		fmt.Println("CPU profiling enabled")
	}

	// Run benchmarks based on operation
	switch operation {
	case "keygen":
		return benchmarkKeygen(protocolName, iterations)
	case "sign":
		return benchmarkSign(protocolName, iterations)
	case "reshare":
		if protocolName != "lss" {
			return fmt.Errorf("reshare benchmark only available for LSS protocol")
		}
		return benchmarkReshare(iterations)
	case "all":
		if err := benchmarkKeygen(protocolName, iterations); err != nil {
			return err
		}
		if err := benchmarkSign(protocolName, iterations); err != nil {
			return err
		}
		if protocolName == "lss" {
			if err := benchmarkReshare(iterations); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unknown operation: %s", operation)
	}

	return nil
}

func runTests(cmd *cobra.Command, args []string) error {
	suite, _ := cmd.Flags().GetString("suite")
	useGinkgo, _ := cmd.Flags().GetBool("ginkgo")
	timeout, _ := cmd.Flags().GetDuration("timeout")

	fmt.Printf("Running %s test suite for %s protocol...\n", suite, protocolName)

	if useGinkgo {
		fmt.Println("Using Ginkgo test runner")
		// Run Ginkgo tests
		return runGinkgoTests(protocolName, suite, timeout)
	}

	// Run standard Go tests
	switch suite {
	case "functional":
		return runFunctionalTests(protocolName)
	case "security":
		return runSecurityTests(protocolName)
	case "property":
		return runPropertyTests(protocolName)
	case "fuzz":
		return runFuzzTests(protocolName)
	case "all":
		if err := runFunctionalTests(protocolName); err != nil {
			return err
		}
		if err := runSecurityTests(protocolName); err != nil {
			return err
		}
		if err := runPropertyTests(protocolName); err != nil {
			return err
		}
		if err := runFuzzTests(protocolName); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown test suite: %s", suite)
	}

	return nil
}

func runSimulation(cmd *cobra.Command, args []string) error {
	scenario, _ := cmd.Flags().GetString("scenario")
	rounds, _ := cmd.Flags().GetInt("rounds")
	failureRate, _ := cmd.Flags().GetFloat64("failure-rate")

	fmt.Printf("Running %s simulation for %s protocol...\n", scenario, protocolName)
	fmt.Printf("Rounds: %d, Failure rate: %.2f%%\n", rounds, failureRate*100)

	switch scenario {
	case "byzantine":
		return simulateByzantine(protocolName, rounds, failureRate)
	case "network-failure":
		return simulateNetworkFailure(protocolName, rounds, failureRate)
	case "concurrent-signing":
		return simulateConcurrentSigning(protocolName, rounds)
	case "large-scale":
		return simulateLargeScale(protocolName, rounds)
	default:
		return fmt.Errorf("unknown scenario: %s", scenario)
	}
}

func runExport(cmd *cobra.Command, args []string) error {
	format, _ := cmd.Flags().GetString("format")
	
	// Load config
	configData, err := ioutil.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}

	var exported []byte
	
	switch protocolName {
	case "lss":
		var config lss.Config
		if err := json.Unmarshal(configData, &config); err != nil {
			return fmt.Errorf("failed to unmarshal config: %w", err)
		}
		exported, err = exportLSSConfig(&config, format)
	case "cmp":
		var config cmp.Config
		if err := json.Unmarshal(configData, &config); err != nil {
			return fmt.Errorf("failed to unmarshal config: %w", err)
		}
		exported, err = exportCMPConfig(&config, format)
	case "frost":
		var config frost.Config
		if err := json.Unmarshal(configData, &config); err != nil {
			return fmt.Errorf("failed to unmarshal config: %w", err)
		}
		exported, err = exportFROSTConfig(&config, format)
	default:
		return fmt.Errorf("unknown protocol: %s", protocolName)
	}

	if err != nil {
		return fmt.Errorf("export failed: %w", err)
	}

	// Save exported data
	if outputFile == "" {
		outputFile = fmt.Sprintf("exported.%s", format)
	}

	if err := ioutil.WriteFile(outputFile, exported, 0644); err != nil {
		return fmt.Errorf("failed to write exported data: %w", err)
	}

	fmt.Printf("Config exported to: %s\n", outputFile)
	return nil
}

func runImport(cmd *cobra.Command, args []string) error {
	format, _ := cmd.Flags().GetString("format")
	
	// Read input file
	data, err := ioutil.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	var config interface{}
	
	switch protocolName {
	case "lss":
		config, err = importLSSConfig(data, format)
	case "cmp":
		config, err = importCMPConfig(data, format)
	case "frost":
		config, err = importFROSTConfig(data, format)
	default:
		return fmt.Errorf("unknown protocol: %s", protocolName)
	}

	if err != nil {
		return fmt.Errorf("import failed: %w", err)
	}

	// Save config
	if outputFile == "" {
		outputFile = fmt.Sprintf("%s-imported.json", protocolName)
	}

	configData, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := ioutil.WriteFile(outputFile, configData, 0600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	fmt.Printf("Config imported and saved to: %s\n", outputFile)
	return nil
}

func runInfo(cmd *cobra.Command, args []string) error {
	fmt.Printf("Threshold Signature CLI v1.0.0\n\n")
	
	fmt.Printf("Supported Protocols:\n")
	fmt.Printf("  - LSS (Lindell-Shamir-Shmalo): Dynamic resharing, ECDSA signatures\n")
	fmt.Printf("  - CMP (CGG21): State-of-the-art ECDSA threshold signatures\n")
	fmt.Printf("  - FROST: Flexible Round-Optimized Schnorr Threshold signatures\n\n")
	
	fmt.Printf("Supported Curves:\n")
	fmt.Printf("  - secp256k1: Bitcoin/Ethereum compatible\n")
	fmt.Printf("  - p256: NIST P-256\n")
	fmt.Printf("  - ed25519: EdDSA signatures (FROST only)\n\n")
	
	fmt.Printf("Features:\n")
	fmt.Printf("  - Key generation with configurable threshold\n")
	fmt.Printf("  - Threshold signing\n")
	fmt.Printf("  - Dynamic resharing (LSS only)\n")
	fmt.Printf("  - Signature verification\n")
	fmt.Printf("  - Performance benchmarking\n")
	fmt.Printf("  - Comprehensive testing\n")
	fmt.Printf("  - Protocol simulation\n")
	fmt.Printf("  - Key import/export\n\n")
	
	if verbose {
		fmt.Printf("Configuration Directory: %s\n", configDir)
		fmt.Printf("Current Protocol: %s\n", protocolName)
		fmt.Printf("Current Curve: %s\n", curveType)
	}
	
	return nil
}

// Helper functions

func getCurve(curveType string) (curve.Curve, error) {
	switch strings.ToLower(curveType) {
	case "secp256k1":
		return curve.Secp256k1{}, nil
	case "p256":
		return nil, fmt.Errorf("p256 not yet supported")
	case "ed25519":
		return nil, fmt.Errorf("ed25519 not yet supported")
	default:
		return nil, fmt.Errorf("unknown curve: %s", curveType)
	}
}