module github.com/luxfi/threshold

go 1.25.5

require (
	// External dependencies
	github.com/cloudflare/circl v1.6.2 // BLS12-381 curve operations
	github.com/fxamacker/cbor/v2 v2.9.0
	// Lux crypto stack - this is the HIGH-LEVEL orchestration layer
	// that consumes primitives from these packages (LP-5703, LP-5704)
	github.com/luxfi/crypto v1.17.28 // ECDSA, EdDSA, BLS curves
	github.com/luxfi/fhe v1.3.0 // FHE primitives for TFHE protocol
	github.com/luxfi/lattice/v7 v7.0.0 // Lattice ops for Corona (post-quantum) + GPU acceleration
	github.com/luxfi/corona v0.2.0 // Post-quantum threshold signatures (uses lattice/v7)
	github.com/prometheus/client_golang v1.23.2
	github.com/spf13/cobra v1.10.2
	github.com/stretchr/testify v1.11.1
	github.com/zeebo/blake3 v0.2.4
	golang.org/x/crypto v0.46.0
	golang.org/x/sync v0.19.0
)

require (
	github.com/cronokirby/saferith v0.33.0
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0
	github.com/luxfi/log v1.1.26
	github.com/onsi/ginkgo/v2 v2.27.3
	github.com/onsi/gomega v1.38.3
)

require (
	github.com/ALTree/bigfloat v0.2.0 // indirect
	github.com/Masterminds/semver/v3 v3.4.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-task/slim-sprig/v3 v3.0.0 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/pprof v0.0.0-20251213031049-b05bdaca462f // indirect
	github.com/holiman/uint256 v1.3.2 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/montanaflynn/stats v0.7.1 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.67.5 // indirect
	github.com/prometheus/procfs v0.19.2 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/supranational/blst v0.3.16 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.1 // indirect
	go.yaml.in/yaml/v2 v2.4.3 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/exp v0.0.0-20251219203646-944ab1f22d93 // indirect
	golang.org/x/mod v0.31.0 // indirect
	golang.org/x/net v0.48.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
	golang.org/x/text v0.32.0 // indirect
	golang.org/x/tools v0.40.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/lux../loggerger => ../logger
