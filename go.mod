module github.com/luxfi/threshold

go 1.26.3

require (
	// External dependencies
	github.com/cloudflare/circl v1.6.3 // BLS12-381 curve operations
	github.com/fxamacker/cbor/v2 v2.9.0
	// Lux crypto stack - this is the HIGH-LEVEL orchestration layer
	// that consumes primitives from these packages (LP-5703, LP-5704)
	github.com/luxfi/crypto v1.19.10 // ECDSA, EdDSA, BLS curves
	github.com/luxfi/fhe v1.8.2 // FHE primitives for TFHE protocol
	github.com/luxfi/lattice/v7 v7.1.4 // Lattice ops for Corona (post-quantum) + GPU acceleration
	github.com/spf13/cobra v1.10.2
	github.com/stretchr/testify v1.11.1
	github.com/zeebo/blake3 v0.2.4
	golang.org/x/crypto v0.49.0
	golang.org/x/sync v0.20.0
)

require (
	filippo.io/edwards25519 v1.2.0
	github.com/ChainSafe/go-schnorrkel v1.1.0
	github.com/cronokirby/saferith v0.33.0
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1
	github.com/gtank/merlin v0.1.1
	github.com/gtank/ristretto255 v0.2.0
	github.com/luxfi/log v1.4.1
	github.com/onsi/ginkgo/v2 v2.27.5
	github.com/onsi/gomega v1.38.3
)

require (
	github.com/ALTree/bigfloat v0.2.0 // indirect
	github.com/Masterminds/semver/v3 v3.4.0 // indirect
	github.com/cosmos/go-bip39 v0.0.0-20180819234021-555e2067c45d // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-task/slim-sprig/v3 v3.0.0 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/pprof v0.0.0-20251213031049-b05bdaca462f // indirect
	github.com/gorilla/rpc v1.2.1 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/luxfi/accel v1.1.2 // indirect
	github.com/luxfi/math v1.4.1 // indirect
	github.com/luxfi/pq v1.0.3 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mimoo/StrobeGo v0.0.0-20220103164710-9a04d6ca976b // indirect
	github.com/montanaflynn/stats v0.9.0 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/supranational/blst v0.3.16 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/exp v0.0.0-20260312153236-7ab1446f8b90 // indirect
	golang.org/x/mod v0.34.0 // indirect
	golang.org/x/net v0.52.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/text v0.35.0 // indirect
	golang.org/x/tools v0.43.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

require (
	github.com/luxfi/corona v0.7.5
	github.com/luxfi/lens v0.1.4
	github.com/luxfi/magnetar v0.5.2
	github.com/luxfi/metric v1.5.7
	github.com/luxfi/pulsar v1.0.23
)
