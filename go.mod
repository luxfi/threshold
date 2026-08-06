module github.com/luxfi/threshold

go 1.26.4

require (
	// External dependencies
	github.com/cloudflare/circl v1.6.3 // BLS12-381 curve operations
	github.com/fxamacker/cbor/v2 v2.9.1
	// Lux crypto stack - this is the HIGH-LEVEL orchestration layer
	// that consumes primitives from these packages (LP-5703, LP-5704)
	github.com/luxfi/crypto v1.20.2 // ECDSA, EdDSA, BLS curves
	github.com/luxfi/lattice/v7 v7.1.4 // Lattice ops for Corona (post-quantum) + GPU acceleration
	github.com/spf13/cobra v1.10.2
	github.com/stretchr/testify v1.11.1
	github.com/zeebo/blake3 v0.2.4
	golang.org/x/crypto v0.52.0
	golang.org/x/sync v0.20.0
)

require (
	filippo.io/edwards25519 v1.2.0
	github.com/ChainSafe/go-schnorrkel v1.1.0
	github.com/cronokirby/saferith v0.33.0
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1
	github.com/gtank/merlin v0.1.1
	github.com/gtank/ristretto255 v0.2.0
	github.com/luxfi/log v1.4.3
	github.com/mr-tron/base58 v1.3.0
	github.com/onsi/ginkgo/v2 v2.28.1
	github.com/onsi/gomega v1.39.1
)

require (
	github.com/ALTree/bigfloat v0.2.0 // indirect
	github.com/Masterminds/semver/v3 v3.4.0 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/s3 v1.97.3 // indirect
	github.com/bits-and-blooms/bitset v1.24.4 // indirect
	github.com/cenkalti/backoff v2.2.1+incompatible // indirect
	github.com/consensys/gnark-crypto v0.20.1 // indirect
	github.com/cosmos/go-bip39 v1.0.0 // indirect
	github.com/crate-crypto/go-eth-kzg v1.5.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/deckarep/golang-set/v2 v2.8.0 // indirect
	github.com/emicklei/dot v1.11.0 // indirect
	github.com/ethereum/c-kzg-4844/v2 v2.1.7 // indirect
	github.com/ethereum/go-bigmodexpfix v0.0.0-20250911101455-f9e208c548ab // indirect
	github.com/ferranbt/fastssz v1.0.0 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/go-task/slim-sprig/v3 v3.0.0 // indirect
	github.com/gofrs/flock v0.13.0 // indirect
	github.com/golang/snappy v1.0.0 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/pprof v0.0.0-20260302011040-a15ffb7f9dcc // indirect
	github.com/gorilla/rpc v1.2.1 // indirect
	github.com/gorilla/websocket v1.5.4-0.20250319132907-e064f32e3674 // indirect
	github.com/grandcat/zeroconf v1.0.0 // indirect
	github.com/holiman/bloomfilter/v2 v2.0.3 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/klauspost/compress v1.18.6 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/luxfi/accel v1.2.4 // indirect
	github.com/luxfi/atomic v1.0.0 // indirect
	github.com/luxfi/cache v1.3.1 // indirect
	github.com/luxfi/compress v0.1.1 // indirect
	github.com/luxfi/concurrent v0.1.1 // indirect
	github.com/luxfi/consensus v1.36.2 // indirect
	github.com/luxfi/constants v1.6.2 // indirect
	github.com/luxfi/container v0.2.1 // indirect
	github.com/luxfi/crypto/ipa v1.2.4 // indirect
	github.com/luxfi/database v1.21.1 // indirect
	github.com/luxfi/dkg v0.3.5 // indirect
	github.com/luxfi/ids v1.3.2 // indirect
	github.com/luxfi/math v1.5.1 // indirect
	github.com/luxfi/math/big v0.1.0 // indirect
	github.com/luxfi/mdns v0.1.1 // indirect
	github.com/luxfi/mlwe v0.3.0 // indirect
	github.com/luxfi/mock v0.1.1 // indirect
	github.com/luxfi/p2p v1.22.1 // indirect
	github.com/luxfi/pq v1.1.0 // indirect
	github.com/luxfi/precompile v0.19.3 // indirect
	github.com/luxfi/runtime v1.3.1 // indirect
	github.com/luxfi/sampler v1.1.0 // indirect
	github.com/luxfi/utils v1.3.1 // indirect
	github.com/luxfi/validators v1.3.1 // indirect
	github.com/luxfi/version v1.0.1 // indirect
	github.com/luxfi/vm v1.3.1 // indirect
	github.com/luxfi/warp v1.24.1 // indirect
	github.com/mattn/go-colorable v0.1.15 // indirect
	github.com/mattn/go-isatty v0.0.22 // indirect
	github.com/miekg/dns v1.1.72 // indirect
	github.com/mimoo/StrobeGo v0.0.0-20220103164710-9a04d6ca976b // indirect
	github.com/minio/sha256-simd v1.0.1 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/montanaflynn/stats v0.9.0 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/shirou/gopsutil v3.21.11+incompatible // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/supranational/blst v0.3.16 // indirect
	github.com/tklauser/go-sysconf v0.4.0 // indirect
	github.com/tklauser/numcpus v0.12.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	go.uber.org/mock v0.6.0 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/exp v0.0.0-20260529124908-c761662dc8c9 // indirect
	golang.org/x/mod v0.36.0 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	golang.org/x/tools v0.45.0 // indirect
	gonum.org/v1/gonum v0.17.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

require (
	github.com/holiman/uint256 v1.3.2
	github.com/luxfi/corona v0.10.4
	github.com/luxfi/geth v1.20.1
	github.com/luxfi/lens v0.2.1
	github.com/luxfi/magnetar v1.2.3
	github.com/luxfi/metric v1.8.1
	github.com/luxfi/pulsar v1.9.2
	github.com/luxfi/zap v1.2.6
)

// e2e validation harness pin (2026-05-31): luxfi/node v1.27.8 is
// referenced transitively but has no published tag (gap between
// v1.27.7 and v1.27.9). Local replace pins to the workspace
// checkout so the e2e harness can build against the same node
// sources that produced the live testnet luxd image.
