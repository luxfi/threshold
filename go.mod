module github.com/luxfi/threshold

go 1.26.4

require (
	// External dependencies
	github.com/cloudflare/circl v1.6.3 // BLS12-381 curve operations
	github.com/fxamacker/cbor/v2 v2.9.1
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
	github.com/onsi/ginkgo/v2 v2.28.1
	github.com/onsi/gomega v1.39.1
)

require (
	cloud.google.com/go v0.123.0 // indirect
	cloud.google.com/go/auth v0.20.0 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.8 // indirect
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	cloud.google.com/go/iam v1.7.0 // indirect
	cloud.google.com/go/kms v1.27.0 // indirect
	cloud.google.com/go/longrunning v0.9.0 // indirect
	cloud.google.com/go/secretmanager v1.18.0 // indirect
	filippo.io/age v1.3.1 // indirect
	filippo.io/hpke v0.4.0 // indirect
	github.com/ALTree/bigfloat v0.2.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.20.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.13.1 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.11.2 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys v1.4.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets v1.4.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/internal v1.2.0 // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v1.6.0 // indirect
	github.com/Masterminds/semver/v3 v3.4.0 // indirect
	github.com/ansel1/merry v1.8.1 // indirect
	github.com/ansel1/merry/v2 v2.2.2 // indirect
	github.com/aws/aws-sdk-go-v2 v1.41.5 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.32.7 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.19.7 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.17 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.21 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.21 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.17 // indirect
	github.com/aws/aws-sdk-go-v2/service/kms v1.50.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.41.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.0.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.30.9 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.35.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.41.6 // indirect
	github.com/aws/smithy-go v1.24.2 // indirect
	github.com/cenkalti/backoff v2.2.1+incompatible // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cosmos/go-bip39 v0.0.0-20180819234021-555e2067c45d // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/gemalto/flume v1.0.0 // indirect
	github.com/gemalto/kmip-go v0.1.0 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-task/slim-sprig/v3 v3.0.0 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/google/pprof v0.0.0-20260115054156-294ebfa9ad83 // indirect
	github.com/google/s2a-go v0.1.9 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.14 // indirect
	github.com/googleapis/gax-go/v2 v2.21.0 // indirect
	github.com/gorilla/rpc v1.2.1 // indirect
	github.com/grandcat/zeroconf v1.0.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/klauspost/compress v1.18.5 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/luxfi/accel v1.1.8 // indirect
	github.com/luxfi/cache v1.2.1 // indirect
	github.com/luxfi/compress v0.0.5 // indirect
	github.com/luxfi/concurrent v0.0.3 // indirect
	github.com/luxfi/database v1.18.3 // indirect
	github.com/luxfi/hsm v1.1.3 // indirect
	github.com/luxfi/ids v1.2.9 // indirect
	github.com/luxfi/math v1.4.1 // indirect
	github.com/luxfi/math/big v0.1.0 // indirect
	github.com/luxfi/mdns v0.1.0 // indirect
	github.com/luxfi/mock v0.1.1 // indirect
	github.com/luxfi/pq v1.0.3 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mgutz/ansi v0.0.0-20200706080929-d51e80ef957d // indirect
	github.com/miekg/dns v1.1.72 // indirect
	github.com/miekg/pkcs11 v1.1.1 // indirect
	github.com/mimoo/StrobeGo v0.0.0-20220103164710-9a04d6ca976b // indirect
	github.com/montanaflynn/stats v0.9.0 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/rs/zerolog v1.35.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/supranational/blst v0.3.16 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.67.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.67.0 // indirect
	go.opentelemetry.io/otel v1.43.0 // indirect
	go.opentelemetry.io/otel/metric v1.43.0 // indirect
	go.opentelemetry.io/otel/trace v1.43.0 // indirect
	go.uber.org/mock v0.6.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.1 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/exp v0.0.0-20260312153236-7ab1446f8b90 // indirect
	golang.org/x/mod v0.34.0 // indirect
	golang.org/x/net v0.52.0 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/text v0.35.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	golang.org/x/tools v0.43.0 // indirect
	google.golang.org/api v0.275.0 // indirect
	google.golang.org/genproto v0.0.0-20260406210006-6f92a3bedf2d // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260401024825-9d38bb4040a9 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260401024825-9d38bb4040a9 // indirect
	google.golang.org/grpc v1.80.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

require (
	github.com/google/go-sev-guest v0.14.1
	github.com/luxfi/corona v0.7.6
	github.com/luxfi/lens v0.1.4
	github.com/luxfi/magnetar v1.2.0
	github.com/luxfi/metric v1.5.7
	github.com/luxfi/mpc v1.14.13
	github.com/luxfi/pulsar v1.1.1
	github.com/luxfi/zap v0.3.1
)

// e2e validation harness pin (2026-05-31): luxfi/node v1.27.8 is
// referenced transitively but has no published tag (gap between
// v1.27.7 and v1.27.9). Local replace pins to the workspace
// checkout so the e2e harness can build against the same node
// sources that produced the live testnet luxd image.
