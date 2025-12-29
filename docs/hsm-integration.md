# HSM Integration Guide

This document explains **what "HSM compatible" means** for `luxfi/threshold`,
and gives concrete integration walkthroughs for the four HSMs / KMS
services we see most often in production deployments: AWS CloudHSM,
Azure Key Vault, GCP Cloud HSM, and Zymbit SCM.

It is the substantive response to [#4](https://github.com/luxfi/threshold/issues/4) and is cross-linked from
[`docs/audit.md`](./audit.md) § Deployment Considerations.

---

## What "HSM Compatible" Means Here

Every protocol in this repo produces a **`Config`** — an encoding of the
party's secret share plus associated public material. The `Config` types
expose `MarshalBinary()` / `UnmarshalBinary()` (see
`protocols/cmp/config/marshal.go`, and the equivalents under
`protocols/frost/`, `protocols/lss/`, `protocols/doerner/`,
`protocols/ringtail/`).

From the HSM's perspective, a `Config` is **opaque bytes**. You can:

1. Generate a `Config` via `Keygen`, serialize it with `MarshalBinary`,
   and have the HSM **envelope-encrypt** the bytes under a KMS key. Store
   the ciphertext on ordinary disk or a database.
2. Or have the HSM **store the ciphertext** directly in a secure slot
   that only a specific principal can read.

The MPC computation itself **does not run inside the HSM enclave**. The
share leaves the HSM encrypted, is decrypted into process memory,
participates in the MPC rounds in the clear, and (if the session
produced a new / refreshed share) the new ciphertext is written back.
**The HSM is a storage-and-access-control boundary, not a compute
boundary.** If you need enclave-grade runtime isolation, see
[Runtime isolation (Nitro Enclaves, SGX)](#runtime-isolation-nitro-enclaves-sgx)
below.

Running the full CGGMP21 protocol **inside** a PKCS#11 HSM's
command-processing environment is not feasible with commodity hardware
— the round-trip latency to hardware HSMs would make distributed keygen
impractically slow, and the protocol state machine does not fit the
PKCS#11 model. FROST, which is simpler, is closer to feasible but still
not offered by current hardware.

### Recommended Adapter Interface

We recommend callers define a small interface that any HSM implementation
can satisfy, and pass that interface at the edges of their custody code.
This is the same pattern used by `luxfi/mpc`, and we restate it here so
integrators can adopt it without reading another repo:

```go
package custody // or wherever you keep your share-storage plumbing

import "context"

// ShareStore is the interface your KMS / HSM adapter should satisfy.
// The bytes passed to Put and returned by Get are the result of
// Config.MarshalBinary() on the protocol's Config type — opaque to
// this interface.
type ShareStore interface {
    // Put stores the encrypted share for (orgID, walletID, partyID).
    // Implementations envelope-encrypt share under a KMS key before
    // persisting (or store in an HSM slot bound to the principal).
    Put(ctx context.Context, orgID, walletID, partyID string, share []byte) error

    // Get returns the previously stored share, decrypted in process
    // memory. The caller is responsible for zeroizing the returned
    // slice after use (pkg/mpc/secret.go in luxfi/mpc has helpers).
    Get(ctx context.Context, orgID, walletID, partyID string) ([]byte, error)

    // Rotate re-encrypts the stored share under a new KMS key version.
    // The underlying MPC share is unchanged; this is a KMS-envelope
    // key rotation. For MPC share refresh, use the protocol's
    // Refresh / Reshare call.
    Rotate(ctx context.Context, orgID, walletID, partyID string) error
}
```

None of the walkthroughs below assume a specific interface name — adopt
the one above, or your own — the wire contract is the same: the caller
treats a share as opaque bytes and the adapter wraps a specific HSM.

---

## AWS CloudHSM

### Prereqs

- An active CloudHSM cluster in a VPC reachable from the pods / VMs
  running your `luxfi/threshold` process.
- The CloudHSM client (`cloudhsm-cli` or the PKCS#11 library) installed
  on each node. AWS publishes packages for Amazon Linux and Ubuntu.
- IAM permissions: `cloudhsm:DescribeClusters`, `cloudhsm:DescribeHsm`
  on the cluster; `cloudhsm:ListTags` for observability. For
  envelope-encrypt-with-KMS (simpler) you instead need `kms:Encrypt`,
  `kms:Decrypt`, `kms:GenerateDataKey` on the KMS key.

### Credential plumbing

- **Preferred.** Attach an IAM role to the pod / EC2 / ECS task. The
  AWS SDK picks it up via IRSA (EKS) or the instance profile. No secrets
  on disk.
- **Fallback.** Short-lived static credentials via `AWS_ACCESS_KEY_ID`
  and `AWS_SECRET_ACCESS_KEY` in environment — rotate via an external
  broker, never bake into container images.

### Key-share storage contract

Two deployment modes:

1. **Envelope encryption with AWS KMS (recommended).** Generate a data
   key, encrypt the `Config` bytes locally with the data key, store the
   encrypted-data-key ciphertext alongside the share ciphertext. This is
   what the example below shows. Works with AWS KMS (cheaper) or
   CloudHSM's KMS integration.
2. **PKCS#11 slot storage.** Open a PKCS#11 session, store the share
   ciphertext as a `CKO_DATA` object, read it back via a `C_FindObjects`
   + `C_GetAttributeValue`. Slower, but keeps the ciphertext inside the
   HSM's storage boundary.

### Runnable example (envelope mode)

```go
package custody

import (
    "context"
    "fmt"

    "github.com/aws/aws-sdk-go-v2/aws"
    "github.com/aws/aws-sdk-go-v2/config"
    "github.com/aws/aws-sdk-go-v2/service/kms"
)

type AWSKMSShareStore struct {
    client    *kms.Client
    keyARN    string
    backend   BlobStore // S3, DynamoDB, Postgres — anywhere you want the ciphertext
}

func NewAWSKMSShareStore(ctx context.Context, keyARN string, backend BlobStore) (*AWSKMSShareStore, error) {
    cfg, err := config.LoadDefaultConfig(ctx)
    if err != nil {
        return nil, fmt.Errorf("aws config: %w", err)
    }
    return &AWSKMSShareStore{
        client:  kms.NewFromConfig(cfg),
        keyARN:  keyARN,
        backend: backend,
    }, nil
}

func (s *AWSKMSShareStore) Put(ctx context.Context, orgID, walletID, partyID string, share []byte) error {
    out, err := s.client.Encrypt(ctx, &kms.EncryptInput{
        KeyId:     aws.String(s.keyARN),
        Plaintext: share,
        EncryptionContext: map[string]string{
            "org_id":    orgID,
            "wallet_id": walletID,
            "party_id":  partyID,
        },
    })
    if err != nil {
        return fmt.Errorf("kms encrypt: %w", err)
    }
    return s.backend.Write(ctx, blobKey(orgID, walletID, partyID), out.CiphertextBlob)
}

func (s *AWSKMSShareStore) Get(ctx context.Context, orgID, walletID, partyID string) ([]byte, error) {
    ciphertext, err := s.backend.Read(ctx, blobKey(orgID, walletID, partyID))
    if err != nil {
        return nil, fmt.Errorf("blob read: %w", err)
    }
    out, err := s.client.Decrypt(ctx, &kms.DecryptInput{
        KeyId:          aws.String(s.keyARN),
        CiphertextBlob: ciphertext,
        EncryptionContext: map[string]string{
            "org_id":    orgID,
            "wallet_id": walletID,
            "party_id":  partyID,
        },
    })
    if err != nil {
        return nil, fmt.Errorf("kms decrypt: %w", err)
    }
    return out.Plaintext, nil
}

// ... Rotate implementation uses kms.ReEncrypt or generate-data-key + re-encrypt locally.
```

The encryption context (`org_id`, `wallet_id`, `party_id`) is mandatory
— KMS will refuse to decrypt a share with the wrong context, so a
disk-level theft of one share does not let the attacker decrypt a
different org's share under the same KMS key.

### Known limits

- **FIPS level:** CloudHSM v2 is FIPS 140-2 Level 3. AWS KMS is FIPS 140-2
  Level 2 with FIPS-validated endpoints available (`kms-fips.<region>.amazonaws.com`).
- **Rate limits:** KMS is 5,500 requests per second per key by default
  in most regions; request an increase for high-volume signing. CloudHSM
  throughput depends on cluster size — plan ≥2 HSMs per AZ for
  production.
- **Cost:** CloudHSM is roughly $1.50–$2.00/hour per HSM. KMS is
  $1/month/key + $0.03 per 10,000 requests. KMS is cheaper at low
  volumes; CloudHSM wins for multi-million-request-per-day throughput.
- **Cold start:** CloudHSM clusters take ~20 minutes to provision; plan
  disaster recovery accordingly.

---

## Azure Key Vault

### Prereqs

- An Azure Key Vault with **Managed HSM** pricing tier if you need FIPS
  140-2 Level 3. Standard Key Vault is Level 1 and is not sufficient for
  many regulated custody contexts.
- A Service Principal (SPN) or Managed Identity with `Key Vault Crypto User`
  role, or the narrower `Key Vault Crypto Service Encryption User` if you
  only wrap / unwrap.

### Credential plumbing

- **Preferred.** Managed Identity on the AKS pod / VM — the Azure SDK
  picks it up via `DefaultAzureCredential`. No secrets on disk.
- **Fallback.** SPN with `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, and
  `AZURE_CLIENT_SECRET` or a federated-workload-identity token. Again,
  do not bake into images.

### Key-share storage contract

Envelope encryption only — Key Vault does not store arbitrary blobs in a
way that serves as a share database. You encrypt the share with a Key
Vault key (`WrapKey` on an RSA / octet key, or `Encrypt` on an AES key)
and persist the wrapped ciphertext in your own storage.

### Runnable example

```go
package custody

import (
    "context"
    "fmt"

    "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
    "github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
)

type AzureKeyVaultShareStore struct {
    client    *azkeys.Client
    keyName   string
    keyVersion string
    backend   BlobStore
}

func NewAzureKeyVaultShareStore(vaultURL, keyName, keyVersion string, backend BlobStore) (*AzureKeyVaultShareStore, error) {
    cred, err := azidentity.NewDefaultAzureCredential(nil)
    if err != nil {
        return nil, fmt.Errorf("default credential: %w", err)
    }
    client, err := azkeys.NewClient(vaultURL, cred, nil)
    if err != nil {
        return nil, fmt.Errorf("azkeys client: %w", err)
    }
    return &AzureKeyVaultShareStore{client: client, keyName: keyName, keyVersion: keyVersion, backend: backend}, nil
}

func (s *AzureKeyVaultShareStore) Put(ctx context.Context, orgID, walletID, partyID string, share []byte) error {
    // Wrap the share via Key Vault — use RSA-OAEP-256 or CKM_AES_KEY_WRAP_KWP depending on your key type.
    wrap, err := s.client.WrapKey(ctx, s.keyName, s.keyVersion, azkeys.KeyOperationsParameters{
        Algorithm: to.Ptr(azkeys.EncryptionAlgorithmRSAOAEP256),
        Value:     share,
    }, nil)
    if err != nil {
        return fmt.Errorf("key vault wrap: %w", err)
    }
    return s.backend.Write(ctx, blobKey(orgID, walletID, partyID), wrap.Result)
}

// Get / Rotate symmetric.
```

### Known limits

- **FIPS level:** Managed HSM is FIPS 140-2 Level 3; Standard Key Vault
  is Level 1. Choose Managed HSM for custody.
- **Rate limits:** ~2,000 RSA operations per second per vault; ~10 RSA
  HSM operations per second on Standard. Use batched wrapping for
  high-volume keygen.
- **Cost:** Managed HSM is ~$3.20/hour. Key Vault Standard is ~$1/month
  per key + a per-operation fee.
- **Key versions:** Every wrap call is against a specific key version;
  rotation requires re-wrapping existing shares (implement in
  `Rotate`).

---

## GCP Cloud HSM

### Prereqs

- A Cloud KMS keyring with `HSM` protection level (Google's integration
  with a FIPS 140-2 Level 3 HSM fleet; from the caller's perspective it
  looks identical to Cloud KMS).
- A Google Cloud service account with `roles/cloudkms.cryptoKeyEncrypterDecrypter`
  on the key.

### Credential plumbing

- **Preferred.** Workload Identity Federation on GKE — the GCP SDK
  picks it up automatically.
- **Fallback.** `GOOGLE_APPLICATION_CREDENTIALS` pointing at a service-
  account JSON. Rotate regularly; avoid committing.

### Key-share storage contract

Envelope encryption with a symmetric KMS key set to `HSM` protection
level. Ciphertext is stored in your own backend (GCS, Firestore, Cloud
SQL).

### Runnable example

```go
package custody

import (
    "context"
    "fmt"

    kms "cloud.google.com/go/kms/apiv1"
    "cloud.google.com/go/kms/apiv1/kmspb"
)

type GCPKMSShareStore struct {
    client  *kms.KeyManagementClient
    keyName string // projects/<p>/locations/<l>/keyRings/<kr>/cryptoKeys/<k>
    backend BlobStore
}

func NewGCPKMSShareStore(ctx context.Context, keyName string, backend BlobStore) (*GCPKMSShareStore, error) {
    client, err := kms.NewKeyManagementClient(ctx)
    if err != nil {
        return nil, fmt.Errorf("kms client: %w", err)
    }
    return &GCPKMSShareStore{client: client, keyName: keyName, backend: backend}, nil
}

func (s *GCPKMSShareStore) Put(ctx context.Context, orgID, walletID, partyID string, share []byte) error {
    resp, err := s.client.Encrypt(ctx, &kmspb.EncryptRequest{
        Name:                        s.keyName,
        Plaintext:                   share,
        AdditionalAuthenticatedData: []byte(orgID + "|" + walletID + "|" + partyID),
    })
    if err != nil {
        return fmt.Errorf("kms encrypt: %w", err)
    }
    return s.backend.Write(ctx, blobKey(orgID, walletID, partyID), resp.Ciphertext)
}

// Get / Rotate symmetric.
```

Like AWS, the AAD (`org_id|wallet_id|party_id`) binds the ciphertext to
the specific share — rotating a share between parties requires
re-encryption under the destination party's AAD.

### Known limits

- **FIPS level:** HSM-protection-level keys are FIPS 140-2 Level 3.
- **Rate limits:** 3,000 operations per second per key by default;
  request quota increase for higher throughput. Regional keys have
  independent quotas.
- **Cost:** $1/month/key-version + $0.03 per 10,000 HSM operations.
  Economical at custody volumes.
- **Protection level:** Specify `PROTECTION_LEVEL = HSM` at key creation
  — you cannot upgrade a `SOFTWARE` key to `HSM`.

---

## Zymbit SCM (Secure Compute Module)

Zymbit SCM is aimed at **edge / on-premises** deployments (Raspberry Pi
HAT / industrial PCs) where you want an HSM boundary without a cloud
dependency.

### Prereqs

- A Zymbit SCM device (Zymkey 4i or SCM LTE) attached to the host.
- The `zkapputilslib` installed (`apt install zkapputilslib`).
- The host user added to the `zymbit` group.

### Credential plumbing

- Zymbit is a local hardware device — there are no cloud credentials.
  The boundary is physical possession of the device and the root of
  trust burned into it at manufacture.
- For provisioning-time attestation, Zymbit exposes a factory
  certificate chain; verify it before trusting a new device.

### Key-share storage contract

Two options:

1. **Local AES wrap.** Derive a symmetric key from the Zymbit-resident
   master, wrap the share locally. Fast; works offline.
2. **ECDSA signature as authentication.** Use the device's ECDSA
   signing capability to sign a challenge from a peer node before the
   share is released from encrypted-at-rest storage. This gates share
   decryption on the physical device being present.

### Example (local wrap via zkapputils)

```go
package custody

/*
#cgo LDFLAGS: -lzk_app_utils
#include <zk_app_utils.h>
*/
import "C"
import (
    "context"
    "fmt"
    "unsafe"
)

type ZymbitShareStore struct {
    slot    int // Zymbit key slot for the share-encrypting key
    backend BlobStore
}

func (s *ZymbitShareStore) Put(ctx context.Context, orgID, walletID, partyID string, share []byte) error {
    var ctxt unsafe.Pointer
    var ctxtLen C.int
    rc := C.zkLockData(
        (*C.uint8_t)(unsafe.Pointer(&share[0])),
        C.int(len(share)),
        (**C.uint8_t)(unsafe.Pointer(&ctxt)),
        &ctxtLen,
    )
    if rc != 0 {
        return fmt.Errorf("zkLockData failed: %d", rc)
    }
    defer C.free(ctxt)
    wrapped := C.GoBytes(ctxt, ctxtLen)
    return s.backend.Write(ctx, blobKey(orgID, walletID, partyID), wrapped)
}

// Get uses zkUnlockData symmetrically.
```

### Known limits

- **FIPS level:** Zymbit SCM is not FIPS certified as of this writing.
  Check the current Zymbit specsheet before deploying into a regulated
  environment.
- **Rate limits:** The device is single-threaded over a hardware bus;
  expect tens to low-hundreds of wrap/unwrap operations per second on
  current hardware, not thousands.
- **Cost:** One-time device cost in the low-hundreds of dollars per
  unit. No per-operation cost after provisioning.
- **Recovery:** A destroyed / lost device is unrecoverable in isolation
  — the share is permanently inaccessible. Always operate with enough
  MPC redundancy that losing one party's device is an operational
  event, not a key-loss event. See the reshare guidance in
  [`audit.md`](./audit.md) § 5.

---

## Runtime Isolation (Nitro Enclaves, SGX)

If your threat model requires that **the share never exists unencrypted
in the host OS's memory**, the HSM envelope patterns above are not
enough. You need runtime isolation:

- **AWS Nitro Enclaves** — a separate VM partition with its own vsock;
  no shell access, no persistent storage. The MPC process runs inside
  the enclave and communicates with the parent instance over vsock.
  Share decryption happens inside the enclave using KMS grants that
  require enclave attestation. Feasible today for FROST and CMP; adds
  10–30 ms of vsock round-trip to each signing session.
- **Intel SGX / AMD SEV-SNP** — enclave partition at the CPU level.
  More finicky than Nitro operationally; supported by some cloud
  providers and specific on-prem hardware.

Runtime isolation is an order of magnitude more work than the envelope
patterns above — usually the right first step is envelope encryption and
MPC-level share distribution, and enclaves come second when the threat
model demands it.

---

## Summary Table

| HSM / KMS           | FIPS level       | Best for                        | Throughput   | Approx. cost          |
| ------------------- | ---------------- | ------------------------------- | ------------ | --------------------- |
| AWS CloudHSM        | 140-2 L3         | Multi-million ops / day custody | ~10k ops/sec per HSM | ~$1.50–$2/hr/HSM    |
| AWS KMS (envelope)  | 140-2 L2 endpoint, L3 via CloudHSM-backed keys | General custody, cheap | ~5.5k req/s/key  | ~$1/mo/key + $0.03/10k req |
| Azure Managed HSM   | 140-2 L3         | Regulated custody on Azure       | ~2k RSA/s     | ~$3.20/hr             |
| Azure Key Vault Std | 140-2 L1         | Non-regulated use only           | ~10 HSM/s     | ~$1/mo/key + per-op   |
| GCP Cloud KMS (HSM) | 140-2 L3         | General custody on GCP           | ~3k ops/s/key | ~$1/mo/version + per-op |
| Zymbit SCM          | Not FIPS (check current) | Edge / on-prem                   | Tens to hundreds ops/s | One-time $   |

---

## Further Reading

- [`docs/audit.md`](./audit.md) — threat model and deployment considerations.
- [`luxfi/mpc`](https://github.com/luxfi/mpc) — a production-ready MPC node that implements a `pkg/hsm` abstraction following the adapter pattern described here.
- AWS: [CloudHSM](https://docs.aws.amazon.com/cloudhsm/latest/userguide/) / [KMS encryption context](https://docs.aws.amazon.com/kms/latest/developerguide/encrypt_context.html).
- Azure: [Managed HSM](https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/overview) / [Key operations](https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys).
- GCP: [Cloud HSM](https://cloud.google.com/kms/docs/hsm) / [Protection levels](https://cloud.google.com/kms/docs/algorithms).
- Zymbit: [Product documentation](https://www.zymbit.com/docs/).
