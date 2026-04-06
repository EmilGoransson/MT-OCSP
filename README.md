# Merkle OCSP

A proof-of-concept OCSP responder that replaces per-certificate signed responses with cryptographic Merkle proofs anchored to an append-only log.

Standard OCSP requires the CA to sign every response individually, which is computationally expensive when using quantum safe signature algorithms, and creates a single point of trust. This prototype instead commits batches of certificate state into a combined Merkle tree at each epoch, signs only the tree root, and lets clients verify any status locally using inclusion or exclusion proofs.


---

## Prerequisites

- Go 1.21 or later
- Run `go mod download` before building

---

## Running

Start the responder (server):

```bash
go run ./cmd/responder
```

Start the client (in a separate terminal):

```bash
go run ./cmd/client
```

The client posts two certificates (one good, one revoked), waits one epoch for them to be committed, then requests and verifies proofs for all three statuses — good, revoked, and unknown.

---


## Client example

```go
// 1. Post certificates to the responder
serial := big.NewInt(1111)
date   := time.Now()
postCertificates([][]byte{serial.Bytes()})

// 2. Wait for the next epoch to include them (default = 20s)
time.Sleep(20 * time.Second)

// 3. Fetch the latest signed landmark and the server public key
lm,  _ := TestGetSignedLandmark()
key, _ := getPublicKey()

// 4. Verify the landmark signature
valid, _ := ValidateLandmark(lm, key)

// 5. Request and verify a proof
response := postGetResponseProof(serial, date)
serialHash := sha256.Sum256(serial.Bytes())
ok, err := ocsp.Verify(response, lm, serialHash[:], date)
```
---

## How it works

Each epoch the responder:

1. Drains the queue of issued and revoked certificate hashes
2. Builds a new Combined tree, a sorted Merkle tree for issuance and a sparse Merkle tree for revocation
3. Commits `SHA256(combinedRoot + date)` to an append-only RFC 6962 log
4. Creates a Landmark pointing to that log entry

The CA signs only the log root (a `SignedLandmark`) and distributes it out-of-band. Clients chains the proof verification against that signed root. 

```
Client --serial + issueDate-->  Responder
Client <---status + proof-----  Responder

CA signs and publishes SignedLandmark out of band -->  Client uses it to verify proof
```

### Proof content by status

| Status | Issue proof | Revocation proof |
|--------|-------------|---|
| `Good` | Inclusion in sorted MT | Non-membership in sparse MT |
| `Revoked` | Inclusion in sorted MT | Membership in sparse MT |
| `Unknown` | Non-membership (exclusion) in sorted MT for the claimed epoch | - |

For `Unknown`, the client also checks that the requested date falls within the epoch window covered by the landmark, so the responder cannot claim a certificate is unknown for an epoch it never covered.

---

## Architecture

```
Controller
├── Log            (append-only, RFC 6962)
├── Revocation     (Sparse Merkle Tree, persists across epochs)
└── Landmarks []
    └── Landmark
        ├── LogIndex
        ├── Date
        └── Combined
            ├── IssuedMT   (Sorted Merkle Tree, rebuilt each epoch)
            └── RevSMT     (Sparse Merkle Tree, only stores root)
```

### Trees

**Sorted Merkle Tree** (`IssuedMT`, [`txaty/go-merkletree`](https://github.com/txaty/go-merkletree))
- Leaves are SHA-256 hashes of serial numbers, sorted before insertion
- Sorted order enables non-membership (exclusion) proofs: to prove a hash is absent, prove its two sorted neighbours are present
- Rebuilt from scratch each epoch

**Sparse Merkle Tree** (`RevSMT`, [`celestiaorg/smt`](https://github.com/celestiaorg/smt))
- Key and value are both the certificate hash, empty value signals non-membership
- Persists across epochs, only the root is stored at epoch boundaries, leaves are pruned
- Membership proves revocation, non-membership proves `Good` status

**Append-only Log** ([`transparency-dev/merkle`](https://github.com/transparency-dev/merkle))
- RFC 6962 hash tree
- Each entry is `SHA256(combinedRoot + date)`
- Log inclusion proofs let the client verify that a landmark root was genuinely committed to the log and covered by the signed head

### Signed Landmark

```
SignedLandmark = RSA_Sign( SHA256(logRoot + logSize + frequency + date) )
```

The signed landmark is the only thing clients need to trust. All other data (proof paths, roots, timestamps) is verified against it.

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/ping` | Health check |
| GET | `/start` | Start the epoch ticker |
| GET | `/stop` | Stop the epoch ticker |
| POST | `/cert/add` | Queue issued certificate hashes |
| POST | `/cert/revoke` | Queue revoked certificate hashes |
| GET | `/landmark` | Fetch the latest signed landmark |
| GET | `/key` | Fetch the server RSA public key |
| POST | `/proof/response` | Request a status proof for a certificate |
| POST | `/proof/hash` | Request a landmark proof by hash |


---


