## Merkle OCSP

Merkle-based OCSP prototype.

Implements proof of concept Merkle OCSP responder and requesting client 


Proofs by status:
- `Good`: hash-chaining
- `Revoked`: hash-chaining
- `Unknown`: hash-chaining + date-based proof


Sample Certificate:
```go
// In OCSP a certificate is represented as the serial number
serial := big.NewInt(1111)
date := time.Now() 
```

Client proof request to responder:
```go
response , _ := postGetResponseProof(serial, date)
// POST to /proof/response
```


Verification:
```go
key, _ := getPublicKey()
valid, err := ValidateLandmark(lm, key)
valid, _ := ocsp.Verify(serverProof, signedLandmark, serial.Bytes(), date)
```

Flow:
```text
Client -> Responder: serial + issueDate
Responder -> Client: status + landmarkProof

CA -> issued / revoked certs
Responder -> current + previous landmarks
Landmark -> sorted MT + sparse MT
```

Expected proof content:
- `Good`: `memberIssueProof` + `nonMemberRevocationProof`
- `Revoked`: `memberIssueProof` + `memberRevocationProof`
- `Unknown`: `nonMemberIssueProof` for the claimed issue date

Note:
- The sorted tree proves issuance
- The sparse tree proves revocation against the newest epoch


## Architecture

```text
Controller
├── Log (append-only, rfc6962)
├── Revocation (Sparse Merkle Tree, persists across epochs)
└── Landmarks []
    └── Landmark
        ├── LogIndex
        ├── Date
        └── Combined
            ├── IssuedMT  (Sorted Merkle Tree, per epoch)
            └── RevSMT    (Sparse Merkle Tree, cumulative)
```

Each epoch the controller:
1. Drains the queued issued and revoked certificates
2. Builds a new `Combined` tree (sorted MT + sparse MT)
3. Commits the combined root + date to the append-only log
4. Creates a new `Landmark` pointing to that log entry


## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/ping` | Health check |
| GET | `/start` | Start the epoch ticker |
| GET | `/stop` | Stop the epoch ticker |
| POST | `/cert/add` | Queue issued certificates |
| POST | `/cert/revoke` | Queue revoked certificates |
| GET | `/landmark` | Fetch the latest signed landmark |
| GET | `/key` | Fetch the server's public key |
| POST | `/proof/response` | Request a status proof for a certificate |
| POST | `/proof/hash` | Request a landmark proof by hash |


## Running

Start the responder (server):
```bash
go run ./cmd/responder
```

Start the client:
```bash
go run ./cmd/client
```

The default epoch frequency is 20 seconds. Certificates queued with `/cert/add` or `/cert/revoke` are committed at the next epoch.


## Signed Landmark

The CA signs and distributes a `SignedLandmark` out of band following the frequency. It covers:

```text
SHA256(logRoot + logSize + frequency + date)
```

Clients use the `SignedLandmark` to anchor all proof verification without trusting the responder directly.


## Trees

**Sorted Merkle Tree** (`IssuedMT`)
- Leaves are serial numbers, which are sorted before insertion
- Supports membership and non-membership (exclusion) proofs
- Rebuilt each epoch from the issued certificates
- github.com/txaty/go-merkletree

**Sparse Merkle Tree** (`RevSMT`)
- Leaves are hashed, and inserted as a key-value pair 
- Persists and grows across epochs. At a new epoch, only the tree-head value is stored, and the leaves pruned
- Membership proves revocation; non-membership proves `Good` status
- github.com/celestiaorg/smt

**Append-only Log**
- rfc6962 hash tree
- Each entry commits `SHA256(combinedRoot + date)` for one epoch
- Log proofs allow clients to verify a landmark is genuinely in the log
- github.com/transparency-dev
