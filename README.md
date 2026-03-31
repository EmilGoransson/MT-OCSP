## Merkle OCSP

Each leaf contains (Serial | IssueDate)


Status =Good, =Revoked:
- Uses Hash-chaining

Status = Unknown
- Uses Hash-chaining + Date-based proof.


A certificate can be represented as:
```
serial := big.NewInt(1111)
serialBytes := serial.Bytes()
date := time.Now()
```

A client can verify the validity of the OCSP-proof via:
```
ocsp.Verify(serverProof, signedLandmark, serialBytes, date)
```

What implements what / Flow

```

      --- Client ---  <-> Cert to validate
      |		       ^
      v		       |
  OCSPRequest    OCSPResponse [landmarkProof, status]
(Cert & Landmark- ID) ^
      |	 	          |
      v 	          |    		              ----> CurrentEpoch [CombinedTree] 	  -> Sorted & Sparse MT [sortedMT & SMT]
    OCSP Server (Responder) ---> [Landmark]  |
      ^			   		                      ----> LastEpoch    [CombinedTree]    -> Sorted & Sparse MT [sortedMT & SMT]
      |
      |
      CA -> Issues & Revokes certs


```
Add: Client sends Serial + Issue-date

Basic Flow
- Client sends cert 
- Client gets status + landmarkProof.
- Depending on the status, it expects landmarkProof to contain certain stuff.
- Good -> memberIssueProof & nonMemberRevocationProof
- Revoked -> memberIssueProof & memberRevocationProof
- Unknown -> nonMemberIssueProof for the date / time the cert was issued. (Might require the user to send whole cert OR cert ID + date)
