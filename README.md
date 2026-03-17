
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
Basic Flow
- Client gets status + landmarkProof.
- Depending on the status, it expects landmarkProof to contain certain stuff.
- Good -> memberIssueProof & nonMemberRevocationProof
- Revoked -> memberIssueProof & memberRevocationProof
- Unknown -> nonMemberIssueProof & nonMemberRevocationProof(redundant?)

```
// Distributed out of band
SignedLandmark {
     SignedData      // (RootHash + TreeSize + Date)
     RootHash        // Append-log root hash
     TreeSize        // Needed to calculate proof
     Date            // Timestamp    
   }
```


```
// Proof sent as part of response to OCSPRequest
OCSPProof {
    TimeSent        // timestamp generated
    Epoch           // What epoch / landmark nr
    CombinedProof   // IssueProof + RevProof
    LogProof        // Append-log proof  
  }
```


```
// Where the append-log is stored
AppendLog {
    treeRange      // Stores the "peeks" / Calculated root
    nodeStore      // Stores the leaf and intermediate nodes
  }
```