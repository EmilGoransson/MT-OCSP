To fix: 


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
- Client sends cert 
- Client gets status + landmarkProof.
- Depending on the status, it expects landmarkProof to contain certain stuff.
- Good -> memberIssueProof & nonMemberRevocationProof
- Revoked -> memberIssueProof & memberRevocationProof
- Unknown -> nonMemberIssueProof for the date / time the cert was issued. (Might require the user to send whole cert OR cert ID + date)

```
// Distributed out of band
SignedLandmark {
     SignedData         // hashed & signed (RootHash + TreeSize + Date)
     LogRoot            // Append-log root hash
     LogSize            // Needed to calculate proof
     Date               // Timestamp    
   }
```


```
// Proof sent as part of response to OCSPRequest
LandmarkProof {
    LogProof            // Append-log proof  
    LogIndex            // What epoch / landmark nr
    CombinedProof       // IssueProof + RevProof
  }
```



```
// Where the append-log is stored
AppendLog {
    TreeRange           // Stores the "peeks" / Calculated root
    NodeStore           // Stores the leaf and intermediate nodesw, ID -> hash
    LeafIndexStore      // reverse Nodestore, hash -> ID
  }
```
type AppendLog struct {
treeRange      *compact.Range            // Stores the "peeks" / Calculated root
nodeStore      map[compact.NodeID][]byte // Stores the leaf and intermediate nodes
leafIndexStore map[string]uint64
}