To fix: 
Unknown case. Its currently skipped over in NewResponse because new response takes a landmark (which is fetched from the hash), but since the cert isnt a part of the issue tree,
landmark is passed as nil. 
Perhaps- make it date-based?


Bug:
Verify flow fails if: 
Reason: They belong to two different trees.
In Verify I assume that both together creates the hash that i commited to the tree, however, that is not true.

Change needed: Inclusion proof needs to include the rev-root for "that tree"
Perhaps verify both side by side? 

1) Epoch 1: Add cert
2) Epoch 2: Revoke same cert
3) Verify fails- mismatched root

Succeeds if: 
1) Epoch 1: Add cert & Revoke same cert
2) Verify ok

// Maybe add some guard against this => This works because rev is "copied" into the later epochs. certs thats been issued however, isnt
1) Epoch 0: Revoke cert
2) Epoch 1: Add cert
3) Verify ok

1) Epoch 1: Add cert
2) Verify ok

1) Epoch 0: Add cert
2) Verify ok

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