
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
