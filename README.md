To fix: 
Unknown case. Its currently skipped over in NewResponse because new response takes a landmark (which is fetched from the hash), but since the cert isnt a part of the issue tree,
landmark is passed as nil. 
Perhaps- make it date-based?

Todo: Fix unknown status

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
