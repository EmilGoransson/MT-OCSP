- 
To consider: 
- If status= good/revoked should use date-based proofing as well
- If the date should be commited to the log (can adversary "fake" the date?)
- Alternative to date, but is safer: you would need to create an exclusion-proof for each issued epoch. 

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
