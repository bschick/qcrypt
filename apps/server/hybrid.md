I am wrestling with concerns about rushing into PQC standards that are likely to change, but it does not seem correct that because software can be easily updated that we can wait. Specifically, I am using libsodium to create long-term artifacts that depend on key exchange strength (keys must be regenerated in the future). So although libsodium could be updated 15 years from now, the artifacts created with it today could be exposed in a PQ world.

After SIKE, just using ML-KEM today seems risky. Many important projects seem to be concluding that the best choice right now is a  hybrid protocol like XWing that is in the RFC process. I created a scenario table to help think about this. My conclusion is that many people believe (or perhaps want) _Scenario 1_ to become the steady state, but are highly concerned it could be _Scenario 4_ for a long while.

| **Scenario** | **DH Broken (aka workable QC) later** | **ML-KEM Broken later** | **DH only now secure later** | **ML-KEM only now secure later** | **Hybrid now secure later** |
|--------------|---------------------------------|-------------------|------------------------------|----------------------------------|-----------------------------|
| 1            | yes                             | no                | no                           | yes                              | yes                         |
| 2            | yes                             | yes               | no                           | no                               | no                          |
| 3            | no                              | no                | yes                          | yes                              | yes                         |
| 4            | no                              | yes               | yes                          | no                               | yes                         |

The time to "later" is of course important. The existence of hybrid indicates many think we're living either scenario 1 or 4 and that "later" could be soon (so ML-KEM and DH only are out). Interestingly if you think hybrid is important today because scenario 4 is likely true for a while, but you don't completely disregard QC, then scenario 2 should be highly concerning for any long-term artifacts created today.

Overall it looks like the anti-negative strategy is increasingly common... which is that hybrid is not broken in 3 of the 4 laters.

