# Sipster
**Sipster: Settling IOU of Smart Meters Privately and Quickly**


**Abstract:**
Cyber-physical systems revolutionize the way computing systems
interact with our physical world. Smart grid is a prominent example.
With advanced features such as fine-grained billing, user privacy
is at a greater risk than before. For instance, a utility company
(UC) can infer customers’ (fine-grained) usage patterns from their
payment. The literature only focuses on hiding individual meter
readings in bill calculation. It is unclear how to preserve amount
privacy in verifiable payment. After all, UC needs to assert that
each customer has settled the amount as calculated in the bill. Note
that e-cash by itself only preserves privacy for withdrawal and
spending of e-coins but does not hide the payment amount.
How to settle the bill issued by a smart meter, while UC (who
owns the meter) cannot learn about the bill that leaks one’s finegrained
utility usage?We avoid this seemingly unavoidable privacy
leakage by advocating a new paradigm of cash payment settlement.
Our protocol Sipster preserves the privacy of users by letting them
pay their bills in unit amount, which also allows the UC to obtain
payments earlier in the pay-as-you-go model. Sipster thus enables a
win-win situation. A highlight of Sipster is that the receipts for the
payments can be combined into a 𝑂(1)-size receipt certifying the
smart meter’s certification. Without such aggregation, techniques
such as zero-knowledge proof would fail since it typically cannot
hide the size of the witness. Indeed, seemingly helpful tools, e.g.,
aggregate signatures or fully homomorphic signatures, also fail.
The novelty of Sipster lies in achieving our five goals simultaneously:
1) privacy-preserving: UC cannot infer a customer’s payment
amount; 2) prover-efficient: no zero-knowledge proof is ever needed;
3) verifier-efficient: it takes constant time to verify a combined receipt;
4) double-claiming-free: customers cannot present the same
receipt twice; and 5) minimalistic smart meter: it can report signed
readings (needed even in a non-private setting).

**Instructions of running the code:**
1. Required tool kits: PBL http://crypto.stanford.edu/pbc, OpenSSL:https://www.openssl.org/
2. Using GCC to complie the source file in the "Codes" folder and then run "./Sipster.run".
3. You can also directly download and run the complied file "./Sipster.run".
4. The **interactive program** is stored under the folder “Example# Evaluate the computation time of SM” and “RU_UC” which takes different inputs to test the proposed algorithm from various aspects, such as different billing phases and the number of tokens. 
5. **An additional interactive program** is stored under the folder "Sipster_codes" which benchmark the Sipster by taking more inputs including the different Sipster role (devices), algorithm (billing) phases, the number of RUs (i.e., N), and the number of tokens (i.e., K). 

**Example compile commands on iMac devices:**

gcc  Sipster.c RU_CombineReceipt_Sipster.c RU_Verify_Sipster.c SM_BillGen_Sipster.c SM_TokenGen_Sipster.c UC_Bill_Verify_Sipster.c UC_ReceiptGen_Sipster.c -o ./Sipster.run -I /usr/local/Cellar/pbc/0.5.14/include/pbc -I /usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib  -l pbc -lgmp -lssl -lcrypto 
