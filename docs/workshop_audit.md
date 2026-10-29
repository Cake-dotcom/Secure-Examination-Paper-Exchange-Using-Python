# Workshop audit and submission map

Audit date: 29 October 2026. Existing architecture retained. Existing participant keys were found and preserved; no force rotation was performed.

| Requirement | Initial assessment and evidence | Final action |
|---|---|---|
| Separate RSA-4096 pairs, exponent 65537 | Correct: key_manager generation and validation; separation test L | Preserved |
| Encrypted private keys, secure loading | Correct: encrypted PKCS#8, getpass/environment, bounded loading, key checks | Preserved; OS isolation limitations remain documented |
| Trusted public exchange | Correct: exchange_public_keys copies only public keys | Preserved; simulated trusted channel explicitly assumed |
| Fresh AES-256 key and 12-byte nonce | Correct: fresh library random generation inside every encrypt call | Extended test G to compare unwrapped actual AES keys, not merely randomized OAEP ciphertexts |
| AES-GCM and 16-byte tag | Correct: high-level AESGCM API and explicit tag length | Preserved |
| RSA-OAEP SHA256 / MGF1-SHA256 | Correct: recipient public key, fixed empty label | Preserved |
| RSA-PSS SHA256 / MGF1-SHA256 | Correct: sender private key, 32-byte salt | Preserved |
| Complete signed envelope | Correct: all fields except signature canonicalized; exact schema | Preserved |
| Metadata AAD | Correct: version, identities, filename, time, algorithms, nonce | Preserved; diagram updated |
| Trusted verification and identity binding | Correct: pinned public key, signature then identities before private-key use | Preserved; tests F, I and ordering test |
| Authenticate before plaintext publication | Correct: one-shot AESGCM followed by atomic_write | Preserved; valid-signature GCM failure tests K |
| Useful errors and safe failure | Correct: dedicated exceptions, CLI exit codes, output snapshots | Preserved; malformed, wrong-key and output-safety tests |
| Successful transfer and binary equality | Existing test A and simulate compare bytes | Re-executed using expanded paper and both independent encryptions |
| Ciphertext, metadata, signature attacks | Existing B/C/D negative tests | Re-executed through attack-demo |
| Wrong private/public keys | Existing E/F tests isolate OAEP/signature failures | Re-executed |
| Distinct repeated encryption | Existing G checked nonce and envelope fields | Added actual AES-key assertion; independently checked in finalizer |
| No plaintext leakage / regression | Existing negative tests snapshot output and sentinel files | Full suite rerun; no rewrite needed |
| Substantial sample | Incomplete: original contained only two questions | Replaced sender input and sample copy with 10 explicit text pages, 2557 words, 100 marks |
| Required named diagram | Existing diagram useful but requested file absent | Added docs/secure_exam_exchange.mmd with explicit algorithms and security notes |
| Fresh matching encrypted sample | Historical sample existed for old demonstration | Created samples/workshop_exam_paper.secure and matching public verification key; preserved historical pair |
| Reproducible simulation | Existing demo used short built-in fallback | Demo launcher now copies current sender paper; finalizer runs supported CLI commands in a fresh isolated workspace |
| Readable current results | Prior results alone insufficient | results/test_results.txt, workshop_attacks.txt, workshop_simulation.txt and workshop_verification.json |
| Security explanation and local scope | README already accurate | Added submission guide; no network/PKI/replay/revocation claims |

The exam has 10 sections of 10 marks: Q1–Q10 carry 1 mark each; Q11–Q28 carry 5 marks each. Total: 10 + 18*5 = 100. Nine form-feed page breaks delimit ten pages; actual printer pagination depends on text rendering. Content includes MCQs, short/conceptual answers, supplied-formula numerical problems, toy RSA working, scenarios and implementation review. No answers are supplied.

Diagram syntax was manually reviewed against sequenceDiagram participant, message, opt, alt/else/end and Note syntax. No mmdc executable or bundled Mermaid package was available, so automated Mermaid parsing/rendering was not performed. To independently render: `mmdc -i docs/secure_exam_exchange.mmd -o docs/secure_exam_exchange.svg` with Mermaid CLI installed.

The finalizer uses independently generated temporary demonstration passwords, discarded after verification, following the existing launcher policy. It retains matching encrypted keys in its isolated results workspace but cannot later unlock them without those discarded passwords. Existing user keys are untouched. For durable transfers use the normal prompted setup/encrypt/deliver/decrypt workflow. The generated sample is verified during creation, not claimed decryptable with historical or replacement keys.

No functional cryptographic defect requiring a protocol rewrite was identified. Remaining boundaries: same-account folders are role simulation, output parents must be trusted, Unix branches are not executed on this Windows host, and there is no real network transport, replay prevention, certificate PKI or production revocation.
