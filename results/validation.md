# Observed validation — 29 October 2026

Environment: Windows, Python 3.12.6, cryptography 50.0.2, pytest 9.2.0. Exact installed dependency versions are in `requirements.lock.txt`. Installation completed in the project-local `.venv`; `pip check` reported no broken requirements. Source, scripts and tests passed `compileall`.

## Final runs

From the project root, PowerShell:

```powershell
# Local temporary directory avoids this managed environment's system-temp restrictions.
$env:TEMP = "$PWD\.tmp"
$env:TMP = $env:TEMP
.\.venv\Scripts\python.exe -m secure_exam.cli test
.\.venv\Scripts\python.exe -m secure_exam.cli attack-demo
.\.venv\Scripts\python.exe scripts\demo.py
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m compileall -q src scripts tests
```

| Run | Observed result | Evidence |
| --- | --- | --- |
| Full suite through CLI `test` | **86 passed**, 36.08 seconds; no failures/skips | `cli-test.txt` |
| CLI `attack-demo` | **79 passed**, 7 deselected, 27.18 seconds; no failures/skips | `attack-demo.txt`, `attack-demo.xml` |
| Standalone CLI simulation via launcher | **PASS**, byte-for-byte equality | `simulation.txt` |
| Independent inspection | Both package signatures valid; hashes equal; private keys separated; transfer contains packages only | `inspection.json` |
| Dependency consistency | No broken requirements found | Executed `pip check` |

The initial test runs exposed a Windows hard-link restriction and two test-fixture portability/conflict issues. Those were fixed before the successful final runs. Final hardening added tests for staging-file collision preservation and cleanup after publication failure. The earlier 84-test direct pytest run is retained as `pytest.txt` and `pytest.xml`; the **86-test CLI log is the final full-suite result**.

## Demonstration artifacts

Latest isolated workspace: `results/demo-053be8bf9445de03/`.

* Original: `sender/input/exam_paper.txt` inside that workspace.
* Delivered sample: `transfer/inbox/demo-6e9b3364de658292.secure`.
* Sender copy: `transfer/outbox/demo-6e9b3364de658292.secure`.
* Recovered file: `recipient/output/demo-6e9b3364de658292/exam_paper.txt`.
* Original and recovered SHA-256: `0931d5117c5c5488432e34044078a3d704efe33e4974a22c64079a8184ce12a1`.
* A stable copy of the generated envelope and its public verification key is in `samples/`.

The launcher generated separate random passwords and encrypted RSA private keys; passwords were not printed or persisted and were discarded on exit. The isolated artifacts demonstrate the completed transfer; repeat the launcher for a fresh run. For keys you can use later, run normal `setup` and enter your own passwords. No default-workspace private keys were generated, so the prompted workflow is ready for first-time setup.

## Acceptance coverage

The full suite covers A–L: authorised binary transfer, ciphertext/metadata/signature tampering, wrong recipient private key, wrong sender public key, independent encryption of identical inputs, strict malformed-package rejection, recipient binding, filename/output safety, valid-signature GCM authentication failure, and private-key separation. Additional cases cover empty input, wrong passwords, sender binding, size limits, bad key types/sizes/exponents, duplicate/noncanonical JSON, invalid Base64 and dates, repeatable setup/simulation, CLI exit codes, output symlinks, temporary collisions, cleanup, and verification order.

Rejected receives snapshot all existing destination files and assert that no new plaintext is published. Existing-output tests assert preservation before deliberate authorised replacement. Symlink tests ran successfully on this account; none were skipped. These observations apply to the tested Windows environment. Unix branches and operational isolation still require deployment-specific verification. This remains a demonstration application.
