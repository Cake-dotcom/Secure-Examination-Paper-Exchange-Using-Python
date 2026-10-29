# Secure examination-paper exchange

A Python 3.11+ demonstration of confidential examination-paper delivery from an authorised faculty member to an examination coordinator across an untrusted file-transfer channel. It treats every received package as untrusted and publishes plaintext only after signature verification, identity checks, RSA key recovery and GCM authentication all succeed.

## Install and run

From the project directory, on PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e '.[test]'
.\.venv\Scripts\python.exe -m secure_exam.cli setup
.\.venv\Scripts\python.exe -m secure_exam.cli encrypt sender/input/exam_paper.txt
.\.venv\Scripts\python.exe -m secure_exam.cli deliver
.\.venv\Scripts\python.exe -m secure_exam.cli decrypt transfer/inbox/exam_paper.secure
.\.venv\Scripts\python.exe -m secure_exam.cli simulate
.\.venv\Scripts\python.exe -m secure_exam.cli test
.\.venv\Scripts\python.exe -m secure_exam.cli attack-demo
```

On Linux/macOS use `.venv/bin/python` instead. `pip install -r requirements.txt` followed by `pip install -e .` is an alternative. `requirements.lock.txt` records exact dependency versions used for this validation; install it before `pip install -e .` to reproduce them. The installed `secure-exam` command is equivalent to `python -m secure_exam.cli`. `--root PATH` and `--verbose` precede the subcommand; relative input/output paths resolve under that root. Run tests from this source checkout; the CLI test commands require its tests and pytest.

For a no-prompt, repeatable demonstration, run `.\.venv\Scripts\python.exe scripts/demo.py`. This creates a new `results/demo-*/` participant workspace, generates independent random passwords in process memory, runs the actual `simulate` command and prints its encrypted-package and verified-output paths. Those passwords are discarded on exit, so the demonstration keys cannot be reused later. Use the normal prompted `setup` workflow for durable keys. Encrypted packages and verified recovered files remain available for inspection in the isolated demo workspace.

Private-key passwords are prompted with `getpass`, with confirmation during generation/setup. They are never stored in source or command arguments. Automated runs may provide `SECURE_EXAM_SENDER_PASSWORD` and `SECURE_EXAM_RECIPIENT_PASSWORD` through a secret-aware environment. Environment variables are visible to privileged processes; clear them after use. Use distinct strong passwords. Forgotten passwords cannot be recovered. The generated demonstration keys are local, ignored files.

`setup` creates both separate key pairs, exchanges **only public keys**, and creates sample input if absent. Repeating it checks and reuses matching keys and preserves inputs. `setup --force` deliberately replaces both pairs and pinned public keys; old packages then need the old keys. `generate-keys sender` and `generate-keys recipient` generate individual pairs; run setup afterwards to exchange their public keys. A conflicting existing key requires deliberate `--force`.

`simulate` performs setup, encryption, delivery, verification, decryption and an actual byte comparison. It uses new package and output paths on every invocation and never rotates existing keys. Its printed paths identify the sample encrypted packages under `transfer/`. Existing setup-generated input is reused. `--force` is unnecessary for simulations. Run `--help` on any command for options.

## Architecture and key ownership

```text
src/secure_exam/     CLI, key management, primitives, wire format, validation,
                    sender, recipient and simulation modules
sender/input/       Binary examination papers (text, PDF, DOCX, etc.)
sender/keys/        Encrypted sender private key; own and recipient public keys
recipient/keys/     Encrypted recipient private key; own and sender public keys
recipient/output/   Plaintext only after successful authentication
transfer/outbox/    Sender's encrypted packages
transfer/inbox/     Copies delivered over the simulated untrusted channel
attacker/modified_packages/  Separate attacker copies
samples/            Sample examination paper
tests/              Automated acceptance and adversarial tests
results/            Recorded validation results
docs/sequence_diagram.mmd   Mermaid sequence diagram
```

The sender never receives the recipient private key; the recipient never receives the sender private key. The simulation process necessarily orchestrates both directories on one computer. Directory separation alone does **not** enforce OS isolation: use separate accounts, ownership/ACLs, or separate hosts for real participants. The transfer channel gets encrypted packages only.

Public-key exchange is assumed authenticated. `setup` simulates this assumption by locally copying public keys. In deployment, verify SHA-256 public-key fingerprints out of band or use a managed PKI. A signature proves origin only relative to the recipient's pinned sender key and configured sender identifier. An attacker who substitutes that key defeats the trust model.

## Cryptography and exact package format

* **Confidentiality:** a fresh cryptography-generated 32-byte AES key and 12-byte nonce for every encryption; AES-256-GCM encrypts arbitrary binary data. RSA-4096-OAEP wraps only the session key for the recipient, with exponent 65537, SHA-256, MGF1-SHA256 and fixed label `None` (empty label).
* **Integrity:** the standard 16-byte GCM tag authenticates ciphertext and the exact metadata AAD. The high-level AESGCM API returns plaintext only after authentication. A valid sender signature does not replace this independent check.
* **Sender authentication:** RSA-4096-PSS using SHA-256, MGF1-SHA256 and exactly 32 salt bytes signs the complete unsigned envelope. All loaded RSA keys must be 4096 bits with exponent 65537. Private keys use password-encrypted PKCS#8 PEM with `BestAvailableEncryption`.

Version 1 is a JSON object with **exactly** these fields:

| Fields | Representation |
| --- | --- |
| `version` | Integer `1` (boolean is prohibited) |
| `sender`, `recipient` | 1â€“64 ASCII letters/digits and `_.@-`, beginning with a letter/digit |
| `filename` | Conservative portable basename, at most 120 ASCII characters |
| `created_utc` | Valid UTC calendar timestamp `YYYY-MM-DDTHH:MM:SSZ` |
| `algorithms` | Exact map defined below |
| `encrypted_key` | Canonical standard Base64 of 512 RSA ciphertext bytes |
| `nonce` | Canonical standard Base64 of 12 bytes |
| `ciphertext` | Canonical standard Base64, possibly empty for empty input |
| `tag` | Canonical standard Base64 of 16 bytes |
| `signature` | Canonical standard Base64 of 512 bytes |

Exact algorithm map:

```json
{"content":"AES-256-GCM","key":"RSA-4096-OAEP-SHA256-MGF1-SHA256-LABEL-EMPTY","signature":"RSA-4096-PSS-SHA256-MGF1-SHA256-SALT32"}
```

Canonical serialization is Python `json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('utf-8')`. The restricted schema has no floating-point values or arbitrary Unicode strings. The wire file must equal this canonical serialization byte for byte; pretty-printing it invalidates the format. Duplicate keys (including nested keys), unknown fields, noncanonical encodings, BOMs, invalid JSON constants, trailing bytes, unsupported algorithms/versions, malformed dates, field types and lengths are rejected.

RSA-PSS signs the canonical full object **excluding only `signature`**. GCM AAD is the canonical object consisting of exactly `version`, `sender`, `recipient`, `filename`, `created_utc`, `algorithms`, `nonce`. These same fields are also signed. The RSA-encrypted key, ciphertext and tag are covered by the signature. No plaintext or unwrapped AES key appears in a package.

The recipient parses and validates first, verifies the sender signature second, checks participant identifiers third, loads/decrypts with the recipient private key fourth, authenticates GCM fifth, and only then publishes a safely named file. Structural validation uses metadata only as untrusted input; no trusted identity or output decision occurs before signature verification.

## Limits, output safety and permissions

The default maximum plaintext/ciphertext size is 10 MiB. `encrypt`, `decrypt` and `deliver` accept `--max-size BYTES`. Package reads have a corresponding Base64 expansion bound plus 8192 bytes. Reads stop at limit+1 bytes. All operations use binary I/O. The implementation holds a bounded file in memory rather than streaming unauthenticated plaintext to disk.

Portable filename validation rejects path separators, absolute paths, traversal, colons, control characters, Windows device names and trailing dots/spaces. Input and output paths reject symlinks, junctions and reparse points where detectable. Local output directories must be controlled by the application account: portable path checks cannot prevent a privileged/concurrent attacker from replacing parent directories between checks. Do not use adversary-writable participant/output directories.

Files are staged in their destination directory with exclusive creation and flushed before publication. Without `--force`, Windows uses its no-replace `os.rename`; Unix uses atomic hard-link publication to prevent clobber races. Unix filesystems must support hard links (for example ext4 or APFS); unsupported filesystems fail safely. `--force` deliberately replaces an existing regular file with `os.replace`; it still rejects observed symlink destinations. Temporary files are cleaned up on handled errors. Process termination or power loss may leave staging files; plaintext staging exists only after authentication. This is atomic visibility, not a full power-loss durability guarantee.

On Unix, newly created files use mode `0600` and setup creates participant directories with mode `0700`. Existing directory permissions are not repaired automatically. On Windows, chmod does not establish an equivalent private-key ACL: use separate Windows users and NTFS ACLs, disable broad inherited access on each participant directory, grant that participant and necessary administrators access, and verify effective permissions. Encrypted PEM mitigates theft but is not a substitute for filesystem access control.

Exit codes: `0` success, `1` rejected operation or filesystem error, `2` argparse usage error. `test`/`attack-demo` forward pytest exit codes (including `1` failed tests and `5` no tests). Useful errors exclude secret material. Verbose logging never includes plaintext, passwords, private keys or session keys.

## Attacks and tests

Create independent attacker copies after producing the default package:

```powershell
.\.venv\Scripts\python.exe -m secure_exam.cli attack ciphertext
.\.venv\Scripts\python.exe -m secure_exam.cli attack metadata
.\.venv\Scripts\python.exe -m secure_exam.cli attack signature
.\.venv\Scripts\python.exe -m secure_exam.cli decrypt --package attacker/modified_packages/ciphertext.secure
.\.venv\Scripts\python.exe -m secure_exam.cli attack-demo
.\.venv\Scripts\python.exe -m pytest -v
```

The tampered decrypt must return exit code 1 with a signature error. `attack` also supports `tag`, `nonce`, `encrypted_key`, `--package`, `--output`, `--force`. The original package remains untouched. Repeating the same attack destination requires deliberate `--force` or a new output path.

`attack-demo` runs all test cases named `negative` using temporary participant directories and test-only signing keys, and reports pytest's `PASSED`/`FAILED` per case. It includes ciphertext/metadata/signature tampering, wrong recipient private key, wrong trusted sender key, malformed/ambiguous packages, recipient binding, unsafe filenames, existing output, and **validly re-signed** GCM ciphertext/tag/nonce/AAD changes. Those latter tests isolate GCM independently of signature verification. Every negative decryption compares the complete output snapshot, asserts no new plaintext, and preserves existing files. Wrong-key, size-policy and key overwrite tests also check safe failure. Symlink tests report a skip if the OS denies symlink creation.

The full suite additionally checks byte-identical binary recovery, empty input, fresh keys/nonces for repeated encryption, public/private key separation, repeatable setup, encrypted PEMs, CLI round trips, repeatable simulations and signature-before-private-key processing. Tests generate real RSA-4096 keys, with session-scoped reuse for speed. Test directories are ephemeral and contain no project private keys.

Observed on 29 October 2026: **86 full-suite tests passed; 79 attack checks passed, 7 non-attack tests deselected; no failures or skips.** The standalone simulation recovered byte-identical plaintext. Actual commands, logs, hashes and environment details are recorded in [results/validation.md](results/validation.md). A generated sample package is saved as `samples/exam_paper.secure`, with its public verification key in `samples/demo_sender_public.pub`. This sample belongs to an isolated demo with discarded passwords; create a new transfer with your own prompted setup for later decryption. Never treat the bundled verification key as an authenticated key for real examination papers.

## Security boundaries and future work

This is a teaching/demo application, not a production-ready examination delivery system. It lacks user login/authorisation, revocation, PKI, hardware key storage, secure remote transport, replay prevention, expiry enforcement, audit retention, rate limiting and traffic-analysis protection. A valid package can be replayed to a fresh output directory; timestamps are authenticated data, not a freshness guarantee. Filenames, identifiers, timestamps and length are public metadata. Compromised endpoints or sender signing keys defeat the corresponding protections. Python does not guarantee secure erasure of in-memory keys/passwords/plaintext. Back up keys securely; old private keys are needed for old packages. No forward secrecy is provided by RSA key transport. Production deployment would require isolated identities and hosts, managed trust/rotation, replay tracking and operational security review.


## Final workshop submission

See [requirement audit](docs/workshop_audit.md) for the requirement-by-requirement findings. The existing cryptographic architecture is retained. The current paper is `sender/input/exam_paper.txt` (also `samples/exam_paper.txt`): ten form-feed-delimited pages, 2,557 words and 100 marks. Print with page breaks enabled; pagination otherwise depends on the viewer.

The current matching encrypted sample is `samples/workshop_exam_paper.secure`, with `samples/workshop_sender_public.pub`. Historical sample names retain the earlier short demonstration and must not be mistaken for this expanded paper. The new diagram is [secure_exam_exchange.mmd](docs/secure_exam_exchange.mmd). Automated Mermaid validation was unavailable; syntax was manually reviewed.

Commands executed for finalization in PowerShell:

```powershell
$env:TEMP = 'V:\cryptography_workshop\.tmp'
$env:TMP = $env:TEMP
.\.venv\Scripts\python.exe -O scripts\finalize_workshop.py > results\workshop_simulation.txt
.\.venv\Scripts\python.exe -m secure_exam.cli test > results\test_results.txt
.\.venv\Scripts\python.exe -m secure_exam.cli attack-demo > results\workshop_attacks.txt
```

The finalizer invokes setup, simulate, encrypt, deliver, decrypt and second encryption/decryption with a fresh isolated root. Exact resolved command arguments and byte-comparison/fresh-key evidence are in `results/workshop_verification.json`. It preserves existing participant keys and historical packages. Passwords for its demonstration keys are discarded; use prompted setup with your own passwords for durable key ownership. Re-running the finalizer intentionally refreshes the two `workshop_*` sample artifacts and evidence file.

Current results: 86 passed, 0 failed, 0 skipped in the full suite; 79 passed, 0 failed, 0 skipped and 7 deselected in attack-demo. The seven intentional exclusions are successful transfer, repeated encryption, key separation, empty input, repeatable setup, CLI workflow and signature-before-private-key ordering; these run in the full suite. Negative tests assert no new output and preservation of existing files. The repeated-encryption test additionally unwraps and compares the actual AES keys without logging them.

`results/workshop_submission.zip` contains source, configuration, tests, documentation, sample input/encrypted files and current evidence; it excludes private keys, virtual environments and temporary participant workspaces.
