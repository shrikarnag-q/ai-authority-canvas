# Approval execution lab

This companion to the Authority Canvas implements an approval boundary for two fictional SQLite actions: changing a program's integer budget units and appending a note. It makes the difference between a planning worksheet and an execution check observable in code.

The version 1.0 stateless exercise is retained unchanged at the repository root. This lab adds a local approval ledger, authenticated approval artifacts, revocation, version checks, atomic consumption and an audit chain. It is a teaching reference with material AI assistance, not a production service, independent security review, or claim of a new authorization technique.

## Run

Use Python 3.11 or later with its standard `sqlite3` module. No dependencies, model, API key, network connection, installation, or external account is needed.

```sh
python3 lab/demo.py
python3 lab/run_checks.py --output lab/reproduced-checks.json
```

The demo creates and removes a temporary fictional database. Its reviewer identity is scripted: **no actual human approval is collected**. The tests also use temporary databases. `check-results.json` records a real run, including source hashes and the local runtime; reproduce it to evaluate the current checkout. The source and test expectations were developed together, so passing checks establishes the tested behavior, not independent validity.

## Boundary and assumptions

The trusted host supplies an already-authenticated `Principal`, protects the signing key and database, controls policy changes, and obtains actual informed consent before calling `issue_approval`. A principal is a Python value, not proof of identity. Exposing these methods directly to an agent, accepting a model-provided principal, or giving the agent the key would defeat this boundary.

Approval artifacts use HMAC-SHA256, not a human's digital signature. Their canonical action hash binds tenant, actor, tool, target, exact permitted parameters and resource/policy/context versions. Verification checks the current role records and approval state. Tokens expire after at most five minutes; execution checks the trusted host clock during its transaction. A changed preview needs a new approval.

`BEGIN IMMEDIATE` serializes writers. The approval's state change, fictional mutation and execution audit record commit in one SQLite transaction. A successful call therefore commits one local mutation for that approval. Revocation races serialize too: revocation cannot undo an action already committed. Stopping and resuming advances the context version so pre-stop approvals remain invalid.

This atomicity claim applies **only to mutations inside this database transaction**. Adding an email, payment, cloud API, file-system side effect or other remote adapter would break the demonstrated boundary. Remote operations need their own authorization, idempotency and crash-recovery design; this lab does not provide one.

The audit stores action hashes and decision metadata rather than note contents or token MACs. Its separate derived-key HMAC chain detects the tested record edits. Detecting deletion of the last records requires a trusted checkpoint stored elsewhere. A database administrator or compromised host/key can defeat these protections; this is not immutable storage or protection against full database rollback. SQLite durability also depends on its configuration and underlying storage.

## Checks worth challenging

- Changed actor, tenant, target, tool, amount, versions, unexpected fields and duplicate JSON keys.
- Expiration boundary, future-issued tokens, revocation and removal of current roles.
- Stop/resume and changed policy, context or resource after approval.
- Sixteen concurrent uses of one artifact, and a revocation/execution race.
- Audit-write failure and an abrupt worker exit after mutation but before commit.
- Record tampering, and the known inability to detect tail deletion without an external checkpoint.

The suite is bounded and synthetic. It does not test a model's behavior, a real identity provider, actual reviewer comprehension, a production workload, distributed storage, adversarial database administrators, all Unicode/canonicalization issues, or all possible attacks.

## Established guidance and implementation sources

The design illustrates established practices described in the [OWASP AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html) and [Transaction Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html): enforce the boundary outside model context, bind approval to the operation and check it at execution. See also [Python HMAC](https://docs.python.org/3/library/hmac.html), [Python SQLite transaction control](https://docs.python.org/3/library/sqlite3.html#transaction-control), and [SQLite transactions](https://www.sqlite.org/lang_transaction.html). These organizations do not endorse this project.

For critique, identify the exact checkout, violated property, smallest synthetic reproduction, expected result and observed result. Use the existing issue template; keep private data out of public reports. No practitioner review, real use, external endorsement, novel research result or industry impact is currently claimed.
