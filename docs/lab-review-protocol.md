# Review one execution-lab claim

This protocol is an invitation to technical criticism of the version 1.1 local lab. It is not a completed review or a request for an endorsement. A useful first review can focus on one claim; a full security assessment would require substantially more work.

## Record the checkout and reproduce the example

Use Python 3.11 or later with its standard SQLite module, in a local checkout. The lab has no package dependencies and uses temporary fictional databases. It does not connect to a model, account, customer system, or network service.

```sh
git rev-parse HEAD
python3 -c 'import sys, sqlite3; print(sys.version); print(sqlite3.sqlite_version)'
python3 lab/demo.py
python3 lab/run_checks.py --output lab/reproduced-checks.json
```

Record your actual outputs and environment. `reproduced-checks.json` is a local report; do not replace the published `check-results.json` to make it appear to be an external review. A passing rerun only reproduces author-defined checks. Their expectations were developed alongside the implementation with material AI assistance.

The demo attempts a changed amount, then the approved amount, then reuse of the same approval. Its documented expectation is denial, one committed local change, and denial. Read the reported reasons and final state as well as the booleans. The reviewer identity in this demo is scripted; no person is asked to approve it.

## Choose a claim to challenge

Write down an expected property before designing your own small synthetic example. Keep the trusted-host assumptions explicit.

| Claim | Where to inspect | A useful challenge or limit |
| --- | --- | --- |
| Approval covers the exact permitted operation | `validate_action`, `action_hash`, `_verify_token` | Change a parameter, actor, tenant, target, or version after issuance. Does execution deny it without the proposed mutation? |
| Current authority still matters | `_role`, `_current`, `revoke`, `control` | Remove a current role, change context, stop and resume, revoke, or cross the expiry boundary. Check what is actually revalidated. |
| Approval consumption and the local effect commit together | `_transaction`, `execute` | Challenge concurrent reuse or a failure before commit. Inspect committed database state, approval state, and audit records together. A remote email or API call is outside this transaction. |
| The audit has a bounded tamper check | `_append_audit`, `verify_audit` | Compare an edited record with deleted trailing records. Tail deletion needs an independently protected checkpoint; the lab supplies no external checkpoint service. |

Relevant existing examples are in `lab/test_authority_lab.py`. Reading those checks and rerunning them is useful reproduction, but it is different from independently choosing a new scenario. Neither activity establishes production effectiveness.

## Explain the boundary

The trusted host creates the `Principal`, protects the shared HMAC key and database, controls policy, and obtains informed human consent. A Python `Principal` value does not authenticate anyone. An artifact MAC does not prove that a human saw or understood a preview. The code does not implement a real approval interface or identity provider.

The local transaction can atomically commit only its SQLite changes. If an adapter sends an email or changes an external service, reviewers must analyze that service's authorization, idempotency and failure recovery separately. A valid local audit chain does not establish that an external effect happened, or protect against a compromised host, signing key, or full database rollback.

These limits are part of the claimed scope. A finding can still identify an unclear explanation, an implementation error within that scope, or an assumption that makes the example unsuitable for a proposed integration.

## Return an observation with its limits

Use the [blank review record](lab-review-record-template.json), a public issue, or a private response through your existing contact with the author. Include:

- Exact commit, environment, and files inspected.
- Expected property, minimal fictional input, command, observed output, and final state.
- Whether you executed the example or only inspected it, and what remains untested.
- Any relationship or compensation that is relevant to interpreting the review. A name or affiliation is optional for public feedback.

Do not include private data, credentials, or customer records. Public issues are publicly visible. Permission to quote private feedback, use a name, or claim a deployment must be obtained separately for the exact use; the blank record grants none of these permissions.

The author should preserve critical findings and record the correction commit or unresolved issue. Do not turn a rerun, download, issue, or favorable comment into a claim of endorsement, customer adoption, independent security certification, or field impact.

The [related-work page](related-work.md) identifies established OWASP and IETF practices. This lab illustrates a limited example; it does not introduce a new authorization standard or claim conformance to those protocols.
