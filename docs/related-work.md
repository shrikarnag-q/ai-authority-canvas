# Related practice and scope

Action-specific permission, limited authority, human review, and decision records are established practices. This repository offers a small teaching example rather than asserting a new control method.

The [OWASP AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html) describes controls around tool authorization, approval context, records, and the boundary between an agent and its execution environment. The version 1.0 stateless exercise has no approval store or execution boundary. The [version 1.1 execution lab](../lab/README.md) adds a local approval ledger and atomic consumption for fictional SQLite mutations. It still relies on a trusted host for identity, actual human consent, key protection, and policy administration.

The [OWASP Transaction Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html#28-system-should-check-each-transaction-execution-and-make-sure-it-has-been-properly-authorized) describes an execution-time authorization check and protection against changing transaction data after approval. The lab illustrates that established practice inside one database transaction; it does not implement remote transaction recovery.

[RFC 9396, OAuth 2.0 Rich Authorization Requests](https://www.rfc-editor.org/rfc/rfc9396.html#section-2), specifies structured, fine-grained authorization details. Its [resource-server section](https://www.rfc-editor.org/rfc/rfc9396.html#section-9) requires approved details to be available where authorization is enforced. Describing the precise operation is established practice. This lab's custom action object and HMAC artifact do not implement OAuth or claim RFC conformance.

[RFC 9449, OAuth 2.0 Demonstrating Proof of Possession](https://www.rfc-editor.org/rfc/rfc9449.html), addresses sender-constrained tokens. Its [request-integrity section](https://www.rfc-editor.org/rfc/rfc9449.html#section-11.7) explains that the specified proof does not cover the general request body or headers. Sender binding and approval of exact operation parameters are distinct concerns. This observation is not a vulnerability claim against DPoP; the RFC describes the boundary. The lab neither implements nor benchmarks DPoP.

[OWASP LLM06 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/?lang=us) discusses limiting functions and permissions and applying review and downstream authorization. A confirmation prompt alone does not implement those controls.

[NIST AI 600-1](https://doi.org/10.6028/NIST.AI.600-1), published in July 2024, discusses documentation, oversight responsibilities, system inventories, provenance, and evaluation history. It does not prescribe the toy schema in this repository or certify the worksheet.

The exercises intentionally expose gaps that a real integration would have to resolve. Neither the 27 stateless fixture matches nor the lab's author-defined check results establish independent validity, a standards certification, production security, or adoption. The [lab review protocol](lab-review-protocol.md) provides a starting point for a concrete critique.
