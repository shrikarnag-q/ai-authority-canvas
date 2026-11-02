# Related practice and scope

Action-specific permission, limited authority, human review, and decision records are established practices. This repository offers a small teaching example rather than asserting a new control method.

The [OWASP AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html) describes controls around tool authorization, approval context, records, and the boundary between an agent and its execution environment. Its protection against approval reuse requires an atomic check and consume step. This reference has no such store or execution boundary.

[OWASP LLM06 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/?lang=us) discusses limiting functions and permissions and applying review and downstream authorization. A confirmation prompt alone does not implement those controls.

[NIST AI 600-1](https://doi.org/10.6028/NIST.AI.600-1), published in July 2024, discusses documentation, oversight responsibilities, system inventories, provenance, and evaluation history. It does not prescribe the toy schema in this repository or certify the worksheet.

The exercise intentionally exposes gaps that a real integration would have to resolve. Anyone assessing it should examine the assumptions and implementation directly rather than relying on the 27/27 fixture result as assurance.
