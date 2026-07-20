---
name: p2a-review
description: Use when reviewing a Plan2Agent spec, implementation plan, or task graph for missing decisions and execution risk.
---

# Plan2Agent Review

Review planning artifacts before implementation starts.

## Inputs

- `spec_json`.
- `task_graph_json`.
- Optional intake artifact for decision traceability.

## Output

Return `review_json` (schema `p2a.review.v1`). An optional `review_report` Markdown view may be generated from the JSON for human review. `review_json.blocking_issues` must be an empty array when the review passes with no blockers.

`review_json` includes `schema_version`, `projectId`, `sourceSpec`, `sourceTaskGraph`, and:

- `blocking_issues`
- `non_blocking_risks`
- `missing_tests_or_acceptance_criteria`
- `oversized_tasks`
- `dependency_issues`
- `schema_or_gate_issues`
- `evidence_or_citation_issues`
- `recommended_changes`

## Required Checks

- `spec_json.approval` is `approved` before task graph readiness is claimed.
- `spec_json.open_decisions` is empty.
- Approved Gate B status includes `spec_json.approval_audit` with `approved_by`, `approved_at`, `approved_artifacts`, and `approval_note`.
- Every intake `CQ-n` appears exactly once in `spec_json.clarifying_question_disposition`.
- No raw `CQ-n` id appears in `spec_json.open_decisions`; unresolved blockers from clarifying questions must be promoted to `ND-n`.
- Every promoted clarifying question decision is either listed in `open_decisions` while unresolved or has a `resolution` before approval.
- Every task dependency references an existing task id.
- The task graph has no cycles.
- Every task has concrete acceptance criteria and source spec references.
- Tasks that add dependencies have acceptance criteria that are self-satisfiable from that task's scope, especially when auto-configuration side effects could break builds or context loading unless handled in the same task.
- The plan does not silently implement assumptions that were previously marked `needs_user_decision`.
- Approved specs that choose or recommend a library, framework, runtime, protocol, package, database, cloud service, external API, or other material dependency include Gate B Technology Reconnaissance: primary/current source comparison, a nearby rationale/citation, and at least one relevant `WEB-n` evidence item.
- If `spec_json.reference_reconnaissance` is present, every candidate must point to an existing `evidence[].source_id`, every selected/rejected pattern must point to a known `REF-n` candidate, and the selected/rejected rationale must be consistent with the Gate B recommendation.
- Web-grounded decisions have `WEB-n` evidence entries with title, URL, and `used_for` rationale.
- Treat missing Technology Reconnaissance evidence for a material technology choice as a blocking Gate B issue, not as a non-blocking citation nit.

## Rules

- Findings must be concrete and actionable.
- Prefer blocking only when implementation would be unreliable without a decision.
- Do not rewrite the entire spec unless requested.
- Do not edit files or run commands.
