---
name: p2a-intake
description: Use when extracting requirements, assumptions, and clarification questions from a one-sentence Plan2Agent product idea.
---

# Plan2Agent Intake

Convert an early idea into structured planning input.

## Inputs

- One-sentence product or feature idea.
- Optional user notes.
- Optional prior `intake_json` and newly answered decision ids when resuming.

## Output

Return an `intake_json` object conforming to `.plan2agent/schemas/intake.schema.json` with:

- `schema_version`: `p2a.intake.v1`
- `idea`: original idea
- `summary`: one paragraph restating the idea
- `known_facts`: facts stated by the user
- `assumptions`: objects with `id`, `statement`, `risk`, and `confirmation_needed`
- `clarifying_questions`: objects with `id`, `question`, `why_it_matters`, and `blocks`
- `needs_user_decision`: objects with `id`, `question`, `options`, `impact`, `default`, `status`, and optional `answer`
- `evidence`: source objects with `source_id`, `title`, `url`, and `used_for`
- `status`: `blocked_on_user` when any decision is `open` or `deferred`, otherwise `ready_for_spec`

- Also produce a human-readable analysis in the conversation. The harness may generate `intake.md` as an optional view/export from `intake_json`, but `intake_json` is the source of truth. The analysis should follow the harness soft template and contain the restated understanding, each assumption with its reasoning, and for every `needs_user_decision` the option trade-offs, a recommended option with rationale, the downstream artifacts it blocks, and the current decision `status` (`open`, `answered`, or `deferred`). If a decision is `answered`, clearly show the selected option/answer in prose, for example `선택: <option label>` or `Selected: <option label>`.

When `status` is `blocked_on_user`, lead with the analysis narrative (understanding, assumptions with reasoning, and per-decision trade-offs and recommendations). A Markdown decision table may supplement it but must not replace the explanation.

## Decision IDs

- Use stable ids like `ND-1`, `ND-2`, `CQ-1`, and `A-1`.
- Do not renumber existing ids during resume.
- Mark a decision `answered` only when the user's answer selects or clearly overrides an option.
- On resume, when you set a decision to `answered` in `intake_json.needs_user_decision`, update the conversational summary and any generated `intake.md` view from the JSON. Do not maintain Markdown as a second editable source.
- `intake_json` is canonical for each `needs_user_decision` status and selected answer.

## Rules

- Ask only questions that materially change product scope, data shape, UI flow, or implementation risk.
- Prefer defaults for low-risk details and label them as assumptions.
- Stop at intake when high-impact decisions remain open or deferred.
- Do not design the full implementation yet.
- Follow the Evidence and Citation Contract in `.agents/skills/p2a-harness/SKILL.md` for `USER-n`, `LOCAL-n`, `WEB-n`, Feature Radar, and web-lookup evidence. If prior-art or domain lookup changes a question or assumption, cite the source id in the rationale.
- Do not edit files or run commands.
- Do not write files yourself; return your structured content and analysis so the harness orchestrator can persist the artifacts.
