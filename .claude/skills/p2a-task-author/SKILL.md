---
name: p2a-task-author
description: Use when authoring a Gate C task graph draft from a Plan2Agent context bundle so an agent proposes tasks and a human approves them at the gate.
---

# Plan2Agent Task Author

Author a reviewable Gate C task graph draft from an approved active Plan2Agent iteration context. This is a sibling to `p2a-task-breakdown`, but it writes only a draft and hands off to a human approval gate before any canonical task graph is promoted.

## Ownership

- Draft authorship belongs to the read-only `p2a-task-author` subagent.
- The skill owner obtains the context bundle, passes it to the subagent, reviews the returned draft JSON, and is the only agent that persists `task-graph.draft.json`.
- If subagents are unavailable, the active skill owner may author the draft locally, but it must preserve the same authorship-versus-persistence boundary.

## When to use

Use this skill when the active iteration has an approved Gate B spec and needs a Gate C task graph authored as a reviewable draft. The draft is agent-proposed work, not the canonical Gate C artifact; a human must review and approve it before promotion.

## Inputs

The skill owner runs the context command to get the `p2a.task_context.v1` JSON bundle before invoking the task-author subagent:

```bash
node .plan2agent/scripts/p2a_iteration.mjs context --artifacts <root>
```

Use these context fields:

- `project_id`
- `effective_spec.product`
- `effective_spec.implementation`
- `existing_tasks.active`
- `existing_tasks.maintenance`
- `spec_field_changes`
- `idea`
- `active_iteration`
- `code_signals`

Use `context.code_signals` (the real file tree and recent changed files) to author tasks incrementally on top of existing code; do not duplicate code or work that already exists.

## Output

The task-author subagent returns the complete draft JSON to the skill owner without writing files. After reviewing that response, the skill owner writes only this draft artifact:

```text
iterations/<active_iteration>/gate-c-task-graph/task-graph.draft.json
```

The draft must conform to `.plan2agent/schemas/task-graph.schema.json` (`p2a.task_graph.v1`) and include:

- `schema_version`: `p2a.task_graph.v1`
- `projectId`: copied exactly from `context.project_id`.
- `version`: `<active_iteration>-draft`
- `sourceSpec`: `../gate-b-spec/spec.json`
- `tasks[]`

Each task must include:

- `id`: sequential `task-NNN` values within the draft.
- `title`
- `description`
- `status`: `todo`
- `dependencies`: only task ids from the same draft graph.
- `acceptanceCriteria`: at least one concrete criterion.
- `targetArea`
- `suggestedAgentPrompt`: a paste-ready, scope-bounded prompt for the implementing agent.
- `sourceSpecRefs`: at least one reference to a real `effective_spec` field, such as `implementation.architecture`.

Never write `task-graph.json` directly. The canonical graph is created only by `promote-tasks` after human approval.

## Authoring rules

- Split work into small dependent tasks, typically 10-50 tasks for a meaningful iteration.
- Split large features by screen, API, data, and test boundaries.
- Avoid duplicate work: do not create a new task that duplicates `existing_tasks.active`.
- If `existing_tasks.active` is non-empty, do not author or persist an incremental-only draft. The context contains task summaries rather than the complete canonical task bodies. When every canonical task is still `todo`, invoke `diff-tasks --force` as the authoritative check: it generates a complete graph only when the active iteration has no run history. Review that result and promote it with explicit `--replace-existing`. Do not infer safety from the bounded `code_signals.recent_changes` summary. If any canonical task is `in_progress`, `done`, or `blocked`, or the CLI reports run history after a task was reopened to `todo`, do not replace the graph: open a new feature iteration or use the maintenance lane so task state and run lineage remain intact.
- Use `existing_tasks.maintenance` as context, but do not turn maintenance pilot work into this draft.
- Merge trivially connected work; split work that spans multiple target areas.
- Draft each task so its acceptance criteria are self-satisfiable from that task's explicit scope; do not attach AC that require earlier or later draft tasks to complete.
- When a draft task adds a framework dependency that triggers auto-configuration, include the minimal required configuration (for example, a datasource URL) in that same task, or explicitly place build-green AC on the later task that owns that configuration.
- Every task must be traceable: `sourceSpecRefs` must point to actual `effective_spec` product or implementation fields so `validateTaskGraphData` can pass.
- Do not create tasks for scope that is absent from the approved effective spec.
- If `spec_field_changes` is non-empty, focus the draft around changed fields rather than re-authoring unchanged baseline scope.
- Do not put cross-iteration dependencies in `dependencies`; record prerequisites from prior iterations in `description` and `sourceSpecRefs` instead.
- Keep dependency graphs acyclic and reference only ids in the same draft graph.

## Boundaries

Only author tasks backed by the approved spec. If the requested work changes product meaning by adding a new user flow, API, data model, success criterion, or similar product decision, do not author it as a task. Tell the user that it requires a separate feature iteration through Gates A-D.

## After authoring

After the skill owner writes the draft, hand it to the human gate with these steps:

1. Validate the draft:

   ```bash
   node .plan2agent/scripts/p2a_iteration.mjs validate --artifacts <root> --stage gate-c-draft
   ```

2. If the human approves after review, promote the approved draft and record the Gate C audit in `current-spec.json`:

   ```bash
   node .plan2agent/scripts/p2a_iteration.mjs promote-tasks \
     --artifacts <root> \
     --approved-by user \
     --approval-note "<review rationale>"
   ```

   `promote-tasks` records `current-spec.json.gate_c_approval_audits[active_iteration]`, writes `task-graph.draft.meta.json`, and promotes the draft to canonical `task-graph.json`.

   When a canonical task graph already exists, the default promotion is rejected to prevent an incremental-only draft from deleting existing task state. Before execution starts, a complete replacement draft produced and reviewed through `diff-tasks --force` may be promoted only with explicit `--replace-existing`. After any task leaves `todo` or any run is recorded for the active iteration, replacement is rejected even if the task is later reopened to `todo`; the change must use a new feature iteration or maintenance task.

## Constraints

- The task-author subagent is strictly read-only and returns draft content without writing files or running commands.
- The skill owner may write only the draft artifact and run the scoped validation command described above.
- Do not change application code, dependencies, or non-draft artifacts.
- Do not write canonical `task-graph.json`; promotion is the job of `promote-tasks` after the human approval gate.
