# Plan2Agent Project Harness

This repository owns its Plan2Agent planning and development loop in-place.

## Start a greenfield plan

1. Open Claude Code, Codex, or Gemini in this directory and run:

   `/p2a-harness "<one sentence idea>"`

   Planning Gates A-D write artifacts under `.plan2agent/artifacts/<project>/gate-*`.

2. Convert approved planning artifacts into the iteration structure:

   `node .plan2agent/scripts/p2a.mjs iteration init --artifacts .plan2agent/artifacts/<project>`

3. Develop from ready tasks and track execution:

   - `node .plan2agent/scripts/p2a.mjs info`
   - `node .plan2agent/scripts/p2a.mjs execute plan|start|finish|status`
   - `node .plan2agent/scripts/p2a.mjs orchestrate plan|handoff`
   - `node .plan2agent/scripts/p2a.mjs proposals mine|review|curate|draft-patch|approve-draft|digest`
   - `node .plan2agent/scripts/p2a.mjs tasks ready|prompt|start|done`
   - `node .plan2agent/scripts/p2a.mjs runs start|verify|finish`

4. Open the next iteration in this same project:

   `node .plan2agent/scripts/p2a.mjs iteration open|draft|context|promote-tasks`

## Storage policy

The generated `.plan2agent/` directory is local harness state and is ignored by git.
Keep application/source commits focused on product code, and persist P2A planning and run
history through Plan2Agent Memory or an explicit export when needed.
