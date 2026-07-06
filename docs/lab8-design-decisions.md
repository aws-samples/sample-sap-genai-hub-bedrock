# Lab 08 — AgentCore Memory & Evaluation: Design Decisions

## Goal

Demonstrate production-readiness features on top of the Lab 7 deployed agent:
- **Part A**: AgentCore Memory (short-term session + long-term semantic/preference)
- **Part B**: AgentCore Evaluations (built-in + custom evaluators, on-demand via EvaluationClient against OTEL traces)

---

## Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                     Amazon Bedrock AgentCore                            │
│                                                                        │
│  ┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐   │
│  │  Agent Runtime   │    │  AgentCore Memory │    │  Evaluations    │   │
│  │  (from Lab 7)    │◄──►│  - Short-term     │    │  - Built-in     │   │
│  │                  │    │  - Long-term      │    │  - Custom       │   │
│  │  Warehouse Agent │    │  - Semantic       │    │  - On-demand    │   │
│  │  + SAP GenAI Hub │    │  - User Prefs     │    │  - OTEL Traces  │   │
│  └─────────────────┘    └──────────────────┘    └─────────────────┘   │
│           │                                              │             │
│           ▼                                              ▼             │
│  ┌─────────────────┐                          ┌─────────────────┐     │
│  │ SAP S/4HANA     │                          │ CloudWatch Logs  │     │
│  │ OData APIs      │                          │ (OTEL Spans)     │     │
│  └─────────────────┘                          └─────────────────┘     │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Part A: Memory — Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Memory integration pattern | `MemorySessionManager` + Strands `HookProvider` | Non-invasive, composable — hooks inject memory context without modifying agent logic |
| Short-term memory | `get_last_k_turns(k=5)` | Keeps context window manageable while preserving recent conversation |
| Long-term strategies | Semantic + User Preference (built-in) | No custom IAM role needed; covers both factual recall and personalization |
| Namespace pattern | `warehouse/{actorId}/facts/` and `warehouse/{actorId}/preferences/` | Per-user isolation, clear separation of concerns |
| Memory injection | Appended to system prompt on each `MessageAddedEvent` | Simple, works with any model, visible in traces |

---

## Part B: Evaluation — Design Decisions

### Why AgentCore Evaluations (not strands_evals)

| Criteria | strands_evals (previous) | AgentCore Evaluations (current) |
|----------|--------------------------|----------------------------------|
| Where it runs | Local Python process | Against deployed agent's OTEL traces |
| What it evaluates | Local agent invocation output | Real production spans in CloudWatch |
| Evaluator registration | None (ephemeral) | Registered in AgentCore control plane (reusable) |
| Production path | Not applicable | Same evaluators work for online/batch monitoring |
| Dependencies | `strands-agents-evals`, `nest_asyncio` | `bedrock-agentcore` (already needed for memory) |

**Decision**: Use AgentCore Evaluations exclusively. It demonstrates the production evaluation workflow and doesn't require additional dependencies.

### Why we dropped the baseline comparison

The original design compared a baseline agent (no memory) against the memory-enhanced agent. We dropped this because:
1. The deployed agent either has memory or doesn't — there's no easy way to run both variants on AgentCore
2. The pedagogical value is in demonstrating the evaluation workflow, not proving memory helps
3. Simpler notebook flow — one agent, one evaluation pass

### How AgentCore Evaluation works (key insight)

```
Agent invoked → OTEL spans emitted → CloudWatch Logs ingestion (~90s) → EvaluationClient.run() reads spans → Scores returned
```

- No explicit span collector object needed
- The SDK locates spans by `agent_id` + `session_id` + `look_back_time`
- Log group format: `/aws/bedrock-agentcore/runtimes/{AGENT_ID}-DEFAULT`
- OTEL service name: `{agent_runtime_name}.DEFAULT`

### Evaluators used

**Built-in (4):**
| Evaluator | Level | Ground Truth Needed |
|-----------|-------|-------------------|
| `Builtin.Correctness` | TRACE | `expected_response` |
| `Builtin.Helpfulness` | TRACE | None |
| `Builtin.GoalSuccessRate` | SESSION | `assertions` |
| `Builtin.ToolSelectionAccuracy` | SESSION | None |

**Custom (2):**
| Evaluator | Level | Purpose |
|-----------|-------|---------|
| `SAPDataAccuracy` | TRACE | Checks inventory data correctness (product codes, quantities) |
| `WarehouseGoalCompletion` | SESSION | Checks end-to-end task completion (tools + assertions) |

### Evaluation type choice

Available types: On-demand (per-session), On-demand Dataset Runner, Batch, Online.

**Decision**: On-demand per-session via `EvaluationClient.run()`. Most self-contained for a notebook demo — no additional infrastructure (no IAM role for online eval, no batch job management).

---

## Notebook Structure

| # | Section | Cells | Key APIs |
|---|---------|-------|----------|
| 1 | Import + Init | 0-6 | `SAPGenAIHubModel`, `boto3`, `MemoryClient` |
| 2 | Create Memory Resource | 7-8 | `memory_client.create_memory_and_wait()` |
| 3 | Session Manager | 9-10 | `MemorySessionManager`, `create_memory_session()` |
| 4 | Memory Hook Provider | 11-12 | `HookProvider`, `MemorySession` |
| 5 | Create Agent | 13-14 | `Agent()` with hooks |
| 6 | Test Memory (3 turns) | 15-18 | Agent invocations |
| 7 | Test New Session Recall | 19-20 | Fresh agent instance |
| 8 | Inspect Memories | 21-22 | `search_long_term_memories()` |
| 9 | Verify Observability | 24-26 | `describe_log_groups()`, `filter_log_events()` |
| 10 | Create Custom Evaluators | 26-27 | `create_evaluator()` |
| 11 | Define Scenarios | 28-29 | Plain dicts |
| 12 | Invoke Deployed Agent | 30-31 | `invoke_agent_runtime()` |
| 13 | Built-in Evaluation | 32-33 | `EvaluationClient.run()` |
| 14 | Custom Evaluation | 36-37 | `EvaluationClient.run()` |
| 15 | Display Results | 38-39 | Score matrix |
| 16 | Export Report | 40-41 | JSON export |
| 17 | Cleanup | 42-43 | `delete_evaluator()`, `delete_memory_and_wait()` |

---

## Known Constraints

- `runtimeSessionId` must be >= 33 characters (boto3 validation)
- ~90s delay required after agent invocation for CloudWatch span ingestion
- Custom evaluators with reference input placeholders (`{expected_response}`) only work for on-demand evaluation (not online — live traffic has no ground truth)
- `EvaluationClient._evaluator_level_cache` must be pre-populated (SDK quirk)
- Lab 7 agent must be deployed and running for Part B to work

---

## Dependencies

```
bedrock-agentcore>=1.11.0       # Memory + Evaluation SDK
boto3>=1.37.0                   # AWS clients (bedrock-agentcore, bedrock-agentcore-control, logs)
strands-agents==1.5.0           # Agent framework
pyyaml                          # Reading .bedrock_agentcore.yaml (transitive dep)
```

Removed: `strands-agents-evals`, `nest_asyncio`

---

## Reference Implementation

Based on: https://github.com/awslabs/agentcore-samples/tree/main/01-features/06-observe-evaluate-optimize-your-agent/02-evaluate/llm-as-a-judge-evaluation
