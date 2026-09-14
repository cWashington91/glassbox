# Glassbox

> Status: scaffolding. Architecture diagram, full threat model, and cost
> breakdown to come once the pipeline is functionally complete.

An ephemeral, serverless static binary analysis pipeline: drop a binary
into S3, get back a structured Ghidra report plus an AI-generated triage
summary, with no persistent compute or execution of the sample at any
point.

## Repo layout

```
lambdas/
  ghidra-analyzer/   # Stage 1: S3-triggered, runs Ghidra headless
  ai-triage/         # Stage 2: reads the raw report, calls Claude (TBD)
infra/               # CDK app (TBD)
docs/                # architecture diagram + threat model (TBD)
```

## Design principles

- **Static analysis only.** The pipeline never executes the submitted
  binary. Ghidra's headless analyzer disassembles/decompiles; it does
  not run the sample.
- **No outbound internet from the analyzer.** Enforced at the network
  layer (VPC placement + endpoint policy), not just "the code doesn't
  call anything."
- **Nothing persists between runs.** No project files, no leftover
  binaries -- see the /tmp cleanup notes in `handler.py`.