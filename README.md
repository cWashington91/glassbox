# Glassbox

> Status: Stage 1 (Ghidra static analysis) is built, deployed, and
> verified end-to-end in AWS. Stage 2 (AI triage), a full threat-model
> write-up, an architecture diagram, and a detailed cost breakdown are
> still to come.

An ephemeral, serverless static binary analysis pipeline: drop a binary
into S3, get back a structured Ghidra report plus (eventually) an
AI-generated triage summary, with no persistent compute or execution of
the sample at any point.

## How it works today

1. A binary is uploaded to `incoming/` in a private S3 bucket.
2. That upload triggers a Lambda (`lambdas/ghidra-analyzer`) running
   Ghidra 12.1.3 headless, driven natively via PyGhidra's Python API --
   no `analyzeHeadless` subprocess, no Ghidra project files ever touch
   disk.
3. The Lambda extracts functions (signatures, call-graph edges,
   control-flow stats), decompiled pseudocode, imports, strings, and
   memory sections into a structured JSON report. Every phase that
   scales with binary size has its own wall-clock budget, so a large or
   complex binary degrades to a partial-but-honestly-flagged report
   instead of silently hitting Lambda's timeout with nothing written.
4. The report is written back to the same bucket under `reports/`.

Stage 2 -- an AI model interpreting that raw report into a triage
summary -- is not built yet.

## Repo layout

```
lambdas/
  ghidra-analyzer/
    Dockerfile             # Ghidra 12.1.3 + JDK 21 + PyGhidra, checksum-verified
    handler.py             # S3 event entrypoint
    analysis/extract.py    # the actual extraction logic
    test_handler_local.py  # local smoke test, no AWS needed
  ai-triage/                # Stage 2 (TBD)
infra/                       # OpenTofu: VPC, S3, ECR, IAM, Lambda
```

## Infrastructure

Deployed and tested in a single region (`us-east-1`):

- **Network isolation.** The Lambda runs in a private-subnet-only VPC
  with no Internet Gateway and no NAT Gateway -- there is no route to
  the internet at all. S3 access goes through a free Gateway VPC
  endpoint, additionally scoped by its own policy to this bucket only.
  Verified in practice: CloudWatch logging still works with no NAT and
  no Logs endpoint, since Lambda ships stdout/stderr through its own
  internal path rather than the function's VPC networking.
- **IAM.** The Lambda's execution role has exactly three permissions --
  `s3:GetObject` on `incoming/*`, `s3:PutObject` on `reports/*`, and
  `logs:CreateLogStream`/`PutLogEvents` on its own log group. No
  `s3:ListBucket`, no `logs:CreateLogGroup`.
- **S3.** Public access fully blocked, SSE-S3 encryption, a TLS-only
  bucket policy, and a 30-day lifecycle expiration.
- **ECR.** Immutable tags, scan-on-push, lifecycle policy expiring
  untagged images.
- **Compute sizing.** Lambda allocates vCPU proportionally to memory,
  and Ghidra's JVM is CPU-bound -- a real test binary ran in 112s at
  2048MB but only 46s at 3008MB, with *fewer* total GB-seconds billed
  despite the higher memory, since billed cost is memory x duration.
  More memory was both faster and cheaper here, up to a point.
- **Cost.** Comfortably inside AWS's Always Free tier at portfolio/demo
  volume -- a real run bills roughly 140 GB-seconds, against a
  400,000/month free allowance. ECR image storage (~$0.10/GB-month) is
  the one line item that isn't literally free.

## Design principles

- **Static analysis only.** The pipeline never executes the submitted
  binary. Ghidra's headless analyzer disassembles/decompiles; it does
  not run the sample.
- **No outbound internet from the analyzer.** Enforced at the network
  layer -- the analyzer's VPC has no route to the internet, not just
  "the code doesn't call anything."
- **Nothing persists between runs.** No Ghidra project files ever
  touch disk (PyGhidra's projectless load mode); the downloaded binary
  is removed from `/tmp` even on failure, since Lambda execution
  environments can be reused across invocations.
- **Fail loud to S3, not silently into Lambda's retry logic.** Analysis
  errors are caught and written back as an error report rather than
  raised -- a malformed input fails the same way every time, so letting
  it raise would mean paying for the same expensive Ghidra run 2-3x via
  Lambda's automatic async-invoke retries.
