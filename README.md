# Glassbox

> Status: Stage 1 (Ghidra static analysis) and Stage 2 (AI triage via
> Bedrock) are both built and deployed to AWS. Stage 1 is verified
> end-to-end. Stage 2's plumbing (S3 trigger, report condensation, IAM,
> the Bedrock call itself) is confirmed correctly wired -- the one thing
> not yet confirmed live is a successful model response, currently
> blocked on AWS's standard new-account verification hold on Bedrock
> access. A full threat-model write-up, architecture diagram, and
> detailed cost breakdown are still to come.

An ephemeral, serverless static binary analysis pipeline: drop a binary
into S3, get back a structured Ghidra report plus an AI-generated triage
summary, with no persistent compute or execution of the sample at any
point.

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
4. That report is written back to the same bucket under `reports/`.
5. The report write triggers a second Lambda (`lambdas/ai-triage`),
   which condenses the report -- even a 26MB report shrinks to roughly
   35KB, keeping full imports/strings/control-flow stats plus the
   largest already-decompiled functions' pseudocode -- and asks Claude,
   via Bedrock, for a structured triage: capability classification,
   suspicious API calls, obfuscation indicators, notable strings, and a
   confidence level.
6. The triage result is written under `triage/`. A report representing
   a Stage 1 failure is skipped before ever reaching Bedrock -- no
   reason to pay for a model call on a stack trace.

## Repo layout

```
lambdas/
  ghidra-analyzer/
    Dockerfile             # Ghidra 12.1.3 + JDK 21 + PyGhidra, checksum-verified
    handler.py             # S3 event entrypoint
    analysis/extract.py    # the actual extraction logic
    test_handler_local.py  # local smoke test, no AWS needed
  ai-triage/
    handler.py             # S3 event entrypoint
    condense.py            # shrinks a report to a bounded, model-worthy payload
    triage.py              # the Bedrock prompt + call
    test_handler_local.py  # local smoke test, no AWS needed
infra/                      # OpenTofu: VPC, S3, ECR, IAM, both Lambdas
```

## Infrastructure

Deployed and tested in a single region (`us-east-1`):

- **Network isolation (Stage 1 only).** The Ghidra analyzer runs in a
  private-subnet-only VPC with no Internet Gateway and no NAT Gateway --
  there is no route to the internet at all. S3 access goes through a
  free Gateway VPC endpoint, additionally scoped by its own policy to
  this bucket only. Verified in practice: CloudWatch logging still works
  with no NAT and no Logs endpoint, since Lambda ships stdout/stderr
  through its own internal path rather than the function's VPC
  networking.
- **IAM.** Each Lambda's execution role is scoped to exactly what it
  needs. The analyzer gets `s3:GetObject` on `incoming/*` and
  `s3:PutObject` on `reports/*`; the triage Lambda gets `s3:GetObject`
  on `reports/*`, `s3:PutObject` on `triage/*`, and `bedrock:InvokeModel`
  scoped to one specific model. Both get `logs:CreateLogStream`/
  `PutLogEvents` on their own log group -- no `s3:ListBucket`, no
  `logs:CreateLogGroup`, anywhere.
- **S3.** Public access fully blocked, SSE-S3 encryption, a TLS-only
  bucket policy, and a 30-day lifecycle expiration.
- **ECR.** Immutable tags, scan-on-push, lifecycle policy expiring
  untagged images -- used only by Stage 1.
- **Stage 2 packaging.** A plain ZIP deployment, not a container image:
  it's just `boto3` (already bundled in Lambda's Python runtime) plus
  three small files, so no ECR repo or multi-GB image is needed at all.
  Deliberately not VPC-isolated like Stage 1 -- Bedrock has no free
  Gateway endpoint (only paid Interface endpoints), and this Lambda
  processes Stage 1's own structured JSON output rather than raw
  attacker-controlled bytes through a native parser, so the isolation
  cost/benefit tradeoff points the other way here.
- **Compute sizing.** Lambda allocates vCPU proportionally to memory,
  and Ghidra's JVM is CPU-bound -- a real test binary ran in 112s at
  2048MB but only 46s at 3008MB, with *fewer* total GB-seconds billed
  despite the higher memory, since billed cost is memory x duration.
  More memory was both faster and cheaper here, up to a point.
- **Cost.** Comfortably inside AWS's Always Free tier at portfolio/demo
  volume -- a real Stage 1 run bills roughly 140 GB-seconds, against a
  400,000/month free allowance. ECR image storage (~$0.10/GB-month) and
  Bedrock's per-call token cost are the line items that aren't literally
  free, though both are small at this scale.

## Design principles

- **Static analysis only.** The pipeline never executes the submitted
  binary. Ghidra's headless analyzer disassembles/decompiles; it does
  not run the sample.
- **No outbound internet from the analyzer.** Enforced at the network
  layer -- Stage 1's VPC has no route to the internet, not just "the
  code doesn't call anything."
- **Nothing persists between runs.** No Ghidra project files ever touch
  disk (PyGhidra's projectless load mode); the downloaded binary is
  removed from `/tmp` even on failure, since Lambda execution
  environments can be reused across invocations.
- **Fail loud to S3, not silently into Lambda's retry logic.** Both
  stages catch their own failures and write back an error report rather
  than raising. For Stage 1, a malformed input fails the same way every
  time, so letting it raise would mean paying for the same expensive
  Ghidra run 2-3x via Lambda's automatic async-invoke retries. Stage 2
  goes further and skips the model call entirely for a report that's
  already a Stage 1 failure.
