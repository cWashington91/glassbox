"""Calls Bedrock to interpret a condensed Ghidra report.

Stage 1 only extracts facts (see ghidra-analyzer/analysis/extract.py's
own docstring); this is deliberately where judgment -- suspicious or
not, capability guesses -- actually happens, kept in its own module
rather than mixed into Stage 1's extraction code.
"""

import json

import boto3

BEDROCK_ANTHROPIC_VERSION = "bedrock-2023-05-31"
MAX_OUTPUT_TOKENS = 2048

SYSTEM_PROMPT = """You are a malware triage analyst reviewing static analysis \
(disassembly/decompilation) performed by Ghidra on an unknown binary. The \
binary was never executed -- everything you're given comes from static \
analysis only, so you cannot know its actual runtime behavior, only what \
its code appears capable of.

Be calibrated, not alarmist: most submitted binaries are benign. Only flag \
something as suspicious if there's a concrete reason tied to the evidence \
(a specific API, string, or code pattern) -- and say so plainly when the \
evidence is inconclusive or the underlying analysis was incomplete (check \
analysis_status in the report).

Respond with ONLY a single JSON object matching this exact schema, no \
prose before or after it:
{
  "capability_classification": "one short label, e.g. 'benign utility', \
'downloader', 'credential access', 'ransomware-like', 'unknown -- \
insufficient evidence'",
  "confidence": "low" | "medium" | "high",
  "summary": "2-4 sentences, plain English",
  "suspicious_api_calls": [{"api": "...", "concern": "..."}],
  "obfuscation_indicators": [{"indicator": "...", "detail": "..."}],
  "notable_strings": [{"string": "...", "reason": "..."}],
  "caveats": "anything a reader should know about this analysis's \
limitations -- partial analysis, a small sample of decompiled functions, \
a truncated string list, etc. Empty string if none apply."
}"""


def build_user_message(condensed_report: dict) -> str:
    return "Static analysis report (condensed from Ghidra's output):\n\n" + json.dumps(condensed_report)


def invoke_bedrock(condensed_report: dict, model_id: str) -> dict:
    client = boto3.client("bedrock-runtime")

    body = json.dumps({
        "anthropic_version": BEDROCK_ANTHROPIC_VERSION,
        "max_tokens": MAX_OUTPUT_TOKENS,
        "system": SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": build_user_message(condensed_report)}],
    })

    response = client.invoke_model(modelId=model_id, body=body)
    payload = json.loads(response["body"].read())
    text = payload["content"][0]["text"]

    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        # The model didn't return clean JSON despite instructions --
        # surface the raw text rather than silently losing it.
        raise ValueError(f"Model response was not valid JSON: {text[:500]}") from exc
