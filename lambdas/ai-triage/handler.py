"""Stage 2 Lambda entrypoint: S3-triggered AI triage of Stage 1's Ghidra
reports.

Expects input reports under a `reports/` prefix (Stage 1's output).
Writes the triage result to the same bucket under `triage/<key>` -- a
distinct prefix, same self-trigger-avoidance pattern as Stage 1's
incoming/ -> reports/ split.
"""

import json
import logging
import os
import urllib.parse

import boto3

from condense import condense_report
from triage import invoke_bedrock

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client("s3")

INPUT_PREFIX = "reports/"
OUTPUT_PREFIX = "triage/"

MODEL_ID = os.environ["BEDROCK_MODEL_ID"]


def lambda_handler(event, context):
    results = []
    for record in event.get("Records", []):
        results.append(_process_record(record))
    return {"processed": results}


def _process_record(record):
    bucket = record["s3"]["bucket"]["name"]
    key = urllib.parse.unquote_plus(record["s3"]["object"]["key"])
    output_key = _output_key(key)

    report = json.loads(s3.get_object(Bucket=bucket, Key=key)["Body"].read())

    if "error" in report:
        # Stage 1 already reported a failure for this binary -- nothing
        # to triage, and no reason to pay for a model call on a stack
        # trace. Still write a marker so there's a complete audit trail.
        logger.info("Skipping triage for %s: underlying analysis failed", key)
        _put_json(bucket, output_key, {
            "source": {"bucket": bucket, "key": key},
            "skipped": True,
            "reason": "Stage 1 analysis failed; nothing to triage.",
        })
        return {"bucket": bucket, "key": key, "output_key": output_key, "status": "skipped"}

    # NOTE: unlike Stage 1's binary-parsing failures (deterministic --
    # same malformed input fails the same way every retry), a Bedrock
    # call can fail transiently (throttling, brief service issues) where
    # Lambda's automatic async retry is actually useful. This still
    # catches broadly and writes an error report for a complete S3 audit
    # trail either way, but it's a real tradeoff worth revisiting if
    # throttling errors turn out to be common in practice.
    try:
        condensed = condense_report(report)
        triage = invoke_bedrock(condensed, MODEL_ID)
        triage["source"] = {"bucket": bucket, "key": key}
        _put_json(bucket, output_key, triage)
        return {"bucket": bucket, "key": key, "output_key": output_key, "status": "triaged"}

    except Exception as exc:
        logger.exception("Triage failed for s3://%s/%s", bucket, key)
        _put_json(bucket, output_key, {
            "source": {"bucket": bucket, "key": key},
            "error": {"type": type(exc).__name__, "message": str(exc)},
        })
        return {"bucket": bucket, "key": key, "output_key": output_key, "status": "error"}


def _output_key(input_key: str) -> str:
    relative = input_key[len(INPUT_PREFIX):] if input_key.startswith(INPUT_PREFIX) else input_key
    return f"{OUTPUT_PREFIX}{relative}"


def _put_json(bucket: str, key: str, payload: dict):
    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=json.dumps(payload).encode("utf-8"),
        ContentType="application/json",
    )
