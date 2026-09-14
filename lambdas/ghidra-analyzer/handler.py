"""Stage 1 Lambda entrypoint: S3-triggered static analysis via Ghidra.

Expects input binaries under an `incoming/` prefix (see infra/ for the S3
event notification's prefix filter -- this is what keeps the pipeline
from re-triggering itself on its own output). Writes the raw structured
report to the same bucket under `reports/<original-key>.json`.
"""

import json
import logging
import os
import urllib.parse
import uuid

import boto3

from analysis.extract import analyze_binary

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client("s3")

INPUT_PREFIX = "incoming/"
OUTPUT_PREFIX = "reports/"

# Reserve time for S3 download-before/upload-after and JSON serialization
# of a potentially large report, on top of whatever analyze_binary()
# itself uses. Below MIN_USABLE_SECONDS, don't even attempt analysis --
# a Ghidra JVM boot alone costs several seconds, so trying anyway on an
# invocation that's about to be killed just wastes compute for no report.
SAFETY_BUFFER_SECONDS = 20.0
MIN_USABLE_SECONDS = 30.0

ANALYSIS_BUDGET_FRACTION = 0.6
METADATA_BUDGET_FRACTION = 0.2
DECOMPILE_BUDGET_FRACTION = 0.2


def lambda_handler(event, context):
    results = []
    for record in event.get("Records", []):
        results.append(_process_record(record, context))
    return {"processed": results}


def _process_record(record, context):
    bucket = record["s3"]["bucket"]["name"]
    # S3 event keys are URL-encoded (e.g. spaces become '+') -- a classic
    # gotcha if you skip this and pass the raw key straight to GetObject.
    key = urllib.parse.unquote_plus(record["s3"]["object"]["key"])
    output_key = _output_key(key)

    local_path = f"/tmp/{uuid.uuid4().hex}-{os.path.basename(key)}"
    try:
        s3.download_file(bucket, key, local_path)

        usable_seconds = context.get_remaining_time_in_millis() / 1000 - SAFETY_BUFFER_SECONDS
        if usable_seconds < MIN_USABLE_SECONDS:
            raise TimeoutError(
                f"Only {usable_seconds:.1f}s remained after download; "
                f"not enough to attempt analysis (minimum {MIN_USABLE_SECONDS}s)."
            )

        report = analyze_binary(
            local_path,
            analysis_budget_seconds=usable_seconds * ANALYSIS_BUDGET_FRACTION,
            metadata_budget_seconds=usable_seconds * METADATA_BUDGET_FRACTION,
            decompile_budget_seconds=usable_seconds * DECOMPILE_BUDGET_FRACTION,
        )
        report["source"] = {"bucket": bucket, "key": key}
        _put_json(bucket, output_key, report)
        return {"bucket": bucket, "key": key, "output_key": output_key, "status": "analyzed"}

    except Exception as exc:
        # Deliberately not re-raised: S3-triggered Lambda invocations are
        # asynchronous, and AWS retries failed async invocations automatically.
        # A malformed/unsupported binary fails identically every time, so
        # letting it raise would mean paying for the same expensive Ghidra
        # run 2-3x for a guaranteed-identical failure. Report the error to
        # S3 instead and return normally so Lambda considers this "handled."
        logger.exception("Analysis failed for s3://%s/%s", bucket, key)
        error_report = {
            "source": {"bucket": bucket, "key": key},
            "error": {"type": type(exc).__name__, "message": str(exc)},
        }
        _put_json(bucket, output_key, error_report)
        return {"bucket": bucket, "key": key, "output_key": output_key, "status": "error"}

    finally:
        # Lambda execution environments can be reused (warm starts) --
        # nothing from this binary should still be sitting in /tmp for
        # the next invocation that lands on this same container.
        if os.path.exists(local_path):
            os.remove(local_path)


def _output_key(input_key: str) -> str:
    relative = input_key[len(INPUT_PREFIX):] if input_key.startswith(INPUT_PREFIX) else input_key
    return f"{OUTPUT_PREFIX}{relative}.json"


def _put_json(bucket: str, key: str, payload: dict):
    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=json.dumps(payload).encode("utf-8"),
        ContentType="application/json",
    )
