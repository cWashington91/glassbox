"""Local harness for handler.lambda_handler using fake S3 and Bedrock
clients -- no real AWS needed. Not part of the deployed Lambda; for
interactive testing only.
"""

import io
import json
import os

os.environ.setdefault("BEDROCK_MODEL_ID", "test-model-id")

import handler
import triage


class FakeS3:
    def __init__(self, objects: dict):
        self.objects = objects  # key -> dict (will be JSON-encoded on get)
        self.put_calls = []

    def get_object(self, Bucket, Key):
        body = json.dumps(self.objects[Key]).encode("utf-8")
        return {"Body": io.BytesIO(body)}

    def put_object(self, Bucket, Key, Body, ContentType):
        self.put_calls.append({"Bucket": Bucket, "Key": Key, "Body": Body, "ContentType": ContentType})


class FakeBedrockClient:
    def __init__(self, response_text=None, raise_exc=None):
        self.response_text = response_text
        self.raise_exc = raise_exc
        self.invoke_calls = []

    def invoke_model(self, modelId, body):
        self.invoke_calls.append({"modelId": modelId, "body": body})
        if self.raise_exc:
            raise self.raise_exc
        payload = json.dumps({"content": [{"type": "text", "text": self.response_text}]}).encode("utf-8")
        return {"body": io.BytesIO(payload)}


def make_event(bucket, key):
    return {"Records": [{"s3": {"bucket": {"name": bucket}, "object": {"key": key}}}]}


SAMPLE_REPORT = {
    "program": {"name": "sample", "language": "x86:LE:64:default", "executable_format": "ELF"},
    "analysis_status": {"analysis_complete": True, "metadata_complete": True},
    "control_flow_summary": {"function_count": 3, "decompiled_function_count": 2},
    "sections": [{"name": ".text", "executable": True, "writable": False}],
    "imports": {"libraries": ["libc.so.6"], "symbols": [{"name": "system", "library": "libc.so.6"}]},
    "strings": {"items": [{"address": "0x1000", "value": "/bin/sh", "truncated": False}], "total_count": 1},
    "functions": [
        {"name": "main", "entry_point": "0x1100", "signature": "int main(void)", "byte_size": 50,
         "indirect_transfer_count": 0, "calls": ["system"], "decompiled": True,
         "decompiled_code": "int main(void) { return system(\"/bin/sh\"); }"},
    ],
}

ERROR_REPORT = {
    "source": {"bucket": "test-bucket", "key": "incoming/bad.bin"},
    "error": {"type": "LoadException", "message": "No load spec found"},
}


def run_success_case():
    print("\n=== success path ===")
    fake_s3 = FakeS3({"reports/sample.bin.json": SAMPLE_REPORT})
    valid_triage_json = json.dumps({
        "capability_classification": "unknown -- insufficient evidence",
        "confidence": "low",
        "summary": "Test summary.",
        "suspicious_api_calls": [{"api": "system", "concern": "Executes a shell command with a fixed argument."}],
        "obfuscation_indicators": [],
        "notable_strings": [{"string": "/bin/sh", "reason": "Shell invocation target."}],
        "caveats": "",
    })
    fake_bedrock = FakeBedrockClient(response_text=valid_triage_json)

    handler.s3 = fake_s3
    triage.boto3.client = lambda service: fake_bedrock

    result = handler.lambda_handler(make_event("test-bucket", "reports/sample.bin.json"), None)
    print("result:", json.dumps(result))
    assert len(fake_bedrock.invoke_calls) == 1
    assert len(fake_s3.put_calls) == 1
    put = fake_s3.put_calls[0]
    assert put["Key"] == "triage/sample.bin.json", put["Key"]
    body = json.loads(put["Body"])
    print("triage output:", json.dumps(body, indent=2))
    assert body["capability_classification"] == "unknown -- insufficient evidence"
    print("success path: OK")


def run_skip_case():
    print("\n=== skip path (Stage 1 error report) ===")
    fake_s3 = FakeS3({"reports/bad.bin.json": ERROR_REPORT})
    fake_bedrock = FakeBedrockClient(response_text="should never be called")

    handler.s3 = fake_s3
    triage.boto3.client = lambda service: fake_bedrock

    result = handler.lambda_handler(make_event("test-bucket", "reports/bad.bin.json"), None)
    print("result:", json.dumps(result))
    assert len(fake_bedrock.invoke_calls) == 0, "Bedrock should never be called for a Stage 1 error report"
    assert fake_s3.put_calls[0]["Key"] == "triage/bad.bin.json"
    body = json.loads(fake_s3.put_calls[0]["Body"])
    assert body["skipped"] is True
    print("skip path: OK")


def run_bad_json_case():
    print("\n=== error path (model returns non-JSON) ===")
    fake_s3 = FakeS3({"reports/sample.bin.json": SAMPLE_REPORT})
    fake_bedrock = FakeBedrockClient(response_text="Sure, here's my analysis: it looks fine.")

    handler.s3 = fake_s3
    triage.boto3.client = lambda service: fake_bedrock

    result = handler.lambda_handler(make_event("test-bucket", "reports/sample.bin.json"), None)
    print("result:", json.dumps(result))
    body = json.loads(fake_s3.put_calls[0]["Body"])
    assert "error" in body
    print("error report:", body["error"])
    print("bad-json path: OK")


if __name__ == "__main__":
    run_success_case()
    run_skip_case()
    run_bad_json_case()
    print("\nALL CASES PASSED")
