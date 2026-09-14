"""Local harness for handler.lambda_handler using a fake S3 client -- no
real AWS needed. Not part of the deployed image; for interactive testing
inside the built container only.
"""

import json
import os
import shutil
import sys

sys.path.insert(0, "/var/task")

import handler


class FakeContext:
    def __init__(self, remaining_ms):
        self._remaining_ms = remaining_ms

    def get_remaining_time_in_millis(self):
        return self._remaining_ms


class FakeS3:
    """Fakes just enough of the boto3 S3 client for the handler's calls."""

    def __init__(self, local_source_path):
        self.local_source_path = local_source_path
        self.put_calls = []

    def download_file(self, bucket, key, dest_path):
        shutil.copy(self.local_source_path, dest_path)

    def put_object(self, Bucket, Key, Body, ContentType):
        self.put_calls.append({"Bucket": Bucket, "Key": Key, "Body": Body, "ContentType": ContentType})


def make_event(bucket, key):
    return {"Records": [{"s3": {"bucket": {"name": bucket}, "object": {"key": key}}}]}


def run_case(name, source_path, remaining_ms):
    print(f"\n=== {name} ===")
    fake_s3 = FakeS3(source_path)
    handler.s3 = fake_s3
    # S3 event notifications URL-encode keys, with spaces as '+' (not
    # %20) -- use that real encoding here to actually exercise the
    # unquote_plus call in _process_record, not just a literal space.
    event = make_event("test-bucket", "incoming/some+sample.bin")
    context = FakeContext(remaining_ms)

    result = handler.lambda_handler(event, context)
    print("handler result:", json.dumps(result))

    assert len(fake_s3.put_calls) == 1, "expected exactly one S3 put"
    put = fake_s3.put_calls[0]
    print("put key:", put["Key"])
    assert put["Key"] == "reports/some sample.bin.json", put["Key"]
    body = json.loads(put["Body"])
    if "error" in body:
        print("error report:", body["error"])
    else:
        print("analysis_status:", body["analysis_status"])
        print("function_count:", body["control_flow_summary"]["function_count"])
    print(f"{name}: OK")


if __name__ == "__main__":
    real_binary = "/tmp/sample/python_sample"
    os.makedirs("/tmp/sample", exist_ok=True)
    shutil.copy("/var/lang/bin/python3.13", real_binary)

    garbage_path = "/tmp/sample/garbage.bin"
    with open(garbage_path, "wb") as f:
        f.write(os.urandom(64))

    run_case("success path (real ELF, generous time)", real_binary, remaining_ms=120_000)
    run_case("error path (garbage, not a real binary)", garbage_path, remaining_ms=120_000)
    run_case("insufficient time path", real_binary, remaining_ms=5_000)

    print("\nALL CASES PASSED")
