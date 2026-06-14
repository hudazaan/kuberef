import json
import sys
import subprocess

# Test JSON validity
result = subprocess.run(
    [sys.executable, "-m", "poetry", "run", "kuberef", "./test-manifests/", "--json"],
    capture_output=True,
    text=True
)

try:
    data = json.loads(result.stdout)
    print("JSON is valid!")
    print("Summary data keys:", list(data.keys()))
except json.JSONDecodeError as e:
    print(f"Invalid JSON: {e}")
    print("Output received:", result.stdout)

print("\nFull JSON output:", result.stdout)