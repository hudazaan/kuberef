import json
import sys
from pathlib import Path

def sanitize_string(s):
    return str(s).strip()

def find_line_number(yaml_content, key_path, sub_key=None):
    """Locates the line number of a key/sub-key."""
    lines = yaml_content.read_text().splitlines()
    for i, line in enumerate(lines):
        if key_path in line:
            if sub_key:
                for j in range(i + 1, min(i + 10, len(lines))):
                    if sub_key in lines[j]:
                        return j + 1
            return i + 1
    return 1

def print_github_annotations(results):
    """Prints results in GitHub Actions annotation format."""
    for result in results:
        file = result.get('file_path', '')
        rule_id = result.get('rule_id', 'unknown')
        a_type = result.get('type', 'warning')
        res_name = result.get('res_name', '')
        res_key = result.get('res_key', '')
        
        if rule_id == "missing-secret":
            title = "Missing Secret Reference"
            msg = f"The secret '{res_name}' was not found in the cluster."
        elif rule_id == "missing-key":
            title = "Missing Secret Key"
            msg = f"The key '{res_key}' of secret '{res_name}' was not found in the cluster."
        else:
            title = "Issue"
            msg = f"The secret '{res_name}' was not found in the cluster."
            
        print(f"::{a_type} file={file},title={title}::{msg}")

def generate_sarif_report(results, output_file=None):
    """Generates a SARIF report with correct ruleId, level, and tool metadata."""
    sarif_results = []
    for r in results:
        sarif_results.append({
            "ruleId": r.get("rule_id"),
            "level": r.get("type", "warning"),
            "message": {"text": f"Issue with {r.get('res_name')}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": str(r.get('file_path'))}}}]
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "kuberef", "version": "1.0.0"}},
            "results": sarif_results
        }]
    }
    
    if output_file and not isinstance(output_file, int):
        with open(output_file, 'w') as f:
            json.dump(sarif, f, indent=2, default=str)
    return sarif

# --- NDJSON FUNCTIONS ---

def stream_ndjson_event(event_data: dict):
    serializable = {k: (str(v) if isinstance(v, Path) else v) for k, v in event_data.items()}
    sys.stdout.write(json.dumps(serializable) + '\n')
    sys.stdout.flush()

def emit_ndjson(event_type: str, data: dict):
    payload = {"event": event_type}
    payload.update(data)
    print(json.dumps(payload, separators=(',', ':'), default=str))