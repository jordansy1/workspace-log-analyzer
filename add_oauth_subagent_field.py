"""
Add 'sub_agent' field to all anomalies in OAuth detection methods.
"""

import re
from pathlib import Path

DETECTION_FILES = [
    'tier1_detection/detection_methods/T1550_001_oauth_token_abuse.py',
    'tier1_detection/detection_methods/T1528_steal_oauth_token.py',
    'tier1_detection/detection_methods/T1098_001_malicious_oauth_app.py',
]

def add_sub_agent_field(file_path: Path):
    """Add 'sub_agent': 'oauth_token_analyzer' to all anomaly dictionaries."""

    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Pattern to find anomaly dictionaries (looks for 'id': ...)
    # Add sub_agent field after mitre_attack field
    pattern = r"('mitre_attack':\s*\[[^\]]+\],)"
    replacement = r"\1\n                'sub_agent': 'oauth_token_analyzer',"

    modified_content = re.sub(pattern, replacement, content)

    if content != modified_content:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(modified_content)
        print(f"[OK] Updated {file_path.name}")
        return True
    else:
        print(f"[SKIP] No changes needed in {file_path.name}")
        return False

def main():
    print("=" * 70)
    print("Adding 'sub_agent' field to OAuth detection methods")
    print("=" * 70)

    updated_count = 0
    for file_path_str in DETECTION_FILES:
        file_path = Path(file_path_str)
        if file_path.exists():
            if add_sub_agent_field(file_path):
                updated_count += 1
        else:
            print(f"[ERROR] File not found: {file_path}")

    print(f"\n[Complete] Updated {updated_count} files")

if __name__ == "__main__":
    main()
