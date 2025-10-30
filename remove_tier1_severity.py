"""
Quick script to remove 'severity' field from all tier-1 detection methods.
"""
import re
from pathlib import Path

detection_dir = Path('tier1_detection/detection_methods')

# Find all Python files (except __init__.py)
detection_files = [f for f in detection_dir.glob('*.py') if f.name != '__init__.py']

for file_path in detection_files:
    print(f"Processing {file_path.name}...")

    # Read the file
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Remove lines containing 'severity': with optional comments
    # Pattern matches: 'severity': 'value',  # optional comment
    pattern = r"\s*'severity':\s*'[^']+',?\s*(?:#.*)?(?:\n|$)"
    modified_content = re.sub(pattern, '', content)

    # Write back if changed
    if modified_content != content:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(modified_content)
        print(f"  [OK] Removed severity from {file_path.name}")
    else:
        print(f"  - No changes needed for {file_path.name}")

print("\nDone! Removed 'severity' field from all tier-1 detection methods.")
