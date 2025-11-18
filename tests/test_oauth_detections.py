"""
Test script for OAuth token detection pipeline.

Tests tier-1 detections on sample OAuth token data.
"""

import json
from pathlib import Path
from tier1_detection.detector import AnomalyDetector

def main():
    """Test OAuth detections on sample token data."""

    print("=" * 70)
    print("OAuth Token Detection Pipeline Test")
    print("=" * 70)

    # Check if sample file exists
    sample_file = Path('samples/token_events_sample.json')
    if not sample_file.exists():
        print("[ERROR] Sample file not found. Run collect_saml_oauth_samples.py first.")
        return

    # Load sample data
    with open(sample_file, 'r') as f:
        sample_data = json.load(f)

    print(f"\nLoaded {len(sample_data['events'])} OAuth token events")
    print(f"Timespan: {sample_data['lookback_hours']} hours\n")

    # Create a temporary log file with proper structure for detector
    temp_log = {
        'metadata': {
            'fetch_time': sample_data['collection_timestamp'],
            'total_events': len(sample_data['events']),
            'requested_time_range_hours': sample_data['lookback_hours'],
            'actual_time_range': {
                'earliest_event': sample_data['events'][-1]['id']['time'] if sample_data['events'] else '',
                'latest_event': sample_data['events'][0]['id']['time'] if sample_data['events'] else '',
                'actual_span_hours': sample_data['lookback_hours']
            },
            'summary': {
                'unique_users': 1,
                'unique_ips': len(set(e.get('ipAddress', 'unknown') for e in sample_data['events'])),
                'unique_regions': 1,
                'event_type_breakdown': {
                    'authorize': len([e for e in sample_data['events'] if e['events'][0]['name'] == 'authorize']),
                    'revoke': len([e for e in sample_data['events'] if e['events'][0]['name'] == 'revoke'])
                }
            }
        },
        'events': sample_data['events']
    }

    # Write temporary log file
    temp_log_path = Path('samples/temp_oauth_test_log.json')
    with open(temp_log_path, 'w') as f:
        json.dump(temp_log, f, indent=2)

    print(f"[Step 1] Created temporary log file: {temp_log_path}")

    # Initialize detector
    print(f"\n[Step 2] Running tier-1 OAuth detections...")
    detector = AnomalyDetector(str(temp_log_path))

    # Run detection
    anomalies = detector.detect_anomalies()

    print(f"\n[Step 3] Detection Results")
    print("=" * 70)
    print(f"Total anomalies detected: {len(anomalies)}")

    # Group anomalies by type
    oauth_anomalies = [a for a in anomalies if 'oauth' in a.get('type', '').lower() or 'T1550' in a.get('type', '') or 'T1528' in a.get('type', '')]

    if not oauth_anomalies:
        print("[INFO] No OAuth-specific anomalies detected.")
        print("[INFO] This is expected if the sample data contains only legitimate OAuth authorizations.")
    else:
        print(f"\nOAuth-related anomalies: {len(oauth_anomalies)}")

        for idx, anomaly in enumerate(oauth_anomalies, 1):
            print(f"\n  [{idx}] {anomaly['type']}")
            print(f"      ID: {anomaly['id']}")
            print(f"      Description: {anomaly['description'][:100]}...")
            print(f"      Sub-Agent: {anomaly.get('sub_agent', 'NOT SET')}")
            print(f"      MITRE ATT&CK: {', '.join(anomaly.get('mitre_attack', []))}")

    print("\n" + "=" * 70)
    print("Detection Summary by MITRE Technique:")
    print("=" * 70)

    # Count by MITRE technique
    from collections import Counter
    mitre_counts = Counter()
    for anomaly in oauth_anomalies:
        for technique in anomaly.get('mitre_attack', []):
            mitre_counts[technique] += 1

    if mitre_counts:
        for technique, count in mitre_counts.most_common():
            print(f"  {technique}: {count} detections")
    else:
        print("  No OAuth anomalies detected")

    # Cleanup
    temp_log_path.unlink()
    print(f"\n[Cleanup] Removed temporary log file")

    print("\n" + "=" * 70)
    print("Test Complete!")
    print("=" * 70)
    print("\nNext Steps:")
    print("  1. Review detection rules if anomalies seem like false positives")
    print("  2. Adjust thresholds in tier1_detection/detection_methods/*.py")
    print("  3. Test tier-2 analysis by running full pipeline with actual log data")

if __name__ == "__main__":
    main()
