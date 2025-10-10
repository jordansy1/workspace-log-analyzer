"""
Test script to verify MITRE ATT&CK-enhanced detections on attack simulation data.
"""

from analyze_logs import AnomalyDetector
import json

def main():
    print("="*70)
    print("TESTING ENHANCED MITRE ATT&CK TIER-1 DETECTIONS")
    print("="*70)

    # Load attack simulation
    detector = AnomalyDetector('logs/auth_logs_ATTACK_SIMULATION.json')

    print(f"\nDataset: {detector.metadata.get('total_events', 0)} events")
    print(f"Time range: {detector.metadata.get('actual_time_range', {}).get('actual_span_hours', 0):.2f} hours")

    print("\n" + "-"*70)
    print("DETECTION RESULTS BY TECHNIQUE")
    print("-"*70)

    # Test each detection individually
    detections = {
        'Missing MFA (T1556.006, T1621, T1111)': detector._detect_missing_mfa,
        'Geographic Anomalies (T1078)': detector._detect_geographic_anomalies,
        'Failed Logins (T1110)': detector._detect_failed_logins,
        'Rapid Access (T1110)': detector._detect_rapid_access,
        'Credential Stuffing (T1110.004)': detector._detect_credential_stuffing,
        'Password Spray (T1110.003)': detector._detect_password_spray,
        'Impossible Travel': detector._detect_impossible_travel,
        'MFA Fatigue (T1621)': detector._detect_mfa_fatigue,
        'Session Anomalies (T1539, T1185)': detector._detect_session_anomalies,
        'Off-Hours Access (M1036)': detector._detect_off_hours_access,
        'Account Manipulation (T1098)': detector._detect_account_manipulation,
    }

    total_anomalies = 0
    for detection_name, detection_func in detections.items():
        result = detection_func()

        # Handle both single anomaly (dict) and multiple anomalies (list)
        if result is None:
            count = 0
            anomalies = []
        elif isinstance(result, dict):
            count = 1
            anomalies = [result]
        else:
            count = len(result)
            anomalies = result

        total_anomalies += count

        print(f"\n{detection_name}")
        print(f"  Status: {'[DETECTED]' if count > 0 else '[Not detected]'}")

        if count > 0:
            print(f"  Count: {count} anomal{'y' if count == 1 else 'ies'}")
            for i, anomaly in enumerate(anomalies[:3], 1):  # Show first 3
                print(f"    {i}. {anomaly.get('id')} - {anomaly.get('description')}")
                print(f"       Severity: {anomaly.get('severity').upper()}")
            if count > 3:
                print(f"    ... and {count - 3} more")

    print("\n" + "="*70)
    print(f"TOTAL ANOMALIES DETECTED: {total_anomalies}")
    print("="*70)

    # Show breakdown by severity
    all_anomalies = detector.detect_anomalies()
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for anomaly in all_anomalies:
        severity = anomaly.get('severity', 'low')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    print("\nSeverity Breakdown:")
    for severity, count in sorted(severity_counts.items(), key=lambda x: ['critical', 'high', 'medium', 'low'].index(x[0])):
        if count > 0:
            print(f"  {severity.upper()}: {count}")

    # Show attack pattern summary
    print("\n" + "-"*70)
    print("ATTACK PATTERN SUMMARY")
    print("-"*70)

    # Count failures by user
    failures_by_user = {}
    malicious_ips = set()

    for event in detector.events:
        if event.get('event_name') == 'login_failure':
            user = event.get('user_email')
            ip = event.get('ip_address')

            if user not in failures_by_user:
                failures_by_user[user] = {'count': 0, 'ips': set()}
            failures_by_user[user]['count'] += 1
            failures_by_user[user]['ips'].add(ip)

            # Check if IP is malicious
            ip_rep = event.get('ip_reputation', {})
            if ip_rep.get('is_malicious') or ip_rep.get('overall_risk_score', 0) > 50:
                malicious_ips.add(ip)

    print(f"\nFailed Login Attempts:")
    for user, data in failures_by_user.items():
        print(f"  {user}: {data['count']} failures from {len(data['ips'])} unique IP(s)")

    print(f"\nMalicious IP Addresses: {len(malicious_ips)}")
    for ip in sorted(malicious_ips):
        print(f"  - {ip}")

    print("\n" + "="*70)

if __name__ == "__main__":
    main()
