"""
Credential Stuffing Detection - MITRE ATT&CK T1110.004

Detects credential stuffing patterns where attackers use lists of
stolen credentials to attempt access across multiple accounts.

Indicators:
- Multiple failed logins from same IP across different users
- Distributed attack from many IPs targeting few users
- Success after many failures suggesting credential list testing
"""

from typing import Dict, Any, List


def detect_credential_stuffing(events: List[Dict[str, Any]], metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Detect credential stuffing patterns.

    Analyzes failed logins grouped by IP address to identify attackers
    testing credentials against multiple user accounts.

    Args:
        events: List of authentication events from logs
        metadata: Log metadata

    Returns:
        List of anomaly dicts for credential stuffing patterns detected
    """
    anomalies = []

    # Group failures by IP address
    failures_by_ip = {}
    for event in events:
        if event.get('event_name') == 'login_failure':
            ip = event.get('ip_address')
            if ip not in failures_by_ip:
                failures_by_ip[ip] = []
            failures_by_ip[ip].append(event)

    # Detect IPs attacking multiple different accounts
    for ip, failures in failures_by_ip.items():
        unique_users = set(f.get('user_email') for f in failures)
        if len(unique_users) >= 3:  # Threshold: 3+ different users
            anomalies.append({
                'id': f'ANOM-STUFF-{hash(ip) % 1000:03d}',
                'type': 'credential_stuffing',
                'severity': 'high',
                'requires_deep_analysis': True,
                'sub_agent': 'credential_stuffing_analyzer',
                'description': f'Possible credential stuffing from {ip} targeting {len(unique_users)} accounts',
                'evidence': {
                    'source_ip': ip,
                    'targeted_users': list(unique_users),
                    'failure_count': len(failures),
                    'failed_events': failures
                },
                'context_questions': [
                    'Is this IP known to be malicious (check IP reputation)?',
                    'Are any of these login attempts successful?',
                    'Does the pattern suggest automated credential testing?',
                    'Is this a VPN, proxy, or hosting provider IP?'
                ]
            })

    return anomalies
