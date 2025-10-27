"""
Failed Login Detection - MITRE ATT&CK T1110

Detects failed login patterns that may indicate brute force attacks,
password guessing, or legitimate user errors.
"""

from typing import Dict, Any, List


def detect_failed_logins(events: List[Dict[str, Any]], metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Detect failed login patterns.

    Analyzes login_failure events and groups them by user to identify
    potential brute force attempts or authentication issues.

    Args:
        events: List of authentication events from logs
        metadata: Log metadata

    Returns:
        List of anomaly dicts for failed login patterns detected
    """
    anomalies = []

    failed_events = [
        e for e in events
        if e.get('event_name') == 'login_failure'
    ]

    if failed_events:
        # Group by user
        failed_by_user = {}
        for event in failed_events:
            user = event.get('user_email')
            if user not in failed_by_user:
                failed_by_user[user] = []
            failed_by_user[user].append(event)

        for user, failures in failed_by_user.items():
            anomalies.append({
                'id': f'ANOM-FAIL-{hash(user) % 1000:03d}',
                'type': 'failed_login',
                'severity': 'medium' if len(failures) < 3 else 'high',
                'requires_deep_analysis': True,
                'sub_agent': 'failed_login_analyzer',
                'description': f'{len(failures)} failed login attempt(s) for {user}',
                'evidence': {
                    'user': user,
                    'failure_count': len(failures),
                    'failed_events': failures
                },
                'context_questions': [
                    'Is there a successful login immediately after?',
                    'Are failures from same IP or different IPs?',
                    'What is the time interval between failures?',
                    'Could this be legitimate user error vs attack?'
                ]
            })

    return anomalies
