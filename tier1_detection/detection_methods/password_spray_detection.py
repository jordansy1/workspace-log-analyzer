"""
Password Spray Detection - MITRE ATT&CK T1110.003

Detects password spraying patterns where attackers attempt a small number
of commonly used passwords against many accounts to avoid account lockouts.

Indicators:
- Small number of failures per account across many accounts
- Spread out timing to avoid lockouts
- Same source attempting access to many accounts
"""

from typing import Dict, Any, List


def detect_password_spray(events: List[Dict[str, Any]], metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Detect password spraying patterns.

    Analyzes login attempts within time windows to identify patterns
    where an attacker tries common passwords against many accounts.

    Args:
        events: List of authentication events from logs
        metadata: Log metadata

    Returns:
        List of anomaly dicts for password spray patterns detected
    """
    anomalies = []

    # Time window for spray detection (30 minutes)
    time_window_seconds = 1800

    # Group login events by time windows and source IP
    from dateutil import parser
    from collections import defaultdict

    time_windows = defaultdict(lambda: defaultdict(lambda: {'users': set(), 'events': []}))

    for event in events:
        if event.get('event_name') in ['login_failure', 'login_success']:
            try:
                timestamp = parser.isoparse(event.get('timestamp'))
                window = int(timestamp.timestamp() // time_window_seconds)
                ip = event.get('ip_address')
                user = event.get('user_email')
                event_type = event.get('event_name')

                time_windows[window][(ip, event_type)]['users'].add(user)
                time_windows[window][(ip, event_type)]['events'].append(event)
            except Exception:
                continue

    # Detect spray patterns
    for window, data in time_windows.items():
        for (ip, event_type), info in data.items():
            users = info['users']
            events_list = info['events']
            # Password spray: many users targeted with few attempts each
            if event_type == 'login_failure' and len(users) >= 5:
                anomalies.append({
                    'id': f'ANOM-SPRAY-{window % 1000:03d}',
                    'type': 'password_spray',
                    'severity': 'critical',
                    'requires_deep_analysis': True,
                    'sub_agent': 'password_spray_analyzer',
                    'description': f'Password spray detected from {ip} targeting {len(users)} accounts',
                    'evidence': {
                        'source_ip': ip,
                        'targeted_users': list(users),
                        'time_window_start': window * time_window_seconds,
                        'failure_count': len(events_list),
                        'failed_events': events_list
                    },
                    'context_questions': [
                        'Are login attempts evenly distributed across users?',
                        'Is timing consistent with automated spraying (e.g., 1 attempt per user)?',
                        'Does IP reputation indicate malicious activity?',
                        'Are there any successful logins from this IP?'
                    ]
                })

    return anomalies
