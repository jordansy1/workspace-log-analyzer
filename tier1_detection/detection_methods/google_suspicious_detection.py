"""
Google-Flagged Suspicious Events Detection

Detects events that Google Workspace has flagged as suspicious using
their internal machine learning and threat detection systems.

Indicators:
- is_suspicious field set to True by Google
- Google has access to global threat intelligence
- High-confidence signal for malicious activity

Note: This leverages Google's own security signals for enhanced detection.
"""

from typing import Dict, Any, List


def detect_google_suspicious_events(events: List[Dict[str, Any]], metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Detect events that Google has flagged as suspicious.

    Google Workspace's security systems flag events as suspicious based on
    their internal ML models and global threat intelligence. These are
    high-confidence signals that warrant investigation.

    Args:
        events: List of authentication events from logs
        metadata: Log metadata

    Returns:
        List of anomaly dicts for Google-flagged suspicious events
    """
    anomalies = []

    # Find all events where Google flagged is_suspicious=True
    suspicious_events = [
        event for event in events
        if event.get('is_suspicious') is True
    ]

    if not suspicious_events:
        return anomalies

    # Group by user to provide context
    from collections import defaultdict
    users_with_suspicious = defaultdict(list)

    for event in suspicious_events:
        user = event.get('user_email', 'unknown')
        users_with_suspicious[user].append(event)

    # Create anomalies for each user with suspicious events
    for user, user_events in users_with_suspicious.items():
        # Determine severity based on count and event types
        event_count = len(user_events)
        event_types = set(e.get('event_name') for e in user_events)

        # Higher severity if multiple suspicious events or multiple event types
        if event_count >= 5 or len(event_types) >= 3:
            severity = 'critical'
        elif event_count >= 3 or len(event_types) >= 2:
            severity = 'high'
        else:
            severity = 'medium'

        anomalies.append({
            'id': f'ANOM-GOOGLE-SUSPICIOUS-{hash(user) % 1000:03d}',
            'type': 'google_flagged_suspicious',
            'severity': severity,
            'requires_deep_analysis': True,
            'sub_agent': 'behavioral_analyzer',  # Best for analyzing Google's signals
            'description': f'Google flagged {event_count} suspicious event(s) for {user}',
            'evidence': {
                'user': user,
                'suspicious_event_count': event_count,
                'event_types': list(event_types),
                'suspicious_events': user_events,
                'time_range': {
                    'first': min(e.get('timestamp', '') for e in user_events),
                    'last': max(e.get('timestamp', '') for e in user_events)
                }
            },
            'context_questions': [
                'What specific behaviors triggered Google\'s suspicious flag?',
                'Is this part of a broader attack pattern?',
                'Does the user have a history of suspicious activity?',
                'Are there indicators of compromise in the event details?',
                'Should we recommend immediate account investigation?'
            ],
            'mitre_attack': ['T1078']  # Valid Accounts - Google detected abuse
        })

    return anomalies
