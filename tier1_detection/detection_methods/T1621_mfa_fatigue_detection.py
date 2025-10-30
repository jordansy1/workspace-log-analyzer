"""
MFA Fatigue Detection - MITRE ATT&CK T1621

Detects MFA fatigue/bombing attacks where attackers repeatedly trigger
MFA prompts to overwhelm the user into approving a fraudulent request.

Indicators:
- Multiple MFA prompts in short time period
- Repeated denials followed by eventual approval
- Same user receiving many push notifications
"""

from typing import Dict, Any, List


def detect_mfa_fatigue(events: List[Dict[str, Any]], metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Detect MFA fatigue/bombing attacks.

    Analyzes login_verification events to identify rapid bursts of MFA
    challenges that could indicate an attacker attempting to fatigue the user.

    Args:
        events: List of authentication events from logs
        metadata: Log metadata

    Returns:
        List of anomaly dicts for MFA fatigue patterns detected
    """
    anomalies = []

    from dateutil import parser
    from collections import defaultdict

    # Group MFA challenges by user
    user_mfa_events = defaultdict(list)

    for event in events:
        if event.get('event_name') == 'login_verification':
            user = event.get('user_email')
            user_mfa_events[user].append(event)

    # Detect rapid repeated MFA requests
    for user, user_events in user_mfa_events.items():
        if len(user_events) < 3:
            continue

        sorted_events = sorted(user_events, key=lambda e: e.get('timestamp', ''))

        # Count rapid MFA requests (within 5 minutes)
        for i in range(len(sorted_events) - 2):
            try:
                t1 = parser.isoparse(sorted_events[i].get('timestamp'))
                t2 = parser.isoparse(sorted_events[i + 2].get('timestamp'))

                if (t2 - t1).total_seconds() < 300:  # 3+ requests in 5 min
                    # Count how many events in this burst
                    burst_events = []
                    for event in sorted_events[i:]:
                        event_time = parser.isoparse(event.get('timestamp'))
                        if (event_time - t1).total_seconds() <= 300:
                            burst_events.append(event)
                        else:
                            break

                    anomalies.append({
                        'id': f'ANOM-MFA-BOMB-{hash(user) % 1000:03d}',
                        'type': 'mfa_fatigue',                        'requires_deep_analysis': True,
                        'sub_agent': 'mfa_context_analyzer',
                        'description': f'Possible MFA fatigue attack on {user} ({len(burst_events)} requests in 5 minutes)',
                        'evidence': {
                            'user': user,
                            'rapid_mfa_count': len(burst_events),
                            'events': burst_events
                        },
                        'context_questions': [
                            'Were these MFA requests approved or denied?',
                            'Was there eventual successful authentication?',
                            'What is the source IP for these requests?',
                            'Is there a pattern of denials followed by approval (fatigue)?'
                        ]
                    })
                    break  # Only report once per user
            except Exception:
                continue

    return anomalies
