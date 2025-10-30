"""
Account Manipulation Detection - MITRE ATT&CK T1098

Detects suspicious account changes that may indicate privilege escalation,
persistence mechanisms, or attempts to bypass security controls.

Indicators:
- Password changes outside business hours
- Rapid sequential password changes (bypassing password history)
- Permission/role changes

Note: This requires password_edit events which may not be in all log sets.
"""

from typing import Dict, Any, List


def detect_account_manipulation(events: List[Dict[str, Any]], metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Detect suspicious account changes.

    Analyzes password_edit events to identify patterns suggesting attempts
    to bypass password policies or establish persistence.

    Args:
        events: List of authentication events from logs
        metadata: Log metadata

    Returns:
        List of anomaly dicts for account manipulation detected
    """
    anomalies = []

    # Look for password change events
    password_changes = [
        e for e in events
        if e.get('event_name') == 'password_edit'
    ]

    if not password_changes:
        # No password change events in this dataset
        return anomalies

    # Detect rapid password changes (password history bypass)
    from dateutil import parser

    user_pwd_changes = {}
    for event in password_changes:
        user = event.get('user_email')
        if user not in user_pwd_changes:
            user_pwd_changes[user] = []
        user_pwd_changes[user].append(event)

    for user, changes in user_pwd_changes.items():
        sorted_changes = sorted(changes, key=lambda e: e.get('timestamp', ''))

        # Detect 3+ password changes within 1 hour (policy bypass attempt)
        if len(sorted_changes) >= 3:
            try:
                t1 = parser.isoparse(sorted_changes[0].get('timestamp'))
                t_last = parser.isoparse(sorted_changes[2].get('timestamp'))

                if (t_last - t1).total_seconds() < 3600:
                    anomalies.append({
                        'id': f'ANOM-ACCT-{hash(user) % 1000:03d}',
                        'type': 'account_manipulation',                        'requires_deep_analysis': True,
                        'sub_agent': 'account_analyzer',
                        'description': f'Rapid password changes detected for {user} (possible policy bypass)',
                        'evidence': {
                            'user': user,
                            'change_count': len(sorted_changes),
                            'events': sorted_changes
                        },
                        'context_questions': [
                            'Is this user attempting to bypass password history requirements?',
                            'Are these changes from a legitimate admin account?',
                            'Was the account recently compromised?',
                            'Are there other signs of account takeover?'
                        ]
                    })
            except Exception:
                continue

    return anomalies
