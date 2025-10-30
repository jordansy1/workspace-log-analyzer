"""
Missing MFA Detection - MITRE ATT&CK T1556.006, T1621, T1111

Detects authentication events that completed without multi-factor authentication,
which may indicate trusted device usage, policy violations, or MFA bypass attacks.
"""

from typing import Dict, Any, List, Optional


def detect_missing_mfa(events: List[Dict[str, Any]], metadata: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Detect events without multi-factor authentication.

    Checks login_verification events for is_second_factor field to determine if
    2FA was properly challenged during authentication.

    Args:
        events: List of authentication events from logs
        metadata: Log metadata

    Returns:
        Anomaly dict if MFA missing, None otherwise
    """
    login_verification_events = [
        e for e in events
        if e.get('event_name') == 'login_verification'
    ]

    # Check if any verification events have is_second_factor = true
    has_2fa = any(
        e.get('is_second_factor') == True
        for e in login_verification_events
    )

    # Count events with explicit false
    no_2fa_count = sum(
        1 for e in login_verification_events
        if e.get('is_second_factor') == False
    )

    if not has_2fa and no_2fa_count > 0:
        return {
            'id': 'ANOM-MFA-001',
            'type': 'missing_mfa',            'requires_deep_analysis': True,
            'sub_agent': 'mfa_context_analyzer',
            'description': 'No second factor authentication detected in login verification events',
            'evidence': {
                'total_verification_events': len(login_verification_events),
                'events_with_2fa': 0,
                'events_without_2fa': no_2fa_count,
                'verification_events': login_verification_events
            },
            'context_questions': [
                'Could this be a trusted device scenario?',
                'Was there a valid session already established?',
                'Is this an OAuth/API authentication flow?',
                'What is the login_type and does it explain the MFA absence?'
            ]
        }

    return None
