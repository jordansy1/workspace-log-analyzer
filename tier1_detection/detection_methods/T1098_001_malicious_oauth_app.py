"""
MITRE ATT&CK Technique: T1098.001 - Account Manipulation: Additional Cloud Credentials

This detection identifies potentially malicious OAuth applications that establish
additional authentication credentials for attackers. OAuth apps can provide persistent
backdoor access to cloud resources without traditional credential theft.

Detection Logic:
1. First-time OAuth app authorization (new app for user)
2. OAuth app authorized by multiple users in short time (phishing campaign)
3. OAuth apps with suspicious naming patterns
4. High-risk scope requests from new/unknown apps
5. OAuth apps authorized during off-hours or unusual times

References:
- https://attack.mitre.org/techniques/T1098/001/
- https://www.microsoft.com/en-us/security/blog/2021/07/14/microsoft-discovers-threat-actor-targeting-solarwinds-serv-u-software-with-0-day-exploit/
"""

from datetime import datetime, timedelta
from typing import Dict, List, Any, Set
from collections import defaultdict, Counter
import re


# Suspicious keywords in app names (common phishing patterns)
SUSPICIOUS_APP_KEYWORDS = [
    'admin',
    'verify',
    'security',
    'urgent',
    'action required',
    'validate',
    'confirm',
    'update',
    'password',
    'suspended',
    'locked',
    'backup',
    'recovery',
]

# Patterns that indicate test/development apps (often less secure)
DEV_APP_PATTERNS = [
    r'test',
    r'dev',
    r'staging',
    r'demo',
    r'sandbox',
    r'localhost',
    r'ngrok',
]


def detect_malicious_oauth_app(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detect potentially malicious OAuth applications.

    Args:
        events: List of OAuth token events from Google Workspace logs

    Returns:
        List of detected anomalies with evidence
    """
    anomalies = []

    # Filter to 'authorize' events only
    auth_events = [e for e in events if _is_authorize_event(e)]

    if not auth_events:
        return anomalies

    # Detection 1: OAuth app authorized by multiple users (potential phishing campaign)
    anomalies.extend(_detect_multi_user_authorization_surge(auth_events))

    # Detection 2: Suspicious app naming patterns
    anomalies.extend(_detect_suspicious_app_names(auth_events))

    # Detection 3: Development/test apps in production
    anomalies.extend(_detect_dev_test_apps(auth_events))

    # Detection 4: Off-hours OAuth authorizations
    anomalies.extend(_detect_off_hours_authorizations(auth_events))

    return anomalies


def _is_authorize_event(event: Dict[str, Any]) -> bool:
    """Check if event is an OAuth authorization."""
    return (
        event.get('id', {}).get('applicationName') == 'token' and
        len(event.get('events', [])) > 0 and
        event['events'][0].get('name') == 'authorize'
    )


def _extract_oauth_params(event: Dict[str, Any]) -> Dict[str, Any]:
    """Extract OAuth parameters from event."""
    params = {}
    for param in event.get('events', [{}])[0].get('parameters', []):
        name = param.get('name')
        if 'value' in param:
            params[name] = param['value']
        elif 'multiValue' in param:
            params[name] = param['multiValue']
        elif 'multiMessageValue' in param:
            params[name] = param['multiMessageValue']
    return params


def _extract_scopes(oauth_params: Dict[str, Any]) -> List[str]:
    """Extract list of OAuth scopes from parameters."""
    scopes = []
    scope_data = oauth_params.get('scope_data', [])

    if isinstance(scope_data, list):
        for scope_entry in scope_data:
            if isinstance(scope_entry, dict) and 'parameter' in scope_entry:
                for param in scope_entry['parameter']:
                    if param.get('name') == 'scope_name':
                        scopes.append(param.get('value'))

    return scopes


def _detect_multi_user_authorization_surge(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detect OAuth apps authorized by multiple users in short time.

    This pattern often indicates:
    - Phishing campaign targeting multiple users
    - Malicious OAuth app being distributed via social engineering
    - Legitimate app rollout (less suspicious if from known vendor)
    """
    anomalies = []

    # Group by (app_name, client_id)
    app_authorizations = defaultdict(list)

    for event in events:
        oauth_params = _extract_oauth_params(event)
        app_name = oauth_params.get('app_name', 'Unknown')
        client_id = oauth_params.get('client_id', 'unknown')

        key = f"{app_name}:{client_id}"
        app_authorizations[key].append(event)

    # Check for apps authorized by multiple users quickly
    for key, app_events in app_authorizations.items():
        # Need at least 3 users to flag (adjust threshold as needed)
        unique_users = len(set(e.get('actor', {}).get('email', '') for e in app_events))

        if unique_users < 3:
            continue

        # Sort by timestamp
        sorted_events = sorted(
            app_events,
            key=lambda e: datetime.fromisoformat(e['id']['time'].replace('Z', '+00:00'))
        )

        first_time = datetime.fromisoformat(sorted_events[0]['id']['time'].replace('Z', '+00:00'))
        last_time = datetime.fromisoformat(sorted_events[-1]['id']['time'].replace('Z', '+00:00'))

        # If multiple users authorized within 24 hours, flag it
        if last_time - first_time <= timedelta(hours=24):
            app_name, client_id = key.split(':', 1)
            user_emails = [e.get('actor', {}).get('email', '') for e in sorted_events]

            oauth_params = _extract_oauth_params(sorted_events[0])
            scopes = _extract_scopes(oauth_params)

            anomalies.append({
                'id': f"oauth_multi_user_{sorted_events[0]['id']['uniqueQualifier']}",
                'type': 'T1098.001 - Multi-User OAuth App Authorization',
                'description': (
                    f"OAuth app '{app_name}' was authorized by {unique_users} different users "
                    f"within {(last_time - first_time).total_seconds() / 3600:.1f} hours. "
                    f"This may indicate a phishing campaign, social engineering attack, or "
                    f"legitimate app rollout."
                ),
                'mitre_attack': ['T1098.001', 'T1566.002'],
                'sub_agent': 'oauth_token_analyzer',  # Also add phishing technique
                'evidence': {
                    'events': sorted_events,
                    'app_name': app_name,
                    'client_id': client_id,
                    'unique_users': unique_users,
                    'affected_users': list(set(user_emails)),
                    'authorization_count': len(sorted_events),
                    'time_window_hours': (last_time - first_time).total_seconds() / 3600,
                    'requested_scopes': scopes,
                },
                'context_questions': [
                    f"Is '{app_name}' a known/approved business application?",
                    "Was an app rollout or training session scheduled?",
                    "Have any users reported phishing emails with OAuth links?",
                    "Can you verify the app publisher/developer?",
                    "Are the requested permissions appropriate for business use?",
                ],
            })

    return anomalies


def _detect_suspicious_app_names(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detect OAuth apps with suspicious names that may indicate phishing or social engineering.

    Attackers often create apps with names like:
    - "Security Verification Required"
    - "Google Admin Tool"
    - "Account Recovery Service"
    """
    anomalies = []

    for event in events:
        oauth_params = _extract_oauth_params(event)
        app_name = oauth_params.get('app_name', 'Unknown')
        user = event.get('actor', {}).get('email', 'unknown')

        # Check for suspicious keywords
        app_name_lower = app_name.lower()
        matched_keywords = [kw for kw in SUSPICIOUS_APP_KEYWORDS if kw in app_name_lower]

        if matched_keywords:
            scopes = _extract_scopes(oauth_params)

            anomalies.append({
                'id': f"oauth_suspicious_name_{event['id']['uniqueQualifier']}",
                'type': 'T1098.001 - OAuth App with Suspicious Name',
                'description': (
                    f"User '{user}' authorized OAuth app with suspicious name: '{app_name}'. "
                    f"The name contains keywords commonly used in phishing attacks: "
                    f"{', '.join(matched_keywords)}. This may be a social engineering attempt."
                ),
                'mitre_attack': ['T1098.001', 'T1566.002'],
                'sub_agent': 'oauth_token_analyzer',
                'evidence': {
                    'events': [event],
                    'user_email': user,
                    'app_name': app_name,
                    'client_id': oauth_params.get('client_id'),
                    'suspicious_keywords': matched_keywords,
                    'requested_scopes': scopes,
                },
                'context_questions': [
                    f"Did user '{user}' receive a suspicious email or link?",
                    f"Is '{app_name}' a legitimate Google/Workspace service?",
                    "Can you verify the app publisher in Google Admin Console?",
                    "Has the user reported any phishing attempts?",
                ],
            })

    return anomalies


def _detect_dev_test_apps(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detect development/test OAuth apps being used in production.

    Dev/test apps are often less secure and may indicate:
    - Developer mistake (using test credentials in production)
    - Attacker using compromised developer credentials
    - Shadow IT / unauthorized development
    """
    anomalies = []

    for event in events:
        oauth_params = _extract_oauth_params(event)
        app_name = oauth_params.get('app_name', 'Unknown')
        client_id = oauth_params.get('client_id', 'unknown')
        user = event.get('actor', {}).get('email', 'unknown')

        # Check for dev/test patterns
        app_name_lower = app_name.lower()
        client_id_lower = client_id.lower()

        matched_patterns = []
        for pattern in DEV_APP_PATTERNS:
            if re.search(pattern, app_name_lower) or re.search(pattern, client_id_lower):
                matched_patterns.append(pattern)

        if matched_patterns:
            scopes = _extract_scopes(oauth_params)

            anomalies.append({
                'id': f"oauth_dev_app_{event['id']['uniqueQualifier']}",
                'type': 'T1098.001 - Development/Test OAuth App in Production',
                'description': (
                    f"User '{user}' authorized development/test OAuth app '{app_name}' "
                    f"in production environment. Dev/test apps may have weaker security "
                    f"controls and should not be used with production data."
                ),
                'mitre_attack': ['T1098.001'],
                'sub_agent': 'oauth_token_analyzer',
                'evidence': {
                    'events': [event],
                    'user_email': user,
                    'app_name': app_name,
                    'client_id': client_id,
                    'dev_patterns_matched': matched_patterns,
                    'requested_scopes': scopes,
                },
                'context_questions': [
                    f"Is user '{user}' a developer or has development responsibilities?",
                    "Is this a known internal development project?",
                    "Should this app have access to production data?",
                    "Are there policies against using dev apps in production?",
                ],
            })

    return anomalies


def _detect_off_hours_authorizations(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detect OAuth authorizations during off-hours (evenings, weekends, holidays).

    Off-hours authorizations may indicate:
    - Compromised account being accessed by attacker
    - Legitimate after-hours work
    - User in different timezone
    """
    anomalies = []

    for event in events:
        event_time = datetime.fromisoformat(event['id']['time'].replace('Z', '+00:00'))

        # Define off-hours: before 6 AM or after 10 PM (UTC)
        # Note: In production, this should be customized per user's timezone
        hour = event_time.hour

        is_off_hours = hour < 6 or hour >= 22
        is_weekend = event_time.weekday() >= 5  # Saturday=5, Sunday=6

        if is_off_hours or is_weekend:
            oauth_params = _extract_oauth_params(event)
            app_name = oauth_params.get('app_name', 'Unknown')
            user = event.get('actor', {}).get('email', 'unknown')
            scopes = _extract_scopes(oauth_params)

            time_description = []
            if is_off_hours:
                time_description.append(f"off-hours ({hour:02d}:00 UTC)")
            if is_weekend:
                time_description.append("weekend")

            anomalies.append({
                'id': f"oauth_off_hours_{event['id']['uniqueQualifier']}",
                'type': 'T1098.001 - Off-Hours OAuth Authorization',
                'description': (
                    f"User '{user}' authorized OAuth app '{app_name}' during "
                    f"{' and '.join(time_description)}. This may indicate compromised "
                    f"account, legitimate after-hours work, or user in different timezone."
                ),
                'mitre_attack': ['T1098.001', 'T1078.004'],
                'sub_agent': 'oauth_token_analyzer',
                'evidence': {
                    'events': [event],
                    'user_email': user,
                    'app_name': app_name,
                    'client_id': oauth_params.get('client_id'),
                    'event_time_utc': event_time.isoformat(),
                    'hour_utc': hour,
                    'is_weekend': is_weekend,
                    'requested_scopes': scopes,
                },
                'context_questions': [
                    f"Does user '{user}' typically work during these hours?",
                    "Is the user located in a different timezone?",
                    "Has the user reported any suspicious account activity?",
                    "Was this authorization expected/scheduled?",
                ],
            })

    return anomalies
