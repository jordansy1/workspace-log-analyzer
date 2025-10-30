"""
MITRE ATT&CK Technique: T1550.001 - Use Alternate Authentication Material: Application Access Token

This detection identifies suspicious OAuth token usage patterns that may indicate
token abuse or compromise. OAuth tokens provide persistent access to Google Workspace
data and can be abused by attackers to maintain persistence and exfiltrate data.

Detection Logic:
1. Excessive permissions: Apps requesting >10 OAuth scopes (especially admin scopes)
2. Suspicious scope combinations: Apps requesting both read+write sensitive data access
3. High-frequency authorizations: Same app authorized multiple times in short period
4. Authorization from suspicious locations: VPN/proxy/Tor exit nodes
5. Unknown or unverified OAuth applications

References:
- https://attack.mitre.org/techniques/T1550/001/
- https://support.google.com/a/answer/7281227 (Google OAuth security)
"""

from datetime import datetime, timedelta
from typing import Dict, List, Any
from collections import defaultdict


# Suspicious OAuth scope patterns
ADMIN_SCOPES = [
    'https://www.googleapis.com/auth/admin.directory',
    'https://www.googleapis.com/auth/admin.reports',
    'https://www.googleapis.com/auth/cloud-platform',
]

SENSITIVE_WRITE_SCOPES = [
    'https://www.googleapis.com/auth/drive',  # Full Drive access
    'https://www.googleapis.com/auth/gmail.modify',
    'https://www.googleapis.com/auth/gmail.send',
    'https://www.googleapis.com/auth/calendar',  # Full calendar access
    'https://www.googleapis.com/auth/contacts',  # Full contacts access
]

# Known legitimate apps (can be customized per organization)
KNOWN_LEGITIMATE_APPS = [
    'Google Chrome',
    'Google Cloud Shell',
    'Google app for Windows',
    'Google Workspace Marketplace',
]


def detect_oauth_token_abuse(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detect potential OAuth token abuse patterns.

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

    # Detection 1: Excessive permissions
    anomalies.extend(_detect_excessive_permissions(auth_events))

    # Detection 2: Suspicious scope combinations
    anomalies.extend(_detect_suspicious_scope_combinations(auth_events))

    # Detection 3: High-frequency authorizations
    anomalies.extend(_detect_high_frequency_authorizations(auth_events))

    # Detection 4: Authorization from suspicious locations
    anomalies.extend(_detect_suspicious_location_authorizations(auth_events))

    # Detection 5: Unknown/unverified OAuth apps
    anomalies.extend(_detect_unknown_oauth_apps(auth_events))

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


def _detect_excessive_permissions(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Detect apps requesting excessive permissions (>10 scopes or admin scopes)."""
    anomalies = []

    for event in events:
        oauth_params = _extract_oauth_params(event)
        scopes = _extract_scopes(oauth_params)
        app_name = oauth_params.get('app_name', 'Unknown')

        # Check for excessive scope count
        if len(scopes) > 10:
            anomalies.append({
                'id': f"oauth_excessive_perms_{event['id']['uniqueQualifier']}",
                'type': 'T1550.001 - OAuth Excessive Permissions',
                'description': (
                    f"OAuth app '{app_name}' requested excessive permissions "
                    f"({len(scopes)} scopes). This may indicate a malicious or "
                    f"over-privileged application."
                ),
                'mitre_attack': ['T1550.001'],
                'sub_agent': 'oauth_token_analyzer',
                'evidence': {
                    'events': [event],
                    'app_name': app_name,
                    'client_id': oauth_params.get('client_id'),
                    'scope_count': len(scopes),
                    'requested_scopes': scopes,
                },
                'context_questions': [
                    f"Is '{app_name}' a legitimate business application?",
                    f"Does this app require {len(scopes)} different permissions?",
                    "Have other users in the organization authorized this app?",
                    "Was this authorization expected/approved by IT?",
                ],
            })

        # Check for admin scopes
        admin_scopes_requested = [s for s in scopes if any(admin in s for admin in ADMIN_SCOPES)]
        if admin_scopes_requested:
            anomalies.append({
                'id': f"oauth_admin_scopes_{event['id']['uniqueQualifier']}",
                'type': 'T1550.001 - OAuth Admin Scope Request',
                'description': (
                    f"OAuth app '{app_name}' requested administrative permissions. "
                    f"Admin-level OAuth apps can perform privileged operations and "
                    f"should be carefully reviewed."
                ),
                'mitre_attack': ['T1550.001'],
                'sub_agent': 'oauth_token_analyzer',
                'evidence': {
                    'events': [event],
                    'app_name': app_name,
                    'client_id': oauth_params.get('client_id'),
                    'admin_scopes': admin_scopes_requested,
                    'all_scopes': scopes,
                },
                'context_questions': [
                    f"Is '{app_name}' authorized to have admin-level access?",
                    "Has this app been approved by security team?",
                    "What business purpose requires admin permissions?",
                    "Are there alternative apps with fewer privileges?",
                ],
            })

    return anomalies


def _detect_suspicious_scope_combinations(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Detect suspicious combinations of OAuth scopes (e.g., read+write sensitive data)."""
    anomalies = []

    for event in events:
        oauth_params = _extract_oauth_params(event)
        scopes = _extract_scopes(oauth_params)
        app_name = oauth_params.get('app_name', 'Unknown')

        # Check for sensitive write scopes
        sensitive_writes = [s for s in scopes if any(sw in s for sw in SENSITIVE_WRITE_SCOPES)]

        if sensitive_writes:
            anomalies.append({
                'id': f"oauth_sensitive_write_{event['id']['uniqueQualifier']}",
                'type': 'T1550.001 - OAuth Sensitive Write Access',
                'description': (
                    f"OAuth app '{app_name}' requested write access to sensitive data "
                    f"(Drive, Gmail, Calendar, or Contacts). Write access can be abused "
                    f"for data exfiltration, persistence, or lateral movement."
                ),
                'mitre_attack': ['T1550.001'],
                'sub_agent': 'oauth_token_analyzer',
                'evidence': {
                    'events': [event],
                    'app_name': app_name,
                    'client_id': oauth_params.get('client_id'),
                    'sensitive_write_scopes': sensitive_writes,
                    'all_scopes': scopes,
                },
                'context_questions': [
                    f"Does '{app_name}' legitimately need write access to this data?",
                    "Is there a read-only alternative available?",
                    "Has the app been reviewed by security team?",
                    "Are there user reports of unexpected app behavior?",
                ],
            })

    return anomalies


def _detect_high_frequency_authorizations(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Detect same app authorized multiple times in short period."""
    anomalies = []

    # Group by (user, app, client_id)
    auth_by_user_app = defaultdict(list)

    for event in events:
        oauth_params = _extract_oauth_params(event)
        user = event.get('actor', {}).get('email', 'unknown')
        app_name = oauth_params.get('app_name', 'Unknown')
        client_id = oauth_params.get('client_id', 'unknown')

        key = f"{user}:{app_name}:{client_id}"
        auth_by_user_app[key].append(event)

    # Check for multiple authorizations in 24-hour window
    for key, user_events in auth_by_user_app.items():
        if len(user_events) < 3:
            continue

        # Sort by timestamp
        sorted_events = sorted(
            user_events,
            key=lambda e: datetime.fromisoformat(e['id']['time'].replace('Z', '+00:00'))
        )

        # Check if multiple events within 24 hours
        first_time = datetime.fromisoformat(sorted_events[0]['id']['time'].replace('Z', '+00:00'))
        last_time = datetime.fromisoformat(sorted_events[-1]['id']['time'].replace('Z', '+00:00'))

        if last_time - first_time <= timedelta(hours=24):
            user, app_name, client_id = key.split(':', 2)

            anomalies.append({
                'id': f"oauth_high_freq_{sorted_events[0]['id']['uniqueQualifier']}",
                'type': 'T1550.001 - High-Frequency OAuth Authorizations',
                'description': (
                    f"User '{user}' authorized app '{app_name}' {len(sorted_events)} times "
                    f"within 24 hours. Repeated authorizations may indicate trial-and-error "
                    f"by an attacker or misconfigured automation."
                ),
                'mitre_attack': ['T1550.001'],
                'sub_agent': 'oauth_token_analyzer',
                'evidence': {
                    'events': sorted_events,
                    'user_email': user,
                    'app_name': app_name,
                    'client_id': client_id,
                    'authorization_count': len(sorted_events),
                    'time_window_hours': (last_time - first_time).total_seconds() / 3600,
                },
                'context_questions': [
                    f"Why did user '{user}' authorize the same app {len(sorted_events)} times?",
                    "Is this app experiencing authentication issues?",
                    "Could this be automated/scripted behavior?",
                    "Has the user's account been compromised?",
                ],
            })

    return anomalies


def _detect_suspicious_location_authorizations(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Detect OAuth authorizations from suspicious locations (VPN/proxy/Tor)."""
    anomalies = []

    for event in events:
        enriched_location = event.get('enriched_location', {})
        oauth_params = _extract_oauth_params(event)
        app_name = oauth_params.get('app_name', 'Unknown')
        user = event.get('actor', {}).get('email', 'unknown')

        # Check for anonymizing services
        is_suspicious_location = (
            enriched_location.get('is_vpn') or
            enriched_location.get('is_proxy') or
            enriched_location.get('is_tor')
        )

        if is_suspicious_location:
            location_type = []
            if enriched_location.get('is_vpn'):
                location_type.append('VPN')
            if enriched_location.get('is_proxy'):
                location_type.append('Proxy')
            if enriched_location.get('is_tor'):
                location_type.append('Tor')

            anomalies.append({
                'id': f"oauth_suspicious_location_{event['id']['uniqueQualifier']}",
                'type': 'T1550.001 - OAuth Authorization from Suspicious Location',
                'description': (
                    f"User '{user}' authorized OAuth app '{app_name}' from a "
                    f"suspicious location ({', '.join(location_type)}). Attackers "
                    f"often use anonymizing services to hide their true location."
                ),
                'mitre_attack': ['T1550.001'],
                'sub_agent': 'oauth_token_analyzer',
                'evidence': {
                    'events': [event],
                    'user_email': user,
                    'app_name': app_name,
                    'client_id': oauth_params.get('client_id'),
                    'ip_address': event.get('ipAddress'),
                    'location_flags': location_type,
                    'location_details': enriched_location,
                },
                'context_questions': [
                    f"Does user '{user}' typically use VPN/proxy services?",
                    "Was this OAuth authorization expected?",
                    "Is the app legitimate and approved?",
                    "Has the user reported any suspicious activity?",
                ],
            })

    return anomalies


def _detect_unknown_oauth_apps(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Detect unknown or potentially malicious OAuth apps."""
    anomalies = []

    for event in events:
        oauth_params = _extract_oauth_params(event)
        app_name = oauth_params.get('app_name', 'Unknown')
        client_type = oauth_params.get('client_type', 'Unknown')
        user = event.get('actor', {}).get('email', 'unknown')

        # Skip known legitimate apps
        if app_name in KNOWN_LEGITIMATE_APPS:
            continue

        # Flag WEB apps (not native desktop/mobile) as potentially suspicious
        # since malicious OAuth apps are typically web-based
        if client_type == 'WEB':
            anomalies.append({
                'id': f"oauth_unknown_app_{event['id']['uniqueQualifier']}",
                'type': 'T1550.001 - Unknown OAuth Web Application',
                'description': (
                    f"User '{user}' authorized unknown OAuth web application '{app_name}'. "
                    f"Web-based OAuth apps should be verified before authorization, as they "
                    f"can be created by attackers to steal credentials or access data."
                ),
                'mitre_attack': ['T1550.001', 'T1528'],
                'sub_agent': 'oauth_token_analyzer',
                'evidence': {
                    'events': [event],
                    'user_email': user,
                    'app_name': app_name,
                    'client_id': oauth_params.get('client_id'),
                    'client_type': client_type,
                    'scopes': _extract_scopes(oauth_params),
                },
                'context_questions': [
                    f"Is '{app_name}' a legitimate business application?",
                    "Has this app been approved by IT/security team?",
                    "Can you verify the app publisher/developer?",
                    "Are there user reports about this app?",
                ],
            })

    return anomalies
