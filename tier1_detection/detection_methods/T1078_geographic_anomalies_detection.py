"""
Geographic Anomaly Detection - MITRE ATT&CK T1078

Detects unusual geographic patterns in authentication events, including
access from multiple regions which may indicate credential compromise,
VPN usage, or account sharing.
"""

from typing import Dict, Any, List


def detect_geographic_anomalies(events: List[Dict[str, Any]], metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Detect unusual geographic patterns.

    Analyzes authentication events for access from multiple geographic regions,
    which could indicate legitimate travel, VPN usage, or unauthorized access.

    Args:
        events: List of authentication events from logs
        metadata: Log metadata

    Returns:
        List of anomaly dicts for geographic issues detected
    """
    anomalies = []

    # Extract all unique locations
    locations = []
    for event in events:
        network_info = event.get('network_info')
        if network_info:
            locations.append({
                'timestamp': event.get('timestamp'),
                'region_code': network_info.get('region_code'),
                'subdivision': network_info.get('subdivision_code'),
                'ip': event.get('ip_address'),
                'user': event.get('user_email')
            })

    # Check for multiple regions
    unique_regions = set(loc['region_code'] for loc in locations if loc['region_code'])

    if len(unique_regions) > 1:
        anomalies.append({
            'id': 'ANOM-GEO-001',
            'type': 'multiple_locations',            'requires_deep_analysis': True,
            'sub_agent': 'geographic_analyzer',
            'description': f'Authentication from {len(unique_regions)} different geographic regions',
            'evidence': {
                'locations': locations,
                'unique_regions': list(unique_regions)
            },
            'context_questions': [
                'Is impossible travel detected based on timestamps?',
                'Could this be VPN/proxy usage?',
                'Are the regions geographically adjacent?',
                'Is the user known to travel frequently?'
            ]
        })

    return anomalies
