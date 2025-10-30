"""
Analyze OAuth token event samples to identify patterns for tier-1 detections.
"""
import json
from collections import Counter, defaultdict
from pathlib import Path

def analyze_oauth_events():
    """Analyze collected OAuth token events."""

    sample_file = Path('samples/token_events_sample.json')
    if not sample_file.exists():
        print("[ERROR] Sample file not found. Run collect_saml_oauth_samples.py first.")
        return

    with open(sample_file, 'r') as f:
        data = json.load(f)

    print("=" * 70)
    print("OAuth Token Event Analysis")
    print("=" * 70)
    print(f"\nTotal events: {len(data['events'])}")
    print(f"Timespan: {data['lookback_hours']} hours ({data['lookback_hours'] // 24} days)")

    # Event type breakdown
    event_types = Counter()
    apps_by_type = defaultdict(set)
    scopes_by_app = defaultdict(set)
    client_types = Counter()
    users = Counter()
    ip_addresses = Counter()

    for event in data['events']:
        event_name = event['events'][0]['name']
        event_types[event_name] += 1

        # Extract parameters
        params = {}
        for param in event['events'][0]['parameters']:
            if 'value' in param:
                params[param['name']] = param['value']
            elif 'multiValue' in param:
                params[param['name']] = param['multiValue']
            elif 'multiMessageValue' in param:
                params[param['name']] = param['multiMessageValue']

        app_name = params.get('app_name', 'Unknown')
        client_type = params.get('client_type', 'Unknown')
        client_id = params.get('client_id', 'Unknown')

        apps_by_type[event_name].add(f"{app_name} (ID: {client_id[:20]}...)")
        client_types[f"{event_name}:{client_type}"] += 1

        # Extract scopes
        scope_data = params.get('scope_data', [])
        if isinstance(scope_data, list):
            for scope_entry in scope_data:
                if isinstance(scope_entry, dict) and 'parameter' in scope_entry:
                    for sp in scope_entry['parameter']:
                        if sp['name'] == 'scope_name':
                            scopes_by_app[app_name].add(sp['value'])

        # User and IP tracking
        if 'actor' in event:
            users[event['actor']['email']] += 1
        if 'ipAddress' in event:
            ip_addresses[event['ipAddress']] += 1

    # Print results
    print("\n" + "=" * 70)
    print("Event Type Breakdown")
    print("=" * 70)
    for event_type, count in event_types.most_common():
        print(f"  {event_type}: {count}")

    print("\n" + "=" * 70)
    print("Client Type Distribution")
    print("=" * 70)
    for client_combo, count in client_types.most_common():
        event_type, client_type = client_combo.split(':')
        print(f"  {event_type} from {client_type}: {count}")

    print("\n" + "=" * 70)
    print("Top OAuth Apps (by authorization events)")
    print("=" * 70)
    for event_name in ['authorize', 'revoke']:
        if event_name in apps_by_type:
            print(f"\n{event_name.upper()} events:")
            for idx, app in enumerate(sorted(apps_by_type[event_name])[:10], 1):
                print(f"  {idx}. {app}")

    print("\n" + "=" * 70)
    print("Scope Analysis (Top Apps)")
    print("=" * 70)
    # Find apps with most authorizations
    app_auth_counts = Counter()
    for event in data['events']:
        if event['events'][0]['name'] == 'authorize':
            params = {p['name']: p.get('value') for p in event['events'][0]['parameters'] if 'value' in p}
            app_name = params.get('app_name', 'Unknown')
            app_auth_counts[app_name] += 1

    for app_name, count in app_auth_counts.most_common(5):
        print(f"\n{app_name} ({count} authorizations):")
        scopes = sorted(scopes_by_app[app_name])
        for scope in scopes[:8]:
            print(f"  - {scope}")
        if len(scopes) > 8:
            print(f"  ... and {len(scopes) - 8} more scopes")

    print("\n" + "=" * 70)
    print("User Activity")
    print("=" * 70)
    for user, count in users.most_common(5):
        print(f"  {user}: {count} events")

    print("\n" + "=" * 70)
    print("Unique IP Addresses")
    print("=" * 70)
    print(f"  Total unique IPs: {len(ip_addresses)}")
    print(f"  Top 5 IPs:")
    for ip, count in ip_addresses.most_common(5):
        print(f"    {ip}: {count} events")

    # Identify suspicious patterns
    print("\n" + "=" * 70)
    print("Potential Detection Patterns for Tier-1")
    print("=" * 70)

    print("\n1. Suspicious Scope Combinations:")
    print("   - Apps requesting admin.directory scopes")
    print("   - Apps requesting both read AND write access to sensitive data")
    print("   - Apps requesting excessive permissions (>10 scopes)")

    print("\n2. Unusual Authorization Patterns:")
    print("   - Multiple apps authorized from same IP in short time")
    print("   - Unknown/unverified client_ids")
    print("   - Authorization from suspicious geolocations")

    print("\n3. Token Abuse Indicators:")
    print("   - Tokens used from different IPs than authorization")
    print("   - High frequency of token usage (API spam)")
    print("   - Token used for admin operations without admin role")

    print("\n4. Revocation Events:")
    print("   - Mass token revocations (potential compromise cleanup)")
    print("   - Revocation followed by immediate re-authorization")

    print("\n" + "=" * 70)
    print("Recommended MITRE ATT&CK Techniques")
    print("=" * 70)
    print("  T1550.001 - Application Access Token abuse")
    print("  T1528 - Steal Application Access Token")
    print("  T1098.001 - Additional Cloud Credentials (malicious OAuth app)")
    print("  T1078.004 - Valid Accounts: Cloud Accounts (compromised OAuth)")

    print("\n" + "=" * 70)

if __name__ == "__main__":
    analyze_oauth_events()
