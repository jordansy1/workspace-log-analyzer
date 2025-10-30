"""
Sample Collection Script for SAML and OAuth Logs

This script fetches real SAML and OAuth/token events from your Google Workspace
to understand the data structure before building tier-1 detections and tier-2 agents.

Usage:
    python collect_saml_oauth_samples.py

Output:
    - samples/saml_events_sample.json
    - samples/token_events_sample.json
"""

import json
import os
from datetime import datetime
from fetch_logs import WorkspaceLogFetcher


def main():
    print("=" * 70)
    print("SAML & OAuth Log Sample Collection")
    print("=" * 70)
    print()

    # Create samples directory
    os.makedirs('samples', exist_ok=True)

    # Initialize fetcher
    fetcher = WorkspaceLogFetcher()

    # Authenticate
    print("[Step 1/3] Authenticating with Google Workspace...")
    fetcher.authenticate()
    print()

    # Fetch SAML logs
    print("[Step 2/3] Fetching SAML (SSO) events...")
    print("  Looking back 30 days to ensure we capture some events...")
    try:
        saml_logs = fetcher.fetch_saml_logs(hours_back=720)  # 30 days

        if saml_logs:
            # Save full sample
            saml_output = {
                'collection_timestamp': datetime.utcnow().isoformat(),
                'lookback_hours': 720,
                'total_events': len(saml_logs),
                'events': saml_logs
            }

            with open('samples/saml_events_sample.json', 'w', encoding='utf-8') as f:
                json.dump(saml_output, f, indent=2, default=str)

            print(f"\n  [OK] Collected {len(saml_logs)} SAML events")
            print(f"  [OK] Saved to: samples/saml_events_sample.json")

            # Print summary
            event_types = {}
            for event in saml_logs:
                events = event.get('events', [])
                for e in events:
                    event_name = e.get('name', 'unknown')
                    event_types[event_name] = event_types.get(event_name, 0) + 1

            print(f"\n  Event Type Breakdown:")
            for event_type, count in event_types.items():
                print(f"    - {event_type}: {count}")

            # Show first event structure
            print(f"\n  Sample SAML Event Structure:")
            print(f"  {json.dumps(saml_logs[0], indent=4, default=str)[:500]}...")
        else:
            print(f"\n  [INFO] No SAML events found in last 30 days")
            print(f"  This is normal if you haven't used SSO to third-party apps recently")
            print(f"  To generate SAML events, try:")
            print(f"    - Sign into a third-party app using 'Sign in with Google'")
            print(f"    - Use any Google Workspace marketplace app")
            print(f"    - Access SAML-enabled integrations (Slack, Salesforce, etc.)")

    except Exception as e:
        print(f"\n  [ERROR] Failed to fetch SAML logs: {e}")

    print()

    # Fetch OAuth/Token logs
    print("[Step 3/3] Fetching OAuth/Token events...")
    print("  Looking back 30 days to ensure we capture some events...")
    try:
        token_logs = fetcher.fetch_token_logs(hours_back=720)  # 30 days

        if token_logs:
            # Save full sample
            token_output = {
                'collection_timestamp': datetime.utcnow().isoformat(),
                'lookback_hours': 720,
                'total_events': len(token_logs),
                'events': token_logs
            }

            with open('samples/token_events_sample.json', 'w', encoding='utf-8') as f:
                json.dump(token_output, f, indent=2, default=str)

            print(f"\n  [OK] Collected {len(token_logs)} OAuth/token events")
            print(f"  [OK] Saved to: samples/token_events_sample.json")

            # Print summary
            event_types = {}
            for event in token_logs:
                events = event.get('events', [])
                for e in events:
                    event_name = e.get('name', 'unknown')
                    event_types[event_name] = event_types.get(event_name, 0) + 1

            print(f"\n  Event Type Breakdown:")
            for event_type, count in event_types.items():
                print(f"    - {event_type}: {count}")

            # Show first event structure
            print(f"\n  Sample Token Event Structure:")
            print(f"  {json.dumps(token_logs[0], indent=4, default=str)[:500]}...")
        else:
            print(f"\n  [INFO] No OAuth/token events found in last 30 days")
            print(f"  This is normal if you haven't authorized apps or used API tokens recently")
            print(f"  To generate token events, try:")
            print(f"    - Authorize a third-party app to access your Google account")
            print(f"    - Create an API token or service account")
            print(f"    - Use Google Workspace marketplace apps that request permissions")

    except Exception as e:
        print(f"\n  [ERROR] Failed to fetch token logs: {e}")

    print()
    print("=" * 70)
    print("Collection Complete!")
    print("=" * 70)
    print()
    print("Next Steps:")
    print("  1. Review the sample JSON files in the samples/ directory")
    print("  2. Identify key fields for tier-1 detection rules")
    print("  3. Map suspicious patterns to MITRE ATT&CK techniques")
    print("  4. Design tier-2 agent prompts based on available enrichment data")
    print()


if __name__ == "__main__":
    main()
