"""
Google Workspace Log Analyzer - Main Entry Point

Fetches authentication logs from Google Workspace and prepares them
for anomaly analysis using Claude Code agents.
"""

import os
import sys
from datetime import datetime
from dotenv import load_dotenv
from fetch_logs import WorkspaceLogFetcher


def load_config():
    """Load configuration from .env file."""
    load_dotenv()

    config = {
        'domain': os.getenv('WORKSPACE_DOMAIN'),
        'admin_email': os.getenv('ADMIN_USER_EMAIL'),
        'hours_back': int(os.getenv('LOG_HOURS_BACK', 24)),
        'logs_dir': os.getenv('LOGS_OUTPUT_DIR', 'logs'),
        'analysis_dir': os.getenv('ANALYSIS_OUTPUT_DIR', 'analysis')
    }

    # Validate required config
    if not config['domain']:
        print("[ERROR] Error: WORKSPACE_DOMAIN not set in .env file")
        sys.exit(1)

    return config


def print_summary(logs, filepath):
    """Print summary of fetched logs."""
    print("\n" + "="*60)
    print("FETCH SUMMARY")
    print("="*60)

    total = len(logs)
    print(f"Total events: {total}")

    if total > 0:
        # Count by event type
        event_types = {}
        suspicious_count = 0
        unique_users = set()
        unique_ips = set()

        for log in logs:
            event_name = log.get('event_name', 'unknown')
            event_types[event_name] = event_types.get(event_name, 0) + 1

            if log.get('is_suspicious'):
                suspicious_count += 1

            if log.get('user_email'):
                unique_users.add(log['user_email'])
            if log.get('ip_address'):
                unique_ips.add(log['ip_address'])

        print(f"\nUnique users: {len(unique_users)}")
        print(f"Unique IP addresses: {len(unique_ips)}")
        print(f"Suspicious events flagged by Google: {suspicious_count}")

        print("\nEvent breakdown:")
        for event_type, count in sorted(event_types.items(), key=lambda x: x[1], reverse=True):
            print(f"  {event_type}: {count}")

    print(f"\nLogs saved to: {filepath}")
    print("="*60)


def main():
    """Main execution flow."""
    print("Google Workspace Log Analyzer")
    print("-" * 60)

    # Load configuration
    config = load_config()
    print(f"Domain: {config['domain']}")
    print(f"Looking back: {config['hours_back']} hours")
    print("-" * 60 + "\n")

    # Initialize fetcher
    fetcher = WorkspaceLogFetcher()

    # Authenticate
    try:
        fetcher.authenticate()
    except Exception as e:
        print(f"[ERROR] Authentication failed: {e}")
        sys.exit(1)

    # Fetch logs
    try:
        raw_logs = fetcher.fetch_login_logs(hours_back=config['hours_back'])

        if not raw_logs:
            print("\n[WARNING] No logs found for the specified time range")
            return

        # Process logs
        processed_logs = fetcher.process_logs(raw_logs)

        # Save logs
        filepath = fetcher.save_logs(
            processed_logs,
            output_dir=config['logs_dir'],
            hours_back=config['hours_back']
        )

        # Print summary
        print_summary(processed_logs, filepath)

        # Next steps
        print("\nNEXT STEPS:")
        print("1. Review the logs file to understand the data structure")
        print("2. Use Claude Code agent to analyze the logs for anomalies")
        print("3. Example agent prompt:")
        print(f"   'Analyze {filepath} for authentication anomalies'")

    except Exception as e:
        print(f"[ERROR] Error fetching logs: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
