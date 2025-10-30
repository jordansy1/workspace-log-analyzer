"""
Systematic Test Script for Tier-1 and Tier-2 Detection Validation

This script verifies:
1. Tier-1 detection methods are working correctly
2. Tier-2 AI analysis is triggered for suspicious events
3. Sub-agent routing is functioning
4. Results are properly integrated and saved

Usage:
    python tests/test_detection_tiers.py logs/auth_logs_20251027_103412.json
"""

import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import project modules
from tier1_detection.detector import AnomalyDetector
from tier2_analysis.agent_router import AgentRouter
from orchestrator_modular import ModularAnalysisOrchestrator


class DetectionTierValidator:
    """Validates both detection tiers systematically."""

    def __init__(self, log_file_path: str):
        self.log_file_path = log_file_path
        self.results = {
            'tier1_validation': {},
            'tier2_validation': {},
            'integration_validation': {},
            'timestamp': datetime.now().isoformat()
        }

    def run_full_validation(self) -> Dict[str, Any]:
        """Run complete validation suite."""
        print("=" * 70)
        print("DETECTION TIER VALIDATION TEST")
        print("=" * 70)
        print(f"Log file: {self.log_file_path}\n")

        # Step 1: Validate Tier-1
        print("[STEP 1/4] Validating Tier-1 Detection Methods...")
        self.validate_tier1()

        # Step 2: Validate Tier-2 Agent Configuration
        print("\n[STEP 2/4] Validating Tier-2 Agent Configuration...")
        self.validate_tier2_config()

        # Step 3: Run Integrated Analysis
        print("\n[STEP 3/4] Running Integrated Analysis Pipeline...")
        self.run_integrated_analysis()

        # Step 4: Validate Results
        print("\n[STEP 4/4] Validating Results Integration...")
        self.validate_integration()

        # Print summary
        self.print_summary()

        return self.results

    def validate_tier1(self):
        """Validate tier-1 detection methods."""
        try:
            # Load logs
            with open(self.log_file_path, 'r') as f:
                log_data = json.load(f)

            events = log_data.get('events', [])
            print(f"  [OK] Loaded {len(events)} events from log file")

            # Initialize detector
            detector = AnomalyDetector(self.log_file_path)
            print(f"  [OK] Initialized AnomalyDetector")

            # Run detection
            anomalies = detector.detect_all_anomalies()
            print(f"  [OK] Detected {len(anomalies)} anomalies")

            # Analyze anomaly types
            anomaly_types = {}
            for anomaly in anomalies:
                anom_type = anomaly.get('type', 'unknown')
                anomaly_types[anom_type] = anomaly_types.get(anom_type, 0) + 1

            print(f"\n  Anomaly Breakdown:")
            for anom_type, count in anomaly_types.items():
                print(f"    - {anom_type}: {count}")

            self.results['tier1_validation'] = {
                'status': 'success',
                'total_events': len(events),
                'total_anomalies': len(anomalies),
                'anomaly_types': anomaly_types,
                'anomalies': anomalies
            }

        except Exception as e:
            print(f"  [ERROR] {str(e)}")
            self.results['tier1_validation'] = {
                'status': 'failed',
                'error': str(e)
            }

    def validate_tier2_config(self):
        """Validate tier-2 agent router configuration."""
        try:
            router = AgentRouter()
            print(f"  [OK] Initialized AgentRouter")

            # Check available agents
            available_agents = router.get_available_agents()
            print(f"  [OK] Found {len(available_agents)} available agents:")
            for agent_name in available_agents:
                print(f"    - {agent_name}")

            # Verify agent routing logic
            test_routing = {
                'missing_mfa': router.route_anomaly({'type': 'missing_mfa'}),
                'multiple_locations': router.route_anomaly({'type': 'multiple_locations'}),
                'failed_login': router.route_anomaly({'type': 'failed_login'}),
            }

            print(f"\n  Routing Verification:")
            for anom_type, agent_name in test_routing.items():
                print(f"    - {anom_type} → {agent_name}")

            self.results['tier2_validation'] = {
                'status': 'success',
                'available_agents': available_agents,
                'routing_test': test_routing
            }

        except Exception as e:
            print(f"  [ERROR] {str(e)}")
            self.results['tier2_validation'] = {
                'status': 'failed',
                'error': str(e)
            }

    def run_integrated_analysis(self):
        """Run the full integrated analysis pipeline."""
        try:
            orchestrator = ModularAnalysisOrchestrator(
                self.log_file_path,
                output_dir='analysis'
            )
            print(f"  [OK] Initialized ModularAnalysisOrchestrator")

            # Run with tier-2 enabled
            results = orchestrator.run_analysis(enable_tier2=True)
            print(f"  [OK] Analysis completed")

            # Extract key metrics
            tier1_count = results.get('summary', {}).get('tier1_detections', 0)
            tier2_count = results.get('summary', {}).get('tier2_analyses_performed', 0)
            actual_risks = sum(1 for a in results.get('tier2_analyses', [])
                              if a.get('is_actual_risk', False))

            print(f"\n  Analysis Results:")
            print(f"    - Tier-1 detections: {tier1_count}")
            print(f"    - Tier-2 analyses performed: {tier2_count}")
            print(f"    - Actual risks identified: {actual_risks}")
            print(f"    - False positives filtered: {tier1_count - actual_risks}")

            self.results['integration_validation'] = {
                'status': 'success',
                'tier1_detections': tier1_count,
                'tier2_analyses': tier2_count,
                'actual_risks': actual_risks,
                'false_positives': tier1_count - actual_risks,
                'full_results': results
            }

        except Exception as e:
            import traceback
            print(f"  [ERROR] {str(e)}")
            print(f"\n  Stack trace:")
            print(traceback.format_exc())
            self.results['integration_validation'] = {
                'status': 'failed',
                'error': str(e),
                'traceback': traceback.format_exc()
            }

    def validate_integration(self):
        """Validate that results are properly saved and accessible."""
        try:
            # Check for output files
            analysis_dir = Path('analysis')

            # Check anomalies directory
            anomaly_files = list((analysis_dir / 'anomalies').glob('*.json'))
            print(f"  [OK] Found {len(anomaly_files)} anomaly files")

            # Check investigations directory
            investigation_files = list((analysis_dir / 'investigations').glob('*.json'))
            print(f"  [OK] Found {len(investigation_files)} investigation files")

            # Check reports directory
            report_files = list((analysis_dir / 'reports').glob('*.json'))
            print(f"  [OK] Found {len(report_files)} report files")

            # Verify most recent report has tier-2 data
            if report_files:
                latest_report = sorted(report_files)[-1]
                with open(latest_report, 'r') as f:
                    report_data = json.load(f)

                has_tier2 = 'tier2_analyses' in report_data
                tier2_count = len(report_data.get('tier2_analyses', []))

                print(f"\n  Latest Report: {latest_report.name}")
                print(f"    - Contains tier-2 analyses: {has_tier2}")
                print(f"    - Tier-2 analysis count: {tier2_count}")

            self.results['file_validation'] = {
                'status': 'success',
                'anomaly_files': len(anomaly_files),
                'investigation_files': len(investigation_files),
                'report_files': len(report_files)
            }

        except Exception as e:
            print(f"  [ERROR] {str(e)}")
            self.results['file_validation'] = {
                'status': 'failed',
                'error': str(e)
            }

    def print_summary(self):
        """Print validation summary."""
        print("\n" + "=" * 70)
        print("VALIDATION SUMMARY")
        print("=" * 70)

        tier1_status = self.results.get('tier1_validation', {}).get('status')
        tier2_status = self.results.get('tier2_validation', {}).get('status')
        integration_status = self.results.get('integration_validation', {}).get('status')
        file_status = self.results.get('file_validation', {}).get('status')

        print(f"Tier-1 Detection:       {'[PASS]' if tier1_status == 'success' else '[FAIL]'}")
        print(f"Tier-2 Configuration:   {'[PASS]' if tier2_status == 'success' else '[FAIL]'}")
        print(f"Integrated Analysis:    {'[PASS]' if integration_status == 'success' else '[FAIL]'}")
        print(f"File Output:            {'[PASS]' if file_status == 'success' else '[FAIL]'}")

        all_passed = all([
            tier1_status == 'success',
            tier2_status == 'success',
            integration_status == 'success',
            file_status == 'success'
        ])

        print("\n" + "=" * 70)
        if all_passed:
            print("OVERALL RESULT: [PASS] ALL TESTS PASSED")
        else:
            print("OVERALL RESULT: [FAIL] SOME TESTS FAILED")
        print("=" * 70)

        # Save results to file
        output_file = f"analysis/validation_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        print(f"\nDetailed results saved to: {output_file}")


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: python tests/test_detection_tiers.py <log_file_path>")
        print("\nExample:")
        print("  python tests/test_detection_tiers.py logs/auth_logs_20251027_103412.json")
        sys.exit(1)

    log_file_path = sys.argv[1]

    if not Path(log_file_path).exists():
        print(f"ERROR: Log file not found: {log_file_path}")
        sys.exit(1)

    # Run validation
    validator = DetectionTierValidator(log_file_path)
    results = validator.run_full_validation()

    # Exit with appropriate code
    all_success = all(
        v.get('status') == 'success'
        for k, v in results.items()
        if isinstance(v, dict) and 'status' in v
    )
    sys.exit(0 if all_success else 1)


if __name__ == "__main__":
    main()
