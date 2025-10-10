"""
Modular Analysis Orchestrator

Coordinates the tier-1 → tier-2 workflow using the new modular architecture.
This is the updated version that replaces orchestrator_automated.py.
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any
from pathlib import Path

from tier1_detection.detector import AnomalyDetector, _extract_enriched_context
from tier2_analysis.agent_router import AgentRouter


class ModularAnalysisOrchestrator:
    """
    Orchestrates the complete security analysis workflow using modular architecture.

    Workflow:
    1. Tier-1: Run deterministic detection methods (11 MITRE ATT&CK-aligned)
    2. Tier-2: Route anomalies to specialized AI agents for forensic analysis
    3. Aggregation: Combine results into comprehensive security report
    """

    def __init__(self, log_file_path: str, output_dir: str = 'analysis'):
        """
        Initialize orchestrator.

        Args:
            log_file_path: Path to authentication logs JSON file
            output_dir: Directory for analysis output
        """
        self.log_file_path = log_file_path
        self.output_dir = output_dir
        self.detector = AnomalyDetector(log_file_path)
        self.router = AgentRouter()
        self.analysis_results = {
            'metadata': {},
            'tier1_anomalies': [],
            'tier2_analyses': [],
            'summary': {}
        }

        # Create output directories
        os.makedirs(f"{output_dir}/anomalies", exist_ok=True)
        os.makedirs(f"{output_dir}/investigations", exist_ok=True)
        os.makedirs(f"{output_dir}/reports", exist_ok=True)

    def run_analysis(self, enable_tier2: bool = True) -> Dict[str, Any]:
        """
        Run complete multi-tier analysis workflow.

        Args:
            enable_tier2: If True, perform tier-2 AI analysis on anomalies

        Returns:
            Complete analysis results
        """
        print("=" * 70)
        print("MODULAR MULTI-TIER SECURITY ANALYSIS")
        print("=" * 70)

        # Step 1: Tier-1 Detection
        print("\n[TIER 1: Deterministic Detection]")
        tier1_anomalies = self.detector.detect_anomalies()
        self.analysis_results['tier1_anomalies'] = tier1_anomalies

        # Save tier-1 results
        self._save_tier1_results(tier1_anomalies)

        if not tier1_anomalies:
            print("\n[+] No anomalies detected - all authentication activity appears normal")
            self._generate_final_report()
            return self.analysis_results

        # Step 2: Tier-2 Analysis
        if enable_tier2:
            print(f"\n[TIER 2: AI-Powered Forensic Analysis]")
            tier2_analyses = self._execute_tier2_analysis(tier1_anomalies)
            self.analysis_results['tier2_analyses'] = tier2_analyses
        else:
            print("\n[TIER 2: Skipped - Analysis disabled]")

        # Step 3: Generate Final Report
        print("\n[AGGREGATION: Final Report]")
        self._generate_final_report()

        print("\n" + "=" * 70)
        print("ANALYSIS COMPLETE")
        print("=" * 70)

        return self.analysis_results

    def _execute_tier2_analysis(self, anomalies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Execute tier-2 AI analysis on detected anomalies.

        Args:
            anomalies: List of tier-1 detected anomalies

        Returns:
            List of tier-2 analysis results
        """
        analyses = []

        # Filter anomalies requiring deep analysis
        deep_analysis_anomalies = [
            a for a in anomalies
            if a.get('requires_deep_analysis', False)
        ]

        print(f"Analyzing {len(deep_analysis_anomalies)} anomalies requiring deep investigation...")

        for anomaly in deep_analysis_anomalies:
            try:
                # Extract enriched context
                enriched_context = _extract_enriched_context(anomaly)

                # Route to appropriate agent
                analysis = self.router.analyze_anomaly(anomaly, enriched_context)

                # Save individual analysis
                self._save_tier2_analysis(anomaly['id'], analysis)

                analyses.append(analysis)

                # Print summary
                risk_status = "[RISK]" if analysis.get('is_actual_risk') else "[SAFE]"
                severity = analysis.get('adjusted_severity', 'unknown').upper()
                print(f"  {risk_status} | {anomaly['id']} | {severity}")

            except Exception as e:
                print(f"  [!] ERROR | {anomaly.get('id')} | Analysis failed: {e}")
                # Continue with other anomalies even if one fails

        return analyses

    def _save_tier1_results(self, anomalies: List[Dict[str, Any]]):
        """Save tier-1 detection results."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{self.output_dir}/anomalies/tier1_anomalies_{timestamp}.json"

        output = {
            'timestamp': datetime.now().isoformat(),
            'log_file': self.log_file_path,
            'total_events': len(self.detector.events),
            'anomalies_detected': len(anomalies),
            'anomalies': anomalies
        }

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2)

        print(f"  Saved: {filename}")

    def _save_tier2_analysis(self, anomaly_id: str, analysis: Dict[str, Any]):
        """Save individual tier-2 analysis."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        agent_name = analysis.get('agent_name', 'unknown')

        # Create agent-specific directory
        agent_dir = f"{self.output_dir}/investigations/{agent_name}"
        os.makedirs(agent_dir, exist_ok=True)

        filename = f"{agent_dir}/{anomaly_id}_{timestamp}.json"

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(analysis, f, indent=2)

    def _generate_final_report(self):
        """Generate comprehensive final analysis report."""
        tier1_anomalies = self.analysis_results['tier1_anomalies']
        tier2_analyses = self.analysis_results['tier2_analyses']

        # Calculate summary statistics
        total_anomalies = len(tier1_anomalies)
        analyzed_count = len(tier2_analyses)

        # Count by severity
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }

        for analysis in tier2_analyses:
            severity = analysis.get('adjusted_severity', 'low')
            if severity in severity_counts:
                severity_counts[severity] += 1

        # Count actual risks vs false positives
        actual_risks = sum(1 for a in tier2_analyses if a.get('is_actual_risk', False))
        false_positives = analyzed_count - actual_risks

        # Build metadata
        self.analysis_results['metadata'] = {
            'analysis_timestamp': datetime.now().isoformat(),
            'log_file': self.log_file_path,
            'total_events_analyzed': len(self.detector.events),
            'analysis_version': '4.0_modular'
        }

        # Build summary
        self.analysis_results['summary'] = {
            'tier1_detections': total_anomalies,
            'tier2_analyses_performed': analyzed_count,
            'actual_risks_identified': actual_risks,
            'false_positives_filtered': false_positives,
            'severity_breakdown': severity_counts
        }

        # Save final report
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{self.output_dir}/reports/final_report_{timestamp}.json"

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.analysis_results, f, indent=2)

        print(f"  Final Report: {filename}")

        # Print summary to console
        print(f"\n{'-' * 70}")
        print("ANALYSIS SUMMARY")
        print(f"{'-' * 70}")
        print(f"  Tier-1 Detections:      {total_anomalies}")
        print(f"  Tier-2 Analyses:        {analyzed_count}")
        print(f"  Actual Risks:           {actual_risks}")
        print(f"  False Positives:        {false_positives}")
        print(f"\n  Severity Breakdown:")
        print(f"    Critical:             {severity_counts['critical']}")
        print(f"    High:                 {severity_counts['high']}")
        print(f"    Medium:               {severity_counts['medium']}")
        print(f"    Low:                  {severity_counts['low']}")
        print(f"{'-' * 70}")


def main():
    """
    Main entry point for modular orchestrated analysis.

    Usage:
        python orchestrator_modular.py <log_file_path>
    """
    import sys

    if len(sys.argv) < 2:
        print("Usage: python orchestrator_modular.py <log_file_path>")
        print("\nExample:")
        print("  python orchestrator_modular.py logs/auth_logs_ATTACK_SIMULATION.json")
        sys.exit(1)

    log_file = sys.argv[1]

    if not os.path.exists(log_file):
        print(f"Error: Log file not found: {log_file}")
        sys.exit(1)

    orchestrator = ModularAnalysisOrchestrator(log_file)
    results = orchestrator.run_analysis(enable_tier2=True)

    print(f"\n[+] Analysis complete!")
    print(f"Review results in: {orchestrator.output_dir}/")


if __name__ == "__main__":
    main()
