"""
Analysis Orchestrator

Coordinates the multi-agent analysis workflow:
1. Primary analyzer detects potential anomalies
2. Routes anomalies to specialized sub-agents
3. Aggregates refined analysis
4. Produces comprehensive security assessment
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any
from analyze_logs import AnomalyDetector, generate_sub_agent_prompt


class AnalysisOrchestrator:
    """
    Orchestrates multi-agent analysis workflow.

    This class manages the flow from initial detection through
    sub-agent analysis to final report generation.
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
        self.analysis_results = {
            'metadata': {},
            'initial_anomalies': [],
            'refined_anomalies': [],
            'sub_agent_analyses': []
        }

    def run_analysis(self, use_sub_agents: bool = True) -> Dict[str, Any]:
        """
        Run complete analysis workflow.

        Args:
            use_sub_agents: If True, route anomalies to sub-agents for deep analysis

        Returns:
            Complete analysis results
        """
        print("="*60)
        print("MULTI-AGENT LOG ANALYSIS")
        print("="*60)

        # Step 1: Initial anomaly detection
        print("\n[Step 1/3] Running primary anomaly detection...")
        initial_anomalies = self.detector.detect_anomalies()
        self.analysis_results['initial_anomalies'] = initial_anomalies
        print(f"  Detected {len(initial_anomalies)} potential anomalies")

        # Step 2: Sub-agent analysis (if enabled)
        if use_sub_agents and initial_anomalies:
            print("\n[Step 2/3] Routing anomalies to specialized sub-agents...")
            self._route_to_sub_agents(initial_anomalies)
        else:
            print("\n[Step 2/3] Skipping sub-agent analysis (disabled)")
            self.analysis_results['refined_anomalies'] = initial_anomalies

        # Step 3: Generate final report
        print("\n[Step 3/3] Generating comprehensive analysis report...")
        self._generate_report()

        print("\n" + "="*60)
        print("ANALYSIS COMPLETE")
        print("="*60)

        return self.analysis_results

    def _route_to_sub_agents(self, anomalies: List[Dict[str, Any]]):
        """
        Route anomalies requiring deep analysis to appropriate sub-agents.

        This method generates specialized prompts and creates instruction files
        for manual execution with Claude Code sub-agents.
        """
        for idx, anomaly in enumerate(anomalies):
            if not anomaly.get('requires_deep_analysis'):
                # Keep original assessment
                self.analysis_results['refined_anomalies'].append(anomaly)
                continue

            print(f"\n  Anomaly {idx + 1}/{len(anomalies)}: {anomaly['type']}")
            print(f"    Initial severity: {anomaly['severity']}")
            print(f"    Sub-agent: {anomaly['sub_agent']}")

            # Generate specialized prompt
            prompt = generate_sub_agent_prompt(anomaly, self.detector.events)

            # Create sub-agent instruction file
            instruction_file = self._create_sub_agent_instruction(
                anomaly_id=anomaly['id'],
                anomaly=anomaly,
                prompt=prompt
            )

            print(f"    Generated prompt: {instruction_file}")
            print(f"    [ACTION REQUIRED] Review prompt and execute sub-agent analysis")

            # For now, keep initial anomaly
            # In production, this would wait for sub-agent completion
            self.analysis_results['refined_anomalies'].append(anomaly)

            # Store sub-agent task info
            self.analysis_results['sub_agent_analyses'].append({
                'anomaly_id': anomaly['id'],
                'sub_agent': anomaly['sub_agent'],
                'instruction_file': instruction_file,
                'status': 'pending_manual_execution'
            })

    def _create_sub_agent_instruction(
        self,
        anomaly_id: str,
        anomaly: Dict[str, Any],
        prompt: str
    ) -> str:
        """
        Create instruction file for sub-agent analysis.

        Args:
            anomaly_id: Unique anomaly identifier
            anomaly: Anomaly data
            prompt: Specialized analysis prompt

        Returns:
            Path to instruction file
        """
        os.makedirs(f"{self.output_dir}/sub_agent_prompts", exist_ok=True)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{self.output_dir}/sub_agent_prompts/{anomaly_id}_{timestamp}.txt"

        instruction = f"""
# SUB-AGENT ANALYSIS INSTRUCTION
# Anomaly ID: {anomaly_id}
# Generated: {timestamp}

## HOW TO USE THIS FILE
1. Read this entire prompt carefully
2. Execute the analysis as described
3. Save your JSON response to: {self.output_dir}/sub_agent_responses/{anomaly_id}_response.json
4. The orchestrator will integrate your analysis into the final report

{"-"*60}

{prompt}

{"-"*60}

## OUTPUT REQUIREMENTS
Save your response as JSON to:
{self.output_dir}/sub_agent_responses/{anomaly_id}_response.json

Your response must be valid JSON matching the schema described in the prompt above.
"""

        with open(filename, 'w') as f:
            f.write(instruction)

        # Also create response directory
        os.makedirs(f"{self.output_dir}/sub_agent_responses", exist_ok=True)

        return filename

    def _generate_report(self):
        """Generate comprehensive analysis report."""
        # Extract log metadata
        log_metadata = self.detector.metadata

        # Calculate summary statistics
        total_anomalies = len(self.analysis_results['initial_anomalies'])
        high_severity = sum(
            1 for a in self.analysis_results['refined_anomalies']
            if a.get('severity') == 'high'
        )
        medium_severity = sum(
            1 for a in self.analysis_results['refined_anomalies']
            if a.get('severity') == 'medium'
        )
        low_severity = sum(
            1 for a in self.analysis_results['refined_anomalies']
            if a.get('severity') == 'low'
        )

        # Build metadata
        self.analysis_results['metadata'] = {
            'analysis_timestamp': datetime.now().isoformat(),
            'log_file': self.log_file_path,
            'log_metadata': log_metadata,
            'analysis_version': '2.0_multi_agent',
            'total_events_analyzed': log_metadata.get('total_events', 0),
            'anomaly_summary': {
                'total_detected': total_anomalies,
                'high_severity': high_severity,
                'medium_severity': medium_severity,
                'low_severity': low_severity,
                'requires_sub_agent_review': len(self.analysis_results['sub_agent_analyses'])
            }
        }

        # Save report
        self._save_report()

    def _save_report(self):
        """Save analysis report to JSON file."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        # Extract log filename for matching
        log_basename = os.path.basename(self.log_file_path)
        log_timestamp = log_basename.replace('auth_logs_', '').replace('.json', '')

        filename = f"{self.output_dir}/multi_agent_analysis_{log_timestamp}.json"

        with open(filename, 'w') as f:
            json.dump(self.analysis_results, f, indent=2)

        print(f"\n[OK] Analysis report saved: {filename}")

        # Print summary
        print(f"\nSUMMARY:")
        print(f"  Total anomalies detected: {self.analysis_results['metadata']['anomaly_summary']['total_detected']}")
        print(f"  High severity: {self.analysis_results['metadata']['anomaly_summary']['high_severity']}")
        print(f"  Medium severity: {self.analysis_results['metadata']['anomaly_summary']['medium_severity']}")
        print(f"  Low severity: {self.analysis_results['metadata']['anomaly_summary']['low_severity']}")

        if self.analysis_results['sub_agent_analyses']:
            print(f"\n  Sub-agent tasks created: {len(self.analysis_results['sub_agent_analyses'])}")
            print(f"  Review prompts in: {self.output_dir}/sub_agent_prompts/")


def main():
    """
    Main entry point for orchestrated analysis.

    Usage:
        python orchestrator.py <log_file_path>
    """
    import sys

    if len(sys.argv) < 2:
        print("Usage: python orchestrator.py <log_file_path>")
        print("\nExample:")
        print("  python orchestrator.py logs/auth_logs_20251002_131934.json")
        sys.exit(1)

    log_file = sys.argv[1]

    if not os.path.exists(log_file):
        print(f"Error: Log file not found: {log_file}")
        sys.exit(1)

    orchestrator = AnalysisOrchestrator(log_file)
    results = orchestrator.run_analysis(use_sub_agents=True)

    print(f"\nAnalysis complete! Review the report and sub-agent prompts.")


if __name__ == "__main__":
    main()
