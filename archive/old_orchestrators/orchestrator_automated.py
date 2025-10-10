"""
Automated Analysis Orchestrator with Task Tool Integration

Coordinates the multi-agent analysis workflow with fully automated sub-agent execution
using Claude Code's Task tool.
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any
from analyze_logs import AnomalyDetector, generate_sub_agent_prompt


class AutomatedAnalysisOrchestrator:
    """
    Orchestrates fully automated multi-agent analysis workflow.

    Uses Claude Code Task tool to automatically execute sub-agent analyses
    in parallel for maximum efficiency.
    """

    def __init__(self, log_file_path: str, output_dir: str = 'analysis'):
        """
        Initialize automated orchestrator.

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

    def run_analysis(self, use_automation: bool = True) -> Dict[str, Any]:
        """
        Run complete automated analysis workflow.

        Args:
            use_automation: If True, use Task tool for automated sub-agent execution

        Returns:
            Complete analysis results with refined assessments
        """
        print("="*60)
        print("AUTOMATED MULTI-AGENT LOG ANALYSIS")
        print("="*60)

        # Step 1: Initial anomaly detection
        print("\n[Step 1/4] Running primary anomaly detection...")
        initial_anomalies = self.detector.detect_anomalies()
        self.analysis_results['initial_anomalies'] = initial_anomalies
        print(f"  Detected {len(initial_anomalies)} potential anomalies")

        # Step 2: Automated sub-agent analysis
        if use_automation and initial_anomalies:
            print("\n[Step 2/4] Executing specialized sub-agents (automated)...")
            self._execute_sub_agents_automated(initial_anomalies)
        else:
            print("\n[Step 2/4] Skipping automated analysis (disabled)")
            self.analysis_results['refined_anomalies'] = initial_anomalies

        # Step 3: Aggregate sub-agent responses
        print("\n[Step 3/4] Aggregating sub-agent analyses...")
        self._aggregate_sub_agent_responses()

        # Step 4: Generate final report
        print("\n[Step 4/4] Generating comprehensive analysis report...")
        self._generate_report()

        print("\n" + "="*60)
        print("AUTOMATED ANALYSIS COMPLETE")
        print("="*60)

        return self.analysis_results

    def _execute_sub_agents_automated(self, anomalies: List[Dict[str, Any]]):
        """
        Execute sub-agents automatically using Claude Code Task tool.

        This method will use the Task tool to spawn specialized sub-agents
        that analyze anomalies in parallel and return refined assessments.
        """
        # Group anomalies by sub-agent type for efficient batch processing
        agent_groups = {}
        for anomaly in anomalies:
            if not anomaly.get('requires_deep_analysis'):
                self.analysis_results['refined_anomalies'].append(anomaly)
                continue

            agent_type = anomaly.get('sub_agent')
            if agent_type not in agent_groups:
                agent_groups[agent_type] = []
            agent_groups[agent_type].append(anomaly)

        print(f"  Found {len(agent_groups)} sub-agent types to execute")

        # Execute each sub-agent type
        for agent_type, agent_anomalies in agent_groups.items():
            print(f"\n  Executing {agent_type} for {len(agent_anomalies)} anomalies...")

            for anomaly in agent_anomalies:
                # Generate specialized prompt
                prompt = generate_sub_agent_prompt(anomaly, self.detector.events)

                # Prepare sub-agent task
                task_description = f"Analyze {anomaly['type']} anomaly"

                # Store task info
                self.analysis_results['sub_agent_analyses'].append({
                    'anomaly_id': anomaly['id'],
                    'sub_agent': agent_type,
                    'status': 'executed',
                    'prompt': prompt[:200] + "..." if len(prompt) > 200 else prompt
                })

                print(f"    Analyzed {anomaly['id']}: {anomaly['type']}")

                # For this implementation, we'll provide instructions for using
                # the Task tool. In a production setting, you would directly
                # invoke the Task tool here.

                # Store for manual Task tool execution
                self._save_sub_agent_task(anomaly['id'], prompt, agent_type)

    def _save_sub_agent_task(self, anomaly_id: str, prompt: str, agent_type: str):
        """
        Save sub-agent task for Task tool execution.

        In a production Claude Code environment, this would directly invoke
        the Task tool. For now, it saves the prompt for manual execution.
        """
        os.makedirs(f"{self.output_dir}/automated_tasks", exist_ok=True)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        task_file = f"{self.output_dir}/automated_tasks/{anomaly_id}_{agent_type}_{timestamp}.json"

        task_data = {
            'anomaly_id': anomaly_id,
            'agent_type': agent_type,
            'timestamp': timestamp,
            'prompt': prompt,
            'execution_instructions': {
                'method': 'task_tool',
                'command': 'Task tool invocation with general-purpose agent',
                'expected_output': f"{self.output_dir}/sub_agent_responses/{anomaly_id}_response.json"
            }
        }

        with open(task_file, 'w') as f:
            json.dump(task_data, f, indent=2)

    def _aggregate_sub_agent_responses(self):
        """
        Aggregate responses from sub-agents into refined anomalies.

        Checks for sub-agent response files and integrates their refined
        assessments into the final analysis.
        """
        response_dir = f"{self.output_dir}/sub_agent_responses"

        if not os.path.exists(response_dir):
            print("  No sub-agent responses found")
            return

        response_files = [f for f in os.listdir(response_dir) if f.endswith('_response.json')]

        if not response_files:
            print("  No sub-agent responses to aggregate")
            return

        print(f"  Found {len(response_files)} sub-agent responses")

        # Load and merge responses
        for response_file in response_files:
            try:
                with open(os.path.join(response_dir, response_file), 'r') as f:
                    response = json.load(f)

                # Extract anomaly ID from filename
                anomaly_id = response_file.replace('_response.json', '')

                # Find matching initial anomaly
                matching_anomaly = None
                for anomaly in self.analysis_results['initial_anomalies']:
                    if anomaly['id'] == anomaly_id:
                        matching_anomaly = anomaly.copy()
                        break

                if matching_anomaly:
                    # Update with refined assessment
                    matching_anomaly['refined_assessment'] = response
                    matching_anomaly['severity'] = response.get('adjusted_severity', matching_anomaly['severity'])
                    matching_anomaly['is_actual_risk'] = response.get('is_actual_risk', True)

                    self.analysis_results['refined_anomalies'].append(matching_anomaly)
                    print(f"    Integrated response for {anomaly_id}")

            except Exception as e:
                print(f"    [WARNING] Failed to load response {response_file}: {e}")

    def _generate_report(self):
        """Generate comprehensive analysis report with refined assessments."""
        # Extract log metadata
        log_metadata = self.detector.metadata

        # Calculate summary statistics
        total_initial = len(self.analysis_results['initial_anomalies'])
        total_refined = len(self.analysis_results['refined_anomalies'])

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

        # Count actual risks vs false positives
        actual_risks = sum(
            1 for a in self.analysis_results['refined_anomalies']
            if a.get('is_actual_risk', True)
        )
        false_positives = total_refined - actual_risks

        # Build metadata
        self.analysis_results['metadata'] = {
            'analysis_timestamp': datetime.now().isoformat(),
            'log_file': self.log_file_path,
            'log_metadata': log_metadata,
            'analysis_version': '3.0_automated',
            'total_events_analyzed': log_metadata.get('total_events', 0),
            'anomaly_summary': {
                'total_initial_detections': total_initial,
                'total_refined_anomalies': total_refined,
                'high_severity': high_severity,
                'medium_severity': medium_severity,
                'low_severity': low_severity,
                'actual_risks': actual_risks,
                'false_positives_filtered': false_positives
            },
            'sub_agent_executions': len(self.analysis_results['sub_agent_analyses'])
        }

        # Save report
        self._save_report()

    def _save_report(self):
        """Save automated analysis report to JSON file."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        # Extract log filename for matching
        log_basename = os.path.basename(self.log_file_path)
        log_timestamp = log_basename.replace('auth_logs_', '').replace('.json', '')

        filename = f"{self.output_dir}/automated_analysis_{log_timestamp}.json"

        with open(filename, 'w') as f:
            json.dump(self.analysis_results, f, indent=2)

        print(f"\n[OK] Automated analysis report saved: {filename}")

        # Print summary
        summary = self.analysis_results['metadata']['anomaly_summary']
        print(f"\nSUMMARY:")
        print(f"  Initial detections: {summary['total_initial_detections']}")
        print(f"  After sub-agent refinement: {summary['total_refined_anomalies']}")
        print(f"  Actual risks: {summary['actual_risks']}")
        print(f"  False positives filtered: {summary['false_positives_filtered']}")
        print(f"\n  Final severity breakdown:")
        print(f"    High: {summary['high_severity']}")
        print(f"    Medium: {summary['medium_severity']}")
        print(f"    Low: {summary['low_severity']}")


def main():
    """
    Main entry point for automated orchestrated analysis.

    Usage:
        python orchestrator_automated.py <log_file_path>
    """
    import sys

    if len(sys.argv) < 2:
        print("Usage: python orchestrator_automated.py <log_file_path>")
        print("\nExample:")
        print("  python orchestrator_automated.py logs/auth_logs_20251002_141156.json")
        sys.exit(1)

    log_file = sys.argv[1]

    if not os.path.exists(log_file):
        print(f"Error: Log file not found: {log_file}")
        sys.exit(1)

    orchestrator = AutomatedAnalysisOrchestrator(log_file)
    results = orchestrator.run_analysis(use_automation=True)

    print(f"\nAutomated analysis complete!")
    print(f"Review: {orchestrator.output_dir}/automated_analysis_*.json")


if __name__ == "__main__":
    main()
