"""
Tier-2 Agent Evaluator

Runs evaluation suite on tier-2 agents using ground truth test cases.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

from evals.framework.metrics import EvalMetrics


class Tier2AgentEvaluator:
    """
    Evaluate tier-2 agent performance on ground truth dataset.

    Usage:
        evaluator = Tier2AgentEvaluator(
            agent_name='mfa_context_analyzer',
            test_cases_path='evals/dataset/mfa_context_analyzer/test_cases.json'
        )
        results = evaluator.run_eval()
        evaluator.save_results(results)
    """

    def __init__(
        self,
        agent_name: str,
        test_cases_path: str,
        output_dir: str = 'evals/results'
    ):
        """
        Initialize evaluator.

        Args:
            agent_name: Name of agent to evaluate (e.g., 'mfa_context_analyzer')
            test_cases_path: Path to JSON file with test cases
            output_dir: Directory to save results
        """
        self.agent_name = agent_name
        self.test_cases_path = test_cases_path
        self.output_dir = output_dir

        # Load test cases
        self.test_cases = self._load_test_cases()

        # Initialize agent
        self.agent = self._initialize_agent()

        # Initialize metrics calculator
        self.metrics = EvalMetrics()

        print(f"[Evaluator] Initialized for {agent_name}")
        print(f"[Evaluator] Loaded {len(self.test_cases)} test cases")

    def _load_test_cases(self) -> List[Dict[str, Any]]:
        """Load test cases from JSON file."""
        path = Path(self.test_cases_path)

        if not path.exists():
            raise FileNotFoundError(
                f"Test cases not found: {path}\n"
                f"Create test cases file using the provided template."
            )

        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Support both formats: {'eval_cases': [...]} or direct list
        if isinstance(data, dict) and 'eval_cases' in data:
            return data['eval_cases']
        elif isinstance(data, list):
            return data
        else:
            raise ValueError(f"Invalid test cases format in {path}")

    def _initialize_agent(self):
        """Initialize the tier-2 agent to be evaluated."""
        # Import agent class dynamically
        if self.agent_name == 'mfa_context_analyzer':
            from tier2_analysis.agents.mfa_context_analyzer.agent import MFAContextAgent
            return MFAContextAgent()
        elif self.agent_name == 'geographic_analyzer':
            from tier2_analysis.agents.geographic_analyzer.agent import GeographicAgent
            return GeographicAgent()
        elif self.agent_name == 'failed_login_analyzer':
            from tier2_analysis.agents.failed_login_analyzer.agent import FailedLoginAgent
            return FailedLoginAgent()
        elif self.agent_name == 'credential_stuffing_analyzer':
            from tier2_analysis.agents.credential_stuffing_analyzer.agent import CredentialStuffingAgent
            return CredentialStuffingAgent()
        elif self.agent_name == 'password_spray_analyzer':
            from tier2_analysis.agents.password_spray_analyzer.agent import PasswordSprayAgent
            return PasswordSprayAgent()
        elif self.agent_name == 'session_analyzer':
            from tier2_analysis.agents.session_analyzer.agent import SessionAgent
            return SessionAgent()
        elif self.agent_name == 'behavioral_analyzer':
            from tier2_analysis.agents.behavioral_analyzer.agent import BehavioralAgent
            return BehavioralAgent()
        elif self.agent_name == 'oauth_token_analyzer':
            from tier2_analysis.agents import OAuthTokenAgent
            return OAuthTokenAgent()
        else:
            raise ValueError(f"Unknown agent: {self.agent_name}")

    def run_eval(
        self,
        max_cases: Optional[int] = None,
        verbose: bool = True
    ) -> Dict[str, Any]:
        """
        Run evaluation on all test cases.

        Args:
            max_cases: Optional limit on number of cases to run (for testing)
            verbose: Print progress during evaluation

        Returns:
            Evaluation results with scores and aggregated metrics
        """
        if verbose:
            print("\n" + "=" * 70)
            print(f"RUNNING EVAL: {self.agent_name}")
            print("=" * 70)

        case_results = []
        cases_to_run = self.test_cases[:max_cases] if max_cases else self.test_cases

        for idx, case in enumerate(cases_to_run, 1):
            case_id = case.get('case_id', f'case_{idx}')

            if verbose:
                print(f"\n[{idx}/{len(cases_to_run)}] Running case: {case_id}")

            try:
                # Run agent analysis
                prediction = self.agent.analyze(
                    case['anomaly'],
                    case['enriched_context']
                )

                # Score against ground truth
                scores = self.metrics.evaluate_response(
                    prediction,
                    case['ground_truth'],
                    case.get('metadata', {})
                )

                # Store result
                result = {
                    'case_id': case_id,
                    'passed': scores['passed'],
                    'scores': scores,
                    'prediction': prediction,
                    'ground_truth': case['ground_truth'],
                    'metadata': case.get('metadata', {})
                }

                case_results.append(result)

                # Print summary
                if verbose:
                    status = "[PASS]" if scores['passed'] else "[FAIL]"
                    print(f"  {status} | Risk: {prediction.get('is_actual_risk')} (expected: {case['ground_truth']['is_actual_risk']}) | Severity: {prediction.get('adjusted_severity')}")

            except RuntimeError as e:
                # Handle API configuration errors specifically
                error_msg = str(e)

                if verbose:
                    print(f"  [CONFIGURATION ERROR]")
                    print(f"     {error_msg}")

                # Check if this is an API key error (first case only)
                if idx == 1 and "API is not configured" in error_msg:
                    # Stop evaluation and provide clear guidance
                    print("\n" + "=" * 70)
                    print("EVALUATION HALTED: API Configuration Required")
                    print("=" * 70)
                    print("\n" + error_msg)
                    print("\nPlease configure the API and re-run the evaluation.")
                    print("=" * 70 + "\n")

                    # Return early with error state
                    return {
                        'agent_name': self.agent_name,
                        'timestamp': datetime.now().isoformat(),
                        'test_cases_file': self.test_cases_path,
                        'status': 'failed',
                        'error': 'API_NOT_CONFIGURED',
                        'error_message': error_msg,
                        'cases_attempted': idx,
                        'total_cases': len(cases_to_run)
                    }

                # Record error for this specific case
                case_results.append({
                    'case_id': case_id,
                    'passed': False,
                    'error': error_msg,
                    'error_type': 'runtime_error',
                    'ground_truth': case['ground_truth'],
                    'metadata': case.get('metadata', {})
                })

            except Exception as e:
                # Handle other unexpected errors
                if verbose:
                    print(f"  [ERROR] | {str(e)}")

                # Record error
                case_results.append({
                    'case_id': case_id,
                    'passed': False,
                    'error': str(e),
                    'error_type': 'unexpected_error',
                    'ground_truth': case['ground_truth'],
                    'metadata': case.get('metadata', {})
                })

        # Aggregate results
        scores_only = [r['scores'] for r in case_results if 'scores' in r]
        aggregated = self.metrics.aggregate_results(scores_only)

        # Compile final results
        results = {
            'agent_name': self.agent_name,
            'timestamp': datetime.now().isoformat(),
            'test_cases_file': self.test_cases_path,
            'total_cases': len(case_results),
            'passed_cases': sum(1 for r in case_results if r['passed']),
            'failed_cases': sum(1 for r in case_results if not r['passed']),
            'aggregated_metrics': aggregated,
            'case_results': case_results
        }

        if verbose:
            self._print_summary(results)

        return results

    def _print_summary(self, results: Dict[str, Any]):
        """Print evaluation summary to console."""
        print("\n" + "=" * 70)
        print("EVALUATION SUMMARY")
        print("=" * 70)

        print(f"\nAgent: {results['agent_name']}")
        print(f"Total Cases: {results['total_cases']}")
        print(f"Passed: {results['passed_cases']} | Failed: {results['failed_cases']}")

        # Check if we have metrics (won't exist if all cases failed with errors)
        if 'aggregated_metrics' not in results or not results['aggregated_metrics']:
            print("\n[WARNING] No metrics available - all cases encountered errors")
            return

        metrics = results['aggregated_metrics']

        print("\n--- Core Metrics ---")
        core = metrics['core_metrics']
        print(f"  Accuracy:  {core['accuracy']:.1%}")
        print(f"  Precision: {core['precision']:.1%}")
        print(f"  Recall:    {core['recall']:.1%}")
        print(f"  F1 Score:  {core['f1_score']:.1%}")

        print("\n--- Confusion Matrix ---")
        cm = metrics['confusion_matrix']
        print(f"  True Positives:  {cm['true_positives']}")
        print(f"  True Negatives:  {cm['true_negatives']}")
        print(f"  False Positives: {cm['false_positives']}")
        print(f"  False Negatives: {cm['false_negatives']}")

        print("\n--- Severity Metrics ---")
        sev = metrics['severity_metrics']
        print(f"  Exact Match:     {sev['severity_accuracy']:.1%}")
        print(f"  Within 1 Level:  {sev['severity_close_accuracy']:.1%}")

        print("\n--- Quality Metrics ---")
        qual = metrics['quality_metrics']
        print(f"  High Quality:    {qual['high_quality_percentage']:.1%}")
        print(f"  Avg Evidence Citations: {qual['avg_evidence_citations']:.1f}")

        if metrics['difficulty_breakdown']:
            print("\n--- By Difficulty ---")
            for difficulty, accuracy in metrics['difficulty_breakdown'].items():
                print(f"  {difficulty.capitalize()}: {accuracy:.1%}")

        print("\n" + "=" * 70)

    def save_results(
        self,
        results: Dict[str, Any],
        run_name: Optional[str] = None
    ) -> str:
        """
        Save evaluation results to disk.

        Args:
            results: Results from run_eval()
            run_name: Optional custom name for this run (default: timestamp)

        Returns:
            Path to saved results directory
        """
        # Create run directory
        if run_name is None:
            run_name = datetime.now().strftime('%Y%m%d_%H%M%S')

        run_dir = Path(self.output_dir) / f"{self.agent_name}_{run_name}"
        run_dir.mkdir(parents=True, exist_ok=True)

        # Save full results
        results_file = run_dir / 'results.json'
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)

        # Save summary (metrics only)
        summary_file = run_dir / 'summary.json'
        summary = {
            'agent_name': results['agent_name'],
            'timestamp': results['timestamp'],
            'total_cases': results['total_cases'],
            'passed_cases': results['passed_cases'],
            'failed_cases': results['failed_cases'],
            'metrics': results['aggregated_metrics']
        }
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2)

        # Save failures only (for debugging)
        failures = [
            r for r in results['case_results']
            if not r['passed']
        ]
        if failures:
            failures_file = run_dir / 'failures.json'
            with open(failures_file, 'w', encoding='utf-8') as f:
                json.dump(failures, f, indent=2)

        # Generate markdown report
        self._generate_markdown_report(results, run_dir)

        print(f"\n[Evaluator] Results saved to: {run_dir}")

        return str(run_dir)

    def _generate_markdown_report(self, results: Dict[str, Any], output_dir: Path):
        """Generate human-readable markdown report."""
        report_file = output_dir / 'report.md'

        metrics = results['aggregated_metrics']
        core = metrics['core_metrics']
        cm = metrics['confusion_matrix']

        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(f"# Evaluation Report: {results['agent_name']}\n\n")
            f.write(f"**Generated:** {results['timestamp']}\n\n")
            f.write(f"**Test Cases:** {results['test_cases_file']}\n\n")

            f.write("## Summary\n\n")
            f.write(f"- Total Cases: {results['total_cases']}\n")
            f.write(f"- Passed: {results['passed_cases']} ({results['passed_cases']/results['total_cases']:.1%})\n")
            f.write(f"- Failed: {results['failed_cases']} ({results['failed_cases']/results['total_cases']:.1%})\n\n")

            f.write("## Core Metrics\n\n")
            f.write("| Metric | Score |\n")
            f.write("|--------|-------|\n")
            f.write(f"| Accuracy | {core['accuracy']:.1%} |\n")
            f.write(f"| Precision | {core['precision']:.1%} |\n")
            f.write(f"| Recall | {core['recall']:.1%} |\n")
            f.write(f"| F1 Score | {core['f1_score']:.1%} |\n\n")

            f.write("## Confusion Matrix\n\n")
            f.write(f"```\n")
            f.write(f"                Predicted\n")
            f.write(f"                Risk  | Not Risk\n")
            f.write(f"Actual  Risk    {cm['true_positives']:4d}  | {cm['false_negatives']:4d}\n")
            f.write(f"        Not     {cm['false_positives']:4d}  | {cm['true_negatives']:4d}\n")
            f.write(f"```\n\n")

            # Failed cases
            failures = [r for r in results['case_results'] if not r['passed']]
            if failures:
                f.write(f"## Failed Cases ({len(failures)})\n\n")
                for fail in failures:
                    f.write(f"### {fail['case_id']}\n\n")
                    if 'error' in fail:
                        f.write(f"**Error:** {fail['error']}\n\n")
                    else:
                        pred = fail.get('prediction', {})
                        gt = fail.get('ground_truth', {})
                        f.write(f"- **Expected:** is_actual_risk={gt.get('is_actual_risk')}, severity={gt.get('expected_severity')}\n")
                        f.write(f"- **Got:** is_actual_risk={pred.get('is_actual_risk')}, severity={pred.get('adjusted_severity')}\n")
                        f.write(f"- **Difficulty:** {fail.get('metadata', {}).get('difficulty', 'unknown')}\n\n")

        print(f"[Evaluator] Report saved to: {report_file}")

    def compare_to_baseline(self, baseline_results_path: str) -> Dict[str, Any]:
        """
        Compare current results to a baseline run.

        Args:
            baseline_results_path: Path to baseline results.json

        Returns:
            Comparison showing deltas and regressions
        """
        # Load baseline
        with open(baseline_results_path, 'r') as f:
            baseline = json.load(f)

        # Run current eval
        current = self.run_eval(verbose=False)

        # Extract scores
        baseline_scores = [r['scores'] for r in baseline['case_results'] if 'scores' in r]
        current_scores = [r['scores'] for r in current['case_results'] if 'scores' in r]

        # Compare
        comparison = self.metrics.compare_results(baseline_scores, current_scores)

        return comparison
