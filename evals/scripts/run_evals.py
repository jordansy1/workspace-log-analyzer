#!/usr/bin/env python3
"""
CLI tool for running tier-2 agent evaluations.

Usage:
    # Run eval for specific agent
    python evals/scripts/run_evals.py --agent mfa_context_analyzer

    # Run with custom test cases
    python evals/scripts/run_evals.py --agent mfa_context_analyzer --test-cases path/to/cases.json

    # Compare to baseline
    python evals/scripts/run_evals.py --agent mfa_context_analyzer --compare-baseline evals/results/baseline/results.json

    # Run all available agents
    python evals/scripts/run_evals.py --all
"""

import argparse
import sys
from pathlib import Path
from dotenv import load_dotenv

# Load .env file from project root
project_root = Path(__file__).parent.parent.parent
load_dotenv(project_root / '.env')

# Add parent directory to path
sys.path.insert(0, str(project_root))

from evals.framework.evaluator import Tier2AgentEvaluator


# Agent configuration
AVAILABLE_AGENTS = {
    'mfa_context_analyzer': 'evals/dataset/mfa_context_analyzer/test_cases.json',
    'geographic_analyzer': 'evals/dataset/geographic_analyzer/test_cases.json',
    'failed_login_analyzer': 'evals/dataset/failed_login_analyzer/test_cases.json',
}


def run_single_agent(
    agent_name: str,
    test_cases_path: str = None,
    baseline_path: str = None,
    save: bool = True,
    run_name: str = None
):
    """Run evaluation for a single agent."""

    # Use default test cases if not specified
    if test_cases_path is None:
        if agent_name not in AVAILABLE_AGENTS:
            print(f"Error: Unknown agent '{agent_name}'")
            print(f"Available agents: {', '.join(AVAILABLE_AGENTS.keys())}")
            return False
        test_cases_path = AVAILABLE_AGENTS[agent_name]

    # Check if test cases exist
    if not Path(test_cases_path).exists():
        print(f"Error: Test cases not found: {test_cases_path}")
        print(f"\nTo create test cases:")
        print(f"  1. Copy the template from evals/dataset/mfa_context_analyzer/test_cases.json")
        print(f"  2. Adapt it for {agent_name}")
        print(f"  3. Save to {test_cases_path}")
        return False

    # Initialize evaluator
    print(f"\n{'='*70}")
    print(f"Evaluating Agent: {agent_name}")
    print(f"{'='*70}\n")

    try:
        evaluator = Tier2AgentEvaluator(
            agent_name=agent_name,
            test_cases_path=test_cases_path
        )

        # Run evaluation
        if baseline_path:
            print(f"Comparing to baseline: {baseline_path}\n")
            comparison = evaluator.compare_to_baseline(baseline_path)

            # Print comparison
            print("\n" + "="*70)
            print("COMPARISON TO BASELINE")
            print("="*70)

            print("\n--- Metrics ---")
            for metric, values in comparison['deltas'].items():
                symbol = "↑" if values['improved'] else "↓"
                print(f"  {metric:12s}: {symbol} {values['absolute']:+.3f} ({values['percentage']:+.1f}%)")

            if comparison['has_regressions']:
                print("\n⚠️  REGRESSIONS DETECTED:")
                for reg in comparison['regressions']:
                    print(f"  - {reg['metric']}: {reg['drop']:.3f}")
                return False
            else:
                print("\n✅ No regressions detected")

        else:
            # Standard eval run
            results = evaluator.run_eval()

            # Check if evaluation failed due to configuration
            if results.get('status') == 'failed':
                if results.get('error') == 'API_NOT_CONFIGURED':
                    print(f"\n[FAILED] API configuration required")
                    print(f"Attempted {results.get('cases_attempted', 0)} of {results.get('total_cases', 0)} cases")
                    return False
                else:
                    print(f"\n[FAILED] {results.get('error_message', 'Unknown error')}")
                    return False

            # Save results
            if save:
                evaluator.save_results(results, run_name=run_name)

            # Check pass threshold
            accuracy = results['aggregated_metrics']['core_metrics']['accuracy']
            if accuracy < 0.85:
                print(f"\n[WARNING] Accuracy ({accuracy:.1%}) below recommended threshold (85%)")
                print("Consider reviewing failed cases and improving prompts.")
                return False

        print("\n[SUCCESS] Evaluation complete!")
        return True

    except FileNotFoundError as e:
        print(f"Error: {e}")
        return False
    except Exception as e:
        print(f"Error during evaluation: {e}")
        import traceback
        traceback.print_exc()
        return False


def run_all_agents():
    """Run evaluations for all available agents."""
    print("\n" + "="*70)
    print("RUNNING ALL AGENT EVALUATIONS")
    print("="*70)

    results_summary = {}

    for agent_name in AVAILABLE_AGENTS.keys():
        success = run_single_agent(agent_name, save=True)
        results_summary[agent_name] = success

    # Print summary
    print("\n" + "="*70)
    print("ALL AGENTS SUMMARY")
    print("="*70)

    for agent_name, success in results_summary.items():
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"  {status}  {agent_name}")

    all_passed = all(results_summary.values())
    return all_passed


def main():
    parser = argparse.ArgumentParser(
        description='Run tier-2 agent evaluations',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run single agent evaluation
  python evals/scripts/run_evals.py --agent mfa_context_analyzer

  # Use custom test cases
  python evals/scripts/run_evals.py --agent mfa_context_analyzer --test-cases my_cases.json

  # Compare to baseline
  python evals/scripts/run_evals.py --agent mfa_context_analyzer --compare-baseline evals/results/baseline/results.json

  # Run all agents
  python evals/scripts/run_evals.py --all

  # Save with custom name
  python evals/scripts/run_evals.py --agent mfa_context_analyzer --run-name "v2_improved_prompt"
        """
    )

    parser.add_argument(
        '--agent',
        type=str,
        help=f'Agent name to evaluate (options: {", ".join(AVAILABLE_AGENTS.keys())})'
    )

    parser.add_argument(
        '--test-cases',
        type=str,
        help='Path to test cases JSON file (optional, uses default if not specified)'
    )

    parser.add_argument(
        '--compare-baseline',
        type=str,
        help='Path to baseline results.json for comparison'
    )

    parser.add_argument(
        '--all',
        action='store_true',
        help='Run evaluations for all available agents'
    )

    parser.add_argument(
        '--run-name',
        type=str,
        help='Custom name for this evaluation run (default: timestamp)'
    )

    parser.add_argument(
        '--no-save',
        action='store_true',
        help='Do not save results to disk'
    )

    args = parser.parse_args()

    # Validate arguments
    if not args.all and not args.agent:
        parser.print_help()
        print("\nError: Must specify either --agent or --all")
        sys.exit(1)

    # Run evaluations
    if args.all:
        success = run_all_agents()
    else:
        success = run_single_agent(
            agent_name=args.agent,
            test_cases_path=args.test_cases,
            baseline_path=args.compare_baseline,
            save=not args.no_save,
            run_name=args.run_name
        )

    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
