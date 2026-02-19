"""
Comparison Test Runner

Orchestrates the execution of test scenarios through both tier-1
(deterministic) and tier-2 (AI) detection systems, then compares
results against ground truth.

This is the main entry point for running comparison tests.

Usage:
    from tests.comparison import ComparisonRunner

    runner = ComparisonRunner(use_mock_ai=True)

    # Run single scenario
    result = runner.run_scenario(scenario)

    # Run suite from directory
    suite_result = runner.run_suite('tests/scenarios/ambiguous/')
"""

import json
import time
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional

from .tier1_adapter import Tier1Adapter, Tier1Result
from .mock_agent import MockAgent, Tier2Result
from .metrics import ComparisonMetrics, ComparisonResult, AggregateMetrics


@dataclass
class ScenarioResult:
    """
    Complete result for a single scenario.

    Contains tier-1 result, tier-2 result (if ran), and comparison metrics.
    """
    scenario_id: str
    description: str
    category: str
    detection_type: str

    tier1_result: Tier1Result
    tier2_result: Optional[Tier2Result]
    comparison: ComparisonResult

    total_execution_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'scenario_id': self.scenario_id,
            'description': self.description,
            'category': self.category,
            'detection_type': self.detection_type,
            'tier1_result': self.tier1_result.to_dict(),
            'tier2_result': self.tier2_result.to_dict() if self.tier2_result else None,
            'comparison': self.comparison.to_dict(),
            'total_execution_time_ms': self.total_execution_time_ms
        }


@dataclass
class SuiteResult:
    """
    Complete result for a test suite (multiple scenarios).

    Contains individual results and aggregate metrics.
    """
    suite_name: str
    scenario_results: List[ScenarioResult]
    aggregate_metrics: AggregateMetrics
    total_execution_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'suite_name': self.suite_name,
            'total_scenarios': len(self.scenario_results),
            'aggregate_metrics': self.aggregate_metrics.to_dict(),
            'total_execution_time_ms': self.total_execution_time_ms,
            'scenario_results': [r.to_dict() for r in self.scenario_results]
        }


class ComparisonRunner:
    """
    Main runner for comparison testing.

    Executes test scenarios through both tier-1 and tier-2 detection,
    then compares results against ground truth to measure effectiveness.

    Args:
        use_mock_ai: If True, use MockAgent instead of real AI (default: True)
        run_tier2_always: If True, always run tier-2 even for clear verdicts (default: False)
        verbose: If True, print progress messages (default: True)
    """

    def __init__(
        self,
        use_mock_ai: bool = True,
        run_tier2_always: bool = False,
        verbose: bool = True
    ):
        self.use_mock_ai = use_mock_ai
        self.run_tier2_always = run_tier2_always
        self.verbose = verbose

        # Initialize components
        self.tier1_adapter = Tier1Adapter()
        self.mock_agent = MockAgent() if use_mock_ai else None
        self.metrics = ComparisonMetrics()

        # Real AI adapter would be initialized here if use_mock_ai is False
        self.tier2_adapter = None
        if not use_mock_ai:
            try:
                from .tier2_adapter import Tier2Adapter
                self.tier2_adapter = Tier2Adapter()
            except ImportError:
                print("[WARNING] Tier2Adapter not available, falling back to mock")
                self.mock_agent = MockAgent()
                self.use_mock_ai = True

    def run_scenario(self, scenario: Dict[str, Any]) -> ScenarioResult:
        """
        Run a single test scenario through both tiers.

        Args:
            scenario: Test scenario dictionary with raw_events, enriched_context,
                     ground_truth, etc.

        Returns:
            ScenarioResult with complete analysis
        """
        start_time = time.time()

        scenario_id = scenario.get('scenario_id', 'unknown')
        description = scenario.get('description', '')
        category = scenario.get('category', 'ambiguous')
        detection_type = scenario.get('detection_type', 'unknown')

        if self.verbose:
            print(f"\n[Runner] Scenario: {scenario_id}")
            print(f"  Category: {category}, Type: {detection_type}")

        # Extract scenario components
        raw_events = scenario.get('raw_events', {})
        events = raw_events.get('events', [])
        metadata = raw_events.get('metadata', {})
        enriched_context = scenario.get('enriched_context', {})
        ground_truth = scenario.get('ground_truth', {})

        # Phase 1: Run tier-1 detection
        tier1_result = self.tier1_adapter.detect(
            events=events,
            metadata=metadata,
            detection_type=detection_type,
            enriched_context=enriched_context
        )

        if self.verbose:
            print(f"  Tier-1: detected={tier1_result.detected}, verdict={tier1_result.verdict}")

        # Phase 2: Decide whether to run tier-2
        run_tier2 = (
            self.run_tier2_always or
            tier1_result.verdict == 'needs_investigation' or
            tier1_result.detected  # Always run tier-2 if something detected
        )

        tier2_result = None
        if run_tier2:
            # Create anomaly object for tier-2 analysis
            if tier1_result.anomalies:
                anomaly = tier1_result.anomalies[0]
            else:
                # Create synthetic anomaly for testing
                anomaly = self._create_synthetic_anomaly(scenario, tier1_result)

            # Run tier-2 analysis
            if self.use_mock_ai and self.mock_agent:
                tier2_result = self.mock_agent.analyze(anomaly, enriched_context)
            elif self.tier2_adapter:
                tier2_result = self.tier2_adapter.analyze(anomaly, enriched_context)

            if self.verbose and tier2_result:
                print(f"  Tier-2: is_risk={tier2_result.is_actual_risk}, "
                      f"confidence={tier2_result.confidence}")

        # Phase 3: Compare results to ground truth
        comparison = self.metrics.compare(
            tier1_result=tier1_result,
            tier2_result=tier2_result,
            ground_truth=ground_truth.get('final_verdict', ground_truth),
            scenario_id=scenario_id,
            category=category
        )

        total_time = (time.time() - start_time) * 1000

        if self.verbose:
            print(f"  Result: tier1_correct={comparison.tier1_correct}, "
                  f"tier2_correct={comparison.tier2_correct}")

        return ScenarioResult(
            scenario_id=scenario_id,
            description=description,
            category=category,
            detection_type=detection_type,
            tier1_result=tier1_result,
            tier2_result=tier2_result,
            comparison=comparison,
            total_execution_time_ms=total_time
        )

    def run_suite(
        self,
        scenarios_path: str,
        scenario_filter: Optional[str] = None
    ) -> SuiteResult:
        """
        Run all scenarios from a file or directory.

        Args:
            scenarios_path: Path to JSON file or directory containing scenarios
            scenario_filter: Optional filter for scenario IDs (e.g., 'MFA_*')

        Returns:
            SuiteResult with all results and aggregate metrics
        """
        start_time = time.time()
        path = Path(scenarios_path)

        # Load scenarios
        scenarios = []
        if path.is_file():
            scenarios = self._load_scenarios_from_file(path)
            suite_name = path.stem
        elif path.is_dir():
            for json_file in path.glob('**/*.json'):
                scenarios.extend(self._load_scenarios_from_file(json_file))
            suite_name = path.name
        else:
            raise FileNotFoundError(f"Scenarios path not found: {scenarios_path}")

        # Apply filter if provided
        if scenario_filter:
            import fnmatch
            scenarios = [s for s in scenarios if fnmatch.fnmatch(s.get('scenario_id', ''), scenario_filter)]

        if self.verbose:
            print(f"\n[Runner] Running suite '{suite_name}' with {len(scenarios)} scenarios")

        # Run each scenario
        results = []
        for scenario in scenarios:
            try:
                result = self.run_scenario(scenario)
                results.append(result)
            except Exception as e:
                print(f"[ERROR] Failed to run scenario {scenario.get('scenario_id')}: {e}")

        # Calculate aggregate metrics
        comparisons = [r.comparison for r in results]
        aggregate = self.metrics.aggregate(comparisons)

        total_time = (time.time() - start_time) * 1000

        if self.verbose:
            print(f"\n[Runner] Suite complete: {len(results)} scenarios in {total_time:.0f}ms")
            self._print_summary(aggregate)

        return SuiteResult(
            suite_name=suite_name,
            scenario_results=results,
            aggregate_metrics=aggregate,
            total_execution_time_ms=total_time
        )

    def _load_scenarios_from_file(self, path: Path) -> List[Dict[str, Any]]:
        """Load scenarios from a JSON file."""
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Handle both single scenario and list of scenarios
        if isinstance(data, list):
            return data
        elif 'scenarios' in data:
            return data['scenarios']
        else:
            return [data]

    def _create_synthetic_anomaly(
        self,
        scenario: Dict[str, Any],
        tier1_result: Tier1Result
    ) -> Dict[str, Any]:
        """
        Create a synthetic anomaly object for tier-2 analysis.

        Used when tier-1 didn't detect anything but we want to test tier-2.
        """
        return {
            'id': f'SYNTH-{scenario.get("scenario_id", "UNKNOWN")}',
            'type': scenario.get('detection_type', 'unknown'),
            'severity': tier1_result.severity or 'medium',
            'description': scenario.get('description', 'Synthetic anomaly for testing'),
            'evidence': {
                'events': scenario.get('raw_events', {}).get('events', []),
                'source': 'synthetic_for_testing'
            },
            'requires_deep_analysis': True,
            'sub_agent': self._get_sub_agent_for_type(scenario.get('detection_type', 'unknown'))
        }

    def _get_sub_agent_for_type(self, detection_type: str) -> str:
        """Map detection type to appropriate sub-agent."""
        agent_map = {
            'missing_mfa': 'mfa_context_analyzer',
            'mfa_fatigue': 'mfa_context_analyzer',
            'failed_login': 'failed_login_analyzer',
            'rapid_access': 'failed_login_analyzer',
            'password_spray': 'password_spray_analyzer',
            'credential_stuffing': 'credential_stuffing_analyzer',
            'impossible_travel': 'geographic_analyzer',
            'geographic_anomalies': 'geographic_analyzer',
            'session_anomalies': 'session_analyzer',
            'session_cookie_hijacking': 'session_analyzer',
            'off_hours_access': 'behavioral_analyzer',
            'oauth_token_abuse': 'oauth_token_analyzer',
            'stolen_oauth_token': 'oauth_token_analyzer',
            'malicious_oauth_app': 'oauth_token_analyzer',
        }
        return agent_map.get(detection_type, 'behavioral_analyzer')

    def _print_summary(self, metrics: AggregateMetrics) -> None:
        """Print a summary of aggregate metrics."""
        print("\n" + "=" * 60)
        print("COMPARISON SUMMARY")
        print("=" * 60)

        print(f"\nScenarios: {metrics.total_scenarios}")
        print(f"  Clear Threat: {metrics.clear_threat_count}")
        print(f"  Clear Benign: {metrics.clear_benign_count}")
        print(f"  Ambiguous: {metrics.ambiguous_count}")

        print(f"\nTier-1 (Deterministic):")
        print(f"  Accuracy: {metrics.tier1_accuracy:.1%}")
        print(f"  False Positive Rate: {metrics.tier1_false_positive_rate:.1%}")
        print(f"  False Negative Rate: {metrics.tier1_false_negative_rate:.1%}")

        print(f"\nTier-2 (AI):")
        print(f"  Accuracy: {metrics.tier2_accuracy:.1%}")
        print(f"  False Positive Rate: {metrics.tier2_false_positive_rate:.1%}")
        print(f"  False Negative Rate: {metrics.tier2_false_negative_rate:.1%}")

        print(f"\nAI VALUE-ADD METRICS:")
        print(f"  Resolution Rate: {metrics.ai_resolution_rate:.1%}")
        print(f"  Resolution Accuracy: {metrics.ai_resolution_accuracy:.1%}")
        print(f"  False Confidence Rate: {metrics.ai_false_confidence_rate:.1%}")

        print(f"\nAgreement:")
        print(f"  Overall Agreement: {metrics.overall_agreement_rate:.1%}")
        print(f"  Both Detect: {metrics.both_detect_count}")
        print(f"  Both Dismiss: {metrics.both_dismiss_count}")
        print(f"  Tier-1 Only: {metrics.tier1_only_count}")
        print(f"  Tier-2 Only: {metrics.tier2_only_count}")

        print(f"\nCombined System:")
        print(f"  Accuracy: {metrics.combined_accuracy:.1%}")
        print(f"  FP Reduction: {metrics.false_positive_reduction:.1%}")
        print("=" * 60)


def validate_scenario(scenario: Dict[str, Any]) -> List[str]:
    """
    Validate a test scenario against required schema.

    Args:
        scenario: Test scenario dictionary

    Returns:
        List of validation errors (empty if valid)
    """
    errors = []

    required_fields = ['scenario_id', 'detection_type', 'raw_events', 'ground_truth']
    for field in required_fields:
        if field not in scenario:
            errors.append(f"Missing required field: {field}")

    # Validate raw_events structure
    if 'raw_events' in scenario:
        raw_events = scenario['raw_events']
        if 'events' not in raw_events:
            errors.append("raw_events must contain 'events' array")
        elif not isinstance(raw_events['events'], list):
            errors.append("raw_events.events must be an array")

    # Validate ground_truth structure
    if 'ground_truth' in scenario:
        gt = scenario['ground_truth']
        if 'final_verdict' in gt:
            final = gt['final_verdict']
            if 'is_real_threat' not in final:
                errors.append("ground_truth.final_verdict must contain 'is_real_threat'")
        elif 'is_real_threat' not in gt and 'is_actual_risk' not in gt:
            errors.append("ground_truth must contain 'is_real_threat' or 'is_actual_risk'")

    return errors
