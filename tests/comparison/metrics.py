"""
Comparison Metrics

Calculates metrics for comparing tier-1 deterministic and tier-2 AI
detection effectiveness. Key metrics include:

- Resolution Rate: How often AI resolves "needs_investigation" verdicts
- Resolution Accuracy: Correctness of AI confident verdicts
- False Positive/Negative rates for both tiers
- Agreement analysis between tiers

These metrics help answer the core question: where does AI add value
over deterministic rules?
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Tuple


@dataclass
class ComparisonResult:
    """
    Result of comparing tier-1 and tier-2 against ground truth.

    This represents the outcome for a single test scenario.
    """
    # Scenario identification
    scenario_id: str
    category: str  # 'clear_threat', 'clear_benign', 'ambiguous'

    # Tier-1 (Deterministic) results
    tier1_detected: bool
    tier1_verdict: str  # 'clear_threat', 'clear_benign', 'needs_investigation'
    tier1_severity: Optional[str]
    tier1_correct: bool  # Did verdict match ground truth?
    tier1_false_positive: bool
    tier1_false_negative: bool

    # Tier-2 (AI) results
    tier2_ran: bool
    tier2_is_risk: Optional[bool]
    tier2_severity: Optional[str]
    tier2_confidence: Optional[str]
    tier2_correct: Optional[bool]
    tier2_false_positive: bool
    tier2_false_negative: bool

    # AI value-add metrics
    ai_resolved_ambiguous: bool  # Did AI resolve a "needs_investigation"?
    ai_resolution_correct: Optional[bool]  # Was the resolution correct?
    ai_changed_verdict: bool  # Did AI change the tier-1 verdict?
    ai_change_was_improvement: Optional[bool]  # Was the change correct?

    # Agreement analysis
    tiers_agree: bool
    agreement_type: str  # 'both_detect', 'both_dismiss', 'tier1_only', 'tier2_only', 'n/a'

    # Ground truth
    actual_threat: bool
    expected_severity: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'scenario_id': self.scenario_id,
            'category': self.category,
            'tier1': {
                'detected': self.tier1_detected,
                'verdict': self.tier1_verdict,
                'severity': self.tier1_severity,
                'correct': self.tier1_correct,
                'false_positive': self.tier1_false_positive,
                'false_negative': self.tier1_false_negative,
            },
            'tier2': {
                'ran': self.tier2_ran,
                'is_risk': self.tier2_is_risk,
                'severity': self.tier2_severity,
                'confidence': self.tier2_confidence,
                'correct': self.tier2_correct,
                'false_positive': self.tier2_false_positive,
                'false_negative': self.tier2_false_negative,
            },
            'ai_value_add': {
                'resolved_ambiguous': self.ai_resolved_ambiguous,
                'resolution_correct': self.ai_resolution_correct,
                'changed_verdict': self.ai_changed_verdict,
                'change_was_improvement': self.ai_change_was_improvement,
            },
            'agreement': {
                'tiers_agree': self.tiers_agree,
                'agreement_type': self.agreement_type,
            },
            'ground_truth': {
                'actual_threat': self.actual_threat,
                'expected_severity': self.expected_severity,
            }
        }


@dataclass
class AggregateMetrics:
    """
    Aggregated metrics across a test suite.

    Provides overall statistics for comparing tier-1 vs tier-2 effectiveness.
    """
    total_scenarios: int = 0

    # Breakdown by category
    clear_threat_count: int = 0
    clear_benign_count: int = 0
    ambiguous_count: int = 0

    # Tier-1 metrics
    tier1_accuracy: float = 0.0
    tier1_precision: float = 0.0
    tier1_recall: float = 0.0
    tier1_f1: float = 0.0
    tier1_false_positive_rate: float = 0.0
    tier1_false_negative_rate: float = 0.0

    # Tier-2 metrics
    tier2_accuracy: float = 0.0
    tier2_precision: float = 0.0
    tier2_recall: float = 0.0
    tier2_f1: float = 0.0
    tier2_false_positive_rate: float = 0.0
    tier2_false_negative_rate: float = 0.0

    # AI Value-Add metrics (KEY METRICS)
    ai_resolution_rate: float = 0.0  # % of ambiguous cases AI resolved
    ai_resolution_accuracy: float = 0.0  # % of AI resolutions that were correct
    ai_false_confidence_rate: float = 0.0  # % of AI confident verdicts that were wrong
    ai_improvement_rate: float = 0.0  # % of cases where AI changed verdict for better

    # Agreement metrics
    overall_agreement_rate: float = 0.0
    both_detect_count: int = 0
    both_dismiss_count: int = 0
    tier1_only_count: int = 0
    tier2_only_count: int = 0

    # Combined system metrics
    combined_accuracy: float = 0.0  # Using tier-2 to filter tier-1
    false_positive_reduction: float = 0.0  # How much tier-2 reduces tier-1 FP

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'overview': {
                'total_scenarios': self.total_scenarios,
                'clear_threat_count': self.clear_threat_count,
                'clear_benign_count': self.clear_benign_count,
                'ambiguous_count': self.ambiguous_count,
            },
            'tier1_metrics': {
                'accuracy': self.tier1_accuracy,
                'precision': self.tier1_precision,
                'recall': self.tier1_recall,
                'f1_score': self.tier1_f1,
                'false_positive_rate': self.tier1_false_positive_rate,
                'false_negative_rate': self.tier1_false_negative_rate,
            },
            'tier2_metrics': {
                'accuracy': self.tier2_accuracy,
                'precision': self.tier2_precision,
                'recall': self.tier2_recall,
                'f1_score': self.tier2_f1,
                'false_positive_rate': self.tier2_false_positive_rate,
                'false_negative_rate': self.tier2_false_negative_rate,
            },
            'ai_value_add': {
                'resolution_rate': self.ai_resolution_rate,
                'resolution_accuracy': self.ai_resolution_accuracy,
                'false_confidence_rate': self.ai_false_confidence_rate,
                'improvement_rate': self.ai_improvement_rate,
            },
            'agreement': {
                'overall_rate': self.overall_agreement_rate,
                'both_detect': self.both_detect_count,
                'both_dismiss': self.both_dismiss_count,
                'tier1_only': self.tier1_only_count,
                'tier2_only': self.tier2_only_count,
            },
            'combined_system': {
                'accuracy': self.combined_accuracy,
                'false_positive_reduction': self.false_positive_reduction,
            }
        }


class ComparisonMetrics:
    """
    Calculate comparison metrics between tier-1 and tier-2 detection.

    The key insight is measuring where AI adds value:
    - Resolution of ambiguous cases
    - False positive filtering
    - Improved accuracy through context

    Usage:
        metrics = ComparisonMetrics()
        result = metrics.compare(tier1_result, tier2_result, ground_truth)
        aggregate = metrics.aggregate(results)
    """

    def compare(
        self,
        tier1_result: 'Tier1Result',
        tier2_result: Optional['Tier2Result'],
        ground_truth: Dict[str, Any],
        scenario_id: str,
        category: str
    ) -> ComparisonResult:
        """
        Compare tier-1 and tier-2 results against ground truth.

        Args:
            tier1_result: Result from Tier1Adapter
            tier2_result: Result from MockAgent or real AI (optional)
            ground_truth: Ground truth from scenario
            scenario_id: Scenario identifier
            category: Scenario category ('clear_threat', 'clear_benign', 'ambiguous')

        Returns:
            ComparisonResult with detailed comparison
        """
        # Extract ground truth values
        is_actual_threat = ground_truth.get('is_real_threat', ground_truth.get('is_actual_risk', False))
        expected_severity = ground_truth.get('severity', ground_truth.get('expected_severity', 'medium'))

        # Tier-1 assessment
        tier1_says_threat = tier1_result.verdict == 'clear_threat'
        tier1_says_benign = tier1_result.verdict == 'clear_benign'
        tier1_uncertain = tier1_result.verdict == 'needs_investigation'

        tier1_correct = self._evaluate_tier1_correctness(
            verdict=tier1_result.verdict,
            actual_threat=is_actual_threat,
            category=category
        )

        tier1_fp = tier1_says_threat and not is_actual_threat
        tier1_fn = tier1_says_benign and is_actual_threat

        # Tier-2 assessment (if ran)
        tier2_ran = tier2_result is not None
        tier2_is_risk = None
        tier2_severity = None
        tier2_confidence = None
        tier2_correct = None
        tier2_fp = False
        tier2_fn = False

        if tier2_ran:
            tier2_is_risk = tier2_result.is_actual_risk
            tier2_severity = tier2_result.adjusted_severity
            tier2_confidence = tier2_result.confidence

            tier2_correct = tier2_is_risk == is_actual_threat
            tier2_fp = tier2_is_risk and not is_actual_threat
            tier2_fn = not tier2_is_risk and is_actual_threat

        # AI value-add metrics
        ai_resolved = tier1_uncertain and tier2_ran and tier2_confidence in ['high', 'medium']
        ai_resolution_correct = None
        if ai_resolved:
            ai_resolution_correct = tier2_is_risk == is_actual_threat

        ai_changed = tier2_ran and (
            (tier1_says_threat and not tier2_is_risk) or
            (tier1_says_benign and tier2_is_risk) or
            (tier1_uncertain and tier2_confidence in ['high', 'medium'])
        )

        ai_improvement = None
        if ai_changed and tier2_ran:
            # Check if AI's verdict is more correct than tier-1's
            tier2_alignment = tier2_is_risk == is_actual_threat
            tier1_alignment = tier1_says_threat == is_actual_threat if not tier1_uncertain else False
            ai_improvement = tier2_alignment and not tier1_alignment

        # Agreement analysis
        if not tier2_ran:
            tiers_agree = True  # No comparison possible
            agreement_type = 'n/a'
        else:
            tier1_positive = tier1_says_threat or (tier1_uncertain and tier1_result.severity in ['high', 'critical'])
            tier2_positive = tier2_is_risk

            tiers_agree = tier1_positive == tier2_positive

            if tier1_positive and tier2_positive:
                agreement_type = 'both_detect'
            elif not tier1_positive and not tier2_positive:
                agreement_type = 'both_dismiss'
            elif tier1_positive and not tier2_positive:
                agreement_type = 'tier1_only'
            else:
                agreement_type = 'tier2_only'

        return ComparisonResult(
            scenario_id=scenario_id,
            category=category,
            tier1_detected=tier1_result.detected,
            tier1_verdict=tier1_result.verdict,
            tier1_severity=tier1_result.severity,
            tier1_correct=tier1_correct,
            tier1_false_positive=tier1_fp,
            tier1_false_negative=tier1_fn,
            tier2_ran=tier2_ran,
            tier2_is_risk=tier2_is_risk,
            tier2_severity=tier2_severity,
            tier2_confidence=tier2_confidence,
            tier2_correct=tier2_correct,
            tier2_false_positive=tier2_fp,
            tier2_false_negative=tier2_fn,
            ai_resolved_ambiguous=ai_resolved,
            ai_resolution_correct=ai_resolution_correct,
            ai_changed_verdict=ai_changed,
            ai_change_was_improvement=ai_improvement,
            tiers_agree=tiers_agree,
            agreement_type=agreement_type,
            actual_threat=is_actual_threat,
            expected_severity=expected_severity
        )

    def _evaluate_tier1_correctness(
        self,
        verdict: str,
        actual_threat: bool,
        category: str
    ) -> bool:
        """
        Evaluate if tier-1 verdict is correct.

        For ambiguous scenarios, "needs_investigation" is considered
        correct since the system appropriately recognized uncertainty.
        """
        if category == 'ambiguous':
            # For ambiguous cases, "needs_investigation" is correct
            if verdict == 'needs_investigation':
                return True
            # But if it made a confident verdict, check if correct
            if verdict == 'clear_threat':
                return actual_threat
            if verdict == 'clear_benign':
                return not actual_threat

        # For clear cases, verdict should match reality
        if verdict == 'clear_threat':
            return actual_threat
        if verdict == 'clear_benign':
            return not actual_threat

        # "needs_investigation" for clear cases is conservative but not wrong
        return True

    def aggregate(self, results: List[ComparisonResult]) -> AggregateMetrics:
        """
        Aggregate metrics across multiple comparison results.

        Args:
            results: List of ComparisonResult objects

        Returns:
            AggregateMetrics with overall statistics
        """
        if not results:
            return AggregateMetrics()

        metrics = AggregateMetrics()
        metrics.total_scenarios = len(results)

        # Category counts
        metrics.clear_threat_count = sum(1 for r in results if r.category == 'clear_threat')
        metrics.clear_benign_count = sum(1 for r in results if r.category == 'clear_benign')
        metrics.ambiguous_count = sum(1 for r in results if r.category == 'ambiguous')

        # Tier-1 metrics
        tier1_tp = sum(1 for r in results if r.tier1_verdict == 'clear_threat' and r.actual_threat)
        tier1_tn = sum(1 for r in results if r.tier1_verdict == 'clear_benign' and not r.actual_threat)
        tier1_fp = sum(1 for r in results if r.tier1_false_positive)
        tier1_fn = sum(1 for r in results if r.tier1_false_negative)

        metrics.tier1_accuracy = sum(1 for r in results if r.tier1_correct) / metrics.total_scenarios
        metrics.tier1_precision = tier1_tp / (tier1_tp + tier1_fp) if (tier1_tp + tier1_fp) > 0 else 0
        metrics.tier1_recall = tier1_tp / (tier1_tp + tier1_fn) if (tier1_tp + tier1_fn) > 0 else 0
        metrics.tier1_f1 = self._f1_score(metrics.tier1_precision, metrics.tier1_recall)
        metrics.tier1_false_positive_rate = tier1_fp / metrics.total_scenarios
        metrics.tier1_false_negative_rate = tier1_fn / metrics.total_scenarios

        # Tier-2 metrics (only for scenarios where AI ran)
        tier2_results = [r for r in results if r.tier2_ran]
        if tier2_results:
            tier2_tp = sum(1 for r in tier2_results if r.tier2_is_risk and r.actual_threat)
            tier2_tn = sum(1 for r in tier2_results if not r.tier2_is_risk and not r.actual_threat)
            tier2_fp = sum(1 for r in tier2_results if r.tier2_false_positive)
            tier2_fn = sum(1 for r in tier2_results if r.tier2_false_negative)

            n_tier2 = len(tier2_results)
            metrics.tier2_accuracy = sum(1 for r in tier2_results if r.tier2_correct) / n_tier2
            metrics.tier2_precision = tier2_tp / (tier2_tp + tier2_fp) if (tier2_tp + tier2_fp) > 0 else 0
            metrics.tier2_recall = tier2_tp / (tier2_tp + tier2_fn) if (tier2_tp + tier2_fn) > 0 else 0
            metrics.tier2_f1 = self._f1_score(metrics.tier2_precision, metrics.tier2_recall)
            metrics.tier2_false_positive_rate = tier2_fp / n_tier2
            metrics.tier2_false_negative_rate = tier2_fn / n_tier2

        # AI Value-Add metrics (KEY METRICS)
        ambiguous_results = [r for r in results if r.category == 'ambiguous']
        if ambiguous_results:
            resolved = [r for r in ambiguous_results if r.ai_resolved_ambiguous]
            metrics.ai_resolution_rate = len(resolved) / len(ambiguous_results)

            if resolved:
                correct_resolutions = sum(1 for r in resolved if r.ai_resolution_correct)
                metrics.ai_resolution_accuracy = correct_resolutions / len(resolved)
                metrics.ai_false_confidence_rate = 1 - metrics.ai_resolution_accuracy

        # AI improvement rate
        changed = [r for r in results if r.ai_changed_verdict]
        if changed:
            improvements = sum(1 for r in changed if r.ai_change_was_improvement)
            metrics.ai_improvement_rate = improvements / len(changed)

        # Agreement metrics
        tier2_results = [r for r in results if r.tier2_ran]
        if tier2_results:
            metrics.overall_agreement_rate = sum(1 for r in tier2_results if r.tiers_agree) / len(tier2_results)
            metrics.both_detect_count = sum(1 for r in tier2_results if r.agreement_type == 'both_detect')
            metrics.both_dismiss_count = sum(1 for r in tier2_results if r.agreement_type == 'both_dismiss')
            metrics.tier1_only_count = sum(1 for r in tier2_results if r.agreement_type == 'tier1_only')
            metrics.tier2_only_count = sum(1 for r in tier2_results if r.agreement_type == 'tier2_only')

        # Combined system accuracy (using tier-2 to filter tier-1)
        # The combined system: tier-1 detects, tier-2 filters
        combined_correct = 0
        for r in results:
            if not r.tier2_ran:
                # Without tier-2, use tier-1 verdict
                if r.tier1_correct:
                    combined_correct += 1
            else:
                # With tier-2, use tier-2 verdict
                if r.tier2_correct:
                    combined_correct += 1

        metrics.combined_accuracy = combined_correct / metrics.total_scenarios

        # False positive reduction
        if tier1_fp > 0:
            # How many tier-1 FP were correctly dismissed by tier-2?
            tier1_fps_dismissed = sum(
                1 for r in results
                if r.tier1_false_positive and r.tier2_ran and not r.tier2_is_risk
            )
            metrics.false_positive_reduction = tier1_fps_dismissed / tier1_fp

        return metrics

    def _f1_score(self, precision: float, recall: float) -> float:
        """Calculate F1 score from precision and recall."""
        if precision + recall == 0:
            return 0.0
        return 2 * (precision * recall) / (precision + recall)
