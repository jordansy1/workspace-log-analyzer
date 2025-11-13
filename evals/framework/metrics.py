"""
Evaluation Metrics for Tier-2 Agent Performance

Calculates accuracy, precision, recall, and other metrics for agent responses.
"""

from typing import Dict, Any, List
from collections import defaultdict


class EvalMetrics:
    """
    Calculate evaluation metrics for tier-2 agent performance.

    Provides both binary classification metrics (is_actual_risk) and
    severity assessment metrics for comprehensive evaluation.
    """

    def __init__(self):
        """Initialize metrics calculator."""
        self.severity_levels = {
            'low': 0,
            'medium': 1,
            'high': 2,
            'critical': 3
        }

    def evaluate_response(
        self,
        prediction: Dict[str, Any],
        ground_truth: Dict[str, Any],
        case_metadata: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Score a single agent response against ground truth.

        Args:
            prediction: Agent's analysis output
            ground_truth: Expected correct answers
            case_metadata: Optional case metadata (difficulty, tags, etc.)

        Returns:
            Dictionary of scores and evaluation details
        """
        scores = {}

        # 1. Binary Risk Classification
        pred_risk = prediction.get('is_actual_risk', False)
        true_risk = ground_truth.get('is_actual_risk', False)
        scores['risk_correct'] = (pred_risk == true_risk)
        scores['prediction_type'] = self._classify_prediction(pred_risk, true_risk)

        # 2. Severity Assessment
        pred_severity = prediction.get('adjusted_severity', 'low')
        true_severity = ground_truth.get('expected_severity', 'low')

        pred_sev_level = self.severity_levels.get(pred_severity, 0)
        true_sev_level = self.severity_levels.get(true_severity, 0)

        scores['severity_error'] = abs(pred_sev_level - true_sev_level)
        scores['severity_correct'] = (scores['severity_error'] == 0)
        scores['severity_close'] = (scores['severity_error'] <= 1)  # Within 1 level

        # 3. Confidence Assessment
        pred_confidence = prediction.get('confidence', 'medium')
        scores['confidence'] = pred_confidence

        # Penalize overconfidence on wrong answers
        if not scores['risk_correct']:
            confidence_penalty = {
                'high': 1.0,
                'medium': 0.5,
                'low': 0.2
            }
            scores['overconfidence_penalty'] = confidence_penalty.get(pred_confidence, 0.5)
        else:
            scores['overconfidence_penalty'] = 0.0

        # 4. Scenario Classification (if provided)
        if 'expected_scenario' in ground_truth:
            pred_scenario = prediction.get('threat_classification', '')
            true_scenario = ground_truth['expected_scenario']
            scores['scenario_correct'] = (pred_scenario == true_scenario)

        # 5. Reasoning Quality (basic checks)
        forensic_narrative = prediction.get('forensic_narrative', '')
        scores['has_reasoning'] = len(forensic_narrative) > 100
        scores['reasoning_length'] = len(forensic_narrative)

        # Check for evidence citations in reasoning
        evidence_keywords = [
            'is_2fa_enrolled',
            'risk_score',
            'ip',
            'location',
            'baseline',
            'enriched',
            'reputation'
        ]
        scores['evidence_citations'] = sum(
            1 for keyword in evidence_keywords
            if keyword.lower() in forensic_narrative.lower()
        )

        # 6. Recommendation Quality
        recommendations = prediction.get('recommended_actions', [])
        scores['has_recommendations'] = len(recommendations) > 0
        scores['recommendation_count'] = len(recommendations)

        # Check for actionable recommendations (contain specific paths/steps)
        actionable_indicators = ['console', 'navigate', 'verify', 'click', 'set', 'configure']
        scores['actionable_recommendations'] = sum(
            1 for rec in recommendations
            if isinstance(rec, str) and any(ind in rec.lower() for ind in actionable_indicators)
        )

        # 7. Overall Pass/Fail
        # Must get risk classification correct
        scores['passed'] = scores['risk_correct']

        # Additional quality checks
        scores['high_quality'] = (
            scores['risk_correct'] and
            scores['severity_close'] and
            scores['has_reasoning'] and
            scores['has_recommendations']
        )

        # 8. Add metadata if provided
        if case_metadata:
            scores['case_difficulty'] = case_metadata.get('difficulty', 'unknown')
            scores['case_tags'] = case_metadata.get('tags', [])

        return scores

    def _classify_prediction(self, predicted_risk: bool, actual_risk: bool) -> str:
        """Classify prediction as TP, TN, FP, or FN."""
        if predicted_risk and actual_risk:
            return 'true_positive'
        elif not predicted_risk and not actual_risk:
            return 'true_negative'
        elif predicted_risk and not actual_risk:
            return 'false_positive'
        else:  # not predicted_risk and actual_risk
            return 'false_negative'

    def aggregate_results(self, all_scores: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Aggregate individual case scores into overall metrics.

        Args:
            all_scores: List of score dictionaries from evaluate_response()

        Returns:
            Aggregated metrics including accuracy, precision, recall, F1
        """
        if not all_scores:
            return {
                'error': 'No scores to aggregate',
                'total_cases': 0
            }

        total = len(all_scores)

        # Count prediction types
        tp = sum(1 for s in all_scores if s['prediction_type'] == 'true_positive')
        tn = sum(1 for s in all_scores if s['prediction_type'] == 'true_negative')
        fp = sum(1 for s in all_scores if s['prediction_type'] == 'false_positive')
        fn = sum(1 for s in all_scores if s['prediction_type'] == 'false_negative')

        # Calculate core metrics
        accuracy = sum(1 for s in all_scores if s['risk_correct']) / total if total > 0 else 0

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

        # Severity metrics
        severity_accuracy = sum(1 for s in all_scores if s['severity_correct']) / total if total > 0 else 0
        severity_close_accuracy = sum(1 for s in all_scores if s['severity_close']) / total if total > 0 else 0

        # Quality metrics
        high_quality_pct = sum(1 for s in all_scores if s['high_quality']) / total if total > 0 else 0

        # Average evidence citations
        avg_evidence_citations = sum(s['evidence_citations'] for s in all_scores) / total if total > 0 else 0

        # Confidence analysis
        overconfidence_avg = sum(s['overconfidence_penalty'] for s in all_scores) / total if total > 0 else 0

        # Difficulty stratification (if available)
        by_difficulty = defaultdict(list)
        for score in all_scores:
            diff = score.get('case_difficulty', 'unknown')
            by_difficulty[diff].append(score['risk_correct'])

        difficulty_breakdown = {
            diff: sum(scores) / len(scores) if scores else 0
            for diff, scores in by_difficulty.items()
        }

        return {
            'total_cases': total,
            'confusion_matrix': {
                'true_positives': tp,
                'true_negatives': tn,
                'false_positives': fp,
                'false_negatives': fn
            },
            'core_metrics': {
                'accuracy': round(accuracy, 3),
                'precision': round(precision, 3),
                'recall': round(recall, 3),
                'f1_score': round(f1_score, 3)
            },
            'severity_metrics': {
                'severity_accuracy': round(severity_accuracy, 3),
                'severity_close_accuracy': round(severity_close_accuracy, 3)
            },
            'quality_metrics': {
                'high_quality_percentage': round(high_quality_pct, 3),
                'avg_evidence_citations': round(avg_evidence_citations, 2),
                'overconfidence_score': round(overconfidence_avg, 3)
            },
            'difficulty_breakdown': {
                k: round(v, 3) for k, v in difficulty_breakdown.items()
            }
        }

    def compare_results(
        self,
        baseline_scores: List[Dict[str, Any]],
        current_scores: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Compare two sets of results (e.g., before/after prompt changes).

        Args:
            baseline_scores: Original/baseline scores
            current_scores: New/current scores

        Returns:
            Comparison showing improvements/regressions
        """
        baseline_agg = self.aggregate_results(baseline_scores)
        current_agg = self.aggregate_results(current_scores)

        comparison = {
            'baseline': baseline_agg['core_metrics'],
            'current': current_agg['core_metrics'],
            'deltas': {}
        }

        for metric in ['accuracy', 'precision', 'recall', 'f1_score']:
            baseline_val = baseline_agg['core_metrics'][metric]
            current_val = current_agg['core_metrics'][metric]
            delta = current_val - baseline_val

            comparison['deltas'][metric] = {
                'absolute': round(delta, 3),
                'percentage': round((delta / baseline_val * 100) if baseline_val > 0 else 0, 1),
                'improved': delta > 0
            }

        # Detect regressions (>5% drop in critical metrics)
        regressions = []
        for metric in ['accuracy', 'precision', 'recall']:
            if comparison['deltas'][metric]['absolute'] < -0.05:
                regressions.append({
                    'metric': metric,
                    'drop': comparison['deltas'][metric]['absolute']
                })

        comparison['regressions'] = regressions
        comparison['has_regressions'] = len(regressions) > 0

        return comparison
