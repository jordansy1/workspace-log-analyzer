"""
Comparison Testing Framework

A framework for comparing deterministic (tier-1) and AI-powered (tier-2)
detection effectiveness to understand where each approach provides value.

Key Components:
- Tier1Adapter: Runs deterministic detection methods on test scenarios
- MockAgent: Rule-based AI simulation for rapid testing without API costs
- Tier2Adapter: Connects to real AI analysis when needed
- ComparisonRunner: Orchestrates scenario execution across both tiers
- ComparisonMetrics: Calculates effectiveness and value-add metrics

Usage:
    from tests.comparison import ComparisonRunner

    runner = ComparisonRunner(use_mock_ai=True)
    result = runner.run_scenario(scenario)
    suite_result = runner.run_suite('tests/scenarios/ambiguous/')
"""

from .tier1_adapter import Tier1Adapter, Tier1Result
from .mock_agent import MockAgent
from .metrics import ComparisonMetrics, ComparisonResult
from .runner import ComparisonRunner, ScenarioResult, SuiteResult

__all__ = [
    'Tier1Adapter',
    'Tier1Result',
    'MockAgent',
    'ComparisonMetrics',
    'ComparisonResult',
    'ComparisonRunner',
    'ScenarioResult',
    'SuiteResult',
]
