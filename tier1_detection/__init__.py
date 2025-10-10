"""
Tier 1 Detection - Deterministic Anomaly Detection

Fast, rule-based pattern matching to identify potential security anomalies
aligned with MITRE ATT&CK framework.
"""

from tier1_detection.detector import AnomalyDetector

__all__ = ['AnomalyDetector']
