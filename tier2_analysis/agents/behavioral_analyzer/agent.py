"""
Behavioral Analyzer Agent

UEBA specialist focusing on behavioral anomalies.
MITRE ATT&CK: M1036, T1078
"""

from typing import Dict, Any
from tier2_analysis.base_agent import BaseAgent


class BehavioralAgent(BaseAgent):
    """
    UEBA specialist focusing on behavioral anomalies.

    Analyzes:
    - User and Entity Behavior Analytics (M1036)
    - Off-hours access patterns
    - Abnormal activity patterns (T1078)
    - Baseline deviation analysis
    - Access pattern anomalies
    """

    def __init__(self):
        super().__init__(
            agent_dir='tier2_analysis/agents/behavioral_analyzer'
        )

    def analyze(self, anomaly: Dict[str, Any], enriched_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute behavioral analysis.

        Args:
            anomaly: Detected behavioral anomaly from tier-1
            enriched_context: Enriched contextual data

        Returns:
            Forensic analysis results
        """
        prompt = self.render_prompt(anomaly, enriched_context)
        response = self.call_llm(prompt)
        response = self.validate_response(response)
        response['anomaly_id'] = anomaly.get('id')
        response['agent_name'] = self.name
        return response
