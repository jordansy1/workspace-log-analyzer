"""
Geographic Analyzer Agent

Geolocation intelligence analyst specializing in impossible travel detection.
MITRE ATT&CK: T1078
"""

from typing import Dict, Any
from tier2_analysis.base_agent import BaseAgent


class GeographicAgent(BaseAgent):
    """
    Geolocation intelligence analyst specializing in impossible travel detection.

    Analyzes:
    - Impossible travel patterns (T1078 - Valid Accounts)
    - Geographic anomalies
    - Time zone inconsistencies
    - Distance-time calculations
    - Velocity analysis
    """

    def __init__(self):
        super().__init__(
            agent_dir='tier2_analysis/agents/geographic_analyzer'
        )

    def analyze(self, anomaly: Dict[str, Any], enriched_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute geographic analysis.

        Args:
            anomaly: Detected impossible travel anomaly from tier-1
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
