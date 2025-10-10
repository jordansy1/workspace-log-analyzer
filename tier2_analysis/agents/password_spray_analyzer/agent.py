"""
Password Spray Analyzer Agent

Senior incident responder specializing in password spray detection.
MITRE ATT&CK: T1110.003
"""

from typing import Dict, Any
from tier2_analysis.base_agent import BaseAgent


class PasswordSprayAgent(BaseAgent):
    """
    Senior incident responder specializing in password spray detection.

    Analyzes:
    - Password spray attacks (T1110.003)
    - Low-and-slow credential testing
    - Multiple account targeting
    - Lockout avoidance patterns
    - Common password attempts
    """

    def __init__(self):
        super().__init__(
            agent_dir='tier2_analysis/agents/password_spray_analyzer'
        )

    def analyze(self, anomaly: Dict[str, Any], enriched_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute password spray analysis.

        Args:
            anomaly: Detected password spray anomaly from tier-1
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
