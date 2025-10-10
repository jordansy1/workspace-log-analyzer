"""
MFA Context Analyzer Agent

Specializes in Multi-Factor Authentication bypass detection and analysis.
MITRE ATT&CK: T1556.006, T1621, T1111
"""

from typing import Dict, Any
from tier2_analysis.base_agent import BaseAgent


class MFAContextAgent(BaseAgent):
    """
    Senior authentication security analyst specializing in MFA bypass detection.

    Analyzes:
    - Session cookie theft (T1539)
    - MFA bypass attacks (T1556.006)
    - MFA fatigue/bombing (T1621)
    - MFA interception (T1111)
    - Policy violations vs trusted device scenarios
    """

    def __init__(self):
        super().__init__(
            agent_dir='tier2_analysis/agents/mfa_context_analyzer'
        )

    def analyze(self, anomaly: Dict[str, Any], enriched_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute MFA context analysis.

        Args:
            anomaly: Detected missing MFA anomaly from tier-1
            enriched_context: Enriched IP, geolocation, and user context data

        Returns:
            Forensic analysis with verdict on MFA status
        """
        # Render prompt with actual data
        prompt = self.render_prompt(anomaly, enriched_context)

        # Call LLM for analysis
        response = self.call_llm(prompt)

        # Validate and enrich response
        response = self.validate_response(response)
        response['anomaly_id'] = anomaly.get('id')
        response['agent_name'] = self.name

        return response
