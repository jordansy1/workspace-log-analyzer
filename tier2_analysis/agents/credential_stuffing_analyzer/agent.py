"""
Credential Stuffing Analyzer Agent

Threat intelligence analyst specializing in credential stuffing attacks.
MITRE ATT&CK: T1110.004
"""

from typing import Dict, Any
from tier2_analysis.base_agent import BaseAgent


class CredentialStuffingAgent(BaseAgent):
    """
    Threat intelligence analyst specializing in credential stuffing attacks.

    Analyzes:
    - Credential stuffing attacks (T1110.004)
    - Breach credential usage
    - Multiple account targeting
    - Distributed attack patterns
    - Success/failure ratios
    """

    def __init__(self):
        super().__init__(
            agent_dir='tier2_analysis/agents/credential_stuffing_analyzer'
        )

    def analyze(self, anomaly: Dict[str, Any], enriched_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute credential stuffing analysis.

        Args:
            anomaly: Detected credential stuffing anomaly from tier-1
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
