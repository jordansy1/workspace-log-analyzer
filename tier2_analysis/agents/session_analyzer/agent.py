"""
Session Analyzer Agent

Digital forensics investigator specializing in session hijacking.
MITRE ATT&CK: T1539, T1185
"""

from typing import Dict, Any
from tier2_analysis.base_agent import BaseAgent


class SessionAgent(BaseAgent):
    """
    Digital forensics investigator specializing in session hijacking.

    Analyzes:
    - Session hijacking (T1539)
    - Session cookie theft
    - Browser session hijacking (T1185)
    - Concurrent session anomalies
    - Session token reuse patterns
    """

    def __init__(self):
        super().__init__(
            agent_dir='tier2_analysis/agents/session_analyzer'
        )

    def analyze(self, anomaly: Dict[str, Any], enriched_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute session hijacking analysis.

        Args:
            anomaly: Detected session anomaly from tier-1
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
