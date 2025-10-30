"""
OAuth Token Security Agent

Specialized agent for analyzing OAuth token abuse, malicious apps, and token theft.
"""

from tier2_analysis.base_agent import BaseAgent


class OAuthTokenAgent(BaseAgent):
    """
    Analyzes OAuth token-related anomalies including:
    - T1550.001: OAuth token abuse
    - T1528: Stolen OAuth tokens
    - T1098.001: Malicious OAuth applications
    """

    def __init__(self):
        super().__init__(
            name="OAuth Token Security Analyzer",
            agent_dir="oauth_token_analyzer",
            mitre_techniques=["T1550.001", "T1528", "T1098.001"]
        )
