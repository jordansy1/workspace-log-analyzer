"""
Agent Router - Routes Anomalies to Appropriate Sub-Agents

Maps tier-1 detected anomalies to specialized tier-2 analysis agents.
Provides business context to agents for more accurate risk assessment.
"""

from typing import Dict, Any
from tier2_analysis.agents import (
    MFAContextAgent,
    GeographicAgent,
    FailedLoginAgent,
    CredentialStuffingAgent,
    PasswordSprayAgent,
    SessionAgent,
    BehavioralAgent
)
from config import format_context_for_agent


class AgentRouter:
    """
    Routes anomalies to appropriate specialized agents for analysis.

    Maintains a registry of all available agents and performs intelligent
    routing based on anomaly type and sub_agent field from tier-1 detection.
    """

    def __init__(self):
        """Initialize router with all available agents and load business context."""
        self.agents = {
            'mfa_context_analyzer': MFAContextAgent(),
            'geographic_analyzer': GeographicAgent(),
            'failed_login_analyzer': FailedLoginAgent(),
            'credential_stuffing_analyzer': CredentialStuffingAgent(),
            'password_spray_analyzer': PasswordSprayAgent(),
            'session_analyzer': SessionAgent(),
            'behavioral_analyzer': BehavioralAgent(),
        }

        # Load business context for agents
        try:
            self.business_context = format_context_for_agent()
            print(f"[AgentRouter] Loaded business context configuration")
        except Exception as e:
            print(f"[AgentRouter WARNING] Could not load business context: {e}")
            self.business_context = None

        print(f"[AgentRouter] Initialized with {len(self.agents)} agents")
        for name, agent in self.agents.items():
            info = agent.get_info()
            print(f"  - {name}: {info.get('mitre_techniques', [])} (enabled={info.get('enabled')})")

    def route(self, anomaly: Dict[str, Any]):
        """
        Return the appropriate agent for this anomaly type.

        Args:
            anomaly: Detected anomaly with 'sub_agent' field

        Returns:
            Specialized agent instance

        Raises:
            ValueError: If agent name is unknown or agent is disabled
        """
        agent_name = anomaly.get('sub_agent')

        if not agent_name:
            raise ValueError(f"Anomaly missing 'sub_agent' field: {anomaly.get('id')}")

        if agent_name not in self.agents:
            raise ValueError(f"Unknown agent: {agent_name}")

        agent = self.agents[agent_name]

        # Check if agent is enabled
        if not agent.get_info().get('enabled', True):
            raise ValueError(f"Agent is disabled: {agent_name}")

        return agent

    def analyze_anomaly(self, anomaly: Dict[str, Any], enriched_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Route anomaly to appropriate agent and execute analysis.

        Includes business context in the enriched_context to help agents make
        better risk assessments based on organizational patterns.

        Args:
            anomaly: Detected anomaly from tier-1
            enriched_context: Enriched data (IP reputation, geolocation, user context)

        Returns:
            Analysis results from specialized agent

        Raises:
            ValueError: If routing fails
            Exception: If analysis fails
        """
        try:
            agent = self.route(anomaly)
            print(f"[AgentRouter] Routing {anomaly.get('id')} -> {agent.name}")

            # Add business context to enriched context
            if self.business_context:
                enriched_context['business_context'] = self.business_context

            result = agent.analyze(anomaly, enriched_context)

            print(f"[AgentRouter] Analysis complete for {anomaly.get('id')}")
            return result

        except ValueError as e:
            print(f"[AgentRouter ERROR] Routing failed: {e}")
            raise
        except Exception as e:
            print(f"[AgentRouter ERROR] Analysis failed: {e}")
            raise

    def get_available_agents(self) -> Dict[str, Dict[str, Any]]:
        """
        Return metadata for all available agents.

        Returns:
            Dictionary mapping agent names to their metadata
        """
        return {
            name: agent.get_info()
            for name, agent in self.agents.items()
        }

    def get_agent_by_mitre_technique(self, technique: str):
        """
        Find agents that handle a specific MITRE ATT&CK technique.

        Args:
            technique: MITRE technique ID (e.g., "T1110.004")

        Returns:
            List of agent names that handle this technique
        """
        matching_agents = []

        for name, agent in self.agents.items():
            info = agent.get_info()
            if technique in info.get('mitre_techniques', []):
                matching_agents.append(name)

        return matching_agents
