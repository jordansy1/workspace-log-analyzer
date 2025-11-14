"""
Base Agent Class for Tier-2 Sub-Agent Analysis

Provides common functionality for all specialized security analysis agents.
"""

import json
import yaml
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Any, Optional

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False
    print("[WARNING] anthropic package not installed - using mock responses")


class BaseAgent(ABC):
    """
    Abstract base class for all tier-2 sub-agents.

    Provides common functionality:
    - Prompt template loading and rendering
    - Configuration management
    - LLM API calls
    - Response validation
    - Output schema enforcement
    """

    def __init__(self, agent_dir: str):
        """
        Initialize agent with its directory path.

        Args:
            agent_dir: Path to agent directory containing prompt.md, config.yaml
        """
        self.agent_dir = Path(agent_dir)
        self.name = self.agent_dir.name

        # Load agent components
        self.prompt_template = self._load_prompt()
        self.config = self._load_config()

        # Initialize Claude client
        api_key = os.getenv('ANTHROPIC_API_KEY')
        if ANTHROPIC_AVAILABLE and api_key:
            self.client = anthropic.Anthropic(api_key=api_key)
        else:
            self.client = None

    def _load_prompt(self) -> str:
        """Load prompt template from markdown file."""
        prompt_path = self.agent_dir / 'prompt.md'
        if not prompt_path.exists():
            raise FileNotFoundError(f"Prompt file not found: {prompt_path}")

        with open(prompt_path, 'r', encoding='utf-8') as f:
            return f.read()

    def _load_config(self) -> Dict[str, Any]:
        """Load agent configuration from YAML file."""
        config_path = self.agent_dir / 'config.yaml'

        # Return default config if file doesn't exist yet
        if not config_path.exists():
            return self._get_default_config()

        with open(config_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)

    def _get_default_config(self) -> Dict[str, Any]:
        """Provide default configuration."""
        return {
            'agent_name': self.name,
            'llm_settings': {
                'model': 'claude-sonnet-4-5-20250929',
                'temperature': 0.1,
                'max_tokens': 4000
            },
            'enabled': True
        }

    def render_prompt(self, anomaly: Dict[str, Any], enriched_context: Dict[str, Any]) -> str:
        """
        Render prompt template with actual anomaly data.

        Args:
            anomaly: Detected anomaly from tier-1 detection
            enriched_context: Enriched data (IP reputation, geolocation, etc.)

        Returns:
            Fully rendered prompt string ready for LLM
        """
        # Replace placeholders with actual data
        prompt = self.prompt_template.replace(
            '{{ANOMALY_DATA}}',
            json.dumps(anomaly, indent=2)
        )
        prompt = prompt.replace(
            '{{ENRICHED_CONTEXT}}',
            json.dumps(enriched_context, indent=2)
        )

        # Handle any additional placeholders
        if '{{ANOMALY_ID}}' in prompt:
            prompt = prompt.replace('{{ANOMALY_ID}}', anomaly.get('id', 'UNKNOWN'))

        if '{{BASELINE_COMPARISON}}' in prompt:
            baseline = anomaly.get('evidence', {}).get('baseline_comparison', {})
            prompt = prompt.replace('{{BASELINE_COMPARISON}}', json.dumps(baseline, indent=2))

        return prompt

    def call_llm(self, prompt: str) -> Dict[str, Any]:
        """
        Call Claude API with the rendered prompt.

        Args:
            prompt: Fully rendered prompt string

        Returns:
            Parsed JSON response from Claude

        Raises:
            RuntimeError: If API key is not configured
            Exception: If API call fails or response cannot be parsed
        """
        if not self.client:
            # Raise error instead of falling back to mock response
            raise RuntimeError(
                f"[{self.name}] Anthropic API is not configured.\n\n"
                "To enable tier-2 analysis:\n"
                "1. Obtain an API key from https://console.anthropic.com/settings/keys\n"
                "2. Set the ANTHROPIC_API_KEY environment variable\n"
                "3. Restart the application\n\n"
                "Without API access, tier-2 analysis cannot be performed."
            )

        llm_config = self.config.get('llm_settings', {})

        try:
            message = self.client.messages.create(
                model=llm_config.get('model', 'claude-sonnet-4-20250514'),
                max_tokens=llm_config.get('max_tokens', 4000),
                temperature=llm_config.get('temperature', 0.1),
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            )

            # Extract JSON from response
            response_text = message.content[0].text

            # Try to parse JSON from the response
            # Look for JSON block in markdown code fence or raw JSON
            json_text = None

            if '```json' in response_text:
                # JSON in markdown code fence with language tag
                json_start = response_text.find('```json') + 7
                json_end = response_text.find('```', json_start)
                json_text = response_text[json_start:json_end].strip()
            elif '```' in response_text:
                # JSON in markdown code fence without language tag
                json_start = response_text.find('```') + 3
                json_end = response_text.find('```', json_start)
                json_text = response_text[json_start:json_end].strip()
            else:
                # No code fence - find the JSON object by looking for first { and last }
                first_brace = response_text.find('{')
                last_brace = response_text.rfind('}')

                if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
                    json_text = response_text[first_brace:last_brace + 1].strip()
                else:
                    # Fallback: assume entire response is JSON
                    json_text = response_text.strip()

            # Try to parse the JSON
            try:
                return json.loads(json_text)
            except json.JSONDecodeError as e:
                # If parsing fails due to control characters, try with strict=False
                # This is more lenient with escape sequences
                try:
                    return json.loads(json_text, strict=False)
                except json.JSONDecodeError:
                    # Still failed - raise original error
                    raise e

        except json.JSONDecodeError as e:
            raise ValueError(
                f"[{self.name}] Failed to parse JSON response from Claude API.\n"
                f"Error: {str(e)}\n"
                f"Response text: {response_text[:500]}..."
            )
        except Exception as e:
            # Re-raise with more context instead of falling back to mock
            raise RuntimeError(
                f"[{self.name}] Claude API call failed: {str(e)}\n"
                "Please check your API key and network connection."
            ) from e

    def validate_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate LLM response structure.

        Args:
            response: Parsed JSON response from LLM

        Returns:
            Validated response (with corrections if needed)
        """
        # Ensure required fields exist
        required_fields = ['is_actual_risk', 'confidence', 'adjusted_severity']

        for field in required_fields:
            if field not in response:
                print(f"[WARNING] Missing required field '{field}' in {self.name} response")
                # Provide defaults
                if field == 'is_actual_risk':
                    response[field] = False
                elif field == 'confidence':
                    response[field] = 'low'
                elif field == 'adjusted_severity':
                    response[field] = 'low'

        return response

    @abstractmethod
    def analyze(self, anomaly: Dict[str, Any], enriched_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the agent's analysis.

        This method must be implemented by each specialized agent.

        Args:
            anomaly: Detected anomaly from tier-1
            enriched_context: Enriched contextual data

        Returns:
            Analysis results as structured JSON
        """
        pass

    def get_info(self) -> Dict[str, Any]:
        """Return agent metadata."""
        return {
            'name': self.name,
            'enabled': self.config.get('enabled', True),
            'mitre_techniques': self.config.get('mitre_techniques', []),
            'model': self.config['llm_settings'].get('model', 'unknown')
        }
