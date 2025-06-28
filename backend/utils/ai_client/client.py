"""
Main WatsonX AI client implementation.
"""

import requests
import logging
from typing import Dict, Any, Optional
import re

from .config import WatsonXConfig
from .auth import IBMCloudAuth
from .prompts import PromptFormatter, PromptTemplates
from .exceptions import APIError, ResponseParsingError, ConfigurationError

logger = logging.getLogger(__name__)


class WatsonXClient:
    """
    Enhanced WatsonX AI client for legal document analysis.
    
    Provides a clean, modular interface for interacting with IBM WatsonX AI services
    specifically tailored for legal document processing and compliance analysis.
    """
    
    def __init__(self, config: Optional[WatsonXConfig] = None):
        """
        Initialize the WatsonX client.
        
        Args:
            config: Optional configuration object. If not provided, 
                   will attempt to load from environment variables.
                   
        Raises:
            ConfigurationError: If configuration is invalid or incomplete
        """
        if config is None:
            config = WatsonXConfig.from_environment()
        
        config.validate()
        self.config = config
        self.auth = IBMCloudAuth(config.api_key)
        
        logger.info(f"WatsonX client initialized with model: {config.model_id}")
    
    def _make_request(self, prompt: str, system_message: Optional[str] = None) -> str:
        """
        Make a request to the WatsonX API.
        
        Args:
            prompt: The formatted prompt to send
            system_message: Optional system message for context
            
        Returns:
            Generated text response from the model
            
        Raises:
            APIError: If the API request fails
            ResponseParsingError: If response cannot be parsed
        """
        try:
            token = self.auth.get_access_token()
        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            raise
        
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}"
        }
        
        # Format prompt for Granite models
        formatted_prompt = PromptFormatter.format_for_granite(prompt, system_message)
        
        body = {
            "project_id": self.config.project_id,
            "model_id": self.config.model_id,
            "parameters": {
                "temperature": self.config.temperature,
                "max_new_tokens": self.config.max_tokens,
                "top_p": self.config.top_p,
                "stop_sequences": [],  # Remove stop sequences that might truncate JSON
                "include_stop_sequence": False
            },
            "input": formatted_prompt
        }
        
        try:
            logger.debug(f"Making request to WatsonX API: {self.config.base_url}")
            logger.debug(f"Request body: {body}")
            response = requests.post(
                self.config.base_url,
                headers=headers,
                json=body,
                timeout=self.config.timeout
            )
            
            # Log response details for debugging
            logger.debug(f"Response status: {response.status_code}")
            logger.debug(f"Response headers: {dict(response.headers)}")
            
            if response.status_code != 200:
                logger.error(f"API request failed with status {response.status_code}")
                logger.error(f"Response body: {response.text}")
            
            response.raise_for_status()
            
            result = response.json()
            
            if "results" in result and len(result["results"]) > 0:
                generated_text = result["results"][0]["generated_text"]
                logger.debug(f"Successfully received response from WatsonX")
                
                # Clean the response to extract just the JSON part
                cleaned_response = self._extract_json_from_response(generated_text)
                return cleaned_response
            else:
                logger.error(f"Unexpected response format: {result}")
                raise ResponseParsingError("Invalid response format from WatsonX", str(result))
                
        except requests.exceptions.Timeout:
            raise APIError("Request to WatsonX API timed out", 408)
        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code if e.response else None
            response_data = {}
            try:
                response_data = e.response.json() if e.response else {}
            except:
                pass
            raise APIError(f"WatsonX API HTTP error: {e}", status_code, response_data)
        except requests.exceptions.RequestException as e:
            logger.error(f"WatsonX API request failed: {e}")
            raise APIError(f"WatsonX API request failed: {e}")
    
    def analyze_contract(self, contract_text: str, compliance_checklist: Dict[str, Any]) -> str:
        """
        Analyze a contract against a compliance checklist.
        
        Args:
            contract_text: The contract text to analyze
            compliance_checklist: Compliance requirements to check against
            
        Returns:
            JSON string containing analysis results
            
        Raises:
            APIError: If the API request fails
            ResponseParsingError: If response cannot be parsed
        """
        logger.info("Starting contract compliance analysis")
        
        template = PromptTemplates.CONTRACT_ANALYSIS
        prompt = template["builder"](contract_text, compliance_checklist)
        system_message = PromptFormatter.SYSTEM_MESSAGES[template["system"]]
        
        return self._make_request(prompt, system_message)
    
    def extract_contract_metadata(self, contract_text: str) -> str:
        """
        Extract key metadata from a contract.
        
        Args:
            contract_text: The contract text to analyze
            
        Returns:
            JSON string containing extracted metadata
            
        Raises:
            APIError: If the API request fails
            ResponseParsingError: If response cannot be parsed
        """
        logger.info("Starting contract metadata extraction")
        
        template = PromptTemplates.METADATA_EXTRACTION
        prompt = template["builder"](contract_text)
        system_message = PromptFormatter.SYSTEM_MESSAGES[template["system"]]
        
        return self._make_request(prompt, system_message)
    
    def generate_compliance_summary(self, analysis_results: Dict[str, Any]) -> str:
        """
        Generate an executive summary from compliance analysis results.
        
        Args:
            analysis_results: Results from previous compliance analysis
            
        Returns:
            JSON string containing executive summary
            
        Raises:
            APIError: If the API request fails
            ResponseParsingError: If response cannot be parsed
        """
        logger.info("Generating compliance executive summary")
        
        template = PromptTemplates.COMPLIANCE_SUMMARY
        prompt = template["builder"](analysis_results)
        system_message = PromptFormatter.SYSTEM_MESSAGES[template["system"]]
        
        return self._make_request(prompt, system_message)
    
    def refresh_authentication(self) -> None:
        """Force refresh of authentication token"""
        logger.info("Refreshing authentication token")
        self.auth.invalidate_token()
    
    def health_check(self) -> bool:
        """
        Perform a simple health check to verify the client is working.
        
        Returns:
            True if client can successfully authenticate and make a request
        """
        try:
            logger.info("Performing WatsonX client health check")
            # Simple test request
            test_prompt = "Return only the word 'healthy' as a JSON string."
            response = self._make_request(test_prompt)
            logger.info("Health check passed")
            return True
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return False
    
    def _extract_json_from_response(self, response_text: str) -> str:
        """
        Extract JSON content from AI response that may contain extra text.
        
        Args:
            response_text: Raw response from the AI model
            
        Returns:
            Cleaned JSON string
        """
        import json
        
        # First, try to find complete JSON object in the response
        json_pattern = r'\{.*?\}'
        matches = re.findall(json_pattern, response_text, re.DOTALL)
        
        for match in matches:
            try:
                # Test if this is valid JSON
                parsed = json.loads(match)
                
                # Check if it looks like a complete contract analysis response
                if self._is_complete_analysis_response(parsed):
                    # Normalize the compliance issues in the complete response
                    normalized_response = self._normalize_complete_response(parsed)
                    logger.debug(f"Found valid complete JSON in response (length: {len(match)})")
                    return json.dumps(normalized_response)
                elif self._is_partial_compliance_issue(parsed):
                    # Wrap partial response in complete structure
                    logger.debug(f"Found partial compliance issue, wrapping in complete structure")
                    wrapped = self._wrap_partial_response(parsed)
                    return json.dumps(wrapped)
                else:
                    logger.debug(f"Found valid JSON but unknown structure, using as-is")
                    return match
                    
            except json.JSONDecodeError:
                continue
        
        # If no complete JSON found, try to extract and repair incomplete JSON
        lines = response_text.strip().split('\n')
        json_lines = []
        in_json = False
        brace_count = 0
        
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('{') and not in_json:
                in_json = True
                brace_count = 1
                json_lines.append(line)
            elif in_json:
                json_lines.append(line)
                brace_count += stripped.count('{') - stripped.count('}')
                
                # If braces are balanced, we have complete JSON
                if brace_count == 0:
                    break
        
        if json_lines:
            potential_json = '\n'.join(json_lines)
            
            # Try to parse as-is first
            try:
                parsed = json.loads(potential_json)
                if self._is_partial_compliance_issue(parsed):
                    wrapped = self._wrap_partial_response(parsed)
                    return json.dumps(wrapped)
                else:
                    logger.debug(f"Extracted valid JSON by line parsing (length: {len(potential_json)})")
                    return potential_json
            except json.JSONDecodeError:
                # Try to repair incomplete JSON
                repaired_json = self._attempt_json_repair(potential_json)
                if repaired_json:
                    logger.debug(f"Successfully repaired incomplete JSON")
                    return repaired_json
        
        # If all else fails, return a default structure with error message
        logger.warning(f"Could not extract or repair JSON from response, returning fallback")
        fallback = {
            "summary": "Error: Could not parse AI response",
            "flagged_clauses": [],
            "compliance_issues": []
        }
        return json.dumps(fallback)
    
    def _is_complete_analysis_response(self, parsed_json: dict) -> bool:
        """Check if JSON contains expected contract analysis structure."""
        required_keys = {"summary", "flagged_clauses", "compliance_issues"}
        return required_keys.issubset(set(parsed_json.keys()))
    
    def _is_partial_compliance_issue(self, parsed_json: dict) -> bool:
        """Check if JSON looks like a single compliance issue object."""
        compliance_issue_keys = {"law", "missing_requirements", "recommendations"}
        return compliance_issue_keys.issubset(set(parsed_json.keys()))
    
    def _wrap_partial_response(self, partial_json: dict) -> dict:
        """Wrap a partial compliance issue in the expected complete structure."""
        # Normalize the compliance issue data
        normalized_issue = self._normalize_compliance_issue(partial_json)
        
        return {
            "summary": f"Contract analysis found issues with {partial_json.get('law', 'compliance requirements')}",
            "flagged_clauses": [],
            "compliance_issues": [normalized_issue]
        }
    
    def _normalize_complete_response(self, response: dict) -> dict:
        """Normalize a complete response to ensure proper data types."""
        normalized = response.copy()
        
        # Normalize compliance issues
        if "compliance_issues" in normalized and normalized["compliance_issues"]:
            normalized_issues = []
            for issue in normalized["compliance_issues"]:
                normalized_issues.append(self._normalize_compliance_issue(issue))
            normalized["compliance_issues"] = normalized_issues
        
        return normalized
    
    def _normalize_compliance_issue(self, issue: dict) -> dict:
        """Normalize a compliance issue to ensure proper data types."""
        normalized = issue.copy()
        
        # Ensure missing_requirements is a list
        if "missing_requirements" in normalized:
            req = normalized["missing_requirements"]
            if isinstance(req, str):
                # Convert single string to list
                normalized["missing_requirements"] = [req] if req else []
            elif not isinstance(req, list):
                # Convert other types to list
                normalized["missing_requirements"] = [str(req)]
        
        # Ensure recommendations is a list
        if "recommendations" in normalized:
            rec = normalized["recommendations"]
            if isinstance(rec, str):
                # Convert single string to list
                normalized["recommendations"] = [rec] if rec else []
            elif not isinstance(rec, list):
                # Convert other types to list
                normalized["recommendations"] = [str(rec)]
        
        return normalized
    
    def _attempt_json_repair(self, incomplete_json: str) -> str:
        """
        Attempt to repair incomplete JSON by adding missing closing braces/brackets.
        
        Args:
            incomplete_json: Potentially incomplete JSON string
            
        Returns:
            Repaired JSON string or None if repair failed
        """
        import json
        
        # Count open vs closed braces and brackets
        open_braces = incomplete_json.count('{')
        close_braces = incomplete_json.count('}')
        open_brackets = incomplete_json.count('[')
        close_brackets = incomplete_json.count(']')
        
        # Try to complete the JSON
        repaired = incomplete_json.strip()
        
        # If we're missing closing brackets, add them
        missing_brackets = open_brackets - close_brackets
        missing_braces = open_braces - close_braces
        
        # Add missing closing brackets first
        for _ in range(missing_brackets):
            repaired += ']'
        
        # Add missing closing braces
        for _ in range(missing_braces):
            repaired += '}'
        
        # Test if the repair worked
        try:
            json.loads(repaired)
            return repaired
        except json.JSONDecodeError:
            # If simple repair failed, try adding minimal structure
            if incomplete_json.strip().endswith(','):
                # Remove trailing comma and try again
                repaired = incomplete_json.strip().rstrip(',')
                for _ in range(missing_brackets):
                    repaired += ']'
                for _ in range(missing_braces):
                    repaired += '}'
                
                try:
                    json.loads(repaired)
                    return repaired
                except json.JSONDecodeError:
                    pass
            
            return None
    
    def analyze_contract_advanced(self, prompt: str, max_tokens: int = 2048, 
                                 temperature: float = 0.1, top_p: float = 0.9) -> str:
        """
        Advanced contract analysis with configurable parameters.
        
        Args:
            prompt: The complete analysis prompt to send to the model
            max_tokens: Maximum tokens in the response
            temperature: Sampling temperature (0.0 to 1.0)
            top_p: Top-p sampling parameter
            
        Returns:
            JSON string containing analysis results
            
        Raises:
            APIError: If the API request fails
            ResponseParsingError: If response cannot be parsed
        """
        logger.info("Starting advanced contract analysis with custom parameters")
        
        # Use the provided prompt directly with enhanced parameters
        return self._make_request_with_params(prompt, max_tokens, temperature, top_p)
    
    def _make_request_with_params(self, prompt: str, max_tokens: int, 
                                 temperature: float, top_p: float) -> str:
        """
        Make a request to the WatsonX API with custom parameters.
        
        Args:
            prompt: The prompt to send
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature
            top_p: Top-p sampling parameter
            
        Returns:
            Raw response text from the model
            
        Raises:
            APIError: If the API request fails
        """
        try:
            token = self.auth.get_access_token()
            
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            
            payload = {
                "input": prompt,
                "parameters": {
                    "decoding_method": "greedy",
                    "max_new_tokens": max_tokens,
                    "temperature": temperature,
                    "top_p": top_p,
                    "repetition_penalty": 1.1
                },
                "model_id": self.config.model_id,
                "project_id": self.config.project_id
            }
            
            logger.debug(f"Making WatsonX API request with custom params: max_tokens={max_tokens}, temp={temperature}, top_p={top_p}")
            
            response = requests.post(
                f"{self.config.base_url}/ml/v1/text/generation",
                headers=headers,
                json=payload,
                timeout=120
            )
            
            if response.status_code != 200:
                error_detail = response.text if response.text else "Unknown error"
                logger.error(f"WatsonX API error (HTTP {response.status_code}): {error_detail}")
                raise APIError(f"WatsonX API request failed: HTTP {response.status_code} - {error_detail}")
            
            response_json = response.json()
            
            if 'results' not in response_json or not response_json['results']:
                raise APIError("Invalid response format from WatsonX API")
            
            generated_text = response_json['results'][0].get('generated_text', '')
            
            if not generated_text.strip():
                logger.warning("Empty response from WatsonX API")
                return "{}"
            
            logger.debug(f"Received response of length: {len(generated_text)}")
            return generated_text.strip()
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error during WatsonX API request: {str(e)}")
            raise APIError(f"Network error: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error during WatsonX API request: {str(e)}")
            raise APIError(f"Unexpected error: {str(e)}")
