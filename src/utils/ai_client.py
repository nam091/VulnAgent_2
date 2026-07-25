import os
from typing import Any, Dict, Optional

import anthropic
import httpx
import openai
from dotenv import load_dotenv

load_dotenv()

class AIClient:
    def __init__(self) -> None:
        """
        Initialize AI clients with API keys from environment variables.
        Supports OpenAI-compatible providers via OPENAI_BASE_URL / OPENAI_MODEL.
        """

        # Initialize Ollama, OpenAI-compatible, and Anthropic clients
        # self.ollama_base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        openai_api_key = os.getenv("OPENAI_API_KEY")
        openai_base_url = os.getenv("OPENAI_BASE_URL")  # e.g. https://api.xiaomimimo.com/v1
        client_kwargs: Dict[str, Any] = {"api_key": openai_api_key}
        if openai_base_url:
            client_kwargs["base_url"] = openai_base_url
        self.openai_client = openai.Client(**client_kwargs)

        anthropic_api_key = os.getenv("ANTHROPIC_API_KEY")
        self.anthropic_client = (
            anthropic.Anthropic(api_key=anthropic_api_key) if anthropic_api_key else None
        )

        # Default model (override with OPENAI_MODEL for compatible APIs)
        self.openai_default_model = os.getenv("OPENAI_MODEL", "o1-mini-2024-09-12")

        # Default to local model for security analysis (Local Model)
        # self.local_default_model = "deepseek-r1:32b"  # or any other model you have pulled in Ollama

    async def analyze_security(self, prompt: str, model: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze code for security vulnerabilities using AI models

        Args:
            prompt: The prompt to analyze
            model: The model to use for analysis (OpenAI)

        Returns:
            Dict[str, Any]: The analysis result
        """

        try:
            # NOTE: Ollama currently is not able to perform security analysis
            # Try Ollama first (local model)
            # response = await self._analyze_with_ollama(prompt)
            # if self._validate_response(response):
            #     return response

            # Try with OpenAI-compatible API first
            selected_model = model or self.openai_default_model
            response = await self._analyze_with_openai(self.openai_client, prompt, selected_model)
            if self._validate_response(response):
                return response

            # Fallback to Anthropic if configured and OpenAI response is invalid
            if self.anthropic_client is not None:
                response = await self._analyze_with_anthropic(prompt)
                if self._validate_response(response):
                    return response

            raise ValueError("AI models failed to provide valid analysis")

        except Exception as e:
            print(f"Error in security analysis: {str(e)}")
            return {"vulnerabilities": []}

    async def _analyze_with_ollama(self, prompt: str) -> Dict[str, Any]:
        """
        Analyze code using local Ollama model

        Args:
            prompt: The prompt to analyze

        Returns:
            Dict[str, Any]: The analysis result
        """

        system_prompt = self._get_system_prompt()
        full_prompt = f"{system_prompt}\n\nUser: {prompt}\n\nAssistant:"

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.ollama_base_url}/api/generate",
                json={
                    "model": self.local_default_model,
                    "prompt": full_prompt,
                    "stream": False,
                    # "temperature": 0.1
                }
            )
            response.raise_for_status()
            return self._parse_ollama_response(response.json())

    async def _analyze_with_openai(self, client: openai.Client, prompt: str, model: str) -> Dict[str, Any]:
        """
        Analyze code using OpenAI models

        Args:
            client: The OpenAI client
            prompt: The prompt to analyze
            model: The model to use for analysis (OpenAI)

        Returns:
            Dict[str, Any]: The analysis result
        """

        messages = [
            {"role": "system", "content": self._get_system_prompt()},
            {"role": "user", "content": prompt}
        ]

        # store= is OpenAI-only; omit for OpenAI-compatible providers (e.g. Mimo)
        response = client.chat.completions.create(
            model=model,
            messages=messages,
        )

        return self._parse_openai_response(response)

    async def _analyze_with_anthropic(self, prompt: str) -> Dict[str, Any]:
        """
        Analyze code using Anthropic Claude

        Args:
            prompt: The prompt to analyze

        Returns:
            Dict[str, Any]: The analysis result
        """

        system_prompt = self._get_system_prompt()
        full_prompt = f"{system_prompt}\n\nHuman: {prompt}\n\nAssistant:"

        response = await self.anthropic_client.messages.create(
            model="claude-3-sonnet-20240229",
            max_tokens=4000,
            temperature=0.1,
            messages=[{"role": "user", "content": full_prompt}]
        )

        return self._parse_anthropic_response(response)

    def _get_system_prompt(self) -> str:
        """
        Get the system prompt for security analysis

        Returns:
            str: The system prompt
        """

        return """You are a security expert performing code analysis.
        Analyze the provided code for security vulnerabilities, focusing on:
        1. OWASP Top 10 vulnerabilities
        2. SANS Top 25 vulnerabilities
        3. Language-specific security issues
        4. Security best practices

        IMPORTANT: Respond with ONLY the raw JSON data, without any markdown formatting or code blocks.
        Your response should be a valid Python dictionary that can be evaluated using eval().

        The response must follow this structure:
        {
            "vulnerabilities": [
                {
                    "type": "VULNERABILITY_TYPE_NAME_WITH_UNDERSCORES",
                    "severity": "SEVERITY_LEVEL",
                    "location": {
                        "file_path": "path/to/file",
                        "start_line": line_number,
                        "end_line": line_number,
                        "start_col": column_number,
                        "end_col": column_number,
                        "context": "code_snippet"
                    },
                    "description": "Detailed description of the vulnerability",
                    "impact": "Potential impact of exploitation",
                    "remediation": "How to fix the vulnerability",
                    "cwe_id": "CWE_ID",
                    "owasp_category": "OWASP CATEGORY (Format example: A10:2021 - Server-Side Request Forgery (SSRF))",
                    "cvss_score": "CVSS_SCORE",
                    "references": ["REFERENCE_URL_1", "REFERENCE_URL_2", etc.],
                    "proof_of_concept": "POC_CODE",
                    "secure_code_example": "SECURE_CODE_EXAMPLE"
                }
            ]
        }

        Note: The vulnerability type must use UPPERCASE with UNDERSCORES (e.g., INSECURE_DESERIALIZATION, SQL_INJECTION, XSS_VULNERABILITY). If the identified vulnerability type matches any of the predefined types in the predefined Vulnerability Types, use that type instead of creating some new type. If a type doesn't matches predefined type, use it as is.

        Predefined Vulnerability Types:
        - INJECTION
        - SQL_INJECTION
        - OS_COMMAND_INJECTION
        - CODE_INJECTION
        - HTTP_METHOD_INJECTION
        - CROSS_SITE_SCRIPTING
        - CSRF
        - PATH_TRAVERSAL
        - INSECURE_DESERIALIZATION
        - BROKEN_AUTHENTICATION
        - SENSITIVE_DATA_EXPOSURE
        - XML_EXTERNAL_ENTITY
        - BROKEN_ACCESS_CONTROL
        - SECURITY_MISCONFIGURATION
        - SECURE_RANDOMNESS
        - INSUFFICIENT_LOGGING
        - WEAK_CRYPTOGRAPHY
        - USING_COMPONENTS_WITH_KNOWN_VULNERABILITIES
        - BUFFER_OVERFLOW
        - FORMAT_STRING
        - INTEGER_OVERFLOW
        - RACE_CONDITION
        - HARDCODED_CREDENTIALS
        - EXPOSED_SENSITIVE_INFORMATION
        - EXPOSED_SECRET
        - FILE_INCLUSION
        - INSECURE_FILE_READ
        - EXPOSED_GITHUB_URL
        - IMPROPER_ERROR_HANDLING
        - DEPENDENCY_VULNERABILITY
        - INSECURE_IMPORTS
        - UNSAFE_PROPERTY_ACCESS
        - POTENTIAL_INSECURE_USE_OF_OPERATOR
        - TESTING_FLAGS_UNHANDLED
        - INSUFFICIENT_INPUT_VALIDATION
        - DENIAL_OF_SERVICE
        - REGULAR_EXPRESSION_DENIAL_OF_SERVICE
        - EXPOSED_FLASK_DEBUG
        - SERVER_SIDE_REQUEST_FORGERY_(SSRF)
        - ENVIRONMENT_VARIABLE_INJECTION
        - INSECURE_RANDOM_SEEDING
        - USE_OF_WEAK_HASHING_ALGORITHM
        - UNHANDLED_EXCEPTION
        - REMOTE_CODE_EXECUTION_(RCE)
        - INSECURE_DIRECT_OBJECT_REFERENCE_(IDOR)
        - MISSING_AUTHENTICATION
        - EXCESSIVE_DATA_EXPOSURE
        - INFORMATION_EXPOSURE_THROUGH_QUERY_STRING
        - FAILURE_TO_RESTRICT_URL_ACCESS
        - TYPE_COERCION_VULNERABILITY
        - ASSERTION_FAILURE_VULNERABILITY
        - PYTHONIC_TYPE_CHECK_VIOLATION
        - UNVALIDATED_REDIRECTS_AND_FORWARDED_REQUESTS
        - INSECURE_DATA_STORAGE
        - EXPOSED_SECURITY_HEADERS
        - EXPOSED_ADMIN_FUNCTIONALITIES
        - INSECURE_ENVIRONMENT_VARIABLE_USAGE
        - INSECURE_HTTP_HEADERS
        - INJECTION_FLAW
        - SECURE_COOKIE
        - INSECURE_CONFIGURATION_SETTING
"""

    def _validate_response(self, response: Dict[str, Any]) -> bool:
        """
        Validate that the response contains required fields in correct format

        Args:
            response: The response to validate

        Returns:
            bool: True if the response is valid, False otherwise
        """

        try:
            if not isinstance(response, dict):
                return False

            if "vulnerabilities" not in response:
                return False

            for vuln in response["vulnerabilities"]:
                required_fields = ["type", "severity", "location", "description", "impact", "remediation", "cwe_id", "owasp_category", "cvss_score", "references", "proof_of_concept", "secure_code_example"]
                if not all(field in vuln for field in required_fields):
                    return False

            return True

        except Exception:
            return False

    def _parse_openai_response(self, response) -> Dict[str, Any]:
        """
        Parse OpenAI response into standardized format

        Args:
            response: The OpenAI response

        Returns:
            Dict[str, Any]: The parsed response
        """

        try:
            import json
            import re

            content = response.choices[0].message.content
            if not content:
                raise ValueError("Empty model response")

            content = content.strip()
            # Strip markdown code fences if the model wraps JSON
            fence = re.match(r"^```(?:json|python)?\s*([\s\S]*?)\s*```$", content)
            if fence:
                content = fence.group(1).strip()

            try:
                return json.loads(content)
            except json.JSONDecodeError:
                return eval(content)  # fallback for Python-literal style output
        except Exception as e:
            raise ValueError(f"Failed to parse OpenAI response: {str(e)}")

    def _parse_anthropic_response(self, response) -> Dict[str, Any]:
        """
        Parse Anthropic response into standardized format

        Args:
            response: The Anthropic response

        Returns:
            Dict[str, Any]: The parsed response
        """

        try:
            content = response.content[0].text
            return eval(content)  # Safe since we validate the response
        except Exception as e:
            raise ValueError(f"Failed to parse Anthropic response: {str(e)}")

    def _parse_ollama_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse Ollama response into standardized format

        Args:
            response: The Ollama response

        Returns:
            Dict[str, Any]: The parsed response
        """

        try:
            content = response.get("response", "")
            return eval(content)  # Safe since we validate the response
        except Exception as e:
            raise ValueError(f"Failed to parse Ollama response: {str(e)}")
