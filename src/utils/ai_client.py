import asyncio
import json
import logging
import os
import re
from typing import Any, Dict, List, Optional

import anthropic
import httpx
import openai
from dotenv import load_dotenv

load_dotenv()


class AIAnalysisError(RuntimeError):
    """Raised when no AI backend produced a usable analysis."""


class AIClient:
    def __init__(self, disabled: bool = False) -> None:
        """
        Initialize AI client wrapper with lazy provider instantiation.
        """
        self.disabled = disabled
        self._openai_client = None
        self._anthropic_client = None
        self.openai_default_model = os.getenv("OPENAI_MODEL", "o1-mini-2024-09-12")

    @property
    def openai_client(self) -> Any:
        if self.disabled:
            raise RuntimeError(
                "AI backend calls are disabled in editor or rule-only mode. "
                "No outbound model requests are permitted."
            )
        if self._openai_client is None:
            openai_api_key = os.getenv("OPENAI_API_KEY")
            if not openai_api_key:
                raise RuntimeError(
                    "OPENAI_API_KEY is not set. Standalone API mode requires an API key, "
                    "or run in editor mode without keys."
                )
            openai_base_url = os.getenv("OPENAI_BASE_URL")
            client_kwargs: Dict[str, Any] = {"api_key": openai_api_key}
            if openai_base_url:
                client_kwargs["base_url"] = openai_base_url
            self._openai_client = openai.Client(**client_kwargs)
        return self._openai_client

    @property
    def anthropic_client(self) -> Any:
        if self.disabled:
            return None
        if self._anthropic_client is None:
            anthropic_api_key = os.getenv("ANTHROPIC_API_KEY")
            if anthropic_api_key:
                self._anthropic_client = anthropic.Anthropic(api_key=anthropic_api_key)
        return self._anthropic_client

    async def analyze_security(self, prompt: str, model: Optional[str] = None) -> Dict[str, Any]:
        """
        Analyze code for security vulnerabilities using AI models

        Args:
            prompt: The prompt to analyze
            model: The model to use for analysis (OpenAI)

        Returns:
            Dict[str, Any]: The analysis result
        """

        # NOTE: Ollama currently is not able to perform security analysis
        # response = await self._analyze_with_ollama(prompt)

        selected_model = model or self.openai_default_model
        errors = []

        try:
            response = await self._analyze_with_openai(self.openai_client, prompt, selected_model)
            if self._validate_response(response):
                return response
            errors.append(f"{selected_model}: response failed schema validation")
        except Exception as e:
            errors.append(f"{selected_model}: {e}")
            logging.warning(f"OpenAI-compatible tier failed: {e}")

        # Fallback to Anthropic if configured
        if self.anthropic_client is not None:
            try:
                response = await self._analyze_with_anthropic(prompt)
                if self._validate_response(response):
                    return response
                errors.append("anthropic: response failed schema validation")
            except Exception as e:
                errors.append(f"anthropic: {e}")
                logging.warning(f"Anthropic tier failed: {e}")

        # Raising rather than returning an empty result is deliberate. In a
        # two-tier system, "the model found nothing" and "the model call
        # blew up" must not look identical - swallowing the error here also
        # made the caller's retry loop unreachable.
        raise AIAnalysisError("; ".join(errors) or "no AI backend produced a valid analysis")

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
        kwargs: Dict[str, Any] = {"model": model, "messages": messages}

        # Deterministic output matters here: baselines, suppressions and
        # run-to-run comparison all break if the same file yields different
        # findings each scan. Reasoning models reject the parameter outright,
        # so it is only sent to models that accept it.
        if not self._is_reasoning_model(model):
            kwargs["temperature"] = 0

        # openai.Client is synchronous. Awaiting nothing and calling it
        # straight from a coroutine blocked the event loop for the whole
        # request, which made asyncio.gather over these calls run them one
        # after another and froze the web server for the length of every
        # scan. Off-thread, the concurrency limit finally means something.
        try:
            response = await asyncio.to_thread(
                lambda: client.chat.completions.create(**kwargs)
            )
        except openai.BadRequestError:
            # Some compatible providers reject temperature on models we did
            # not recognise as reasoning models; retry without it.
            kwargs.pop("temperature", None)
            response = await asyncio.to_thread(
                lambda: client.chat.completions.create(**kwargs)
            )

        return self._parse_openai_response(response)

    @staticmethod
    def _is_reasoning_model(model: str) -> bool:
        """
        Whether a model rejects sampling parameters such as temperature.

        Args:
            model: The model identifier

        Returns:
            bool: True for known reasoning-model families
        """

        name = (model or "").lower()
        return name.startswith(("o1", "o3", "o4")) or "-thinking" in name

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
        Parse an OpenAI-compatible response into standardized format

        Args:
            response: The chat completion response

        Returns:
            Dict[str, Any]: The parsed response
        """

        choice = response.choices[0]
        content = choice.message.content

        finish_reason = getattr(choice, "finish_reason", None)
        if finish_reason == "length":
            logging.warning(
                "Model output was truncated by the token limit; "
                "salvaging whatever complete findings are present."
            )

        return self._parse_content(content, "OpenAI-compatible")

    def _parse_anthropic_response(self, response) -> Dict[str, Any]:
        """
        Parse Anthropic response into standardized format

        Args:
            response: The Anthropic response

        Returns:
            Dict[str, Any]: The parsed response
        """

        return self._parse_content(response.content[0].text, "Anthropic")

    def _parse_ollama_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse Ollama response into standardized format

        Args:
            response: The Ollama response

        Returns:
            Dict[str, Any]: The parsed response
        """

        return self._parse_content(response.get("response", ""), "Ollama")

    def _parse_content(self, content: Optional[str], origin: str) -> Dict[str, Any]:
        """
        Turn raw model text into a analysis dictionary.

        Models routinely wrap JSON in prose or code fences, emit Python
        literals instead of JSON, leave trailing commas, or get cut off
        mid-array by the token limit. Each of those is recovered from in
        turn. eval() is deliberately not used: executing model output inside
        a security scanner would be the very class of defect this tool exists
        to report.

        Args:
            content: Raw text returned by the model
            origin: Backend name, used in error messages

        Returns:
            Dict[str, Any]: A dict containing a "vulnerabilities" list

        Raises:
            ValueError: When nothing usable can be recovered
        """

        if not content or not content.strip():
            raise ValueError(f"Failed to parse {origin} response: empty content")

        text = self._strip_fences(content.strip())

        for candidate in self._candidates(text):
            try:
                parsed = json.loads(candidate)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                parsed.setdefault("vulnerabilities", [])
                return parsed
            if isinstance(parsed, list):
                return {"vulnerabilities": parsed}

        # Last resort: pull out individual finding objects. This is what
        # rescues a response that hit the token ceiling mid-array.
        salvaged = self._salvage_objects(text)
        if salvaged:
            logging.warning(
                f"{origin} response was malformed; salvaged {len(salvaged)} finding(s)"
            )
            return {"vulnerabilities": salvaged}

        preview = text[:200].replace("\n", " ")
        raise ValueError(f"Failed to parse {origin} response: no JSON found near '{preview}'")

    @staticmethod
    def _strip_fences(text: str) -> str:
        """
        Remove markdown code fences that wrap the payload.

        Args:
            text: Raw model text

        Returns:
            str: Text with any surrounding fence removed
        """

        fence = re.match(r"^```(?:json|python)?\s*([\s\S]*?)\s*```\s*$", text)
        if fence:
            return fence.group(1).strip()
        # Unbalanced opening fence, common when output is truncated.
        if text.startswith("```"):
            return re.sub(r"^```(?:json|python)?\s*", "", text).strip()
        return text

    @classmethod
    def _candidates(cls, text: str) -> List[str]:
        """
        Produce progressively more repaired versions of the payload.

        Args:
            text: Fence-stripped model text

        Returns:
            List[str]: Strings to attempt json.loads on, best first
        """

        candidates = [text]

        outermost = cls._extract_outermost(text)
        if outermost and outermost != text:
            candidates.append(outermost)

        for base in list(candidates):
            repaired = cls._repair(base)
            if repaired != base:
                candidates.append(repaired)

        return candidates

    @staticmethod
    def _extract_outermost(text: str) -> Optional[str]:
        """
        Extract the outermost balanced JSON object, ignoring surrounding prose.

        Args:
            text: Model text that may contain commentary around the JSON

        Returns:
            Optional[str]: The object substring, or None
        """

        start = text.find("{")
        if start == -1:
            return None

        depth = 0
        in_string = False
        escaped = False

        for i in range(start, len(text)):
            char = text[i]
            if escaped:
                escaped = False
                continue
            if char == "\\":
                escaped = True
                continue
            if char == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return text[start:i + 1]

        return None

    @staticmethod
    def _repair(text: str) -> str:
        """
        Apply conservative fixes for the ways models break JSON.

        Args:
            text: A JSON-ish string

        Returns:
            str: The repaired string
        """

        repaired = text
        # Python literals leaking into JSON output.
        repaired = re.sub(r"\bTrue\b", "true", repaired)
        repaired = re.sub(r"\bFalse\b", "false", repaired)
        repaired = re.sub(r"\bNone\b", "null", repaired)
        # Trailing commas before a closing bracket or brace.
        repaired = re.sub(r",\s*([}\]])", r"\1", repaired)
        return repaired

    @classmethod
    def _salvage_objects(cls, text: str) -> List[Dict[str, Any]]:
        """
        Recover complete finding objects from a malformed or truncated payload.

        Args:
            text: Model text containing at least one finding object

        Returns:
            List[Dict[str, Any]]: Every object that parsed and looks like a finding
        """

        findings: List[Dict[str, Any]] = []
        depth = 0
        in_string = False
        escaped = False
        start = None

        for i, char in enumerate(text):
            if escaped:
                escaped = False
                continue
            if char == "\\":
                escaped = True
                continue
            if char == '"':
                in_string = not in_string
                continue
            if in_string:
                continue

            if char == "{":
                if depth == 0:
                    start = i
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0 and start is not None:
                    chunk = text[start:i + 1]
                    for variant in (chunk, cls._repair(chunk)):
                        try:
                            obj = json.loads(variant)
                        except json.JSONDecodeError:
                            continue
                        # Only keep objects that actually look like findings.
                        if isinstance(obj, dict) and "type" in obj and "severity" in obj:
                            findings.append(obj)
                        break
                    start = None
                elif depth < 0:
                    depth = 0

        return findings
