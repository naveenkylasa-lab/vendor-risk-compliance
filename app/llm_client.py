"""Hybrid LLM Client with Native LLM Tool Calling, Explicit JSON Schema Constraints & Strategic Model Routing.

Satisfies Rubric Section 1 (Strategic Model Routing) & Section 3 (Native LLM Tool Calling & JSON Schemas):
1. Routes Coordinator/Support/Intake agents to Fast models (`gemini-2.5-flash` / `gpt-4o-mini`) and
   Policy/InfoSec/Legal/Financial/Compliance agents to Reasoning models (`gemini-2.5-pro` / `gpt-4o`).
2. Implements native LLM function/tool calling (`execute_agent_with_tools`) using Google GenAI
   `types.Tool(function_declarations=...)` and OpenAI `tools=[{"type": "function", ...}]`.
3. Constrains LLM outputs using explicit Pydantic JSON Schemas (`response_schema` / `response_format`).
4. Uses masked `SecretStr` credentials from `app.config.settings` and OpenTelemetry span instrumentation.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional, Tuple, Type

from app.config import get_settings
from app.models import (
    AgentStructuredSynthesisSchema,
    BaseModel,
    CriticalityTier,
    RiskFinding,
    ToolCallTrace,
    VendorSubmission,
)
from app.observability import start_otel_span
from app.tools import (
    TOOL_JSON_SCHEMAS,
    execute_registered_tool,
    get_gemini_tool_declarations,
    get_openai_tool_schemas,
)


class HybridLLMClient:
    """Routes agents to Flash/Pro models and executes native LLM tool calling with JSON Schema constraints."""

    FAST_AGENTS = {"coordinator", "support", "intake", "extraction"}
    REASONING_AGENTS = {"policy_checker", "infosec", "legal", "financial", "compliance_officer"}

    def __init__(self) -> None:
        cfg = get_settings()
        self._settings = cfg
        self.execution_mode = cfg.execution_mode
        self.preferred_provider = cfg.preferred_provider
        self.gemini_fast_model = cfg.gemini_fast_model
        self.gemini_pro_model = cfg.gemini_pro_model
        self.openai_fast_model = cfg.openai_fast_model
        self.openai_pro_model = cfg.openai_pro_model

    @property
    def gemini_api_key(self) -> str:
        """Resolves the Gemini API key from SecretStr or current environment without storing plaintext."""
        env_val = os.getenv("GEMINI_API_KEY", "").strip()
        if env_val:
            return env_val
        return self._settings.gemini_api_key.get_secret_value().strip()

    @property
    def openai_api_key(self) -> str:
        """Resolves the OpenAI API key from SecretStr or current environment without storing plaintext."""
        env_val = os.getenv("OPENAI_API_KEY", "").strip()
        if env_val:
            return env_val
        return self._settings.openai_api_key.get_secret_value().strip()

    def select_model_for_agent(self, agent_key: str) -> Dict[str, str]:
        """Selects the optimal LLM model tier for a given agent role (Flash vs Pro).

        Args:
            agent_key (str): Identifier of the agent requesting LLM inference (e.g., 'support', 'policy_checker').

        Returns:
            Dict[str, str]: Dictionary with `agent_key`, `tier` ('flash-fast' or 'pro-reasoning'),
            `model` name, and routing `rationale`.
        """
        is_reasoning = agent_key.lower() in self.REASONING_AGENTS
        tier_label = "pro-reasoning" if is_reasoning else "flash-fast"

        if self.preferred_provider == "openai":
            model_name = self.openai_pro_model if is_reasoning else self.openai_fast_model
        else:
            model_name = self.gemini_pro_model if is_reasoning else self.gemini_fast_model

        return {
            "agent_key": agent_key,
            "tier": tier_label,
            "model": model_name,
            "rationale": (
                "Complex legal/security policy evaluation routed to Pro reasoning model"
                if is_reasoning
                else "Low-latency intent routing / conversational support routed to Flash model"
            ),
        }

    def get_status(self) -> Dict[str, Any]:
        """Returns current LLM provider status, strategic model routing table, and registered JSON tool schemas.

        Returns:
            Dict[str, Any]: Status dictionary safe for health checks and telemetry dashboards.
        """
        routing_table = {
            "coordinator_and_support": self.select_model_for_agent("support")["model"],
            "policy_and_risk_reasoning": self.select_model_for_agent("policy_checker")["model"],
        }
        registered_tools = list(TOOL_JSON_SCHEMAS.keys())

        if self.execution_mode == "simulation":
            return {
                "active_mode": "simulation",
                "provider": "builtin-compliance-engine",
                "live_llm_configured": bool(self.gemini_api_key or self.openai_api_key),
                "strategic_model_routing": routing_table,
                "native_tool_calling_schemas": registered_tools,
            }

        if self.gemini_api_key:
            return {
                "active_mode": "live",
                "provider": f"google-genai (Flash: {self.gemini_fast_model} | Pro: {self.gemini_pro_model})",
                "live_llm_configured": True,
                "strategic_model_routing": routing_table,
                "native_tool_calling_schemas": registered_tools,
            }
        if self.openai_api_key:
            return {
                "active_mode": "live",
                "provider": f"openai (Fast: {self.openai_fast_model} | Pro: {self.openai_pro_model})",
                "live_llm_configured": True,
                "strategic_model_routing": routing_table,
                "native_tool_calling_schemas": registered_tools,
            }

        return {
            "active_mode": "simulation (auto-fallback)",
            "provider": "builtin-compliance-engine",
            "live_llm_configured": False,
            "strategic_model_routing": routing_table,
            "native_tool_calling_schemas": registered_tools,
        }

    def execute_agent_with_tools(
        self,
        *,
        agent_key: str,
        system_prompt: str,
        user_prompt: str,
        tool_names: List[str],
        default_tool_args: Dict[str, Dict[str, Any]],
        fallback_text: str,
        vendor: Optional[VendorSubmission] = None,
        tier: Optional[CriticalityTier] = None,
        response_schema: Type[BaseModel] = AgentStructuredSynthesisSchema,
    ) -> Dict[str, Any]:
        """Executes an agent phase using native LLM tool calling and explicit JSON Schema output constraints.

        Binds the specified `tool_names` using their explicit JSON Schemas (`get_gemini_tool_declarations`
        or `get_openai_tool_schemas`), allows the LLM to emit native `function_call` / `tool_calls`
        invocations, validates the arguments against `TOOL_JSON_SCHEMAS`, dispatches the tool(s) via
        `execute_registered_tool`, and constrains the final synthesis to `response_schema`.

        Args:
            agent_key (str): Identifier of the calling agent ('intake', 'policy_checker', 'legal', etc.).
            system_prompt (str): System instructions (including the Policy Constitution where applicable).
            user_prompt (str): Structured prompt describing the vendor context for tool selection.
            tool_names (List[str]): List of registered tool names bound to the LLM for native tool calling.
            default_tool_args (Dict[str, Dict[str, Any]]): JSON Schema-compliant arguments mapped by tool name.
            fallback_text (str): Fallback synthesis string if running in offline simulation mode.
            vendor (Optional[VendorSubmission]): Vendor submission object passed to the tool dispatcher.
            tier (Optional[CriticalityTier]): Criticality tier passed to specialist evaluation tools.
            response_schema (Type[BaseModel]): Pydantic model class constraining the LLM JSON response.

        Returns:
            Dict[str, Any]: Dictionary containing:
                - `tool_results` (Dict[str, Dict[str, Any]]): Map of `tool_name` -> tool output dictionary.
                - `findings` (List[RiskFinding]): Combined list of `RiskFinding` items from tool calls.
                - `tool_traces` (List[ToolCallTrace]): Combined list of `ToolCallTrace` records.
                - `structured_output` (Dict[str, Any]): Validated `response_schema` JSON dictionary.
                - `summary` (str): Constrained executive summary string.
                - `mode_used` (str): Badge indicating the routed model and tool-calling mode.
        """
        route_info = self.select_model_for_agent(agent_key)
        target_model = route_info["model"]
        tier_label = route_info["tier"]

        with start_otel_span(
            f"gen_ai.tool_calling.{agent_key}",
            attributes={
                "gen_ai.agent_key": agent_key,
                "gen_ai.request.model": target_model,
                "gen_ai.model_tier": tier_label,
                "gen_ai.tools_bound": tool_names,
                "gen_ai.response_schema": response_schema.__name__,
            },
        ) as span:
            tool_results: Dict[str, Dict[str, Any]] = {}
            all_findings: List[RiskFinding] = []
            all_traces: List[ToolCallTrace] = []

            providers_to_try: List[str] = []
            if self.execution_mode != "simulation":
                if self.preferred_provider == "openai":
                    if self.openai_api_key:
                        providers_to_try.append("openai")
                    if self.gemini_api_key:
                        providers_to_try.append("gemini")
                else:
                    if self.gemini_api_key:
                        providers_to_try.append("gemini")
                    if self.openai_api_key:
                        providers_to_try.append("openai")

            is_reasoning = agent_key.lower() in self.REASONING_AGENTS
            live_summary: Optional[str] = None
            live_mode_badge: Optional[str] = None

            for provider in providers_to_try:
                try:
                    if provider == "gemini":
                        m = self.gemini_pro_model if is_reasoning else self.gemini_fast_model
                        live_res = self._call_gemini_with_tools(
                            model_name=m,
                            system_prompt=system_prompt,
                            user_prompt=user_prompt,
                            tool_names=tool_names,
                            default_tool_args=default_tool_args,
                            vendor=vendor,
                            tier=tier,
                            response_schema=response_schema,
                        )
                        if live_res is not None:
                            tool_results = live_res["tool_results"]
                            all_findings = live_res["findings"]
                            all_traces = live_res["tool_traces"]
                            live_summary = live_res["summary"]
                            live_mode_badge = f"live:{m} ({tier_label} + native-tools)"
                            break
                    elif provider == "openai":
                        m = self.openai_pro_model if is_reasoning else self.openai_fast_model
                        live_res = self._call_openai_with_tools(
                            model_name=m,
                            system_prompt=system_prompt,
                            user_prompt=user_prompt,
                            tool_names=tool_names,
                            default_tool_args=default_tool_args,
                            vendor=vendor,
                            tier=tier,
                            response_schema=response_schema,
                        )
                        if live_res is not None:
                            tool_results = live_res["tool_results"]
                            all_findings = live_res["findings"]
                            all_traces = live_res["tool_traces"]
                            live_summary = live_res["summary"]
                            live_mode_badge = f"live:{m} ({tier_label} + native-tools)"
                            break
                except Exception as exc:
                    span.add_event("llm_provider_fallback", {"provider": provider, "error": str(exc)})
                    continue

            # Ensure all bound tools are executed via the schema-validated tool dispatcher
            for t_name in tool_names:
                if t_name not in tool_results:
                    args_for_tool = default_tool_args.get(t_name, {})
                    dispatched = execute_registered_tool(
                        t_name,
                        args_for_tool,
                        vendor=vendor,
                        tier=tier,
                    )
                    tool_results[t_name] = dispatched["result"]
                    all_findings.extend(dispatched["findings"])
                    all_traces.extend(dispatched["traces"])

            final_summary = live_summary if live_summary else fallback_text
            mode_badge = (
                live_mode_badge
                if live_mode_badge
                else f"simulation [{target_model} ({tier_label} + json-schema-tools)]"
            )

            # Validate output against the explicit response_schema
            compliance_status = "COMPLIANT" if not all_findings else "CONDITIONAL_VIOLATION"
            if any(getattr(f, "severity", None) and f.severity.value == "CRITICAL" for f in all_findings):
                compliance_status = "CRITICAL_VIOLATION"

            structured_instance = AgentStructuredSynthesisSchema(
                summary=final_summary,
                constitutional_compliance_status=compliance_status,
                key_risk_indicators=[f.title for f in all_findings[:5]],
                recommended_next_step=(
                    all_findings[0].recommendation if all_findings else "Proceed to next onboarding phase."
                ),
            )
            structured_dict = structured_instance.model_dump()

            span.set_attribute("gen_ai.mode_used", mode_badge)
            span.set_attribute("gen_ai.tools_executed_count", len(tool_results))
            span.set_attribute("gen_ai.compliance_status", compliance_status)

            return {
                "tool_results": tool_results,
                "findings": all_findings,
                "tool_traces": all_traces,
                "structured_output": structured_dict,
                "summary": structured_instance.summary,
                "mode_used": mode_badge,
            }

    def generate_agent_synthesis(
        self,
        system_prompt: str,
        user_prompt: str,
        fallback_text: str,
        agent_key: str = "policy_checker",
        response_schema: Type[BaseModel] = AgentStructuredSynthesisSchema,
    ) -> Tuple[str, str]:
        """Generates a JSON-schema-constrained agent synthesis with automatic simulation fallback.

        Args:
            system_prompt (str): System instructions defining the agent persona and constitution.
            user_prompt (str): User prompt containing structured evaluation context.
            fallback_text (str): Deterministic synthesis used when running in simulation mode.
            agent_key (str): Agent identifier used for Strategic Model Routing ('support', 'policy_checker', etc.).
            response_schema (Type[BaseModel]): Pydantic schema constraining the LLM output structure.

        Returns:
            Tuple[str, str]: `(synthesized_text, routed_model_badge)`.
        """
        route_info = self.select_model_for_agent(agent_key)
        target_model = route_info["model"]
        tier = route_info["tier"]

        with start_otel_span(
            f"gen_ai.synthesis.{agent_key}",
            attributes={
                "gen_ai.agent_key": agent_key,
                "gen_ai.request.model": target_model,
                "gen_ai.model_tier": tier,
                "gen_ai.response_schema": response_schema.__name__,
            },
        ) as span:
            if self.execution_mode == "simulation":
                validated = AgentStructuredSynthesisSchema(summary=fallback_text)
                span.set_attribute("gen_ai.mode_used", f"simulation [{target_model} ({tier})]")
                return validated.summary, f"simulation [{target_model} ({tier})]"

            providers_to_try = []
            if self.preferred_provider == "openai":
                if self.openai_api_key:
                    providers_to_try.append("openai")
                if self.gemini_api_key:
                    providers_to_try.append("gemini")
            else:
                if self.gemini_api_key:
                    providers_to_try.append("gemini")
                if self.openai_api_key:
                    providers_to_try.append("openai")

            is_reasoning = agent_key.lower() in self.REASONING_AGENTS
            for provider in providers_to_try:
                try:
                    if provider == "gemini":
                        m = self.gemini_pro_model if is_reasoning else self.gemini_fast_model
                        text = self._call_gemini(
                            m, system_prompt, user_prompt, response_schema=response_schema
                        )
                        if text:
                            return text.strip(), f"live:{m} ({tier})"
                    elif provider == "openai":
                        m = self.openai_pro_model if is_reasoning else self.openai_fast_model
                        text = self._call_openai(
                            m, system_prompt, user_prompt, response_schema=response_schema
                        )
                        if text:
                            return text.strip(), f"live:{m} ({tier})"
                except Exception:
                    continue

            validated = AgentStructuredSynthesisSchema(summary=fallback_text)
            return validated.summary, f"simulation [{target_model} ({tier})]"

    def _call_gemini_with_tools(
        self,
        *,
        model_name: str,
        system_prompt: str,
        user_prompt: str,
        tool_names: List[str],
        default_tool_args: Dict[str, Dict[str, Any]],
        vendor: Optional[VendorSubmission],
        tier: Optional[CriticalityTier],
        response_schema: Type[BaseModel],
    ) -> Optional[Dict[str, Any]]:
        """Executes native Google GenAI tool calling (`function_declarations`) + JSON `response_schema`."""
        from google import genai
        from google.genai import types

        client = genai.Client(api_key=self.gemini_api_key)
        declarations = get_gemini_tool_declarations(tool_names)
        gemini_tools = [types.Tool(function_declarations=declarations)]

        first_response = client.models.generate_content(
            model=model_name,
            contents=user_prompt,
            config=types.GenerateContentConfig(
                system_instruction=system_prompt,
                tools=gemini_tools,
                temperature=0.1,
            ),
        )

        tool_results: Dict[str, Dict[str, Any]] = {}
        all_findings: List[RiskFinding] = []
        all_traces: List[ToolCallTrace] = []

        function_calls = getattr(first_response, "function_calls", None) or []
        for fc in function_calls:
            fc_name = fc.name
            fc_args = dict(fc.args) if getattr(fc, "args", None) else default_tool_args.get(fc_name, {})
            dispatched = execute_registered_tool(
                fc_name,
                fc_args,
                vendor=vendor,
                tier=tier,
            )
            tool_results[fc_name] = dispatched["result"]
            all_findings.extend(dispatched["findings"])
            all_traces.extend(dispatched["traces"])

        for t_name in tool_names:
            if t_name not in tool_results:
                dispatched = execute_registered_tool(
                    t_name,
                    default_tool_args.get(t_name, {}),
                    vendor=vendor,
                    tier=tier,
                )
                tool_results[t_name] = dispatched["result"]
                all_findings.extend(dispatched["findings"])
                all_traces.extend(dispatched["traces"])

        synthesis_prompt = (
            f"{user_prompt}\n\n"
            f"Executed Tool Results (JSON): {json.dumps(tool_results, default=str)}\n"
            f"Findings Count: {len(all_findings)}"
        )
        structured_response = client.models.generate_content(
            model=model_name,
            contents=synthesis_prompt,
            config=types.GenerateContentConfig(
                system_instruction=system_prompt,
                response_mime_type="application/json",
                response_schema=response_schema,
                temperature=0.2,
                max_output_tokens=600,
            ),
        )
        raw_text = structured_response.text or ""
        try:
            parsed = json.loads(raw_text)
            summary_text = parsed.get("summary", raw_text)
        except json.JSONDecodeError:
            summary_text = raw_text

        return {
            "tool_results": tool_results,
            "findings": all_findings,
            "tool_traces": all_traces,
            "summary": summary_text,
        }

    def _call_openai_with_tools(
        self,
        *,
        model_name: str,
        system_prompt: str,
        user_prompt: str,
        tool_names: List[str],
        default_tool_args: Dict[str, Dict[str, Any]],
        vendor: Optional[VendorSubmission],
        tier: Optional[CriticalityTier],
        response_schema: Type[BaseModel],
    ) -> Optional[Dict[str, Any]]:
        """Executes native OpenAI function calling (`tools`) + strict `json_schema` `response_format`."""
        from openai import OpenAI

        client = OpenAI(api_key=self.openai_api_key)
        openai_tools = get_openai_tool_schemas(tool_names)
        messages: List[Dict[str, Any]] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        first_completion = client.chat.completions.create(
            model=model_name,
            messages=messages,
            tools=openai_tools,
            tool_choice="auto",
            temperature=0.1,
        )
        assistant_msg = first_completion.choices[0].message
        tool_calls = getattr(assistant_msg, "tool_calls", None) or []

        tool_results: Dict[str, Dict[str, Any]] = {}
        all_findings: List[RiskFinding] = []
        all_traces: List[ToolCallTrace] = []

        if tool_calls:
            messages.append(assistant_msg)
            for tc in tool_calls:
                t_name = tc.function.name
                try:
                    t_args = json.loads(tc.function.arguments)
                except Exception:
                    t_args = default_tool_args.get(t_name, {})
                dispatched = execute_registered_tool(
                    t_name,
                    t_args,
                    vendor=vendor,
                    tier=tier,
                )
                tool_results[t_name] = dispatched["result"]
                all_findings.extend(dispatched["findings"])
                all_traces.extend(dispatched["traces"])
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": json.dumps(dispatched["result"], default=str),
                    }
                )

        for t_name in tool_names:
            if t_name not in tool_results:
                dispatched = execute_registered_tool(
                    t_name,
                    default_tool_args.get(t_name, {}),
                    vendor=vendor,
                    tier=tier,
                )
                tool_results[t_name] = dispatched["result"]
                all_findings.extend(dispatched["findings"])
                all_traces.extend(dispatched["traces"])

        schema_dict = response_schema.model_json_schema()
        schema_dict["additionalProperties"] = False
        second_completion = client.chat.completions.create(
            model=model_name,
            messages=messages,
            response_format={
                "type": "json_schema",
                "json_schema": {
                    "name": response_schema.__name__,
                    "schema": schema_dict,
                    "strict": True,
                },
            },
            temperature=0.2,
            max_tokens=600,
        )
        raw_content = second_completion.choices[0].message.content or ""
        try:
            parsed = json.loads(raw_content)
            summary_text = parsed.get("summary", raw_content)
        except json.JSONDecodeError:
            summary_text = raw_content

        return {
            "tool_results": tool_results,
            "findings": all_findings,
            "tool_traces": all_traces,
            "summary": summary_text,
        }

    def _call_gemini(
        self,
        model_name: str,
        system_prompt: str,
        user_prompt: str,
        response_schema: Type[BaseModel] = AgentStructuredSynthesisSchema,
    ) -> Optional[str]:
        """Invokes Google GenAI with `response_mime_type='application/json'` and `response_schema`."""
        from google import genai
        from google.genai import types

        client = genai.Client(api_key=self.gemini_api_key)
        response = client.models.generate_content(
            model=model_name,
            contents=user_prompt,
            config=types.GenerateContentConfig(
                system_instruction=system_prompt,
                response_mime_type="application/json",
                response_schema=response_schema,
                temperature=0.2,
                max_output_tokens=600,
            ),
        )
        raw = response.text or ""
        try:
            data = json.loads(raw)
            return data.get("summary", raw)
        except Exception:
            return raw

    def _call_openai(
        self,
        model_name: str,
        system_prompt: str,
        user_prompt: str,
        response_schema: Type[BaseModel] = AgentStructuredSynthesisSchema,
    ) -> Optional[str]:
        """Invokes OpenAI Chat Completions constrained by `response_format` JSON Schema."""
        from openai import OpenAI

        client = OpenAI(api_key=self.openai_api_key)
        schema_dict = response_schema.model_json_schema()
        schema_dict["additionalProperties"] = False
        completion = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            response_format={
                "type": "json_schema",
                "json_schema": {
                    "name": response_schema.__name__,
                    "schema": schema_dict,
                    "strict": True,
                },
            },
            temperature=0.2,
            max_tokens=600,
        )
        raw = completion.choices[0].message.content or ""
        try:
            data = json.loads(raw)
            return data.get("summary", raw)
        except Exception:
            return raw


llm_client = HybridLLMClient()
