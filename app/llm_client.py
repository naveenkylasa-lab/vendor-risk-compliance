"""Hybrid LLM Client with Strategic Model Routing (Flash vs Pro) and simulation fallback."""

from __future__ import annotations

import os
from typing import Optional


class HybridLLMClient:
    """Routes Coordinator/Support agents to Fast models (Flash) and Policy agents to Reasoning models (Pro)."""

    FAST_AGENTS = {"coordinator", "support", "intake", "extraction"}
    REASONING_AGENTS = {"policy_checker", "infosec", "legal", "financial", "compliance_officer"}

    def __init__(self) -> None:
        self.execution_mode = os.getenv("EXECUTION_MODE", "auto").lower()
        self.preferred_provider = os.getenv("LLM_PROVIDER", "gemini").lower()
        self.gemini_api_key = os.getenv("GEMINI_API_KEY", "").strip()
        self.gemini_fast_model = os.getenv("GEMINI_FAST_MODEL", "gemini-2.5-flash")
        self.gemini_pro_model = os.getenv("GEMINI_PRO_MODEL", "gemini-2.5-pro")
        self.openai_api_key = os.getenv("OPENAI_API_KEY", "").strip()
        self.openai_fast_model = os.getenv("OPENAI_FAST_MODEL", "gpt-4o-mini")
        self.openai_pro_model = os.getenv("OPENAI_PRO_MODEL", "gpt-4o")

    def select_model_for_agent(self, agent_key: str) -> dict:
        """Strategic Model Routing: Flash for Coordinator/Support, Pro for Policy/Risk evaluation."""
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

    def get_status(self) -> dict:
        routing_table = {
            "coordinator_and_support": self.select_model_for_agent("support")["model"],
            "policy_and_risk_reasoning": self.select_model_for_agent("policy_checker")["model"],
        }
        if self.execution_mode == "simulation":
            return {
                "active_mode": "simulation",
                "provider": "builtin-compliance-engine",
                "live_llm_configured": bool(self.gemini_api_key or self.openai_api_key),
                "strategic_model_routing": routing_table,
            }

        if self.gemini_api_key:
            return {
                "active_mode": "live",
                "provider": f"google-genai (Flash: {self.gemini_fast_model} | Pro: {self.gemini_pro_model})",
                "live_llm_configured": True,
                "strategic_model_routing": routing_table,
            }
        if self.openai_api_key:
            return {
                "active_mode": "live",
                "provider": f"openai (Fast: {self.openai_fast_model} | Pro: {self.openai_pro_model})",
                "live_llm_configured": True,
                "strategic_model_routing": routing_table,
            }

        return {
            "active_mode": "simulation (auto-fallback)",
            "provider": "builtin-compliance-engine",
            "live_llm_configured": False,
            "strategic_model_routing": routing_table,
        }

    def generate_agent_synthesis(
        self,
        system_prompt: str,
        user_prompt: str,
        fallback_text: str,
        agent_key: str = "policy_checker",
    ) -> tuple[str, str]:
        """Returns (synthesized_text, routed_model_badge)."""
        route_info = self.select_model_for_agent(agent_key)
        target_model = route_info["model"]
        tier = route_info["tier"]

        if self.execution_mode == "simulation":
            return fallback_text, f"simulation [{target_model} ({tier})]"

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
                    text = self._call_gemini(m, system_prompt, user_prompt)
                    if text:
                        return text.strip(), f"live:{m} ({tier})"
                elif provider == "openai":
                    m = self.openai_pro_model if is_reasoning else self.openai_fast_model
                    text = self._call_openai(m, system_prompt, user_prompt)
                    if text:
                        return text.strip(), f"live:{m} ({tier})"
            except Exception:
                continue

        return fallback_text, f"simulation [{target_model} ({tier})]"

    def _call_gemini(self, model_name: str, system_prompt: str, user_prompt: str) -> Optional[str]:
        from google import genai
        from google.genai import types

        client = genai.Client(api_key=self.gemini_api_key)
        response = client.models.generate_content(
            model=model_name,
            contents=user_prompt,
            config=types.GenerateContentConfig(
                system_instruction=system_prompt,
                temperature=0.2,
                max_output_tokens=600,
            ),
        )
        return response.text

    def _call_openai(self, model_name: str, system_prompt: str, user_prompt: str) -> Optional[str]:
        from openai import OpenAI

        client = OpenAI(api_key=self.openai_api_key)
        completion = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.2,
            max_tokens=600,
        )
        return completion.choices[0].message.content


llm_client = HybridLLMClient()
