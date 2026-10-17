"""Phase 3: Legal, Privacy & Regulatory Agent (Native LLM Tool Calling + JSON Schema Constraints)."""

from __future__ import annotations

import time

from app.llm_client import llm_client
from app.models import (
    AgentStructuredSynthesisSchema,
    CriticalityTier,
    PhaseAssessment,
    PhaseStatus,
    VendorSubmission,
)
from app.observability import start_otel_span


def run_legal_agent(vendor: VendorSubmission, tier: CriticalityTier) -> PhaseAssessment:
    """Screens OFAC/sanctions watchlists, adverse media, GDPR/CCPA DPAs, SCCs, and MSA liability via LLM tool calling.

    Args:
        vendor (VendorSubmission): Complete vendor submission packet.
        tier (CriticalityTier): Vendor criticality tier assigned in Phase 1.

    Returns:
        PhaseAssessment: Structured Phase 3 legal & regulatory risk assessment.
    """
    start = time.perf_counter()
    effective_tier = tier or CriticalityTier.TIER_2_HIGH
    leg = vendor.legal

    with start_otel_span(
        "agent.legal",
        attributes={
            "agent.name": "Legal, Privacy & Regulatory Agent",
            "agent.phase": "legal",
            "vendor.id": vendor.vendor_id or "VND-NEW",
            "vendor.country": vendor.country,
        },
    ) as span:
        default_tool_args = {
            "evaluate_legal_and_sanctions": {
                "vendor_name": vendor.name,
                "country": vendor.country,
                "criticality_tier": effective_tier.value,
                "data_sensitivity": vendor.data_sensitivity.value,
                "sanctions_watchlist_hit": leg.sanctions_watchlist_hit,
                "dpa_signed": leg.dpa_signed,
                "cross_border_transfers": leg.cross_border_transfers,
                "scc_mechanism_in_place": leg.scc_mechanism_in_place,
                "msa_accepted": leg.msa_accepted,
                "indemnification_clause_accepted": leg.indemnification_clause_accepted,
                "liability_cap_multiplier": leg.liability_cap_multiplier,
            }
        }

        tool_exec = llm_client.execute_agent_with_tools(
            agent_key="legal",
            system_prompt=(
                "You are the Senior Legal, Privacy & Regulatory Counsel Agent for enterprise vendor onboarding. "
                "Invoke `evaluate_legal_and_sanctions` and summarize OFAC/sanctions screening results, "
                "GDPR/CCPA DPA and cross-border SCC posture, and contractual liability status in 2-3 sentences."
            ),
            user_prompt=(
                f"Vendor: {vendor.name} ({vendor.country}) | Tier: {effective_tier.value}\n"
                f"Sanctions Hit: {leg.sanctions_watchlist_hit} | DPA Signed: {leg.dpa_signed}\n"
                f"SCCs In Place: {leg.scc_mechanism_in_place} | Liability Cap: {leg.liability_cap_multiplier}x"
            ),
            tool_names=["evaluate_legal_and_sanctions"],
            default_tool_args=default_tool_args,
            fallback_text="Pending legal synthesis.",
            vendor=vendor,
            tier=effective_tier,
            response_schema=AgentStructuredSynthesisSchema,
        )

        eval_data = tool_exec["tool_results"]["evaluate_legal_and_sanctions"]
        findings = tool_exec["findings"]
        traces = tool_exec["tool_traces"]
        risk_score = eval_data["risk_score"]

        if not findings:
            fallback_summary = (
                f"Legal, privacy, and sanctions review for {vendor.name} ({vendor.country}) cleared with "
                f"low risk ({risk_score}/100). Zero OFAC/sanctions hits or adverse media flags; MSA and DPA "
                f"executed with {leg.liability_cap_multiplier}x ACV liability cap and compliant transfer mechanisms."
            )
        else:
            titles = "; ".join(f.title for f in findings)
            fallback_summary = (
                f"Legal & Regulatory screening of {vendor.name} ({vendor.country}) produced a Risk Score of "
                f"{risk_score}/100 across {len(findings)} finding(s): {titles}. "
                f"Sanctions Hit={leg.sanctions_watchlist_hit}, DPA Signed={leg.dpa_signed}, "
                f"SCCs In Place={leg.scc_mechanism_in_place}, Liability Cap={leg.liability_cap_multiplier}x ACV."
            )

        summary = (
            tool_exec["summary"]
            if tool_exec["summary"] != "Pending legal synthesis."
            else fallback_summary
        )
        mode_used = tool_exec["mode_used"]

        span.set_attribute("risk.legal_score", risk_score)
        span.set_attribute("risk.findings_count", len(findings))

        elapsed_ms = max(1, int((time.perf_counter() - start) * 1000))
        return PhaseAssessment(
            phase_id="legal",
            phase_name="Phase 3: Legal, Privacy & Sanctions Screening",
            agent_name="Legal, Privacy & Regulatory Agent",
            agent_role="MSA/DPA Counsel, GDPR/CCPA Privacy & OFAC Sanctions Specialist",
            status=PhaseStatus.COMPLETED,
            risk_score=risk_score,
            confidence=0.95,
            summary=summary,
            findings=findings,
            tool_calls=traces,
            metrics=eval_data["metrics"],
            llm_mode_used=mode_used,
            duration_ms=elapsed_ms,
        )
