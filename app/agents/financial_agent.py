"""Phase 4: Financial & Operational Viability Agent (Native LLM Tool Calling + JSON Schema Constraints)."""

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


def run_financial_agent(vendor: VendorSubmission, tier: CriticalityTier) -> PhaseAssessment:
    """Evaluates financial stability, credit rating, liquidity runway, BCP/DR RTO/RPO, and SLA guarantees.

    Args:
        vendor (VendorSubmission): Complete vendor submission packet.
        tier (CriticalityTier): Vendor criticality tier assigned in Phase 1.

    Returns:
        PhaseAssessment: Structured Phase 4 financial & operational resilience assessment.
    """
    start = time.perf_counter()
    effective_tier = tier or CriticalityTier.TIER_2_HIGH
    fin = vendor.financial

    with start_otel_span(
        "agent.financial",
        attributes={
            "agent.name": "Financial & Operational Viability Agent",
            "agent.phase": "financial",
            "vendor.id": vendor.vendor_id or "VND-NEW",
            "vendor.tier": effective_tier.value,
        },
    ) as span:
        default_tool_args = {
            "evaluate_financial_and_ops": {
                "vendor_name": vendor.name,
                "criticality_tier": effective_tier.value,
                "cash_runway_months": fin.cash_runway_months,
                "credit_rating_score": fin.credit_rating_score,
                "debt_to_equity_ratio": fin.debt_to_equity_ratio,
                "bcp_dr_tested_annually": fin.bcp_dr_tested_annually,
                "rto_hours": fin.rto_hours,
                "rpo_hours": fin.rpo_hours,
                "committed_sla_uptime_pct": fin.committed_sla_uptime_pct,
                "single_point_of_failure_risk": fin.single_point_of_failure_risk,
            }
        }

        tool_exec = llm_client.execute_agent_with_tools(
            agent_key="financial",
            system_prompt=(
                "You are the Financial Risk & Operational Resilience Agent for vendor onboarding. "
                "Invoke `evaluate_financial_and_ops` and summarize the vendor's credit/liquidity stability, "
                "disaster recovery RTO/RPO readiness, and SLA uptime commitments in 2-3 concise sentences."
            ),
            user_prompt=(
                f"Vendor: {vendor.name} | Tier: {effective_tier.value}\n"
                f"Credit Rating: {fin.credit_rating_score}/100 | Cash Runway: {fin.cash_runway_months}m\n"
                f"RTO: {fin.rto_hours}h | Committed SLA: {fin.committed_sla_uptime_pct}%"
            ),
            tool_names=["evaluate_financial_and_ops"],
            default_tool_args=default_tool_args,
            fallback_text="Pending financial synthesis.",
            vendor=vendor,
            tier=effective_tier,
            response_schema=AgentStructuredSynthesisSchema,
        )

        eval_data = tool_exec["tool_results"]["evaluate_financial_and_ops"]
        findings = tool_exec["findings"]
        traces = tool_exec["tool_traces"]
        risk_score = eval_data["risk_score"]

        if not findings:
            fallback_summary = (
                f"{vendor.name} demonstrates strong financial solvency and operational resilience "
                f"(Risk Score: {risk_score}/100). Credit score {fin.credit_rating_score}/100, "
                f"{fin.cash_runway_months}-month cash runway, {fin.committed_sla_uptime_pct}% uptime SLA, "
                f"and verified annual BCP/DR failover testing (RTO {fin.rto_hours}h / RPO {fin.rpo_hours}h)."
            )
        else:
            titles = "; ".join(f.title for f in findings)
            fallback_summary = (
                f"Financial & Operational review of {vendor.name} yielded a Risk Score of {risk_score}/100 "
                f"with {len(findings)} finding(s): {titles}. "
                f"Credit Rating={fin.credit_rating_score}/100, Runway={fin.cash_runway_months} mos, "
                f"RTO={fin.rto_hours}h, Committed SLA={fin.committed_sla_uptime_pct}%."
            )

        summary = (
            tool_exec["summary"]
            if tool_exec["summary"] != "Pending financial synthesis."
            else fallback_summary
        )
        mode_used = tool_exec["mode_used"]

        span.set_attribute("risk.financial_score", risk_score)
        span.set_attribute("risk.findings_count", len(findings))

        elapsed_ms = max(1, int((time.perf_counter() - start) * 1000))
        return PhaseAssessment(
            phase_id="financial",
            phase_name="Phase 4: Financial & Operational Viability",
            agent_name="Financial & Operational Viability Agent",
            agent_role="Credit Solvency, Business Continuity (BCP/DR) & SLA Analyst",
            status=PhaseStatus.COMPLETED,
            risk_score=risk_score,
            confidence=0.93,
            summary=summary,
            findings=findings,
            tool_calls=traces,
            metrics=eval_data["metrics"],
            llm_mode_used=mode_used,
            duration_ms=elapsed_ms,
        )
