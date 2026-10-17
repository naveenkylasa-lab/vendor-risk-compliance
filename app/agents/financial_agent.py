"""Phase 4: Financial & Operational Viability Agent."""

from __future__ import annotations

import time

from app.llm_client import llm_client
from app.models import (
    CriticalityTier,
    PhaseAssessment,
    PhaseStatus,
    VendorSubmission,
)
from app.tools import evaluate_financial_and_ops


def run_financial_agent(vendor: VendorSubmission, tier: CriticalityTier) -> PhaseAssessment:
    """Evaluates financial stability, credit rating, liquidity runway, BCP/DR RTO/RPO, and SLA guarantees."""
    start = time.perf_counter()
    eval_data, findings, traces = evaluate_financial_and_ops(vendor, tier)
    risk_score = eval_data["risk_score"]
    fin = vendor.financial

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

    summary, mode_used = llm_client.generate_agent_synthesis(
        system_prompt=(
            "You are the Financial Risk & Operational Resilience Agent for vendor onboarding. "
            "Summarize the vendor's credit/liquidity stability, disaster recovery RTO/RPO readiness, "
            "and SLA uptime commitments in 2-3 concise sentences."
        ),
        user_prompt=(
            f"Vendor: {vendor.name} | Tier: {tier.value}\n"
            f"Financial & Ops Risk Score: {risk_score}/100\n"
            f"Findings ({len(findings)}): {[f.title for f in findings]}\n"
            f"Metrics: {eval_data['metrics']}"
        ),
        fallback_text=fallback_summary,
    )

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
