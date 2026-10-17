"""Phase 3: Legal, Privacy & Regulatory Agent."""

from __future__ import annotations

import time

from app.llm_client import llm_client
from app.models import (
    CriticalityTier,
    PhaseAssessment,
    PhaseStatus,
    VendorSubmission,
)
from app.tools import evaluate_legal_and_sanctions


def run_legal_agent(vendor: VendorSubmission, tier: CriticalityTier) -> PhaseAssessment:
    """Screens OFAC/sanctions watchlists, adverse media, GDPR/CCPA DPAs, cross-border SCCs, and MSA liability."""
    start = time.perf_counter()
    eval_data, findings, traces = evaluate_legal_and_sanctions(vendor, tier)
    risk_score = eval_data["risk_score"]
    leg = vendor.legal

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

    summary, mode_used = llm_client.generate_agent_synthesis(
        system_prompt=(
            "You are the Senior Legal, Privacy & Regulatory Counsel Agent for enterprise vendor onboarding. "
            "Summarize OFAC/sanctions screening results, GDPR/CCPA DPA and cross-border SCC posture, and "
            "contractual liability/indemnification status in 2-3 authoritative sentences."
        ),
        user_prompt=(
            f"Vendor: {vendor.name} ({vendor.country}) | Tier: {tier.value}\n"
            f"Legal Risk Score: {risk_score}/100\n"
            f"Findings ({len(findings)}): {[f.title for f in findings]}\n"
            f"Metrics: {eval_data['metrics']}"
        ),
        fallback_text=fallback_summary,
    )

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
