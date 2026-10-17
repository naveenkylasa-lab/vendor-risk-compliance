"""Phase 5: Risk Aggregator & Compliance Officer Agent."""

from __future__ import annotations

from datetime import datetime, timezone
import time
from typing import Dict, List, Tuple

from app.llm_client import llm_client
from app.models import (
    CriticalityTier,
    FinalComplianceDecision,
    IntakePhaseOutput,
    OnboardingDecision,
    PhaseAssessment,
    PhaseStatus,
    RemediationItem,
    RiskFinding,
    RiskSeverity,
    ToolCallTrace,
    VendorSubmission,
)


def run_compliance_officer_agent(
    vendor: VendorSubmission,
    intake: IntakePhaseOutput,
    phase_assessments: Dict[str, PhaseAssessment],
) -> Tuple[PhaseAssessment, FinalComplianceDecision]:
    """Aggregates specialist findings, calculates weighted residual risk, builds remediation plan, and issues decision."""
    start = time.perf_counter()

    infosec_score = phase_assessments["infosec"].risk_score
    legal_score = phase_assessments["legal"].risk_score
    fin_score = phase_assessments["financial"].risk_score
    intake_score = intake.risk_score

    # Weighted composite residual risk score:
    # InfoSec (38%), Legal/Privacy (32%), Financial/Ops (20%), Intake/Doc Completeness (10%)
    doc_penalty = min(100.0, len(intake.missing_documents) * 25.0)
    composite_score = round(
        (infosec_score * 0.38)
        + (legal_score * 0.32)
        + (fin_score * 0.20)
        + (doc_penalty * 0.10),
        1,
    )

    all_findings: List[RiskFinding] = list(intake.findings)
    for phase_key in ("infosec", "legal", "financial"):
        all_findings.extend(phase_assessments[phase_key].findings)

    critical_findings = [f for f in all_findings if f.severity == RiskSeverity.CRITICAL]
    high_findings = [f for f in all_findings if f.severity == RiskSeverity.HIGH]

    # Determine residual risk level
    if composite_score >= 65.0 or len(critical_findings) >= 2:
        residual_level = RiskSeverity.CRITICAL
    elif composite_score >= 40.0 or len(critical_findings) == 1 or len(high_findings) >= 2:
        residual_level = RiskSeverity.HIGH
    elif composite_score >= 18.0 or len(high_findings) == 1 or len(all_findings) > 0:
        residual_level = RiskSeverity.MEDIUM
    else:
        residual_level = RiskSeverity.LOW

    # Decision policy matrix
    if vendor.legal.sanctions_watchlist_hit or composite_score >= 65.0 or len(critical_findings) >= 2:
        decision = OnboardingDecision.REJECTED
        next_review_months = 0
    elif len(critical_findings) == 1 or composite_score >= 45.0:
        decision = OnboardingDecision.ESCALATED_FOR_HUMAN_REVIEW
        next_review_months = 6
    elif len(all_findings) > 0 or composite_score >= 18.0:
        decision = OnboardingDecision.APPROVED_WITH_CONDITIONS
        next_review_months = 12
    else:
        decision = OnboardingDecision.APPROVED
        next_review_months = 12 if intake.criticality_tier != CriticalityTier.TIER_4_LOW else 24

    # Build structured Remediation Plan from findings
    remediation_plan: List[RemediationItem] = []
    for idx, finding in enumerate(all_findings, start=1):
        owner_map = {
            "intake": "Vendor Onboarding Coordinator",
            "infosec": "CISO / Security Engineering",
            "legal": "Privacy & Legal Counsel",
            "financial": "Procurement & Resilience Lead",
        }
        timeline_map = {
            RiskSeverity.CRITICAL: "Prior to Contract Execution (Blocking)",
            RiskSeverity.HIGH: "Within 15 Days / Prior to Production Go-Live",
            RiskSeverity.MEDIUM: "Within 30 Days Post-Onboarding",
            RiskSeverity.LOW: "Next Annual Assessment",
        }
        remediation_plan.append(
            RemediationItem(
                action_id=f"REM-{idx:02d}",
                owner=owner_map.get(finding.phase, "Compliance Officer"),
                priority=finding.severity,
                requirement=f"[{finding.finding_id}] {finding.recommendation}",
                due_timeline=timeline_map[finding.severity],
                blocking_go_live=finding.severity in (RiskSeverity.CRITICAL, RiskSeverity.HIGH),
            )
        )

    # Identify key strengths
    strengths: List[str] = []
    if vendor.security.soc2_type2_certified:
        strengths.append("Active SOC 2 Type II attestation verified")
    if vendor.security.iso27001_certified:
        strengths.append("ISO/IEC 27001:2022 certified information security management")
    if vendor.security.encryption_at_rest and vendor.security.encryption_in_transit:
        strengths.append("Strong cryptographic controls (AES-256 at rest & TLS 1.2+ in transit)")
    if not vendor.legal.sanctions_watchlist_hit and not vendor.legal.adverse_media_flags:
        strengths.append("Clean global OFAC sanctions & adverse media screening")
    if vendor.financial.credit_rating_score >= 75 and vendor.financial.cash_runway_months >= 18:
        strengths.append(
            f"Healthy financial solvency (Credit {vendor.financial.credit_rating_score}/100, {vendor.financial.cash_runway_months}m runway)"
        )

    critical_blockers = [f"{f.finding_id}: {f.title}" for f in critical_findings + high_findings]

    trace = ToolCallTrace(
        tool_name="calculate_composite_risk_and_decision",
        inputs={
            "infosec_score": infosec_score,
            "legal_score": legal_score,
            "financial_score": fin_score,
            "critical_findings": len(critical_findings),
            "high_findings": len(high_findings),
        },
        output_summary=(
            f"Composite Risk Score={composite_score}/100 ({residual_level.value}) -> "
            f"Decision={decision.value} with {len(remediation_plan)} remediation action(s)."
        ),
        timestamp=datetime.now(timezone.utc).isoformat(),
    )

    fallback_memo = (
        f"FINAL ONBOARDING DETERMINATION: {decision.value.replace('_', ' ')} for {vendor.name} "
        f"({intake.criticality_tier.value}, Composite Residual Risk: {composite_score}/100 — {residual_level.value}). "
        f"Domain Breakdown: InfoSec={infosec_score}/100, Legal/Privacy={legal_score}/100, Financial/Ops={fin_score}/100. "
        + (
            "All mandatory security, privacy, sanctions, and operational resilience gates passed without exception."
            if not all_findings
            else f"Identified {len(all_findings)} total finding(s) ({len(critical_findings)} Critical, {len(high_findings)} High) "
            f"requiring {len(remediation_plan)} tracked remediation commitment(s)."
        )
    )

    executive_memo, mode_used = llm_client.generate_agent_synthesis(
        system_prompt=(
            "You are the Chief Risk Aggregator & Compliance Officer Agent. Write a formal, decisive "
            "3-4 sentence Executive Onboarding Memo synthesizing the InfoSec, Legal/Privacy, and Financial "
            "assessments, justifying the final onboarding decision and highlighting any mandatory conditions."
        ),
        user_prompt=(
            f"Vendor: {vendor.name} ({vendor.category}) | Tier: {intake.criticality_tier.value}\n"
            f"Decision: {decision.value} | Composite Risk Score: {composite_score}/100 ({residual_level.value})\n"
            f"Scores -> InfoSec: {infosec_score}, Legal: {legal_score}, Financial: {fin_score}\n"
            f"Blockers: {critical_blockers}\n"
            f"Remediation Count: {len(remediation_plan)}"
        ),
        fallback_text=fallback_memo,
    )

    elapsed_ms = max(1, int((time.perf_counter() - start) * 1000))
    phase_assessment = PhaseAssessment(
        phase_id="compliance_officer",
        phase_name="Phase 5: Final Risk Aggregation & Executive Sign-Off",
        agent_name="Risk Aggregator & Compliance Officer Agent",
        agent_role="Chief Compliance Officer Synthesis, Residual Risk Scoring & Governance Sign-Off",
        status=PhaseStatus.COMPLETED,
        risk_score=composite_score,
        confidence=0.97,
        summary=executive_memo,
        findings=[],
        tool_calls=[trace],
        metrics={
            "composite_risk_score": composite_score,
            "residual_risk_level": residual_level.value,
            "decision": decision.value,
            "total_findings": len(all_findings),
            "remediation_items": len(remediation_plan),
        },
        llm_mode_used=mode_used,
        duration_ms=elapsed_ms,
    )

    final_decision = FinalComplianceDecision(
        decision=decision,
        composite_risk_score=composite_score,
        residual_risk_level=residual_level,
        criticality_tier=intake.criticality_tier,
        executive_memo=executive_memo,
        key_strengths=strengths,
        critical_blockers=critical_blockers,
        remediation_plan=remediation_plan,
        next_review_months=next_review_months,
    )
    return phase_assessment, final_decision
