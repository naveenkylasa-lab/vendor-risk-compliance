"""Phase 2: InfoSec & Constitutional Policy Checking Agent (Sequential Step 2: Policy Check [Pro Model])."""

from __future__ import annotations

import time

from app.llm_client import llm_client
from app.models import (
    CriticalityTier,
    PhaseAssessment,
    PhaseStatus,
    VendorSubmission,
)
from app.policy_constitution import COMPANY_SECURITY_CONSTITUTION
from app.tools import evaluate_infosec_controls


def run_infosec_agent(vendor: VendorSubmission, tier: CriticalityTier) -> PhaseAssessment:
    """Evaluates SOC 2 / ISO 27001 certifications, IAM/encryption, CVEs, and AI governance under the strict Policy Constitution."""
    start = time.perf_counter()
    eval_data, findings, traces = evaluate_infosec_controls(vendor, tier)
    risk_score = eval_data["risk_score"]
    sec = vendor.security

    if not findings:
        fallback_summary = (
            f"[Constitutional Policy Check: PASS] Technical security posture for {vendor.name} satisfies "
            f"Articles I & II of the Enterprise Security Constitution for {tier.value} "
            f"(Residual Cyber Risk: {risk_score}/100). Verified active security certifications "
            f"(SOC 2 Type II={sec.soc2_type2_certified}, ISO 27001={sec.iso27001_certified}), "
            f"AES-256/TLS encryption, MFA/SSO enforcement, and zero open Critical/High CVEs."
        )
    else:
        titles = "; ".join(f.title for f in findings)
        fallback_summary = (
            f"[Constitutional Policy Check: VIOLATION DETECTED] InfoSec evaluation of {vendor.name} "
            f"under Articles I-III resulted in a Cyber Risk Score of {risk_score}/100 "
            f"with {len(findings)} finding(s): {titles}. "
            f"Key controls checked: SOC 2 Type II ({sec.soc2_type2_certified}), ISO 27001 ({sec.iso27001_certified}), "
            f"Open Critical CVEs ({sec.open_critical_cves}), Open High CVEs ({sec.open_high_cves})."
        )

    summary, mode_used = llm_client.generate_agent_synthesis(
        system_prompt=(
            "You are the Principal InfoSec & Policy Checking Agent (routed to a Pro reasoning model). "
            "Evaluate the vendor strictly against the Enterprise Security Constitution below.\n\n"
            + COMPANY_SECURITY_CONSTITUTION
        ),
        user_prompt=(
            f"Vendor: {vendor.name} | Tier: {tier.value}\n"
            f"Cyber Risk Score: {risk_score}/100\n"
            f"Findings ({len(findings)}): {[f.title for f in findings]}\n"
            f"Metrics: {eval_data['metrics']}"
        ),
        fallback_text=fallback_summary,
        agent_key="policy_checker",
    )

    elapsed_ms = max(1, int((time.perf_counter() - start) * 1000))
    return PhaseAssessment(
        phase_id="infosec",
        phase_name="Phase 2: InfoSec & Constitutional Policy Check",
        agent_name="InfoSec & Policy Checking Agent",
        agent_role="Constitutional Security Policy Evaluator (Articles I-III) [Pro Reasoning Model]",
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
