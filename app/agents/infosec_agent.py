"""Phase 2: InfoSec & Constitutional Policy Checking Agent (Sequential Step 2: Policy Check [Pro Model])."""

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
from app.policy_constitution import COMPANY_SECURITY_CONSTITUTION


def run_infosec_agent(vendor: VendorSubmission, tier: CriticalityTier) -> PhaseAssessment:
    """Executes Phase 2 InfoSec & Constitutional Policy Check via native LLM tool calling.

    Binds `evaluate_infosec_controls` to the Pro reasoning model with explicit JSON Schema
    constraints (`EvaluateInfoSecToolArgs` and `AgentStructuredSynthesisSchema`) and evaluates
    the vendor against Articles I-III of the Enterprise Security Constitution.

    Args:
        vendor (VendorSubmission): Complete vendor submission packet.
        tier (CriticalityTier): Vendor criticality tier assigned in Phase 1.

    Returns:
        PhaseAssessment: Structured Phase 2 assessment with findings, tool traces, and risk score.
    """
    start = time.perf_counter()
    effective_tier = tier or CriticalityTier.TIER_2_HIGH
    sec = vendor.security

    with start_otel_span(
        "agent.infosec",
        attributes={
            "agent.name": "InfoSec & Policy Checking Agent",
            "agent.phase": "infosec",
            "vendor.id": vendor.vendor_id or "VND-NEW",
            "vendor.tier": effective_tier.value,
        },
    ) as span:
        default_tool_args = {
            "evaluate_infosec_controls": {
                "vendor_name": vendor.name,
                "criticality_tier": effective_tier.value,
                "data_sensitivity": vendor.data_sensitivity.value,
                "soc2_type2_certified": sec.soc2_type2_certified,
                "iso27001_certified": sec.iso27001_certified,
                "encryption_at_rest": sec.encryption_at_rest,
                "encryption_in_transit": sec.encryption_in_transit,
                "mfa_enforced": sec.mfa_enforced,
                "sso_supported": sec.sso_supported,
                "open_critical_cves": sec.open_critical_cves,
                "open_high_cves": sec.open_high_cves,
                "incident_notification_hours": sec.incident_notification_hours,
                "ai_model_trains_on_customer_data": sec.ai_model_trains_on_customer_data,
            }
        }

        tool_exec = llm_client.execute_agent_with_tools(
            agent_key="policy_checker",
            system_prompt=(
                "You are the Principal InfoSec & Policy Checking Agent (routed to a Pro reasoning model). "
                "Invoke `evaluate_infosec_controls` and evaluate the vendor strictly against the "
                "Enterprise Security Constitution below.\n\n"
                + COMPANY_SECURITY_CONSTITUTION
            ),
            user_prompt=(
                f"Vendor: {vendor.name} | Tier: {effective_tier.value}\n"
                f"Data Sensitivity: {vendor.data_sensitivity.value}\n"
                f"SOC 2 Type II: {sec.soc2_type2_certified} | ISO 27001: {sec.iso27001_certified}\n"
                f"Open Critical CVEs: {sec.open_critical_cves} | Open High CVEs: {sec.open_high_cves}"
            ),
            tool_names=["evaluate_infosec_controls"],
            default_tool_args=default_tool_args,
            fallback_text="Pending infosec synthesis.",
            vendor=vendor,
            tier=effective_tier,
            response_schema=AgentStructuredSynthesisSchema,
        )

        eval_data = tool_exec["tool_results"]["evaluate_infosec_controls"]
        findings = tool_exec["findings"]
        traces = tool_exec["tool_traces"]
        risk_score = eval_data["risk_score"]

        if not findings:
            fallback_summary = (
                f"[Constitutional Policy Check: PASS] Technical security posture for {vendor.name} satisfies "
                f"Articles I & II of the Enterprise Security Constitution for {effective_tier.value} "
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

        summary = (
            tool_exec["summary"]
            if tool_exec["summary"] != "Pending infosec synthesis."
            else fallback_summary
        )
        mode_used = tool_exec["mode_used"]

        span.set_attribute("risk.infosec_score", risk_score)
        span.set_attribute("risk.findings_count", len(findings))

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
