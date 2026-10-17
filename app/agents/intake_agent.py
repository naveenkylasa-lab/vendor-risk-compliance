"""Phase 1: Document Extraction & Intake Triage Agent (Sequential Step 1: Extraction)."""

from __future__ import annotations

import time
from typing import List

from app.llm_client import llm_client
from app.models import (
    IntakePhaseOutput,
    PhaseStatus,
    RiskFinding,
    RiskSeverity,
    VendorSubmission,
)
from app.tools import classify_criticality_tier, extract_vendor_security_certifications


def run_intake_agent(vendor: VendorSubmission) -> IntakePhaseOutput:
    """Runs `extract_vendor_security_certifications` (with guided error handling) and `classify_criticality_tier`."""
    start = time.perf_counter()

    # Step 1A: Specific Document Certification Extraction Tool with Guided Error Handling
    extraction_data, extraction_trace = extract_vendor_security_certifications(vendor)

    # Step 1B: Criticality Tier & Document Completeness Check
    triage_data, triage_trace = classify_criticality_tier(vendor)

    tier = triage_data["criticality_tier"]
    inherent_score = triage_data["inherent_risk_score"]
    missing_docs: List[str] = triage_data["missing_documents"]
    fast_track: bool = triage_data["fast_track_eligible"]
    guided_errors: List[str] = extraction_data["guided_errors"]

    findings: List[RiskFinding] = []
    if guided_errors:
        for idx, err_msg in enumerate(guided_errors, start=1):
            findings.append(
                RiskFinding(
                    finding_id=f"EXT-0{idx}",
                    phase="intake",
                    agent_name="Intake & Extraction Agent",
                    title="Guided Document Extraction Error",
                    description=err_msg,
                    severity=RiskSeverity.HIGH,
                    category="Document Extraction & Guided Error Handling",
                    recommendation=err_msg,
                )
            )

    if missing_docs:
        findings.append(
            RiskFinding(
                finding_id="INT-01",
                phase="intake",
                agent_name="Intake & Extraction Agent",
                title=f"Incomplete Compliance Evidence Packet ({len(missing_docs)} Missing Document(s))",
                description="Missing mandatory onboarding artifacts for tier: " + ", ".join(missing_docs),
                severity=RiskSeverity.HIGH if len(missing_docs) >= 2 else RiskSeverity.MEDIUM,
                category="Onboarding Documentation",
                recommendation="Request missing compliance artifacts from vendor primary contact before final sign-off.",
            )
        )

    required_phases = ["infosec", "legal", "financial", "compliance_officer"]

    fallback_summary = (
        f"[Sequential Pattern: Extraction -> Policy Check] Extracted certifications: "
        f"{extraction_data['extracted_certifications'] or ['None']} "
        f"({len(guided_errors)} guided document error(s)). "
        f"Profiled {vendor.name} ({vendor.category}) as {tier.value} with an Inherent Risk Score of "
        f"{inherent_score}/100 based on {vendor.data_sensitivity.value} data exposure "
        f"({vendor.estimated_records_exposed:,} records) and ${vendor.annual_contract_value_usd:,.0f} ACV."
    )

    summary, mode_used = llm_client.generate_agent_synthesis(
        system_prompt=(
            "You are the Lead Vendor Intake & Extraction Agent (routed to a fast Flash model). "
            "Summarize the extracted security certifications, any guided document extraction errors, "
            "and the vendor's inherent criticality tier in 2-3 concise sentences."
        ),
        user_prompt=(
            f"Vendor: {vendor.name} ({vendor.category})\n"
            f"Extracted Certifications: {extraction_data['extracted_certifications']}\n"
            f"Guided Extraction Errors: {guided_errors}\n"
            f"Assigned Tier: {tier.value} (Inherent Risk: {inherent_score}/100)\n"
            f"Missing Documents: {missing_docs}"
        ),
        fallback_text=fallback_summary,
        agent_key="intake",
    )

    elapsed_ms = max(1, int((time.perf_counter() - start) * 1000))
    return IntakePhaseOutput(
        phase_id="intake",
        phase_name="Phase 1: Document Extraction & Criticality Triage",
        agent_name="Intake & Extraction Agent",
        agent_role="Certification Extraction (`extract_vendor_security_certifications`) & Risk Tiering [Flash Model]",
        status=PhaseStatus.COMPLETED,
        risk_score=inherent_score,
        confidence=0.96,
        summary=summary,
        findings=findings,
        tool_calls=[extraction_trace, triage_trace],
        metrics={
            "criticality_tier": tier.value,
            "inherent_risk_score": inherent_score,
            "extracted_certifications": extraction_data["extracted_certifications"],
            "guided_extraction_errors": guided_errors,
            "submitted_docs_count": len(vendor.submitted_documents),
            "missing_docs_count": len(missing_docs),
        },
        llm_mode_used=mode_used,
        duration_ms=elapsed_ms,
        criticality_tier=tier,
        inherent_risk_score=inherent_score,
        required_documents=triage_data["required_documents"],
        missing_documents=missing_docs,
        fast_track_eligible=fast_track,
        required_phases=required_phases,
    )
