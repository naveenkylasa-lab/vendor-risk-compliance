"""Phase 1: Document Extraction & Intake Triage Agent (Sequential Step 1: Extraction via LLM Tool Calling)."""

from __future__ import annotations

import time
from typing import List

from app.llm_client import llm_client
from app.models import (
    AgentStructuredSynthesisSchema,
    IntakePhaseOutput,
    PhaseStatus,
    RiskFinding,
    RiskSeverity,
    VendorSubmission,
)
from app.observability import start_otel_span


def run_intake_agent(vendor: VendorSubmission) -> IntakePhaseOutput:
    """Executes Phase 1 Intake & Extraction using native LLM tool calling and JSON Schema constraints.

    Binds `extract_vendor_security_certifications` and `classify_criticality_tier` tools to the
    Flash model via `llm_client.execute_agent_with_tools`, validates tool arguments and outputs
    against explicit JSON Schemas, and traces execution with OpenTelemetry child spans.

    Args:
        vendor (VendorSubmission): The complete vendor onboarding submission packet.

    Returns:
        IntakePhaseOutput: Validated Phase 1 assessment including extracted certifications,
        guided document errors, criticality tier, inherent risk score, and tool traces.
    """
    start = time.perf_counter()

    with start_otel_span(
        "agent.intake",
        attributes={
            "agent.name": "Intake & Extraction Agent",
            "agent.phase": "intake",
            "vendor.id": vendor.vendor_id or "VND-NEW",
            "vendor.name": vendor.name,
        },
    ) as span:
        default_tool_args = {
            "extract_vendor_security_certifications": {
                "vendor_name": vendor.name,
                "submitted_documents": list(vendor.submitted_documents),
            },
            "classify_criticality_tier": {
                "data_sensitivity": vendor.data_sensitivity.value,
                "requires_network_integration": vendor.requires_network_integration,
                "estimated_records_exposed": vendor.estimated_records_exposed,
                "annual_contract_value_usd": vendor.annual_contract_value_usd,
                "submitted_documents": list(vendor.submitted_documents),
            },
        }

        # Execute native LLM tool calling for both intake tools
        tool_exec = llm_client.execute_agent_with_tools(
            agent_key="intake",
            system_prompt=(
                "You are the Lead Vendor Intake & Extraction Agent (routed to a fast Flash model). "
                "Call `extract_vendor_security_certifications` and `classify_criticality_tier` to "
                "extract verified compliance certifications, detect guided document errors, and "
                "assign the vendor's inherent criticality tier."
            ),
            user_prompt=(
                f"Vendor: {vendor.name} ({vendor.category})\n"
                f"Data Sensitivity: {vendor.data_sensitivity.value}\n"
                f"Network Integration: {vendor.requires_network_integration}\n"
                f"Records Exposed: {vendor.estimated_records_exposed}\n"
                f"ACV USD: {vendor.annual_contract_value_usd}\n"
                f"Submitted Documents: {vendor.submitted_documents}"
            ),
            tool_names=[
                "extract_vendor_security_certifications",
                "classify_criticality_tier",
            ],
            default_tool_args=default_tool_args,
            fallback_text="Pending intake synthesis.",
            vendor=vendor,
            response_schema=AgentStructuredSynthesisSchema,
        )

        extraction_data = tool_exec["tool_results"]["extract_vendor_security_certifications"]
        triage_data = tool_exec["tool_results"]["classify_criticality_tier"]
        traces = tool_exec["tool_traces"]

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

        summary = (
            tool_exec["summary"]
            if tool_exec["summary"] != "Pending intake synthesis."
            else fallback_summary
        )
        mode_used = tool_exec["mode_used"]

        span.set_attribute("risk.inherent_score", inherent_score)
        span.set_attribute("vendor.criticality_tier", tier.value)

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
            tool_calls=traces,
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
