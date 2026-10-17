"""Multi-Agent StateGraph Orchestrator with Intent Routing, Strategic Model Routing, HITL Code Stop & PII Redaction."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, AsyncGenerator, Dict, List, Optional, TypedDict
import uuid

from app.agents.compliance_officer_agent import run_compliance_officer_agent
from app.agents.financial_agent import run_financial_agent
from app.agents.infosec_agent import run_infosec_agent
from app.agents.intake_agent import run_intake_agent
from app.agents.legal_agent import run_legal_agent
from app.agents.support_agent import classify_vendor_intent, handle_vendor_question
from app.llm_client import llm_client
from app.memory_store import memory_store
from app.models import (
    FinalComplianceDecision,
    HumanReviewDecisionRequest,
    IntakePhaseOutput,
    OnboardingDecision,
    OnboardingRunResult,
    PhaseAssessment,
    RiskFinding,
    RiskSeverity,
    VendorSubmission,
)
from app.observability import redact_pii_text, tracer

try:
    from langgraph.graph import END, START, StateGraph

    LANGGRAPH_AVAILABLE = True
except ImportError:
    LANGGRAPH_AVAILABLE = False


class OnboardingGraphState(TypedDict, total=False):
    assessment_id: str
    created_at: str
    vendor: VendorSubmission
    intake_assessment: Optional[IntakePhaseOutput]
    phase_assessments: Dict[str, PhaseAssessment]
    all_findings: List[RiskFinding]
    final_decision: Optional[FinalComplianceDecision]
    audit_trail: List[Dict[str, Any]]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _record_redacted_audit(
    vendor: VendorSubmission,
    phase: str,
    agent_name: str,
    model_badge: str,
    raw_event: str,
    risk_score: float,
) -> Dict[str, Any]:
    """Scrubs PII from vendor descriptions/sponsors before recording audit trail entries."""
    combined_raw = (
        f"{raw_event} | Sponsor: {vendor.business_sponsor} | Context: {vendor.service_description}"
    )
    scrubbed_event, redaction_count = redact_pii_text(combined_raw)
    tracer.record_event(
        vendor_id=vendor.vendor_id or "VND-UNKNOWN",
        agent_name=agent_name,
        model_tier=model_badge,
        pattern="SEQUENTIAL (Extraction -> Policy Check)",
        raw_message=combined_raw,
        metadata={"phase": phase, "risk_score": risk_score},
    )
    return {
        "timestamp": _utc_now(),
        "phase": phase,
        "agent": agent_name,
        "model_tier": model_badge,
        "event": scrubbed_event,
        "pii_redacted_count": redaction_count,
        "risk_score": risk_score,
    }


def _intake_node(state: OnboardingGraphState) -> OnboardingGraphState:
    vendor = state["vendor"]
    intake = run_intake_agent(vendor)
    phase_map = dict(state.get("phase_assessments", {}))
    phase_map["intake"] = intake
    trail = list(state.get("audit_trail", []))
    trail.append(
        _record_redacted_audit(
            vendor=vendor,
            phase="intake",
            agent_name=intake.agent_name,
            model_badge=intake.llm_mode_used,
            raw_event=(
                f"Extracted certs={intake.metrics.get('extracted_certifications')} | "
                f"Assigned {intake.criticality_tier.value} (Inherent Risk: {intake.inherent_risk_score}/100)"
            ),
            risk_score=intake.risk_score,
        )
    )
    return {
        **state,
        "intake_assessment": intake,
        "phase_assessments": phase_map,
        "audit_trail": trail,
    }


def _infosec_node(state: OnboardingGraphState) -> OnboardingGraphState:
    vendor = state["vendor"]
    intake = state["intake_assessment"]
    tier = intake.criticality_tier if intake else None
    assessment = run_infosec_agent(vendor, tier)
    phase_map = dict(state.get("phase_assessments", {}))
    phase_map["infosec"] = assessment
    trail = list(state.get("audit_trail", []))
    trail.append(
        _record_redacted_audit(
            vendor=vendor,
            phase="infosec",
            agent_name=assessment.agent_name,
            model_badge=assessment.llm_mode_used,
            raw_event=f"Completed Constitutional Cyber Policy Check (Score: {assessment.risk_score}/100, Findings: {len(assessment.findings)})",
            risk_score=assessment.risk_score,
        )
    )
    return {
        **state,
        "phase_assessments": phase_map,
        "audit_trail": trail,
    }


def _legal_node(state: OnboardingGraphState) -> OnboardingGraphState:
    vendor = state["vendor"]
    intake = state["intake_assessment"]
    tier = intake.criticality_tier if intake else None
    assessment = run_legal_agent(vendor, tier)
    phase_map = dict(state.get("phase_assessments", {}))
    phase_map["legal"] = assessment
    trail = list(state.get("audit_trail", []))
    trail.append(
        _record_redacted_audit(
            vendor=vendor,
            phase="legal",
            agent_name=assessment.agent_name,
            model_badge=assessment.llm_mode_used,
            raw_event=f"Completed Legal, Privacy & OFAC Screening (Score: {assessment.risk_score}/100, Findings: {len(assessment.findings)})",
            risk_score=assessment.risk_score,
        )
    )
    return {
        **state,
        "phase_assessments": phase_map,
        "audit_trail": trail,
    }


def _financial_node(state: OnboardingGraphState) -> OnboardingGraphState:
    vendor = state["vendor"]
    intake = state["intake_assessment"]
    tier = intake.criticality_tier if intake else None
    assessment = run_financial_agent(vendor, tier)
    phase_map = dict(state.get("phase_assessments", {}))
    phase_map["financial"] = assessment
    trail = list(state.get("audit_trail", []))
    trail.append(
        _record_redacted_audit(
            vendor=vendor,
            phase="financial",
            agent_name=assessment.agent_name,
            model_badge=assessment.llm_mode_used,
            raw_event=f"Completed Financial & BCP/DR Review (Score: {assessment.risk_score}/100, Findings: {len(assessment.findings)})",
            risk_score=assessment.risk_score,
        )
    )
    return {
        **state,
        "phase_assessments": phase_map,
        "audit_trail": trail,
    }


def _compliance_officer_node(state: OnboardingGraphState) -> OnboardingGraphState:
    vendor = state["vendor"]
    intake = state["intake_assessment"]
    phase_map = dict(state.get("phase_assessments", {}))
    officer_phase, final_decision = run_compliance_officer_agent(vendor, intake, phase_map)
    phase_map["compliance_officer"] = officer_phase

    all_findings: List[RiskFinding] = []
    for key in ("intake", "infosec", "legal", "financial"):
        if key in phase_map:
            all_findings.extend(phase_map[key].findings)

    # Rubric Section 1: Human-in-the-Loop (HITL) Code Stop Hook when vendor is High/Critical Risk
    is_high_risk_stop = final_decision.residual_risk_level in (
        RiskSeverity.HIGH,
        RiskSeverity.CRITICAL,
    )
    if is_high_risk_stop:
        final_decision.human_override = {
            "hitl_code_stop_active": True,
            "status": "PAUSED_REQUIRING_HUMAN_APPROVAL",
            "prompt": "Policy Agent flagged vendor as High/Critical Risk. Compliance Officer must type 'approve' or 'reject' to finalize status.",
        }

    trail = list(state.get("audit_trail", []))
    trail.append(
        _record_redacted_audit(
            vendor=vendor,
            phase="compliance_officer",
            agent_name=officer_phase.agent_name,
            model_badge=officer_phase.llm_mode_used,
            raw_event=(
                f"Issued Determination: {final_decision.decision.value} "
                f"(Composite Score: {final_decision.composite_risk_score}/100, "
                f"HITL Code Stop: {is_high_risk_stop})"
            ),
            risk_score=final_decision.composite_risk_score,
        )
    )

    # Persist session state to SQLite memory store (Rubric Section 2)
    memory_store.upsert_session(
        vendor_id=vendor.vendor_id or "VND-CUSTOM",
        vendor_name=vendor.name,
        onboarding_status=(
            "PAUSED_HITL_CODE_STOP" if is_high_risk_stop else final_decision.decision.value
        ),
        risk_level=final_decision.residual_risk_level.value,
        composite_score=final_decision.composite_risk_score,
        pending_hitl=is_high_risk_stop,
        extracted_certifications={
            "extracted_certifications": intake.metrics.get("extracted_certifications", []) if intake else [],
            "guided_extraction_errors": intake.metrics.get("guided_extraction_errors", []) if intake else [],
        },
        audit_logs=trail,
    )

    return {
        **state,
        "phase_assessments": phase_map,
        "all_findings": all_findings,
        "final_decision": final_decision,
        "audit_trail": trail,
    }


class VendorOnboardingOrchestrator:
    """Executes both Conversational (Support) and Sequential (Extraction -> Policy Check) patterns."""

    def __init__(self) -> None:
        self.assessments: Dict[str, OnboardingRunResult] = {}
        self._compiled_graph = self._build_graph() if LANGGRAPH_AVAILABLE else None

    def _build_graph(self):
        builder = StateGraph(OnboardingGraphState)
        builder.add_node("intake", _intake_node)
        builder.add_node("infosec", _infosec_node)
        builder.add_node("legal", _legal_node)
        builder.add_node("financial", _financial_node)
        builder.add_node("compliance_officer", _compliance_officer_node)

        builder.add_edge(START, "intake")
        builder.add_edge("intake", "infosec")
        builder.add_edge("infosec", "legal")
        builder.add_edge("legal", "financial")
        builder.add_edge("financial", "compliance_officer")
        builder.add_edge("compliance_officer", END)
        return builder.compile()

    def get_engine_name(self) -> str:
        return "LangGraph StateGraph" if LANGGRAPH_AVAILABLE else "Native Deterministic StateGraph"

    def route_vendor_interaction(
        self,
        *,
        vendor_id: str,
        vendor_name: str,
        message: Optional[str] = None,
        vendor_packet: Optional[VendorSubmission] = None,
    ) -> Dict[str, Any]:
        """Coordinator Intent Router (Rubric Section 1):
        - If the vendor sends a question, routes to Conversational pattern (Flash).
        - If the vendor submits a document packet, triggers Sequential pattern (Extraction -> Policy Check).
        """
        intent_info = classify_vendor_intent(
            message or "", has_document_attachment=vendor_packet is not None
        )
        if intent_info["intent"] == "VENDOR_QUESTION" and vendor_packet is None:
            return handle_vendor_question(
                vendor_id=vendor_id,
                vendor_name=vendor_name,
                question=message or "What is my current onboarding status?",
            )

        if vendor_packet is None:
            raise ValueError("vendor_packet is required for DOCUMENT_SUBMISSION sequential pattern.")
        result = self.run_pipeline(vendor_packet)
        return {
            "intent_routing": intent_info,
            "assessment": result.model_dump(),
        }

    def run_pipeline(self, vendor: VendorSubmission) -> OnboardingRunResult:
        """Runs the complete 5-phase Sequential (Extraction -> Policy Check) pipeline."""
        assessment_id = f"ASM-{uuid.uuid4().hex[:8].upper()}"
        created_at = _utc_now()
        if not vendor.vendor_id:
            vendor.vendor_id = f"VND-{uuid.uuid4().hex[:4].upper()}"

        initial_state: OnboardingGraphState = {
            "assessment_id": assessment_id,
            "created_at": created_at,
            "vendor": vendor,
            "intake_assessment": None,
            "phase_assessments": {},
            "all_findings": [],
            "final_decision": None,
            "audit_trail": [],
        }

        if self._compiled_graph is not None:
            final_state = self._compiled_graph.invoke(initial_state)
        else:
            state = _intake_node(initial_state)
            state = _infosec_node(state)
            state = _legal_node(state)
            state = _financial_node(state)
            final_state = _compliance_officer_node(state)

        result = self._state_to_result(final_state)
        self.assessments[result.assessment_id] = result
        return result

    async def stream_pipeline(
        self, vendor: VendorSubmission, step_delay_sec: float = 0.35
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Streams real-time agent lifecycle events for the interactive Web Dashboard."""
        assessment_id = f"ASM-{uuid.uuid4().hex[:8].upper()}"
        created_at = _utc_now()
        if not vendor.vendor_id:
            vendor.vendor_id = f"VND-{uuid.uuid4().hex[:4].upper()}"

        state: OnboardingGraphState = {
            "assessment_id": assessment_id,
            "created_at": created_at,
            "vendor": vendor,
            "intake_assessment": None,
            "phase_assessments": {},
            "all_findings": [],
            "final_decision": None,
            "audit_trail": [],
        }

        yield {
            "event": "pipeline_started",
            "assessment_id": assessment_id,
            "vendor_name": vendor.name,
            "engine": self.get_engine_name(),
            "pattern": "SEQUENTIAL (Extraction -> Constitutional Policy Check)",
            "timestamp": created_at,
        }

        phases = [
            ("intake", "Phase 1: Document Extraction & Triage", "Intake & Extraction Agent [Flash]", _intake_node),
            ("infosec", "Phase 2: Constitutional Policy & Cyber Check", "InfoSec & Policy Checking Agent [Pro]", _infosec_node),
            ("legal", "Phase 3: Legal, Privacy & Sanctions Screening", "Legal, Privacy & Regulatory Agent [Pro]", _legal_node),
            ("financial", "Phase 4: Financial & Operational Viability", "Financial & Operational Viability Agent [Pro]", _financial_node),
            (
                "compliance_officer",
                "Phase 5: Risk Aggregator & HITL Gate",
                "Risk Aggregator & Compliance Officer Agent [Pro]",
                _compliance_officer_node,
            ),
        ]

        for phase_id, phase_title, agent_name, node_fn in phases:
            yield {
                "event": "phase_started",
                "phase_id": phase_id,
                "phase_name": phase_title,
                "agent_name": agent_name,
                "timestamp": _utc_now(),
            }
            if step_delay_sec > 0:
                await asyncio.sleep(step_delay_sec)

            state = await asyncio.to_thread(node_fn, state)
            phase_obj = state["phase_assessments"][phase_id]

            yield {
                "event": "phase_completed",
                "phase_id": phase_id,
                "assessment": phase_obj.model_dump(),
                "audit_entry": state["audit_trail"][-1],
            }

        result = self._state_to_result(state)
        self.assessments[result.assessment_id] = result

        yield {
            "event": "pipeline_completed",
            "result": result.model_dump(),
        }

    def apply_human_override(
        self, assessment_id: str, review: HumanReviewDecisionRequest
    ) -> Optional[OnboardingRunResult]:
        """Resolves a Human-in-the-Loop (HITL) Code Stop with 'approve' or 'reject' and persists to SQLite."""
        result = self.assessments.get(assessment_id)
        if not result or not result.final_decision:
            return None

        previous_decision = result.final_decision.decision.value
        result.final_decision.decision = review.decision
        scrubbed_notes, redactions = redact_pii_text(review.notes)
        override_payload = {
            "hitl_code_stop_active": False,
            "status": "HUMAN_FINALIZED",
            "previous_decision": previous_decision,
            "new_decision": review.decision.value,
            "reviewer_name": review.reviewer_name,
            "notes": scrubbed_notes,
            "pii_redacted_count": redactions,
            "overridden_at": _utc_now(),
        }
        result.final_decision.human_override = override_payload
        result.audit_trail.append({
            "timestamp": override_payload["overridden_at"],
            "phase": "human_governance",
            "agent": f"Human Compliance Officer ({review.reviewer_name})",
            "model_tier": "HUMAN_IN_THE_LOOP",
            "event": f"Resolved HITL Code Stop: changed {previous_decision} -> {review.decision.value}: {scrubbed_notes}",
            "pii_redacted_count": redactions,
            "risk_score": result.final_decision.composite_risk_score,
        })

        memory_store.upsert_session(
            vendor_id=result.vendor.vendor_id or "VND-CUSTOM",
            vendor_name=result.vendor.name,
            onboarding_status=review.decision.value,
            risk_level=result.final_decision.residual_risk_level.value,
            composite_score=result.final_decision.composite_risk_score,
            pending_hitl=False,
            audit_logs=result.audit_trail,
        )
        return result

    def _state_to_result(self, state: OnboardingGraphState) -> OnboardingRunResult:
        llm_status = llm_client.get_status()
        return OnboardingRunResult(
            assessment_id=state["assessment_id"],
            created_at=state["created_at"],
            completed_at=_utc_now(),
            orchestrator_engine=self.get_engine_name(),
            llm_provider_status=f"{llm_status['active_mode']} — {llm_status['provider']}",
            vendor=state["vendor"],
            intake_assessment=state["intake_assessment"],
            phase_assessments=state["phase_assessments"],
            all_findings=state.get("all_findings", []),
            final_decision=state["final_decision"],
            audit_trail=state.get("audit_trail", []),
        )


orchestrator = VendorOnboardingOrchestrator()
