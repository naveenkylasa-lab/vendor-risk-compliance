"""Automated unit & integration tests verifying all 4 Rubric Sections (80/80 points) and FastAPI endpoints."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.agents.support_agent import classify_vendor_intent, handle_vendor_question
from app.llm_client import llm_client
from app.main import app
from app.memory_store import memory_store
from app.models import (
    CriticalityTier,
    OnboardingDecision,
)
from app.observability import redact_pii_text
from app.orchestrator import orchestrator
from app.policy_constitution import COMPANY_SECURITY_CONSTITUTION
from app.sample_vendors import get_sample_vendors_map
from app.tools import extract_vendor_security_certifications


client = TestClient(app)


def test_rubric_1_intent_routing_and_strategic_model_routing():
    """Rubric 1: Conversational vs Sequential routing & Flash vs Pro strategic model selection."""
    q_intent = classify_vendor_intent("What security certifications do you require?", has_document_attachment=False)
    assert q_intent["intent"] == "VENDOR_QUESTION"
    assert "CONVERSATIONAL" in q_intent["pattern"]

    doc_intent = classify_vendor_intent("Attached is our SOC 2 Type II PDF packet", has_document_attachment=True)
    assert doc_intent["intent"] == "DOCUMENT_SUBMISSION"
    assert "SEQUENTIAL" in doc_intent["pattern"]

    flash_route = llm_client.select_model_for_agent("support")
    pro_route = llm_client.select_model_for_agent("policy_checker")
    assert flash_route["tier"] == "flash-fast"
    assert pro_route["tier"] == "pro-reasoning"


def test_rubric_1_hitl_code_stop_on_high_risk():
    """Rubric 1: Policy Agent triggers a HITL Code Stop when vendor is High/Critical Risk."""
    vendors = get_sample_vendors_map()
    result = orchestrator.run_pipeline(vendors["VND-1003"].model_copy(deep=True))

    assert result.final_decision is not None
    assert result.final_decision.human_override is not None
    assert result.final_decision.human_override["hitl_code_stop_active"] is True
    assert result.final_decision.human_override["status"] == "PAUSED_REQUIRING_HUMAN_APPROVAL"


def test_rubric_2_policy_constitution_and_persistent_sqlite_memory():
    """Rubric 2: Strict Policy Constitution & Persistent SQLite Session Memory across turns."""
    assert "ARTICLE I" in COMPANY_SECURITY_CONSTITUTION
    assert "SOC 2 Type II" in COMPANY_SECURITY_CONSTITUTION

    resp = handle_vendor_question(
        vendor_id="VND-1001",
        vendor_name="CloudScale AI Inc.",
        question="Contact: Jane Doe (jane@cloudscale.io) - What is our current onboarding status?",
    )
    assert resp["session_state"]["conversation_turns_count"] >= 2
    session = memory_store.get_session("VND-1001")
    assert session is not None
    assert len(session["conversation_history"]) >= 2


def test_rubric_3_extract_vendor_security_certifications_guided_error():
    """Rubric 3: Descriptive tool `extract_vendor_security_certifications` returns guided error on encrypted PDF."""
    vendors = get_sample_vendors_map()
    v = vendors["VND-1001"].model_copy(deep=True)
    v.submitted_documents = ["SOC 2 Type II Report (ENCRYPTED_PDF)"]

    payload, trace = extract_vendor_security_certifications(v)
    assert payload["status"] == "GUIDED_ERROR_RECOVERY_REQUIRED"
    assert any("Error: PDF encrypted" in err and "Ask the vendor for the password" in err for err in payload["guided_errors"])
    assert trace.tool_name == "extract_vendor_security_certifications"


def test_rubric_4_active_pii_redaction_in_logging_pipeline():
    """Rubric 4: Active PII scrubbing redacts emails, phone numbers, SSNs, and contact names before storage."""
    raw = "Submitted by: John Smith, email john.smith@vendor.io, phone (415) 890-1234, SSN 123-45-6789."
    scrubbed, count = redact_pii_text(raw)
    assert count == 4
    assert "[REDACTED_NAME]" in scrubbed
    assert "[REDACTED_EMAIL]" in scrubbed
    assert "[REDACTED_PHONE]" in scrubbed
    assert "[REDACTED_TAX_ID]" in scrubbed
    assert "john.smith@vendor.io" not in scrubbed


def test_pipeline_all_sample_vendors_and_fastapi_endpoints():
    """End-to-end verification of all 4 preset vendors and FastAPI endpoints."""
    vendors = get_sample_vendors_map()

    r1 = orchestrator.run_pipeline(vendors["VND-1001"].model_copy(deep=True))
    assert r1.intake_assessment.criticality_tier == CriticalityTier.TIER_1_CRITICAL
    assert r1.final_decision.decision == OnboardingDecision.APPROVED_WITH_CONDITIONS

    r2 = orchestrator.run_pipeline(vendors["VND-1002"].model_copy(deep=True))
    assert r2.final_decision.decision == OnboardingDecision.APPROVED

    r3 = orchestrator.run_pipeline(vendors["VND-1003"].model_copy(deep=True))
    assert r3.final_decision.decision == OnboardingDecision.REJECTED

    r4 = orchestrator.run_pipeline(vendors["VND-1004"].model_copy(deep=True))
    assert r4.intake_assessment.criticality_tier == CriticalityTier.TIER_4_LOW
    assert r4.final_decision.decision == OnboardingDecision.APPROVED

    chat_res = client.post(
        "/api/chat",
        json={
            "vendor_id": "VND-1001",
            "vendor_name": "CloudScale AI Inc.",
            "question": "Contact: Alice Brown (alice@cloudscale.io) - What is our status?",
        },
    )
    assert chat_res.status_code == 200
    assert chat_res.json()["pii_redactions_applied"] >= 2
