"""Coordinator Intent Router & Conversational Vendor Support Agent (Rubric Sections 1, 2 & 4)."""

from __future__ import annotations

from typing import Any, Dict

from app.llm_client import llm_client
from app.memory_store import memory_store
from app.observability import redact_pii_text, tracer
from app.policy_constitution import COMPANY_SECURITY_CONSTITUTION


def classify_vendor_intent(user_input: str, has_document_attachment: bool = False) -> Dict[str, Any]:
    """Coordinator Agent (Flash Model) reads the vendor's intent:
    - If it's a question, selects the 'CONVERSATIONAL' pattern (Coordinator -> Support Agent).
    - If it's a document submission, selects the 'SEQUENTIAL' pattern (Extraction -> Policy Check).
    """
    route_info = llm_client.select_model_for_agent("coordinator")
    text_lower = (user_input or "").strip().lower()

    is_doc_keywords = any(
        kw in text_lower
        for kw in ("upload", "attached", "submitting", "soc 2", "soc2", "pdf", "certificate", "packet", "dpa")
    ) and not text_lower.endswith("?")

    if has_document_attachment or is_doc_keywords:
        intent = "DOCUMENT_SUBMISSION"
        pattern = "SEQUENTIAL (Extraction -> Constitutional Policy Check -> HITL Gate)"
    else:
        intent = "VENDOR_QUESTION"
        pattern = "CONVERSATIONAL (Coordinator -> Vendor Support Agent + Persistent Memory)"

    return {
        "intent": intent,
        "pattern": pattern,
        "coordinator_model": route_info["model"],
        "coordinator_tier": route_info["tier"],
    }


def handle_vendor_question(
    *,
    vendor_id: str,
    vendor_name: str,
    question: str,
) -> Dict[str, Any]:
    """Handles a vendor's conversational question using Gemini Flash + Persistent SQLite Session Memory."""
    intent_meta = classify_vendor_intent(question, has_document_attachment=False)
    session = memory_store.get_session(vendor_id)

    prev_turns = session["conversation_history"] if session else []
    status = session["onboarding_status"] if session else "NOT_STARTED"
    risk_level = session["risk_level"] if session else "UNASSESSED"
    extracted_certs = session["extracted_certifications"] if session else {}

    # Record incoming vendor question in persistent SQLite session (automatically PII-redacted)
    memory_store.append_conversation_turn(
        vendor_id=vendor_id,
        vendor_name=vendor_name,
        role="vendor",
        message=question,
        agent_name="VendorUser",
        model_used="n/a",
    )

    q_lower = question.lower()
    if "status" in q_lower or "progress" in q_lower or "where" in q_lower:
        fallback_reply = (
            f"Welcome back, {vendor_name} (ID: {vendor_id}). From your persistent onboarding session, "
            f"your current status is **{status}** (Risk Level: **{risk_level}**). "
            f"Verified certifications on file: {extracted_certs.get('extracted_certifications', ['None yet'])}. "
            f"We have {len(prev_turns)} previous message(s) saved in your session history so you don't need to repeat any prior details."
        )
    elif "password" in q_lower or "encrypt" in q_lower or "unreadable" in q_lower:
        fallback_reply = (
            f"For {vendor_name}: If your SOC 2 PDF was flagged by `extract_vendor_security_certifications` "
            "as password-protected or unreadable, please provide the decryption password here or upload an "
            "unlocked searchable PDF so our Sequential Extraction -> Policy Check pipeline can resume."
        )
    else:
        fallback_reply = (
            f"Hello {vendor_name} (Status: {status}). Per our Enterprise Security Constitution: "
            "(1) All Tier 1/2 vendors handling PII/Confidential data must provide an active SOC 2 Type II or ISO 27001 certification, "
            "(2) Zero open Critical CVEs are permitted, and (3) A signed GDPR/CCPA DPA with EU/UK SCCs is required for cross-border transfers."
        )

    reply_text, model_badge = llm_client.generate_agent_synthesis(
        system_prompt=(
            "You are the Conversational Vendor Support Agent (routed to a fast Flash model). "
            "Use the vendor's persistent session state and the company constitution below to answer "
            "concisely without asking them to repeat information already in memory.\n\n"
            + COMPANY_SECURITY_CONSTITUTION
        ),
        user_prompt=(
            f"Vendor: {vendor_name} ({vendor_id}) | Current Onboarding Status: {status} | Risk: {risk_level}\n"
            f"Extracted Certifications in Memory: {extracted_certs}\n"
            f"Previous Conversation Turns ({len(prev_turns)}): {prev_turns[-3:]}\n"
            f"Vendor Question: {question}"
        ),
        fallback_text=fallback_reply,
        agent_key="support",
    )

    updated_session = memory_store.append_conversation_turn(
        vendor_id=vendor_id,
        vendor_name=vendor_name,
        role="assistant",
        message=reply_text,
        agent_name="VendorSupportAgent",
        model_used=model_badge,
    )

    trace_entry = tracer.record_event(
        vendor_id=vendor_id,
        agent_name="VendorSupportAgent",
        model_tier=model_badge,
        pattern=intent_meta["pattern"],
        raw_message=f"Q: {question} | A: {reply_text}",
    )

    scrubbed_q, q_redactions = redact_pii_text(question)
    return {
        "vendor_id": vendor_id,
        "vendor_name": vendor_name,
        "intent_routing": intent_meta,
        "model_used": model_badge,
        "original_question_redacted": scrubbed_q,
        "pii_redactions_applied": q_redactions + trace_entry["pii_redacted_count"],
        "reply": reply_text,
        "session_state": {
            "onboarding_status": updated_session["onboarding_status"],
            "risk_level": updated_session["risk_level"],
            "conversation_turns_count": len(updated_session["conversation_history"]),
            "conversation_history": updated_session["conversation_history"],
        },
    }
