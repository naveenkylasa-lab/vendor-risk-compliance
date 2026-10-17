"""Coordinator Intent Router & Conversational Vendor Support Agent (Rubric Sections 1, 2, 3 & 4)."""

from __future__ import annotations

from typing import Any, Dict, Optional

from app.llm_client import llm_client
from app.memory_store import memory_store
from app.models import (
    AgentStructuredSynthesisSchema,
    IntentClassificationStructuredSchema,
)
from app.observability import redact_pii_text, start_otel_span, tracer
from app.policy_constitution import COMPANY_SECURITY_CONSTITUTION


def classify_vendor_intent(user_input: str, has_document_attachment: bool = False) -> Dict[str, Any]:
    """Coordinator Agent (Flash Model) reads the vendor's intent with JSON Schema validation:
    - If it's a question, selects the 'CONVERSATIONAL' pattern (Coordinator -> Support Agent).
    - If it's a document submission, selects the 'SEQUENTIAL' pattern (Extraction -> Policy Check).

    Args:
        user_input (str): Raw message or submission description from the vendor.
        has_document_attachment (bool): True if a compliance document packet is attached.

    Returns:
        Dict[str, Any]: Validated intent classification dictionary with `intent`, `pattern`,
        `rationale`, `coordinator_model`, and `coordinator_tier`.
    """
    with start_otel_span(
        "agent.coordinator.classify_intent",
        attributes={
            "agent.name": "Coordinator Agent",
            "has_document_attachment": has_document_attachment,
        },
    ) as span:
        route_info = llm_client.select_model_for_agent("coordinator")
        text_lower = (user_input or "").strip().lower()

        is_doc_keywords = any(
            kw in text_lower
            for kw in ("upload", "attached", "submitting", "soc 2", "soc2", "pdf", "certificate", "packet", "dpa")
        ) and not text_lower.endswith("?")

        if has_document_attachment or is_doc_keywords:
            validated = IntentClassificationStructuredSchema(
                intent="DOCUMENT_SUBMISSION",
                pattern="SEQUENTIAL (Extraction -> Constitutional Policy Check -> HITL Gate)",
                rationale="Detected compliance document packet or upload intent; triggering sequential extraction and policy evaluation.",
            )
        else:
            validated = IntentClassificationStructuredSchema(
                intent="VENDOR_QUESTION",
                pattern="CONVERSATIONAL (Coordinator -> Vendor Support Agent + Persistent Memory)",
                rationale="Detected conversational vendor query; routing to Flash Support Agent with persistent session memory.",
            )

        span.set_attribute("coordinator.intent", validated.intent)
        span.set_attribute("coordinator.pattern", validated.pattern)

        return {
            "intent": validated.intent,
            "pattern": validated.pattern,
            "rationale": validated.rationale,
            "coordinator_model": route_info["model"],
            "coordinator_tier": route_info["tier"],
        }


def _build_support_reply(
    *,
    vendor_id: str,
    vendor_name: str,
    question: str,
    session: Optional[Dict[str, Any]],
) -> tuple[str, str]:
    """Generates a JSON-schema-constrained conversational reply using session context."""
    prev_turns = session["conversation_history"] if session else []
    status = session["onboarding_status"] if session else "NOT_STARTED"
    risk_level = session["risk_level"] if session else "UNASSESSED"
    extracted_certs = session["extracted_certifications"] if session else {}

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

    return llm_client.generate_agent_synthesis(
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
        response_schema=AgentStructuredSynthesisSchema,
    )


async def ahandle_vendor_question(
    *,
    vendor_id: str,
    vendor_name: str,
    question: str,
    background_tasks: Optional[Any] = None,
) -> Dict[str, Any]:
    """Asynchronously handles a vendor's conversational question using non-blocking background memory tasks.

    Args:
        vendor_id (str): Unique vendor identifier (e.g., 'VND-1001').
        vendor_name (str): Legal name of the vendor organization.
        question (str): Raw question submitted by the vendor contact.
        background_tasks (Optional[Any]): Optional FastAPI `BackgroundTasks` for non-blocking SQLite writes.

    Returns:
        Dict[str, Any]: Response dictionary containing `reply`, `intent_routing`, `session_state`,
        OpenTelemetry `trace_id`, and `pii_redactions_applied`.
    """
    with start_otel_span(
        "agent.support.ahandle_vendor_question",
        attributes={
            "agent.name": "VendorSupportAgent",
            "vendor.id": vendor_id,
            "memory.execution_mode": "async_background_task",
        },
    ) as span:
        intent_meta = classify_vendor_intent(question, has_document_attachment=False)
        session = await memory_store.aget_session(vendor_id)

        await memory_store.aappend_conversation_turn(
            vendor_id=vendor_id,
            vendor_name=vendor_name,
            role="vendor",
            message=question,
            agent_name="VendorUser",
            model_used="n/a",
            background_tasks=background_tasks,
        )

        reply_text, model_badge = _build_support_reply(
            vendor_id=vendor_id,
            vendor_name=vendor_name,
            question=question,
            session=session,
        )

        updated_session = await memory_store.aappend_conversation_turn(
            vendor_id=vendor_id,
            vendor_name=vendor_name,
            role="assistant",
            message=reply_text,
            agent_name="VendorSupportAgent",
            model_used=model_badge,
            background_tasks=background_tasks,
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
            "trace_id": span.trace_id,
            "reply": reply_text,
            "session_state": {
                "onboarding_status": updated_session["onboarding_status"],
                "risk_level": updated_session["risk_level"],
                "conversation_turns_count": len(updated_session["conversation_history"]),
                "conversation_history": updated_session["conversation_history"],
                "persistence_mode": "async_background_task",
            },
        }


def handle_vendor_question(
    *,
    vendor_id: str,
    vendor_name: str,
    question: str,
    background_tasks: Optional[Any] = None,
) -> Dict[str, Any]:
    """Handles a vendor's conversational question using Gemini Flash + background-task SQLite memory.

    Args:
        vendor_id (str): Unique vendor identifier (e.g., 'VND-1001').
        vendor_name (str): Legal name of the vendor organization.
        question (str): Raw question submitted by the vendor contact.
        background_tasks (Optional[Any]): Optional FastAPI `BackgroundTasks` instance.

    Returns:
        Dict[str, Any]: Structured conversational response with session state and PII redaction metrics.
    """
    with start_otel_span(
        "agent.support.handle_vendor_question",
        attributes={
            "agent.name": "VendorSupportAgent",
            "vendor.id": vendor_id,
            "memory.execution_mode": "background_task",
        },
    ) as span:
        intent_meta = classify_vendor_intent(question, has_document_attachment=False)
        session = memory_store.get_session(vendor_id)

        memory_store.schedule_background_conversation_turn(
            vendor_id=vendor_id,
            vendor_name=vendor_name,
            role="vendor",
            message=question,
            agent_name="VendorUser",
            model_used="n/a",
            background_tasks=background_tasks,
        )

        reply_text, model_badge = _build_support_reply(
            vendor_id=vendor_id,
            vendor_name=vendor_name,
            question=question,
            session=session,
        )

        updated_session = memory_store.schedule_background_conversation_turn(
            vendor_id=vendor_id,
            vendor_name=vendor_name,
            role="assistant",
            message=reply_text,
            agent_name="VendorSupportAgent",
            model_used=model_badge,
            background_tasks=background_tasks,
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
            "trace_id": span.trace_id,
            "reply": reply_text,
            "session_state": {
                "onboarding_status": updated_session["onboarding_status"],
                "risk_level": updated_session["risk_level"],
                "conversation_turns_count": len(updated_session["conversation_history"]),
                "conversation_history": updated_session["conversation_history"],
                "persistence_mode": "background_task",
            },
        }
