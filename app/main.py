"""FastAPI Backend & Web Dashboard Server for Vendor Risk & Compliance Multi-Agent Onboarding."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

from app.agents.support_agent import handle_vendor_question
from app.llm_client import llm_client
from app.memory_store import memory_store
from app.models import (
    HumanReviewDecisionRequest,
    OnboardingRunResult,
    VendorSubmission,
)
from app.observability import tracer
from app.orchestrator import orchestrator
from app.policy_constitution import COMPANY_SECURITY_CONSTITUTION
from app.sample_vendors import SAMPLE_VENDORS, get_sample_vendors_map

STATIC_DIR = Path(__file__).resolve().parent / "static"


class VendorQuestionRequest(BaseModel):
    vendor_id: str = "VND-1001"
    vendor_name: str = "CloudScale AI Inc."
    question: str


app = FastAPI(
    title="Vendor Risk & Compliance Multi-Agent System",
    description=(
        "Autonomous 5-Agent Third-Party Risk Management (TPRM) & Vendor Onboarding Pipeline "
        "with Conversational vs Sequential Routing, Strategic Model Routing (Flash vs Pro), "
        "Constitutional Policy Check, Persistent SQLite Session Memory, Guided Tool Errors, and Active PII Redaction."
    ),
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", include_in_schema=False)
async def serve_dashboard() -> FileResponse:
    """Serves the interactive Web Dashboard UI."""
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
async def health_check() -> dict:
    """Returns system health, orchestrator graph engine, model routing, and observability metrics."""
    return {
        "status": "healthy",
        "orchestrator_engine": orchestrator.get_engine_name(),
        "llm": llm_client.get_status(),
        "total_pii_redacted": tracer.total_pii_redacted,
        "agents": [
            {"phase": 0, "id": "coordinator", "name": "Coordinator & Support Agent", "model_tier": "flash-fast"},
            {"phase": 1, "id": "intake", "name": "Intake & Extraction Agent", "model_tier": "flash-fast"},
            {"phase": 2, "id": "infosec", "name": "InfoSec & Policy Checking Agent", "model_tier": "pro-reasoning"},
            {"phase": 3, "id": "legal", "name": "Legal, Privacy & Regulatory Agent", "model_tier": "pro-reasoning"},
            {"phase": 4, "id": "financial", "name": "Financial & Operational Viability Agent", "model_tier": "pro-reasoning"},
            {"phase": 5, "id": "compliance_officer", "name": "Risk Aggregator & Compliance Officer Agent", "model_tier": "pro-reasoning"},
        ],
    }


@app.get("/api/constitution")
async def get_policy_constitution() -> Dict[str, str]:
    """Returns the strict Enterprise Security & Compliance Constitution injected into the Policy Agent."""
    return {"constitution": COMPANY_SECURITY_CONSTITUTION}


@app.post("/api/chat")
async def vendor_conversational_support(req: VendorQuestionRequest) -> Dict[str, Any]:
    """Conversational Multi-Agent Pattern (Coordinator [Flash] -> Support Agent [Flash] + Persistent SQLite Memory)."""
    return handle_vendor_question(
        vendor_id=req.vendor_id,
        vendor_name=req.vendor_name,
        question=req.question,
    )


@app.get("/api/sessions")
async def list_persistent_sessions() -> List[Dict[str, Any]]:
    """Lists all persistent vendor sessions from SQLite memory."""
    return memory_store.list_all_sessions()


@app.get("/api/sessions/{vendor_id}")
async def get_persistent_session(vendor_id: str) -> Dict[str, Any]:
    """Retrieves a vendor's persistent session history and onboarding status from SQLite."""
    session = memory_store.get_session(vendor_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session for {vendor_id} not found")
    return session


@app.get("/api/vendors/presets", response_model=List[VendorSubmission])
async def list_preset_vendors() -> List[VendorSubmission]:
    """Returns realistic sample vendor onboarding packets across risk tiers."""
    return SAMPLE_VENDORS


@app.get("/api/assessments", response_model=List[OnboardingRunResult])
async def list_assessments() -> List[OnboardingRunResult]:
    """Returns all completed vendor onboarding assessments (most recent first)."""
    items = list(orchestrator.assessments.values())
    items.sort(key=lambda r: r.created_at, reverse=True)
    return items


@app.get("/api/assessments/{assessment_id}", response_model=OnboardingRunResult)
async def get_assessment(assessment_id: str) -> OnboardingRunResult:
    """Retrieves a specific vendor onboarding assessment by ID."""
    result = orchestrator.assessments.get(assessment_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Assessment {assessment_id} not found")
    return result


@app.post("/api/onboarding/run", response_model=OnboardingRunResult)
async def run_onboarding(
    vendor: Optional[VendorSubmission] = None,
    preset_id: Optional[str] = Query(default=None, description="Optional sample vendor ID (e.g. VND-1001)"),
) -> OnboardingRunResult:
    """Executes the full 5-phase Sequential (Extraction -> Policy Check) pipeline synchronously."""
    target_vendor = _resolve_vendor(vendor, preset_id)
    return orchestrator.run_pipeline(target_vendor)


@app.post("/api/onboarding/stream")
async def stream_onboarding(
    vendor: Optional[VendorSubmission] = None,
    preset_id: Optional[str] = Query(default=None, description="Optional sample vendor ID (e.g. VND-1001)"),
    step_delay_ms: int = Query(default=350, ge=0, le=2000),
) -> StreamingResponse:
    """Streams real-time Server-Sent Events (SSE) as each specialist agent executes its onboarding phase."""
    target_vendor = _resolve_vendor(vendor, preset_id)
    delay_sec = step_delay_ms / 1000.0

    async def event_generator():
        async for event in orchestrator.stream_pipeline(target_vendor, step_delay_sec=delay_sec):
            yield f"data: {json.dumps(event)}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.post("/api/assessments/{assessment_id}/human-override", response_model=OnboardingRunResult)
async def human_review_override(
    assessment_id: str,
    review: HumanReviewDecisionRequest,
) -> OnboardingRunResult:
    """Resolves a Human-in-the-Loop (HITL) Code Stop with 'approve' or 'reject'."""
    updated = orchestrator.apply_human_override(assessment_id, review)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Assessment {assessment_id} not found")
    return updated


def _resolve_vendor(
    vendor: Optional[VendorSubmission], preset_id: Optional[str]
) -> VendorSubmission:
    if preset_id:
        presets = get_sample_vendors_map()
        if preset_id not in presets:
            raise HTTPException(status_code=404, detail=f"Preset vendor '{preset_id}' not found")
        return presets[preset_id].model_copy(deep=True)
    if vendor is not None:
        return vendor
    raise HTTPException(
        status_code=422,
        detail="Provide either a `preset_id` query parameter or a `VendorSubmission` JSON body.",
    )
