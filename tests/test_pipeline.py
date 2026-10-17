"""Comprehensive Automated Pytest Suite for the Vendor Risk & Compliance Multi-Agent System.

Covers:
1. Rubric Section 1: Conversational vs Sequential Intent Routing, Strategic Model Routing (Flash vs Pro),
   and Human-in-the-Loop (HITL) Code Stop & Override.
2. Rubric Section 2: Constitutional Policy Prompting & Non-Blocking Async / Background Task SQLite Memory
   (`aget_session`, `aupsert_session`, `aappend_conversation_turn`, FastAPI `BackgroundTasks`, concurrent I/O).
3. Rubric Section 3: Explicit Tool Docstrings (`Args:`, `Returns:`, `Raises:`), Strict JSON Schemas
   (`TOOL_JSON_SCHEMAS`, OpenAI `tools`, Gemini `function_declarations`), Schema Validation Edge Cases,
   Native LLM Tool Calling (`execute_agent_with_tools`), and Guided Error Recovery.
4. Rubric Section 4: Dedicated Structured Logging (`structlog` / JSON formatter), OpenTelemetry Distributed
   Tracing (`trace_id`, `span_id`, parent-child span hierarchy), and Active PII Redaction across logs & spans.
5. Production Readiness: `SecretStr` API Key Masking, Mounted Secret File Resolution, and Infrastructure
   as Code (Terraform, Dockerfile, Docker Compose, Kubernetes, OpenTelemetry Collector) verification.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Callable, Dict, List, Tuple
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.agents.support_agent import (
    ahandle_vendor_question,
    classify_vendor_intent,
    handle_vendor_question,
)
from app.config import AppSettings, _load_secret_value
from app.llm_client import HybridLLMClient, llm_client
from app.main import app
from app.memory_store import PersistentVendorMemoryStore, memory_store
from app.models import (
    AgentStructuredSynthesisSchema,
    CriticalityTier,
    HumanReviewDecisionRequest,
    OnboardingDecision,
    RiskSeverity,
)
from app.observability import (
    otel_span_exporter,
    redact_pii_payload,
    redact_pii_text,
    start_otel_span,
    tracer,
)
from app.orchestrator import orchestrator
from app.policy_constitution import COMPANY_SECURITY_CONSTITUTION
from app.sample_vendors import get_sample_vendors_map
from app.tools import (
    TOOL_JSON_SCHEMAS,
    TOOL_REGISTRY,
    execute_registered_tool,
    extract_vendor_security_certifications,
    get_gemini_tool_declarations,
    get_openai_tool_schemas,
    validate_tool_arguments_against_schema,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
client = TestClient(app)


# ---------------------------------------------------------------------------
# 1. Orchestration, Intent Routing, Strategic Model Routing & HITL Code Stop
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "user_input,has_attachment,expected_intent,expected_pattern_keyword",
    [
        (
            "What security certifications do you require for Tier 1 vendors?",
            False,
            "VENDOR_QUESTION",
            "CONVERSATIONAL",
        ),
        (
            "Where are we in the onboarding review?",
            False,
            "VENDOR_QUESTION",
            "CONVERSATIONAL",
        ),
        (
            "Attached is our SOC 2 Type II PDF packet and signed DPA",
            True,
            "DOCUMENT_SUBMISSION",
            "SEQUENTIAL",
        ),
        (
            "Uploading our latest SOC 2 certificate PDF for extraction",
            False,
            "DOCUMENT_SUBMISSION",
            "SEQUENTIAL",
        ),
    ],
)
def test_rubric_1_parametrized_intent_routing(
    user_input: str,
    has_attachment: bool,
    expected_intent: str,
    expected_pattern_keyword: str,
) -> None:
    """Verifies Coordinator intent classification across conversational and document submission inputs."""
    result = classify_vendor_intent(user_input, has_document_attachment=has_attachment)
    assert result["intent"] == expected_intent
    assert expected_pattern_keyword in result["pattern"]
    assert result["coordinator_tier"] == "flash-fast"
    assert len(result["rationale"]) > 10


@pytest.mark.parametrize(
    "agent_key,expected_tier",
    [
        ("coordinator", "flash-fast"),
        ("support", "flash-fast"),
        ("intake", "flash-fast"),
        ("extraction", "flash-fast"),
        ("policy_checker", "pro-reasoning"),
        ("infosec", "pro-reasoning"),
        ("legal", "pro-reasoning"),
        ("financial", "pro-reasoning"),
        ("compliance_officer", "pro-reasoning"),
    ],
)
def test_rubric_1_strategic_model_routing_all_agents(
    agent_key: str, expected_tier: str
) -> None:
    """Verifies fast agents route to Flash and complex policy/risk agents route to Pro reasoning models."""
    route = llm_client.select_model_for_agent(agent_key)
    assert route["tier"] == expected_tier


def test_rubric_1_hitl_code_stop_and_async_override_resolution() -> None:
    """Verifies High/Critical risk vendor triggers HITL Code Stop and resolves via async human override."""
    vendors = get_sample_vendors_map()
    result = orchestrator.run_pipeline(vendors["VND-1003"].model_copy(deep=True))

    assert result.final_decision is not None
    assert result.final_decision.human_override is not None
    assert result.final_decision.human_override["hitl_code_stop_active"] is True
    assert result.final_decision.human_override["status"] == "PAUSED_REQUIRING_HUMAN_APPROVAL"

    override_req = HumanReviewDecisionRequest(
        decision=OnboardingDecision.REJECTED,
        reviewer_name="Chief Compliance Officer",
        notes="Confirmed rejection by Officer: Jane Doe (jane.doe@enterprise.com).",
    )
    updated = asyncio.run(
        orchestrator.aapply_human_override(result.assessment_id, override_req)
    )
    assert updated is not None
    assert updated.final_decision.human_override["hitl_code_stop_active"] is False
    assert updated.final_decision.human_override["status"] == "HUMAN_FINALIZED"
    assert "[REDACTED_EMAIL]" in updated.final_decision.human_override["notes"]


# ---------------------------------------------------------------------------
# 2. Context & Async / Background Task Memory Operations
# ---------------------------------------------------------------------------
def test_rubric_2_policy_constitution_articles() -> None:
    """Verifies the Enterprise Security Constitution contains all 5 mandatory governance articles."""
    for article in ("ARTICLE I", "ARTICLE II", "ARTICLE III", "ARTICLE IV", "ARTICLE V"):
        assert article in COMPANY_SECURITY_CONSTITUTION
    assert "SOC 2 Type II" in COMPANY_SECURITY_CONSTITUTION


def test_rubric_2_async_and_background_task_memory_store(tmp_path: Path) -> None:
    """Verifies non-blocking async memory methods and FastAPI BackgroundTasks execution."""
    temp_db = tmp_path / "test_async_sessions.db"
    store = PersistentVendorMemoryStore(db_path=temp_db)

    scheduled_callbacks: List[Tuple[Callable[..., Any], Tuple[Any, ...]]] = []

    class DummyBackgroundTasks:
        def add_task(self, func: Callable[..., Any], *args: Any) -> None:
            scheduled_callbacks.append((func, args))

    bg = DummyBackgroundTasks()

    # Schedule non-blocking background upsert
    cached = store.schedule_background_upsert(
        vendor_id="VND-BG-01",
        vendor_name="AsyncCloud Corp.",
        onboarding_status="APPROVED_WITH_CONDITIONS",
        risk_level="MEDIUM",
        composite_score=22.5,
        pending_hitl=False,
        extracted_certifications={"extracted_certifications": ["SOC 2 Type II"]},
        background_tasks=bg,
    )
    assert cached["vendor_id"] == "VND-BG-01"
    assert len(scheduled_callbacks) == 1
    assert store.background_writes_scheduled >= 1

    # Immediate read succeeds from non-blocking write-through cache before disk task runs
    immediate = store.get_session("VND-BG-01")
    assert immediate is not None
    assert immediate["onboarding_status"] == "APPROVED_WITH_CONDITIONS"

    # Execute the background task callback and verify SQLite disk persistence
    fn, fn_args = scheduled_callbacks.pop(0)
    fn(*fn_args)
    assert store.background_writes_completed >= 1

    # Verify async coroutines (`aget_session`, `aappend_conversation_turn`, `alist_all_sessions`)
    async def _run_async_memory_checks() -> None:
        await store.aappend_conversation_turn(
            vendor_id="VND-BG-01",
            vendor_name="AsyncCloud Corp.",
            role="vendor",
            message="Contact: Bob Lee (bob@asynccloud.io) - What is our status?",
        )
        await store.aflush_background_tasks()
        fetched = await store.aget_session("VND-BG-01")
        assert fetched is not None
        assert len(fetched["conversation_history"]) == 1
        assert "[REDACTED_EMAIL]" in fetched["conversation_history"][0]["content"]

        all_sessions = await store.alist_all_sessions()
        assert any(s["vendor_id"] == "VND-BG-01" for s in all_sessions)

    asyncio.run(_run_async_memory_checks())


def test_rubric_2_concurrent_async_conversation_turns() -> None:
    """Verifies concurrent async vendor support queries execute without blocking."""
    async def _concurrent_queries() -> List[Dict[str, Any]]:
        tasks = [
            ahandle_vendor_question(
                vendor_id="VND-1001",
                vendor_name="CloudScale AI Inc.",
                question="What is our current onboarding status?",
            ),
            ahandle_vendor_question(
                vendor_id="VND-1002",
                vendor_name="PayStream Global Ltd.",
                question="What certifications are required under the constitution?",
            ),
        ]
        results = await asyncio.gather(*tasks)
        await memory_store.aflush_background_tasks()
        return list(results)

    responses = asyncio.run(_concurrent_queries())
    assert len(responses) == 2
    assert responses[0]["session_state"]["persistence_mode"] == "async_background_task"
    assert responses[1]["session_state"]["persistence_mode"] == "async_background_task"


# ---------------------------------------------------------------------------
# 3. Tool Docstrings, Explicit JSON Schemas & Native LLM Tool Calling
# ---------------------------------------------------------------------------
def test_rubric_3_all_tools_have_explicit_parameter_docstrings() -> None:
    """Verifies every registered tool function has explicit Args, Returns, and Raises docstrings."""
    for tool_name, tool_fn in TOOL_REGISTRY.items():
        doc = tool_fn.__doc__ or ""
        assert "Args:" in doc, f"Tool '{tool_name}' missing 'Args:' section in docstring"
        assert "Returns:" in doc, f"Tool '{tool_name}' missing 'Returns:' section in docstring"
        assert "Raises:" in doc, f"Tool '{tool_name}' missing 'Raises:' section in docstring"


def test_rubric_3_explicit_json_schemas_for_openai_and_gemini() -> None:
    """Verifies explicit JSON Schema definitions constrain LLM tool calls for both OpenAI and Gemini."""
    openai_tools = get_openai_tool_schemas()
    gemini_decls = get_gemini_tool_declarations()

    assert len(openai_tools) == len(TOOL_JSON_SCHEMAS) == 5
    assert len(gemini_decls) == len(TOOL_JSON_SCHEMAS) == 5

    for oa_tool in openai_tools:
        assert oa_tool["type"] == "function"
        fn_spec = oa_tool["function"]
        assert fn_spec["strict"] is True
        params = fn_spec["parameters"]
        assert params["type"] == "object"
        assert "properties" in params and len(params["properties"]) >= 2
        assert "required" in params and len(params["required"]) >= 2
        assert params["additionalProperties"] is False


@pytest.mark.parametrize(
    "tool_name,invalid_args,expected_error_substr",
    [
        (
            "extract_vendor_security_certifications",
            {"vendor_name": "Acme Corp"},  # missing submitted_documents
            "missing required parameter",
        ),
        (
            "extract_vendor_security_certifications",
            {
                "vendor_name": "Acme Corp",
                "submitted_documents": ["SOC 2"],
                "unexpected_field": 123,
            },
            "unexpected parameter",
        ),
        (
            "classify_criticality_tier",
            {
                "data_sensitivity": "INVALID_ENUM_VALUE",
                "requires_network_integration": True,
                "estimated_records_exposed": 1000,
                "annual_contract_value_usd": 50000.0,
                "submitted_documents": [],
            },
            "not in allowed enum",
        ),
        (
            "evaluate_financial_and_ops",
            {
                "vendor_name": "Acme Corp",
                "criticality_tier": "TIER_1_CRITICAL",
                "cash_runway_months": 12,
                "credit_rating_score": 150,  # exceeds maximum 100
                "rto_hours": 4.0,
                "committed_sla_uptime_pct": 99.9,
            },
            "exceeds maximum",
        ),
    ],
)
def test_rubric_3_json_schema_validation_rejects_malformed_llm_tool_args(
    tool_name: str,
    invalid_args: Dict[str, Any],
    expected_error_substr: str,
) -> None:
    """Verifies JSON Schema validation strictly rejects malformed or out-of-bounds LLM arguments."""
    with pytest.raises(ValueError, match=expected_error_substr):
        validate_tool_arguments_against_schema(tool_name, invalid_args)


def test_rubric_3_native_llm_tool_calling_dispatch_and_mocked_live_provider() -> None:
    """Verifies native LLM tool calling dispatches tools and constrains output to AgentStructuredSynthesisSchema."""
    vendors = get_sample_vendors_map()
    vendor = vendors["VND-1001"].model_copy(deep=True)

    # Test mocked live Gemini tool-calling flow
    test_client = HybridLLMClient()
    test_client.execution_mode = "live"

    def _mock_gemini_tools(**kwargs: Any) -> Dict[str, Any]:
        dispatched = execute_registered_tool(
            "evaluate_infosec_controls",
            kwargs["default_tool_args"]["evaluate_infosec_controls"],
            vendor=kwargs["vendor"],
            tier=kwargs["tier"],
        )
        return {
            "tool_results": {"evaluate_infosec_controls": dispatched["result"]},
            "findings": dispatched["findings"],
            "tool_traces": dispatched["traces"],
            "summary": "Live Gemini native tool call verified SOC 2 Type II with 1 exception.",
        }

    with patch.object(HybridLLMClient, "gemini_api_key", "AIzaSyMockKeyForUnitTesting123456789"):
        with patch.object(test_client, "_call_gemini_with_tools", side_effect=_mock_gemini_tools):
            exec_res = test_client.execute_agent_with_tools(
                agent_key="policy_checker",
                system_prompt="Policy prompt",
                user_prompt="Evaluate vendor",
                tool_names=["evaluate_infosec_controls"],
                default_tool_args={
                    "evaluate_infosec_controls": {
                        "vendor_name": vendor.name,
                        "criticality_tier": "TIER_1_CRITICAL",
                        "data_sensitivity": vendor.data_sensitivity.value,
                        "soc2_type2_certified": True,
                        "iso27001_certified": False,
                        "open_critical_cves": 0,
                    }
                },
                fallback_text="Fallback",
                vendor=vendor,
                tier=CriticalityTier.TIER_1_CRITICAL,
                response_schema=AgentStructuredSynthesisSchema,
            )

    assert "live:" in exec_res["mode_used"]
    assert "native-tools" in exec_res["mode_used"]
    assert exec_res["structured_output"]["constitutional_compliance_status"] == "CONDITIONAL_VIOLATION"
    assert exec_res["tool_traces"][0].json_schema_validated is True
    assert exec_res["tool_traces"][0].invocation_mechanism == "native_llm_tool_calling"


@pytest.mark.parametrize(
    "bad_doc_name,expected_error_phrase",
    [
        ("SOC 2 Type II Report (ENCRYPTED_PDF)", "Error: PDF encrypted"),
        ("ISO 27001 Certificate (CORRUPT_BAD_OCR)", "Error: Document unreadable"),
        ("SOC 2 Type II Audit (2023 EXPIRED)", "Error: Certification expired"),
    ],
)
def test_rubric_3_extract_vendor_security_certifications_guided_errors(
    bad_doc_name: str, expected_error_phrase: str
) -> None:
    """Verifies guided error handling across encrypted, OCR-unreadable, and expired documents."""
    vendors = get_sample_vendors_map()
    v = vendors["VND-1001"].model_copy(deep=True)
    v.submitted_documents = [bad_doc_name]

    payload, trace = extract_vendor_security_certifications(v)
    assert payload["status"] == "GUIDED_ERROR_RECOVERY_REQUIRED"
    assert any(expected_error_phrase in err for err in payload["guided_errors"])
    assert trace.json_schema_validated is True


# ---------------------------------------------------------------------------
# 4. Structured Logging (`structlog`), OpenTelemetry Tracing & PII Redaction
# ---------------------------------------------------------------------------
def test_rubric_4_opentelemetry_distributed_tracing_and_pii_redaction() -> None:
    """Verifies OpenTelemetry parent-child span hierarchy, W3C trace_id, and active PII scrubbing."""
    otel_span_exporter.clear()

    raw = (
        "Submitted by: John Smith, email john.smith@vendor.io, "
        "phone (415) 890-1234, SSN 123-45-6789, key sk-1234567890abcdef1234."
    )
    scrubbed, count = redact_pii_text(raw)
    assert count == 5
    assert "[REDACTED_NAME]" in scrubbed
    assert "[REDACTED_EMAIL]" in scrubbed
    assert "[REDACTED_PHONE]" in scrubbed
    assert "[REDACTED_TAX_ID]" in scrubbed
    assert "[REDACTED_SECRET]" in scrubbed

    with start_otel_span(
        "test.parent_span",
        attributes={"sponsor.contact": "Sponsor: Alice Roe (alice@corp.io)"},
    ) as parent_span:
        with start_otel_span(
            "test.child_span",
            attributes={"vendor.email": "security@vendor.io"},
        ) as child_span:
            assert child_span.trace_id == parent_span.trace_id
            assert child_span.parent_span_id == parent_span.span_id

    spans = otel_span_exporter.get_finished_spans()
    assert len(spans) >= 2
    child_recorded = next(s for s in spans if s["name"] == "test.child_span")
    parent_recorded = next(s for s in spans if s["name"] == "test.parent_span")
    assert child_recorded["trace_id"] == parent_recorded["trace_id"]
    assert child_recorded["parent_span_id"] == parent_recorded["span_id"]
    assert "[REDACTED_EMAIL]" in str(child_recorded["attributes"])
    assert "[REDACTED_NAME]" in str(parent_recorded["attributes"])


# ---------------------------------------------------------------------------
# 5. Production Readiness: SecretStr Masking, IaC Configurations & Endpoints
# ---------------------------------------------------------------------------
def test_production_secret_masking_and_secret_file_loading(tmp_path: Path) -> None:
    """Verifies API keys are wrapped in SecretStr and can be loaded from mounted secret files."""
    secret_file = tmp_path / "gemini_api_key_secret"
    secret_file.write_text("AIzaSyMountedSecretKeyValue999999999\n", encoding="utf-8")

    with patch.dict("os.environ", {"GEMINI_API_KEY_FILE": str(secret_file)}):
        resolved = _load_secret_value("GEMINI_API_KEY")
        assert resolved == "AIzaSyMountedSecretKeyValue999999999"
        cfg = AppSettings()
        assert cfg.has_gemini_key() is True
        summary = cfg.masked_summary()
        assert summary["gemini_key_masked"] == "**********"
        assert "AIzaSyMountedSecretKeyValue999999999" not in str(summary)
        assert "AIzaSyMountedSecretKeyValue999999999" not in repr(cfg.gemini_api_key)


def test_production_infrastructure_as_code_files_exist_and_valid() -> None:
    """Verifies Terraform, Dockerfile, Docker Compose, Kubernetes, and OTel Collector IaC files exist."""
    required_iac_files = [
        PROJECT_ROOT / "infra" / "terraform" / "main.tf",
        PROJECT_ROOT / "infra" / "terraform" / "variables.tf",
        PROJECT_ROOT / "infra" / "terraform" / "outputs.tf",
        PROJECT_ROOT / "infra" / "k8s" / "deployment.yaml",
        PROJECT_ROOT / "infra" / "otel-collector-config.yaml",
        PROJECT_ROOT / "Dockerfile",
        PROJECT_ROOT / "docker-compose.yml",
        PROJECT_ROOT / ".github" / "workflows" / "ci-cd.yml",
    ]
    for path in required_iac_files:
        assert path.is_file(), f"Missing required IaC configuration file: {path}"
        content = path.read_text(encoding="utf-8")
        assert len(content) > 100

    tf_main = (PROJECT_ROOT / "infra" / "terraform" / "main.tf").read_text(encoding="utf-8")
    assert "google_cloud_run_v2_service" in tf_main
    assert "google_secret_manager_secret" in tf_main
    assert "google_service_account" in tf_main


def test_pipeline_all_sample_vendors_and_fastapi_endpoints() -> None:
    """End-to-end verification of all 4 preset vendors, OpenTelemetry spans, and FastAPI endpoints."""
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

    # Verify FastAPI endpoints (/api/chat, /api/tools/schemas, /api/telemetry/spans, /api/health)
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
    assert chat_res.json()["trace_id"] is not None

    schemas_res = client.get("/api/tools/schemas")
    assert schemas_res.status_code == 200
    assert "extract_vendor_security_certifications" in schemas_res.json()["tool_json_schemas"]

    otel_res = client.get("/api/telemetry/spans")
    assert otel_res.status_code == 200
    assert otel_res.json()["total_spans"] > 0

    health_res = client.get("/api/health")
    assert health_res.status_code == 200
    assert health_res.json()["otel_spans_recorded"] > 0
