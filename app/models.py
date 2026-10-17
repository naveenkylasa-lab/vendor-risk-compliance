"""Pydantic data models & explicit JSON Schemas for the Vendor Risk & Compliance multi-agent workflow."""

from __future__ import annotations

import copy
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

try:
    from pydantic import BaseModel, Field

    PYDANTIC_V2_AVAILABLE = True
except ImportError:
    PYDANTIC_V2_AVAILABLE = False

    class _FieldDefault:
        def __init__(self, default: Any = None, default_factory: Any = None, **kwargs: Any) -> None:
            self.default = default
            self.default_factory = default_factory
            self.metadata = kwargs

    def Field(default: Any = None, *, default_factory: Any = None, **kwargs: Any) -> Any:  # type: ignore
        return _FieldDefault(default=default, default_factory=default_factory, **kwargs)

    class BaseModel:  # type: ignore
        def __init__(self, **kwargs: Any) -> None:
            for cls in reversed(self.__class__.__mro__):
                if cls is object:
                    continue
                for k, v in cls.__dict__.items():
                    if k.startswith("_") or callable(v):
                        continue
                    if isinstance(v, _FieldDefault):
                        setattr(self, k, v.default_factory() if v.default_factory else copy.deepcopy(v.default))
                    else:
                        setattr(self, k, copy.deepcopy(v))
            for k, v in kwargs.items():
                setattr(self, k, v)

        def model_copy(self, *, deep: bool = False) -> Any:
            return copy.deepcopy(self) if deep else copy.copy(self)

        def model_dump(self) -> Dict[str, Any]:
            def _conv(val: Any) -> Any:
                if isinstance(val, Enum):
                    return val.value
                if hasattr(val, "model_dump"):
                    return val.model_dump()
                if isinstance(val, list):
                    return [_conv(x) for x in val]
                if isinstance(val, dict):
                    return {dk: _conv(dv) for dk, dv in val.items()}
                return val

            return {k: _conv(v) for k, v in self.__dict__.items() if not k.startswith("_")}

        @classmethod
        def model_json_schema(cls) -> Dict[str, Any]:
            props: Dict[str, Any] = {}
            req: List[str] = []
            for k, v in cls.__dict__.items():
                if k.startswith("_") or callable(v):
                    continue
                desc = v.metadata.get("description", "") if isinstance(v, _FieldDefault) else ""
                props[k] = {"type": "string", "description": desc}
                if isinstance(v, _FieldDefault) and v.default is Ellipsis:
                    req.append(k)
            return {"title": cls.__name__, "type": "object", "properties": props, "required": req}


class CriticalityTier(str, Enum):
    TIER_1_CRITICAL = "TIER_1_CRITICAL"
    TIER_2_HIGH = "TIER_2_HIGH"
    TIER_3_MEDIUM = "TIER_3_MEDIUM"
    TIER_4_LOW = "TIER_4_LOW"


class DataSensitivity(str, Enum):
    RESTRICTED_PII_PHI_PCI = "RESTRICTED_PII_PHI_PCI"
    CONFIDENTIAL_INTERNAL = "CONFIDENTIAL_INTERNAL"
    INTERNAL_NON_SENSITIVE = "INTERNAL_NON_SENSITIVE"
    PUBLIC_ONLY = "PUBLIC_ONLY"


class OnboardingDecision(str, Enum):
    APPROVED = "APPROVED"
    APPROVED_WITH_CONDITIONS = "APPROVED_WITH_CONDITIONS"
    ESCALATED_FOR_HUMAN_REVIEW = "ESCALATED_FOR_HUMAN_REVIEW"
    REJECTED = "REJECTED"


class RiskSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class PhaseStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    SKIPPED = "SKIPPED"
    FAILED = "FAILED"


class SecurityPostureInput(BaseModel):
    soc2_type2_certified: bool = Field(
        default=False, description="True if vendor holds an active SOC 2 Type II attestation."
    )
    soc2_exceptions: List[str] = Field(
        default_factory=list, description="List of noted exceptions in the SOC 2 Type II report."
    )
    iso27001_certified: bool = Field(
        default=False, description="True if vendor holds ISO/IEC 27001:2022 certification."
    )
    encryption_at_rest: bool = Field(
        default=True, description="True if AES-256 or equivalent encryption at rest is enforced."
    )
    encryption_in_transit: bool = Field(
        default=True, description="True if TLS 1.2/1.3 encryption in transit is enforced."
    )
    mfa_enforced: bool = Field(
        default=True, description="True if Multi-Factor Authentication is mandatory."
    )
    sso_supported: bool = Field(
        default=True, description="True if SAML 2.0 / OIDC enterprise SSO is supported."
    )
    recent_pentest_completed: bool = Field(
        default=False, description="True if an independent penetration test was completed within 12 months."
    )
    open_critical_cves: int = Field(
        default=0, ge=0, description="Count of unpatched Critical-severity CVEs."
    )
    open_high_cves: int = Field(
        default=0, ge=0, description="Count of unpatched High-severity CVEs."
    )
    incident_notification_hours: int = Field(
        default=72, ge=1, description="Contractual security breach notification SLA in hours."
    )
    subprocessors_disclosed: bool = Field(
        default=True, description="True if fourth-party subprocessors are publicly disclosed."
    )
    ai_model_trains_on_customer_data: bool = Field(
        default=False, description="True if vendor trains shared AI/ML foundation models on customer data."
    )


class LegalPrivacyInput(BaseModel):
    msa_accepted: bool = Field(
        default=True, description="True if the Master Services Agreement terms are accepted."
    )
    dpa_signed: bool = Field(
        default=False, description="True if the Data Processing Addendum (DPA) is signed."
    )
    gdpr_compliant: bool = Field(
        default=False, description="True if GDPR Article 28 processor controls are verified."
    )
    ccpa_compliant: bool = Field(
        default=False, description="True if CCPA/CPRA service provider terms are verified."
    )
    hipaa_baa_available: bool = Field(
        default=False, description="True if a HIPAA Business Associate Agreement is available."
    )
    cross_border_transfers: bool = Field(
        default=False, description="True if personal data is transferred across international borders."
    )
    scc_mechanism_in_place: bool = Field(
        default=False, description="True if EU/UK Standard Contractual Clauses (SCCs) are executed."
    )
    liability_cap_multiplier: float = Field(
        default=2.0, ge=0.0, description="Contractual super-cap liability multiplier relative to ACV."
    )
    indemnification_clause_accepted: bool = Field(
        default=True, description="True if mutual IP and data breach indemnification is accepted."
    )
    sanctions_watchlist_hit: bool = Field(
        default=False, description="True if OFAC, EU, or UN sanctions screening returned a match."
    )
    adverse_media_flags: List[str] = Field(
        default_factory=list, description="List of regulatory enforcement or adverse media alerts."
    )
    data_retention_deletion_sla_days: int = Field(
        default=30, ge=1, description="Contractual SLA in days for data deletion upon termination."
    )


class FinancialOpsInput(BaseModel):
    years_in_business: int = Field(
        default=5, ge=0, description="Number of years the vendor entity has been operating."
    )
    annual_revenue_usd: float = Field(
        default=10_000_000.0, ge=0.0, description="Annual recurring or gross revenue in USD."
    )
    debt_to_equity_ratio: float = Field(
        default=0.8, ge=0.0, description="Total debt-to-equity financial leverage ratio."
    )
    cash_runway_months: int = Field(
        default=24, ge=0, description="Estimated liquidity cash runway in months."
    )
    credit_rating_score: int = Field(
        default=75, ge=0, le=100, description="Commercial credit rating score on a 0-100 scale."
    )
    bcp_dr_tested_annually: bool = Field(
        default=True, description="True if Business Continuity & Disaster Recovery is tested annually."
    )
    rto_hours: float = Field(
        default=4.0, ge=0.0, description="Recovery Time Objective (RTO) in hours."
    )
    rpo_hours: float = Field(
        default=1.0, ge=0.0, description="Recovery Point Objective (RPO) in hours."
    )
    committed_sla_uptime_pct: float = Field(
        default=99.9, ge=0.0, le=100.0, description="Contractually committed availability SLA percentage."
    )
    cyber_insurance_coverage_usd: float = Field(
        default=5_000_000.0, ge=0.0, description="Active cyber liability insurance coverage in USD."
    )
    single_point_of_failure_risk: bool = Field(
        default=False, description="True if single-region hosting or SPOF concentration risk exists."
    )


class VendorSubmission(BaseModel):
    vendor_id: Optional[str] = Field(default=None, description="Unique vendor identifier (e.g. VND-1001).")
    name: str = Field(..., description="Legal name of the vendor organization.")
    category: str = Field(..., description="Service category or industry vertical.")
    website: str = Field(..., description="Corporate website URL.")
    country: str = Field(default="United States", description="Primary country of incorporation.")
    business_sponsor: str = Field(default="VP of Engineering", description="Internal executive sponsor.")
    service_description: str = Field(..., description="Description of the product/service and data scope.")
    annual_contract_value_usd: float = Field(default=100_000.0, ge=0.0, description="Annual contract value in USD.")
    data_sensitivity: DataSensitivity = Field(
        default=DataSensitivity.CONFIDENTIAL_INTERNAL,
        description="Highest sensitivity tier of enterprise data shared with the vendor.",
    )
    requires_network_integration: bool = Field(
        default=True, description="True if vendor integrates directly with internal networks or APIs."
    )
    estimated_records_exposed: int = Field(
        default=10_000, ge=0, description="Estimated volume of sensitive records accessible by the vendor."
    )
    submitted_documents: List[str] = Field(
        default_factory=list, description="List of compliance evidence documents provided by the vendor."
    )
    security: SecurityPostureInput = Field(default_factory=SecurityPostureInput)
    legal: LegalPrivacyInput = Field(default_factory=LegalPrivacyInput)
    financial: FinancialOpsInput = Field(default_factory=FinancialOpsInput)


# ---------------------------------------------------------------------------
# Explicit Tool Input / Output Pydantic Schemas & LLM Output Constraints
# ---------------------------------------------------------------------------
class ExtractCertificationsToolArgs(BaseModel):
    """Explicit JSON Schema input parameters for `extract_vendor_security_certifications`."""

    vendor_name: str = Field(
        ..., description="Legal name of the vendor submitting compliance artifacts."
    )
    submitted_documents: List[str] = Field(
        default_factory=list,
        description="List of compliance document filenames or titles uploaded by the vendor.",
    )


class ExtractCertificationsToolResult(BaseModel):
    """Explicit JSON Schema output structure for `extract_vendor_security_certifications`."""

    status: str = Field(
        ...,
        description="Extraction status: 'EXTRACTION_SUCCESS' or 'GUIDED_ERROR_RECOVERY_REQUIRED'.",
    )
    extracted_certifications: List[str] = Field(
        default_factory=list,
        description="Verified compliance certifications extracted from valid documents.",
    )
    guided_errors: List[str] = Field(
        default_factory=list,
        description="Actionable guided recovery messages for encrypted, unreadable, or expired files.",
    )
    documents_scanned: int = Field(
        ..., ge=0, description="Total number of submitted document artifacts inspected."
    )


class ClassifyCriticalityToolArgs(BaseModel):
    """Explicit JSON Schema input parameters for `classify_criticality_tier`."""

    data_sensitivity: DataSensitivity = Field(
        ..., description="Highest sensitivity classification of enterprise data exposed."
    )
    requires_network_integration: bool = Field(
        ..., description="Whether the vendor requires direct VPC/API/SSO network integration."
    )
    estimated_records_exposed: int = Field(
        ..., ge=0, description="Estimated number of customer or employee records exposed."
    )
    annual_contract_value_usd: float = Field(
        ..., ge=0.0, description="Annual contract spend in USD."
    )
    submitted_documents: List[str] = Field(
        default_factory=list,
        description="List of compliance document filenames or titles submitted by the vendor.",
    )


class ClassifyCriticalityToolResult(BaseModel):
    """Explicit JSON Schema output structure for `classify_criticality_tier`."""

    inherent_risk_score: float = Field(
        ..., ge=0.0, le=100.0, description="Calculated inherent risk score on a 0-100 scale."
    )
    criticality_tier: CriticalityTier = Field(
        ..., description="Assigned vendor criticality tier (TIER_1_CRITICAL to TIER_4_LOW)."
    )
    required_documents: List[str] = Field(
        default_factory=list, description="Mandatory onboarding documents required for this tier."
    )
    missing_documents: List[str] = Field(
        default_factory=list, description="Mandatory documents missing from the vendor submission."
    )
    fast_track_eligible: bool = Field(
        ..., description="True if vendor qualifies for streamlined Tier 4 fast-track onboarding."
    )


class EvaluateInfoSecToolArgs(BaseModel):
    """Explicit JSON Schema input parameters for `evaluate_infosec_controls`."""

    vendor_name: str = Field(..., description="Legal name of the vendor being audited.")
    criticality_tier: CriticalityTier = Field(
        ..., description="Vendor criticality tier governing mandatory security controls."
    )
    data_sensitivity: DataSensitivity = Field(
        ..., description="Sensitivity level of data handled by the vendor."
    )
    security: SecurityPostureInput = Field(
        ..., description="Technical security posture, certifications, CVEs, and AI training flags."
    )


class EvaluateLegalSanctionsToolArgs(BaseModel):
    """Explicit JSON Schema input parameters for `evaluate_legal_and_sanctions`."""

    vendor_name: str = Field(..., description="Legal name of the vendor being screened.")
    country: str = Field(
        ..., description="Primary country of incorporation for OFAC/sanctions watchlist screening."
    )
    criticality_tier: CriticalityTier = Field(
        ..., description="Vendor criticality tier governing contractual liability super-caps."
    )
    data_sensitivity: DataSensitivity = Field(
        ..., description="Sensitivity level of data handled by the vendor."
    )
    legal: LegalPrivacyInput = Field(
        ..., description="Legal, privacy, DPA, cross-border SCC, and sanctions screening inputs."
    )


class EvaluateFinancialOpsToolArgs(BaseModel):
    """Explicit JSON Schema input parameters for `evaluate_financial_and_ops`."""

    vendor_name: str = Field(..., description="Legal name of the vendor being evaluated.")
    criticality_tier: CriticalityTier = Field(
        ..., description="Vendor criticality tier governing BCP/DR RTO and SLA uptime thresholds."
    )
    financial: FinancialOpsInput = Field(
        ..., description="Financial solvency, credit score, cash runway, BCP/DR, and SLA inputs."
    )


class AgentStructuredSynthesisSchema(BaseModel):
    """Explicit JSON Schema used to constrain LLM structured outputs (`response_schema`)."""

    summary: str = Field(
        ...,
        description="Authoritative 2-4 sentence synthesis of the agent's domain risk evaluation.",
    )
    constitutional_compliance_status: str = Field(
        default="COMPLIANT",
        description="Constitutional compliance status: 'COMPLIANT', 'CONDITIONAL_VIOLATION', or 'CRITICAL_VIOLATION'.",
    )
    key_risk_indicators: List[str] = Field(
        default_factory=list,
        description="Structured list of key risk indicators or control gaps identified.",
    )
    recommended_next_step: str = Field(
        default="Proceed to next onboarding phase.",
        description="Concrete governance action recommended by the specialist agent.",
    )


class IntentClassificationStructuredSchema(BaseModel):
    """Explicit JSON Schema constraining the Coordinator Agent's intent routing output."""

    intent: str = Field(
        ...,
        description="Classified vendor intent: 'VENDOR_QUESTION' or 'DOCUMENT_SUBMISSION'.",
    )
    pattern: str = Field(
        ...,
        description="Selected multi-agent execution pattern: 'CONVERSATIONAL' or 'SEQUENTIAL'.",
    )
    rationale: str = Field(
        ...,
        description="Concise justification for selecting the conversational or sequential pattern.",
    )


class RiskFinding(BaseModel):
    finding_id: str
    phase: str
    agent_name: str
    title: str
    description: str
    severity: RiskSeverity
    category: str
    recommendation: str


class RemediationItem(BaseModel):
    action_id: str
    owner: str
    priority: RiskSeverity
    requirement: str
    due_timeline: str
    blocking_go_live: bool = False


class ToolCallTrace(BaseModel):
    tool_name: str
    inputs: Dict[str, Any] = Field(default_factory=dict)
    output_summary: str
    timestamp: str
    json_schema_validated: bool = True
    invocation_mechanism: str = "native_llm_tool_calling"
    otel_span_id: Optional[str] = None


class PhaseAssessment(BaseModel):
    phase_id: str
    phase_name: str
    agent_name: str
    agent_role: str
    status: PhaseStatus = PhaseStatus.COMPLETED
    risk_score: float = Field(ge=0.0, le=100.0, description="0 = lowest risk, 100 = highest risk")
    confidence: float = Field(default=0.92, ge=0.0, le=1.0)
    summary: str
    findings: List[RiskFinding] = Field(default_factory=list)
    tool_calls: List[ToolCallTrace] = Field(default_factory=list)
    metrics: Dict[str, Any] = Field(default_factory=dict)
    llm_mode_used: str = "simulation"
    duration_ms: int = 0


class IntakePhaseOutput(PhaseAssessment):
    criticality_tier: CriticalityTier = CriticalityTier.TIER_2_HIGH
    inherent_risk_score: float = 50.0
    required_documents: List[str] = Field(default_factory=list)
    missing_documents: List[str] = Field(default_factory=list)
    fast_track_eligible: bool = False
    required_phases: List[str] = Field(default_factory=list)


class FinalComplianceDecision(BaseModel):
    decision: OnboardingDecision
    composite_risk_score: float = Field(ge=0.0, le=100.0)
    residual_risk_level: RiskSeverity
    criticality_tier: CriticalityTier
    executive_memo: str
    key_strengths: List[str] = Field(default_factory=list)
    critical_blockers: List[str] = Field(default_factory=list)
    remediation_plan: List[RemediationItem] = Field(default_factory=list)
    next_review_months: int = 12
    human_override: Optional[Dict[str, Any]] = None


class OnboardingRunResult(BaseModel):
    assessment_id: str
    created_at: str
    completed_at: Optional[str] = None
    orchestrator_engine: str
    llm_provider_status: str
    vendor: VendorSubmission
    intake_assessment: Optional[IntakePhaseOutput] = None
    phase_assessments: Dict[str, PhaseAssessment] = Field(default_factory=dict)
    all_findings: List[RiskFinding] = Field(default_factory=list)
    final_decision: Optional[FinalComplianceDecision] = None
    audit_trail: List[Dict[str, Any]] = Field(default_factory=list)


class HumanReviewDecisionRequest(BaseModel):
    decision: OnboardingDecision
    reviewer_name: str = "Chief Compliance Officer"
    notes: str
