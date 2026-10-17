"""Pydantic data models for the Vendor Risk & Compliance multi-agent workflow."""

from __future__ import annotations

import copy
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

try:
    from pydantic import BaseModel, Field
except ImportError:
    class _FieldDefault:
        def __init__(self, default: Any = None, default_factory: Any = None, **kwargs: Any) -> None:
            self.default = default
            self.default_factory = default_factory

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
    soc2_type2_certified: bool = False
    soc2_exceptions: List[str] = Field(default_factory=list)
    iso27001_certified: bool = False
    encryption_at_rest: bool = True
    encryption_in_transit: bool = True
    mfa_enforced: bool = True
    sso_supported: bool = True
    recent_pentest_completed: bool = False
    open_critical_cves: int = 0
    open_high_cves: int = 0
    incident_notification_hours: int = 72
    subprocessors_disclosed: bool = True
    ai_model_trains_on_customer_data: bool = False


class LegalPrivacyInput(BaseModel):
    msa_accepted: bool = True
    dpa_signed: bool = False
    gdpr_compliant: bool = False
    ccpa_compliant: bool = False
    hipaa_baa_available: bool = False
    cross_border_transfers: bool = False
    scc_mechanism_in_place: bool = False
    liability_cap_multiplier: float = 2.0  # e.g., 2x annual contract value
    indemnification_clause_accepted: bool = True
    sanctions_watchlist_hit: bool = False
    adverse_media_flags: List[str] = Field(default_factory=list)
    data_retention_deletion_sla_days: int = 30


class FinancialOpsInput(BaseModel):
    years_in_business: int = 5
    annual_revenue_usd: float = 10_000_000.0
    debt_to_equity_ratio: float = 0.8
    cash_runway_months: int = 24
    credit_rating_score: int = 75  # 0 to 100 scale
    bcp_dr_tested_annually: bool = True
    rto_hours: float = 4.0
    rpo_hours: float = 1.0
    committed_sla_uptime_pct: float = 99.9
    cyber_insurance_coverage_usd: float = 5_000_000.0
    single_point_of_failure_risk: bool = False


class VendorSubmission(BaseModel):
    vendor_id: Optional[str] = None
    name: str
    category: str
    website: str
    country: str = "United States"
    business_sponsor: str = "VP of Engineering"
    service_description: str
    annual_contract_value_usd: float = 100_000.0
    data_sensitivity: DataSensitivity = DataSensitivity.CONFIDENTIAL_INTERNAL
    requires_network_integration: bool = True
    estimated_records_exposed: int = 10_000
    submitted_documents: List[str] = Field(default_factory=list)
    security: SecurityPostureInput = Field(default_factory=SecurityPostureInput)
    legal: LegalPrivacyInput = Field(default_factory=LegalPrivacyInput)
    financial: FinancialOpsInput = Field(default_factory=FinancialOpsInput)


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
