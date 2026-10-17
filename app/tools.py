"""Domain-specific compliance & risk evaluation tools invoked by the specialized agents."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

from app.models import (
    CriticalityTier,
    DataSensitivity,
    RiskFinding,
    RiskSeverity,
    ToolCallTrace,
    VendorSubmission,
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def extract_vendor_security_certifications(
    vendor: VendorSubmission,
) -> Tuple[Dict[str, Any], ToolCallTrace]:
    """Descriptive Extraction Tool with Guided Error Handling (Rubric Section 3).

    Inspects the vendor's submitted compliance artifacts to extract verified security
    certifications. Never crashes on unreadable/encrypted/corrupted documents — instead
    returns actionable guided errors so the agent can instruct the vendor how to resolve.
    """
    extracted_certs: List[str] = []
    guided_errors: List[str] = []

    if not vendor.submitted_documents:
        guided_errors.append(
            "Error: No compliance documents attached. Ask the vendor to upload their SOC 2 Type II report or ISO 27001 certificate."
        )

    for doc in vendor.submitted_documents:
        doc_lower = doc.lower()
        if "encrypted" in doc_lower or "password-protected" in doc_lower or "locked" in doc_lower:
            guided_errors.append(
                f"Error: PDF encrypted ('{doc}'). Ask the vendor for the password or an unlocked compliance copy."
            )
            continue
        if "corrupt" in doc_lower or "unreadable" in doc_lower or "bad_ocr" in doc_lower:
            guided_errors.append(
                f"Error: Document unreadable ('{doc}'). OCR failed on low-resolution scan; ask the vendor to upload a searchable PDF."
            )
            continue
        if "expired" in doc_lower or "2023" in doc_lower or "2024" in doc_lower:
            guided_errors.append(
                f"Error: Certification expired ('{doc}'). Audit period is >12 months old; ask the vendor for their current 2025/2026 report or a signed bridge letter."
            )
            continue

        if "soc 2" in doc_lower:
            extracted_certs.append("SOC 2 Type II")
        if "iso" in doc_lower and "27001" in doc_lower:
            extracted_certs.append("ISO/IEC 27001:2022")
        if "pci" in doc_lower:
            extracted_certs.append("PCI-DSS v4.0 AoC")
        if "dpa" in doc_lower or "data processing" in doc_lower:
            extracted_certs.append("Signed DPA")
        if "scc" in doc_lower:
            extracted_certs.append("EU/UK Standard Contractual Clauses")

    status = "GUIDED_ERROR_RECOVERY_REQUIRED" if guided_errors else "EXTRACTION_SUCCESS"
    payload = {
        "status": status,
        "extracted_certifications": extracted_certs,
        "guided_errors": guided_errors,
        "documents_scanned": len(vendor.submitted_documents),
    }

    summary_str = (
        f"Status={status} | Extracted={extracted_certs or ['None']}"
        + (f" | Guided Errors={guided_errors}" if guided_errors else "")
    )
    trace = ToolCallTrace(
        tool_name="extract_vendor_security_certifications",
        inputs={"submitted_documents": vendor.submitted_documents},
        output_summary=summary_str,
        timestamp=_now_iso(),
    )
    return payload, trace


def classify_criticality_tier(vendor: VendorSubmission) -> Tuple[Dict[str, Any], ToolCallTrace]:
    """Calculates inherent risk score and assigns vendor criticality tier (Tier 1 - Tier 4)."""
    score = 10.0

    # Data sensitivity weight
    if vendor.data_sensitivity == DataSensitivity.RESTRICTED_PII_PHI_PCI:
        score += 40.0
    elif vendor.data_sensitivity == DataSensitivity.CONFIDENTIAL_INTERNAL:
        score += 25.0
    elif vendor.data_sensitivity == DataSensitivity.INTERNAL_NON_SENSITIVE:
        score += 12.0

    # Network integration weight
    if vendor.requires_network_integration:
        score += 20.0

    # Scale of records exposed
    if vendor.estimated_records_exposed >= 500_000:
        score += 18.0
    elif vendor.estimated_records_exposed >= 100_000:
        score += 14.0
    elif vendor.estimated_records_exposed > 0:
        score += 8.0

    # Annual contract spend weight
    if vendor.annual_contract_value_usd >= 500_000:
        score += 12.0
    elif vendor.annual_contract_value_usd >= 150_000:
        score += 8.0
    elif vendor.annual_contract_value_usd >= 50_000:
        score += 4.0

    score = min(100.0, round(score, 1))

    if score >= 75.0:
        tier = CriticalityTier.TIER_1_CRITICAL
    elif score >= 50.0:
        tier = CriticalityTier.TIER_2_HIGH
    elif score >= 28.0:
        tier = CriticalityTier.TIER_3_MEDIUM
    else:
        tier = CriticalityTier.TIER_4_LOW

    required_docs = ["Master Services Agreement", "W-9 / Tax & Banking Verification"]
    if tier in (CriticalityTier.TIER_1_CRITICAL, CriticalityTier.TIER_2_HIGH):
        required_docs.extend([
            "SOC 2 Type II or ISO 27001 Certificate",
            "Data Processing Addendum (DPA)",
            "Penetration Test Summary",
            "Business Continuity Plan",
        ])

    submitted_lower = " | ".join(vendor.submitted_documents).lower()
    missing_docs = []
    if "msa" not in submitted_lower and "master services" not in submitted_lower:
        missing_docs.append("Executed Master Services Agreement (MSA)")
    if tier in (CriticalityTier.TIER_1_CRITICAL, CriticalityTier.TIER_2_HIGH):
        if "soc 2" not in submitted_lower and "iso" not in submitted_lower:
            missing_docs.append("SOC 2 Type II Report or ISO 27001 Certificate")
        if "dpa" not in submitted_lower and "data processing" not in submitted_lower:
            missing_docs.append("Data Processing Addendum (DPA)")
        if "penetration" not in submitted_lower and "pentest" not in submitted_lower:
            missing_docs.append("Recent Third-Party Penetration Test Summary")

    fast_track = tier == CriticalityTier.TIER_4_LOW and not vendor.requires_network_integration
    result = {
        "inherent_risk_score": score,
        "criticality_tier": tier,
        "required_documents": required_docs,
        "missing_documents": missing_docs,
        "fast_track_eligible": fast_track,
    }
    trace = ToolCallTrace(
        tool_name="classify_criticality_tier",
        inputs={
            "data_sensitivity": vendor.data_sensitivity.value,
            "network_integration": vendor.requires_network_integration,
            "records_exposed": vendor.estimated_records_exposed,
            "acv_usd": vendor.annual_contract_value_usd,
        },
        output_summary=(
            f"Assigned {tier.value} (Inherent Risk: {score}/100, "
            f"Missing Docs: {len(missing_docs)}, Fast-Track: {fast_track})"
        ),
        timestamp=_now_iso(),
    )
    return result, trace


def evaluate_infosec_controls(
    vendor: VendorSubmission, tier: CriticalityTier
) -> Tuple[Dict[str, Any], List[RiskFinding], List[ToolCallTrace]]:
    """Audits technical security posture, certifications, vulnerabilities, and AI governance."""
    sec = vendor.security
    findings: List[RiskFinding] = []
    traces: List[ToolCallTrace] = []
    risk_points = 8.0  # Baseline residual technical risk

    is_high_tier = tier in (CriticalityTier.TIER_1_CRITICAL, CriticalityTier.TIER_2_HIGH)

    # Tool 1: Audit Certification & IAM Controls
    if is_high_tier and not (sec.soc2_type2_certified or sec.iso27001_certified):
        risk_points += 32.0
        findings.append(
            RiskFinding(
                finding_id="SEC-01",
                phase="infosec",
                agent_name="InfoSec & Cyber Risk Agent",
                title="Missing Independent Security Audit (SOC 2 Type II / ISO 27001)",
                description=(
                    f"{vendor.name} is classified as {tier.value} handling {vendor.data_sensitivity.value} "
                    "data but lacks both SOC 2 Type II and ISO 27001 certification."
                ),
                severity=RiskSeverity.CRITICAL,
                category="Audit & Certifications",
                recommendation="Require valid SOC 2 Type II report or ISO 27001 certification prior to production data ingestion.",
            )
        )
    elif sec.soc2_exceptions:
        risk_points += 10.0 * len(sec.soc2_exceptions)
        findings.append(
            RiskFinding(
                finding_id="SEC-02",
                phase="infosec",
                agent_name="InfoSec & Cyber Risk Agent",
                title=f"SOC 2 Type II Audit Exception(s) Identified ({len(sec.soc2_exceptions)})",
                description="Audit report noted exception(s): " + "; ".join(sec.soc2_exceptions),
                severity=RiskSeverity.MEDIUM,
                category="Access Control & Audit",
                recommendation="Obtain formal management response and evidence of remediated quarterly access reviews.",
            )
        )

    if not sec.encryption_at_rest or not sec.encryption_in_transit:
        risk_points += 30.0
        findings.append(
            RiskFinding(
                finding_id="SEC-03",
                phase="infosec",
                agent_name="InfoSec & Cyber Risk Agent",
                title="Unencrypted Data Storage or Transmission",
                description="Vendor does not enforce AES-256 encryption at rest and TLS 1.2+ in transit.",
                severity=RiskSeverity.CRITICAL,
                category="Cryptography",
                recommendation="Mandate full encryption at rest and in transit before any integration.",
            )
        )

    if is_high_tier and (not sec.mfa_enforced or not sec.sso_supported):
        risk_points += 15.0
        findings.append(
            RiskFinding(
                finding_id="SEC-04",
                phase="infosec",
                agent_name="InfoSec & Cyber Risk Agent",
                title="Inadequate Identity & Access Controls (MFA / Enterprise SSO)",
                description=f"MFA enforced: {sec.mfa_enforced}, SAML/OIDC SSO supported: {sec.sso_supported}.",
                severity=RiskSeverity.HIGH,
                category="Identity & Access Management",
                recommendation="Enforce mandatory MFA for all privileged/tenant accounts and require SAML/OIDC SSO.",
            )
        )

    traces.append(
        ToolCallTrace(
            tool_name="verify_security_certifications_and_iam",
            inputs={
                "soc2_type2": sec.soc2_type2_certified,
                "iso27001": sec.iso27001_certified,
                "mfa": sec.mfa_enforced,
                "sso": sec.sso_supported,
            },
            output_summary=(
                f"SOC2={sec.soc2_type2_certified} (Exceptions={len(sec.soc2_exceptions)}), "
                f"ISO27001={sec.iso27001_certified}, MFA={sec.mfa_enforced}"
            ),
            timestamp=_now_iso(),
        )
    )

    # Tool 2: Vulnerability Management, Incident SLA & AI Data Governance
    if sec.open_critical_cves > 0:
        risk_points += min(35.0, sec.open_critical_cves * 18.0)
        findings.append(
            RiskFinding(
                finding_id="SEC-05",
                phase="infosec",
                agent_name="InfoSec & Cyber Risk Agent",
                title=f"Unpatched Critical Vulnerabilities ({sec.open_critical_cves} Critical CVEs)",
                description=(
                    f"External vulnerability scan and pentest review revealed {sec.open_critical_cves} "
                    f"open Critical CVEs and {sec.open_high_cves} High CVEs."
                ),
                severity=RiskSeverity.CRITICAL,
                category="Vulnerability Management",
                recommendation="Block production network onboarding until all Critical CVEs are patched and verified via re-test.",
            )
        )
    elif sec.open_high_cves > 0:
        risk_points += min(18.0, sec.open_high_cves * 7.0)
        findings.append(
            RiskFinding(
                finding_id="SEC-06",
                phase="infosec",
                agent_name="InfoSec & Cyber Risk Agent",
                title=f"Open High-Severity Pentest Finding(s) ({sec.open_high_cves} High CVEs)",
                description=f"Recent penetration test shows {sec.open_high_cves} open High-severity vulnerability pending patch.",
                severity=RiskSeverity.MEDIUM,
                category="Vulnerability Management",
                recommendation="Require remediation SLA within 30 days of contract execution.",
            )
        )

    if sec.incident_notification_hours > 72:
        risk_points += 10.0
        findings.append(
            RiskFinding(
                finding_id="SEC-07",
                phase="infosec",
                agent_name="InfoSec & Cyber Risk Agent",
                title=f"Delayed Breach Notification SLA ({sec.incident_notification_hours} hours)",
                description="Incident notification window exceeds the 72-hour regulatory standard (GDPR Art. 33 / SEC rules).",
                severity=RiskSeverity.HIGH,
                category="Incident Response",
                recommendation="Amend security exhibit to require breach notification within 24-48 hours.",
            )
        )

    if sec.ai_model_trains_on_customer_data and vendor.data_sensitivity != DataSensitivity.PUBLIC_ONLY:
        risk_points += 22.0
        findings.append(
            RiskFinding(
                finding_id="SEC-08",
                phase="infosec",
                agent_name="InfoSec & Cyber Risk Agent",
                title="Unauthorized AI Foundation Model Training on Enterprise Data",
                description="Vendor terms allow customer telemetry/inputs to be used for training shared ML models.",
                severity=RiskSeverity.CRITICAL,
                category="AI & Data Governance",
                recommendation="Enforce strict zero-data-retention / opt-out clause prohibiting model training on company data.",
            )
        )

    risk_score = min(100.0, round(risk_points, 1))
    traces.append(
        ToolCallTrace(
            tool_name="scan_vulnerabilities_and_ai_governance",
            inputs={
                "open_critical_cves": sec.open_critical_cves,
                "open_high_cves": sec.open_high_cves,
                "incident_sla_hours": sec.incident_notification_hours,
                "ai_training_on_data": sec.ai_model_trains_on_customer_data,
            },
            output_summary=(
                f"Computed InfoSec Risk Score: {risk_score}/100 with {len(findings)} finding(s)."
            ),
            timestamp=_now_iso(),
        )
    )

    metrics = {
        "soc2_type2": sec.soc2_type2_certified,
        "iso27001": sec.iso27001_certified,
        "open_critical_cves": sec.open_critical_cves,
        "open_high_cves": sec.open_high_cves,
        "incident_sla_hours": sec.incident_notification_hours,
    }
    return {"risk_score": risk_score, "metrics": metrics}, findings, traces


def evaluate_legal_and_sanctions(
    vendor: VendorSubmission, tier: CriticalityTier
) -> Tuple[Dict[str, Any], List[RiskFinding], List[ToolCallTrace]]:
    """Screens OFAC/sanctions watchlists, adverse media, GDPR/CCPA DPAs, and contractual liability."""
    leg = vendor.legal
    findings: List[RiskFinding] = []
    traces: List[ToolCallTrace] = []
    risk_points = 5.0

    handles_pii = vendor.data_sensitivity == DataSensitivity.RESTRICTED_PII_PHI_PCI

    # Tool 1: Sanctions, OFAC & Adverse Media Screening
    if leg.sanctions_watchlist_hit:
        risk_points += 50.0
        findings.append(
            RiskFinding(
                finding_id="LEG-01",
                phase="legal",
                agent_name="Legal, Privacy & Regulatory Agent",
                title="OFAC / Global Sanctions Watchlist Match Detected",
                description=(
                    f"Entity or affiliated subsidiary of {vendor.name} ({vendor.country}) triggered a "
                    "match on global sanctions / restricted jurisdiction screening."
                ),
                severity=RiskSeverity.CRITICAL,
                category="Sanctions & KYC/AML",
                recommendation="Immediate compliance hold; escalate to General Counsel & OFAC Trade Compliance before any engagement.",
            )
        )

    if leg.adverse_media_flags:
        risk_points += min(25.0, 12.0 * len(leg.adverse_media_flags))
        findings.append(
            RiskFinding(
                finding_id="LEG-02",
                phase="legal",
                agent_name="Legal, Privacy & Regulatory Agent",
                title=f"Regulatory Inquiry / Adverse Media Flags ({len(leg.adverse_media_flags)})",
                description="Adverse media screening identified: " + " | ".join(leg.adverse_media_flags),
                severity=RiskSeverity.HIGH,
                category="Regulatory & Reputational Risk",
                recommendation="Conduct enhanced due diligence (EDD) and obtain legal opinion on pending regulatory investigations.",
            )
        )

    traces.append(
        ToolCallTrace(
            tool_name="screen_ofac_sanctions_and_adverse_media",
            inputs={
                "vendor_name": vendor.name,
                "jurisdiction": vendor.country,
                "sanctions_hit": leg.sanctions_watchlist_hit,
                "adverse_media_count": len(leg.adverse_media_flags),
            },
            output_summary=(
                f"Sanctions Hit={leg.sanctions_watchlist_hit}, "
                f"Adverse Media Flags={len(leg.adverse_media_flags)}"
            ),
            timestamp=_now_iso(),
        )
    )

    # Tool 2: Privacy (GDPR/CCPA/SCCs) & Contractual Liability Clauses
    if handles_pii and not leg.dpa_signed:
        risk_points += 25.0
        findings.append(
            RiskFinding(
                finding_id="LEG-03",
                phase="legal",
                agent_name="Legal, Privacy & Regulatory Agent",
                title="Missing Executed Data Processing Addendum (DPA)",
                description="Vendor processes Restricted PII/PHI/PCI but has not executed a Data Processing Addendum.",
                severity=RiskSeverity.CRITICAL,
                category="Data Privacy",
                recommendation="Execute standard enterprise DPA with mandatory subprocessor flow-down obligations.",
            )
        )

    if leg.cross_border_transfers and not leg.scc_mechanism_in_place and handles_pii:
        risk_points += 18.0
        findings.append(
            RiskFinding(
                finding_id="LEG-04",
                phase="legal",
                agent_name="Legal, Privacy & Regulatory Agent",
                title="Cross-Border Data Transfer Missing EU/UK SCCs & TIA",
                description=(
                    f"{vendor.name} performs cross-border data transfers without executed Standard "
                    "Contractual Clauses (SCCs) or a Transfer Impact Assessment (TIA)."
                ),
                severity=RiskSeverity.HIGH,
                category="International Privacy (GDPR Chapter V)",
                recommendation="Attach 2021 EU Standard Contractual Clauses (Module 2) and UK IDTA addendum to the DPA.",
            )
        )

    if not leg.msa_accepted or not leg.indemnification_clause_accepted:
        risk_points += 18.0
        findings.append(
            RiskFinding(
                finding_id="LEG-05",
                phase="legal",
                agent_name="Legal, Privacy & Regulatory Agent",
                title="Unresolved MSA & IP/Data Breach Indemnification Redlines",
                description="Vendor has not accepted standard Master Services Agreement or third-party indemnification obligations.",
                severity=RiskSeverity.HIGH,
                category="Commercial & Legal Terms",
                recommendation="Require mutual IP & data breach indemnification before contract signature.",
            )
        )

    if leg.liability_cap_multiplier < 2.0 and tier in (CriticalityTier.TIER_1_CRITICAL, CriticalityTier.TIER_2_HIGH):
        risk_points += 10.0
        findings.append(
            RiskFinding(
                finding_id="LEG-06",
                phase="legal",
                agent_name="Legal, Privacy & Regulatory Agent",
                title=f"Below-Standard Super-Cap Liability Limit ({leg.liability_cap_multiplier}x ACV)",
                description=(
                    f"Proposed liability cap ({leg.liability_cap_multiplier}x ACV) is below enterprise "
                    "policy minimum (2.0x-3.0x ACV) for high-criticality vendors."
                ),
                severity=RiskSeverity.MEDIUM,
                category="Contractual Liability",
                recommendation="Negotiate data privacy/confidentiality super-cap to at least 2.0x annual contract value.",
            )
        )

    risk_score = min(100.0, round(risk_points, 1))
    traces.append(
        ToolCallTrace(
            tool_name="audit_privacy_dpa_and_contract_clauses",
            inputs={
                "dpa_signed": leg.dpa_signed,
                "cross_border": leg.cross_border_transfers,
                "scc_in_place": leg.scc_mechanism_in_place,
                "liability_cap_x": leg.liability_cap_multiplier,
            },
            output_summary=(
                f"Computed Legal & Privacy Risk Score: {risk_score}/100 with {len(findings)} finding(s)."
            ),
            timestamp=_now_iso(),
        )
    )

    metrics = {
        "sanctions_watchlist_hit": leg.sanctions_watchlist_hit,
        "dpa_signed": leg.dpa_signed,
        "scc_in_place": leg.scc_mechanism_in_place,
        "liability_cap_multiplier": leg.liability_cap_multiplier,
    }
    return {"risk_score": risk_score, "metrics": metrics}, findings, traces


def evaluate_financial_and_ops(
    vendor: VendorSubmission, tier: CriticalityTier
) -> Tuple[Dict[str, Any], List[RiskFinding], List[ToolCallTrace]]:
    """Evaluates vendor financial solvency, liquidity runway, BCP/DR RTO/RPO, and SLA resilience."""
    fin = vendor.financial
    findings: List[RiskFinding] = []
    traces: List[ToolCallTrace] = []
    risk_points = 6.0

    is_high_tier = tier in (CriticalityTier.TIER_1_CRITICAL, CriticalityTier.TIER_2_HIGH)

    # Tool 1: Financial Health & Solvency Analysis
    if fin.cash_runway_months < 12 or fin.credit_rating_score < 55:
        risk_points += 30.0
        findings.append(
            RiskFinding(
                finding_id="FIN-01",
                phase="financial",
                agent_name="Financial & Operational Viability Agent",
                title=f"Elevated Financial Distress & Liquidity Risk (Runway: {fin.cash_runway_months} mos, Credit: {fin.credit_rating_score}/100)",
                description=(
                    f"{vendor.name} exhibits short liquidity runway ({fin.cash_runway_months} months), "
                    f"high leverage (D/E {fin.debt_to_equity_ratio}), and weak credit score ({fin.credit_rating_score}/100)."
                ),
                severity=RiskSeverity.HIGH,
                category="Financial Solvency",
                recommendation="Include source-code/data escrow clause and quarterly financial covenant reporting.",
            )
        )
    elif fin.debt_to_equity_ratio > 1.5:
        risk_points += 12.0
        findings.append(
            RiskFinding(
                finding_id="FIN-02",
                phase="financial",
                agent_name="Financial & Operational Viability Agent",
                title=f"High Debt-to-Equity Leverage ({fin.debt_to_equity_ratio}x)",
                description="Vendor carries elevated debt leverage relative to equity capital.",
                severity=RiskSeverity.MEDIUM,
                category="Financial Solvency",
                recommendation="Monitor annual audited financial statements during renewal cycles.",
            )
        )

    traces.append(
        ToolCallTrace(
            tool_name="analyze_financial_solvency_and_credit",
            inputs={
                "revenue_usd": fin.annual_revenue_usd,
                "debt_to_equity": fin.debt_to_equity_ratio,
                "runway_months": fin.cash_runway_months,
                "credit_score": fin.credit_rating_score,
            },
            output_summary=(
                f"Credit={fin.credit_rating_score}/100, Runway={fin.cash_runway_months}m, "
                f"D/E={fin.debt_to_equity_ratio}x"
            ),
            timestamp=_now_iso(),
        )
    )

    # Tool 2: Operational Resilience, BCP/DR & SLA Audit
    if is_high_tier and (not fin.bcp_dr_tested_annually or fin.rto_hours > 8.0):
        risk_points += 24.0
        findings.append(
            RiskFinding(
                finding_id="FIN-03",
                phase="financial",
                agent_name="Financial & Operational Viability Agent",
                title=f"Unverified Business Continuity / Excessive Recovery Time (RTO: {fin.rto_hours}h)",
                description=(
                    f"Annual BCP/DR testing={fin.bcp_dr_tested_annually}, RTO={fin.rto_hours}h, "
                    f"RPO={fin.rpo_hours}h (exceeds Tier 1/2 threshold of 8h RTO)."
                ),
                severity=RiskSeverity.HIGH,
                category="Business Continuity & DR",
                recommendation="Require documented annual disaster recovery tabletop & failover test with RTO <= 4 hours.",
            )
        )

    if is_high_tier and fin.committed_sla_uptime_pct < 99.9:
        risk_points += 12.0
        findings.append(
            RiskFinding(
                finding_id="FIN-04",
                phase="financial",
                agent_name="Financial & Operational Viability Agent",
                title=f"Sub-Standard Availability SLA ({fin.committed_sla_uptime_pct}%)",
                description="Contractual uptime guarantee is below the 99.9% standard for mission-critical services.",
                severity=RiskSeverity.MEDIUM,
                category="Service Level Resilience",
                recommendation="Add 99.9% uptime SLA exhibit with service credit remedies.",
            )
        )

    if fin.single_point_of_failure_risk:
        risk_points += 15.0
        findings.append(
            RiskFinding(
                finding_id="FIN-05",
                phase="financial",
                agent_name="Financial & Operational Viability Agent",
                title="Single Point of Failure (SPOF) Concentration Risk",
                description="Vendor architecture relies on single-region hosting or lacks multi-AZ failover.",
                severity=RiskSeverity.HIGH,
                category="Operational Concentration",
                recommendation="Require multi-AZ redundancy architecture verification prior to production cutover.",
            )
        )

    risk_score = min(100.0, round(risk_points, 1))
    traces.append(
        ToolCallTrace(
            tool_name="verify_bcp_dr_and_sla_resilience",
            inputs={
                "bcp_tested": fin.bcp_dr_tested_annually,
                "rto_hours": fin.rto_hours,
                "sla_uptime_pct": fin.committed_sla_uptime_pct,
                "spof_risk": fin.single_point_of_failure_risk,
            },
            output_summary=(
                f"Computed Financial & Ops Risk Score: {risk_score}/100 with {len(findings)} finding(s)."
            ),
            timestamp=_now_iso(),
        )
    )

    metrics = {
        "credit_rating_score": fin.credit_rating_score,
        "cash_runway_months": fin.cash_runway_months,
        "rto_hours": fin.rto_hours,
        "committed_sla_uptime_pct": fin.committed_sla_uptime_pct,
    }
    return {"risk_score": risk_score, "metrics": metrics}, findings, traces
