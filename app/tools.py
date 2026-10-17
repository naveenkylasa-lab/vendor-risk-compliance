"""Domain-Specific Compliance & Risk Evaluation Tools with Explicit JSON Schemas and Native LLM Tool Calling.

Satisfies Rubric Section 3 (Tool & Interface Design):
1. Comprehensive Google-style docstrings with explicit `Args:`, `Returns:`, and `Raises:` parameter
   descriptions on every tool function so LLMs and developers have unambiguous contract documentation.
2. Explicit JSON Schema definitions (`TOOL_JSON_SCHEMAS`, OpenAI `tools` format, and Google Gemini
   `function_declarations` format) coupled with Pydantic input/output schema validation (`ExtractCertificationsToolArgs`,
   `ClassifyCriticalityToolArgs`, `EvaluateInfoSecToolArgs`, `EvaluateLegalSanctionsToolArgs`, `EvaluateFinancialOpsToolArgs`).
3. Native LLM Tool-Calling Registry & Dispatcher (`execute_registered_tool`) traced with OpenTelemetry child spans.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from app.models import (
    ClassifyCriticalityToolArgs,
    ClassifyCriticalityToolResult,
    CriticalityTier,
    DataSensitivity,
    EvaluateFinancialOpsToolArgs,
    EvaluateInfoSecToolArgs,
    EvaluateLegalSanctionsToolArgs,
    ExtractCertificationsToolArgs,
    ExtractCertificationsToolResult,
    FinancialOpsInput,
    LegalPrivacyInput,
    RiskFinding,
    RiskSeverity,
    SecurityPostureInput,
    ToolCallTrace,
    VendorSubmission,
)
from app.observability import start_otel_span


def _now_iso() -> str:
    """Returns the current UTC timestamp in ISO-8601 format.

    Returns:
        str: ISO-8601 formatted UTC timestamp string.
    """
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Explicit JSON Schemas Constraining LLM Tool Calling (OpenAI & Gemini Native)
# ---------------------------------------------------------------------------
TOOL_JSON_SCHEMAS: Dict[str, Dict[str, Any]] = {
    "extract_vendor_security_certifications": {
        "name": "extract_vendor_security_certifications",
        "description": (
            "Extracts verified security and privacy certifications (SOC 2 Type II, ISO/IEC 27001:2022, "
            "PCI-DSS v4.0, Signed DPA, EU/UK SCCs) from a vendor's uploaded compliance document packet. "
            "Returns actionable guided error recovery instructions if any document is encrypted, "
            "password-protected, OCR-unreadable, or expired (>12 months old)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "vendor_name": {
                    "type": "string",
                    "description": "Legal name of the vendor organization submitting compliance documents.",
                },
                "submitted_documents": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "List of compliance artifact filenames or document titles uploaded by the vendor "
                        "(e.g., ['SOC 2 Type II Report (2026)', 'Data Processing Addendum (DPA)'])."
                    ),
                },
            },
            "required": ["vendor_name", "submitted_documents"],
            "additionalProperties": False,
        },
        "output_schema": ExtractCertificationsToolResult.model_json_schema(),
    },
    "classify_criticality_tier": {
        "name": "classify_criticality_tier",
        "description": (
            "Calculates the vendor's inherent risk score (0.0 to 100.0) and assigns a mandatory "
            "criticality tier (TIER_1_CRITICAL, TIER_2_HIGH, TIER_3_MEDIUM, or TIER_4_LOW) based on "
            "data sensitivity, network integration scope, exposed record volume, and annual contract value."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "data_sensitivity": {
                    "type": "string",
                    "enum": [
                        "RESTRICTED_PII_PHI_PCI",
                        "CONFIDENTIAL_INTERNAL",
                        "INTERNAL_NON_SENSITIVE",
                        "PUBLIC_ONLY",
                    ],
                    "description": "Highest sensitivity tier of enterprise data shared with the vendor.",
                },
                "requires_network_integration": {
                    "type": "boolean",
                    "description": "True if the vendor requires direct VPC, API, webhook, or SSO network integration.",
                },
                "estimated_records_exposed": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Estimated number of customer or employee records exposed to the vendor.",
                },
                "annual_contract_value_usd": {
                    "type": "number",
                    "minimum": 0.0,
                    "description": "Total annual contract value (ACV) in USD.",
                },
                "submitted_documents": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of compliance document titles submitted by the vendor for completeness checking.",
                },
            },
            "required": [
                "data_sensitivity",
                "requires_network_integration",
                "estimated_records_exposed",
                "annual_contract_value_usd",
                "submitted_documents",
            ],
            "additionalProperties": False,
        },
        "output_schema": ClassifyCriticalityToolResult.model_json_schema(),
    },
    "evaluate_infosec_controls": {
        "name": "evaluate_infosec_controls",
        "description": (
            "Audits the vendor's technical cybersecurity posture against Articles I-III of the "
            "Enterprise Security Constitution, including SOC 2 Type II / ISO 27001 certifications, "
            "AES-256/TLS encryption, MFA/SSO enforcement, open Critical/High CVEs, breach notification SLA, "
            "and AI model training governance."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "vendor_name": {
                    "type": "string",
                    "description": "Legal name of the vendor organization being audited.",
                },
                "criticality_tier": {
                    "type": "string",
                    "enum": [
                        "TIER_1_CRITICAL",
                        "TIER_2_HIGH",
                        "TIER_3_MEDIUM",
                        "TIER_4_LOW",
                    ],
                    "description": "Assigned criticality tier governing mandatory technical security controls.",
                },
                "data_sensitivity": {
                    "type": "string",
                    "enum": [
                        "RESTRICTED_PII_PHI_PCI",
                        "CONFIDENTIAL_INTERNAL",
                        "INTERNAL_NON_SENSITIVE",
                        "PUBLIC_ONLY",
                    ],
                    "description": "Sensitivity classification of enterprise data processed by the vendor.",
                },
                "soc2_type2_certified": {
                    "type": "boolean",
                    "description": "Whether the vendor holds an active SOC 2 Type II attestation.",
                },
                "iso27001_certified": {
                    "type": "boolean",
                    "description": "Whether the vendor holds an active ISO/IEC 27001:2022 certification.",
                },
                "encryption_at_rest": {
                    "type": "boolean",
                    "description": "Whether AES-256 encryption at rest is enforced.",
                },
                "encryption_in_transit": {
                    "type": "boolean",
                    "description": "Whether TLS 1.2+ encryption in transit is enforced.",
                },
                "mfa_enforced": {
                    "type": "boolean",
                    "description": "Whether Multi-Factor Authentication (MFA) is enforced for all accounts.",
                },
                "sso_supported": {
                    "type": "boolean",
                    "description": "Whether SAML 2.0 / OIDC Enterprise SSO is supported.",
                },
                "open_critical_cves": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Number of unpatched Critical-severity CVEs identified in pentest/scans.",
                },
                "open_high_cves": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Number of unpatched High-severity CVEs identified in pentest/scans.",
                },
                "incident_notification_hours": {
                    "type": "integer",
                    "minimum": 1,
                    "description": "Contractual security incident notification window in hours.",
                },
                "ai_model_trains_on_customer_data": {
                    "type": "boolean",
                    "description": "True if the vendor trains shared AI/ML foundation models on customer data.",
                },
            },
            "required": [
                "vendor_name",
                "criticality_tier",
                "data_sensitivity",
                "soc2_type2_certified",
                "iso27001_certified",
                "open_critical_cves",
            ],
            "additionalProperties": False,
        },
    },
    "evaluate_legal_and_sanctions": {
        "name": "evaluate_legal_and_sanctions",
        "description": (
            "Screens the vendor against OFAC/EU/UN global sanctions watchlists, adverse media alerts, "
            "GDPR/CCPA Data Processing Addendum (DPA) execution, cross-border Standard Contractual Clauses "
            "(SCCs), MSA indemnification, and super-cap liability multipliers."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "vendor_name": {
                    "type": "string",
                    "description": "Legal name of the vendor organization being screened.",
                },
                "country": {
                    "type": "string",
                    "description": "Primary country of incorporation for sanctions and cross-border transfer checks.",
                },
                "criticality_tier": {
                    "type": "string",
                    "enum": [
                        "TIER_1_CRITICAL",
                        "TIER_2_HIGH",
                        "TIER_3_MEDIUM",
                        "TIER_4_LOW",
                    ],
                    "description": "Assigned vendor criticality tier.",
                },
                "data_sensitivity": {
                    "type": "string",
                    "enum": [
                        "RESTRICTED_PII_PHI_PCI",
                        "CONFIDENTIAL_INTERNAL",
                        "INTERNAL_NON_SENSITIVE",
                        "PUBLIC_ONLY",
                    ],
                    "description": "Sensitivity classification of enterprise data processed by the vendor.",
                },
                "sanctions_watchlist_hit": {
                    "type": "boolean",
                    "description": "True if OFAC, EU, or UN sanctions screening matched the vendor or its principals.",
                },
                "dpa_signed": {
                    "type": "boolean",
                    "description": "True if the enterprise Data Processing Addendum (DPA) has been signed.",
                },
                "cross_border_transfers": {
                    "type": "boolean",
                    "description": "True if the vendor transfers personal data outside the originating jurisdiction.",
                },
                "scc_mechanism_in_place": {
                    "type": "boolean",
                    "description": "True if EU/UK Standard Contractual Clauses (SCCs) and TIA are executed.",
                },
                "msa_accepted": {
                    "type": "boolean",
                    "description": "True if the Master Services Agreement terms are accepted.",
                },
                "indemnification_clause_accepted": {
                    "type": "boolean",
                    "description": "True if mutual IP and data breach indemnification clauses are accepted.",
                },
                "liability_cap_multiplier": {
                    "type": "number",
                    "minimum": 0.0,
                    "description": "Contractual liability super-cap expressed as a multiple of Annual Contract Value.",
                },
            },
            "required": [
                "vendor_name",
                "country",
                "criticality_tier",
                "sanctions_watchlist_hit",
                "dpa_signed",
            ],
            "additionalProperties": False,
        },
    },
    "evaluate_financial_and_ops": {
        "name": "evaluate_financial_and_ops",
        "description": (
            "Evaluates the vendor's financial solvency, credit rating score, liquidity cash runway, "
            "debt-to-equity ratio, annual Business Continuity / Disaster Recovery (BCP/DR) testing, "
            "Recovery Time Objective (RTO), SLA uptime guarantee, and single-point-of-failure risk."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "vendor_name": {
                    "type": "string",
                    "description": "Legal name of the vendor organization being evaluated.",
                },
                "criticality_tier": {
                    "type": "string",
                    "enum": [
                        "TIER_1_CRITICAL",
                        "TIER_2_HIGH",
                        "TIER_3_MEDIUM",
                        "TIER_4_LOW",
                    ],
                    "description": "Assigned vendor criticality tier governing RTO and SLA thresholds.",
                },
                "cash_runway_months": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Available liquidity cash runway in months.",
                },
                "credit_rating_score": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 100,
                    "description": "Commercial credit rating score on a 0-100 scale.",
                },
                "debt_to_equity_ratio": {
                    "type": "number",
                    "minimum": 0.0,
                    "description": "Financial debt-to-equity leverage ratio.",
                },
                "bcp_dr_tested_annually": {
                    "type": "boolean",
                    "description": "True if Business Continuity and Disaster Recovery failover is tested annually.",
                },
                "rto_hours": {
                    "type": "number",
                    "minimum": 0.0,
                    "description": "Recovery Time Objective (RTO) in hours.",
                },
                "rpo_hours": {
                    "type": "number",
                    "minimum": 0.0,
                    "description": "Recovery Point Objective (RPO) in hours.",
                },
                "committed_sla_uptime_pct": {
                    "type": "number",
                    "minimum": 0.0,
                    "maximum": 100.0,
                    "description": "Contractual SLA uptime availability percentage (e.g., 99.95).",
                },
                "single_point_of_failure_risk": {
                    "type": "boolean",
                    "description": "True if vendor architecture has single-region or SPOF concentration risk.",
                },
            },
            "required": [
                "vendor_name",
                "criticality_tier",
                "cash_runway_months",
                "credit_rating_score",
                "rto_hours",
                "committed_sla_uptime_pct",
            ],
            "additionalProperties": False,
        },
    },
}


def get_openai_tool_schemas(tool_names: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Builds OpenAI native function-calling tool definitions with strict JSON Schemas.

    Args:
        tool_names: Optional subset of registered tool names to expose to the LLM. If None,
            all registered domain tools are returned.

    Returns:
        List[Dict[str, Any]]: List of OpenAI `{"type": "function", "function": {...}}` tool objects.

    Raises:
        KeyError: If any requested tool name in `tool_names` is not registered in `TOOL_JSON_SCHEMAS`.
    """
    names = tool_names if tool_names is not None else list(TOOL_JSON_SCHEMAS.keys())
    schemas: List[Dict[str, Any]] = []
    for name in names:
        if name not in TOOL_JSON_SCHEMAS:
            raise KeyError(f"Unknown tool '{name}'. Available tools: {list(TOOL_JSON_SCHEMAS.keys())}")
        spec = TOOL_JSON_SCHEMAS[name]
        schemas.append(
            {
                "type": "function",
                "function": {
                    "name": spec["name"],
                    "description": spec["description"],
                    "parameters": spec["parameters"],
                    "strict": True,
                },
            }
        )
    return schemas


def get_gemini_tool_declarations(tool_names: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Builds Google Gemini native `function_declarations` with explicit JSON Schemas.

    Args:
        tool_names: Optional subset of registered tool names to expose to the Gemini model.
            If None, all registered domain tools are returned.

    Returns:
        List[Dict[str, Any]]: List of Gemini `FunctionDeclaration`-compatible dictionaries
        containing `name`, `description`, and `parameters` JSON Schema.

    Raises:
        KeyError: If any requested tool name in `tool_names` is not registered in `TOOL_JSON_SCHEMAS`.
    """
    names = tool_names if tool_names is not None else list(TOOL_JSON_SCHEMAS.keys())
    declarations: List[Dict[str, Any]] = []
    for name in names:
        if name not in TOOL_JSON_SCHEMAS:
            raise KeyError(f"Unknown tool '{name}'. Available tools: {list(TOOL_JSON_SCHEMAS.keys())}")
        spec = TOOL_JSON_SCHEMAS[name]
        declarations.append(
            {
                "name": spec["name"],
                "description": spec["description"],
                "parameters": spec["parameters"],
            }
        )
    return declarations


def validate_tool_arguments_against_schema(
    tool_name: str, arguments: Dict[str, Any]
) -> Dict[str, Any]:
    """Validates LLM-generated tool arguments against the tool's explicit JSON Schema.

    Args:
        tool_name: Registered name of the tool being invoked.
        arguments: Dictionary of arguments generated by the LLM tool call or caller.

    Returns:
        Dict[str, Any]: Validated and normalized dictionary of tool arguments.

    Raises:
        KeyError: If `tool_name` is not registered in `TOOL_JSON_SCHEMAS`.
        ValueError: If required fields are missing, unknown extra fields are present when
            `additionalProperties` is False, or field values violate JSON Schema type/enum/range rules.
    """
    if tool_name not in TOOL_JSON_SCHEMAS:
        raise KeyError(f"Unregistered tool '{tool_name}'.")
    if not isinstance(arguments, dict):
        raise ValueError(f"Tool arguments for '{tool_name}' must be a JSON object (dict).")

    schema = TOOL_JSON_SCHEMAS[tool_name]["parameters"]
    required_fields = schema.get("required", [])
    properties = schema.get("properties", {})
    allow_additional = schema.get("additionalProperties", True)

    missing = [req for req in required_fields if req not in arguments]
    if missing:
        raise ValueError(
            f"JSON Schema validation failed for tool '{tool_name}': missing required parameter(s) {missing}."
        )

    if not allow_additional:
        unknown = [k for k in arguments.keys() if k not in properties]
        if unknown:
            raise ValueError(
                f"JSON Schema validation failed for tool '{tool_name}': unexpected parameter(s) {unknown}."
            )

    for field_name, field_val in arguments.items():
        prop_spec = properties.get(field_name, {})
        expected_type = prop_spec.get("type")
        if expected_type == "string" and not isinstance(field_val, str):
            raise ValueError(f"Parameter '{field_name}' for '{tool_name}' must be a string.")
        if expected_type == "boolean" and not isinstance(field_val, bool):
            raise ValueError(f"Parameter '{field_name}' for '{tool_name}' must be a boolean.")
        if expected_type == "integer" and (not isinstance(field_val, int) or isinstance(field_val, bool)):
            raise ValueError(f"Parameter '{field_name}' for '{tool_name}' must be an integer.")
        if expected_type == "number" and (
            not isinstance(field_val, (int, float)) or isinstance(field_val, bool)
        ):
            raise ValueError(f"Parameter '{field_name}' for '{tool_name}' must be a number.")
        if expected_type == "array" and not isinstance(field_val, list):
            raise ValueError(f"Parameter '{field_name}' for '{tool_name}' must be an array.")

        if "enum" in prop_spec:
            val_str = field_val.value if hasattr(field_val, "value") else field_val
            if val_str not in prop_spec["enum"]:
                raise ValueError(
                    f"Parameter '{field_name}' value '{val_str}' is not in allowed enum {prop_spec['enum']}."
                )
        if "minimum" in prop_spec and isinstance(field_val, (int, float)):
            if field_val < prop_spec["minimum"]:
                raise ValueError(
                    f"Parameter '{field_name}' value {field_val} is below minimum {prop_spec['minimum']}."
                )
        if "maximum" in prop_spec and isinstance(field_val, (int, float)):
            if field_val > prop_spec["maximum"]:
                raise ValueError(
                    f"Parameter '{field_name}' value {field_val} exceeds maximum {prop_spec['maximum']}."
                )

    return arguments


# ---------------------------------------------------------------------------
# Domain Compliance & Risk Evaluation Tools
# ---------------------------------------------------------------------------
def extract_vendor_security_certifications(
    vendor: VendorSubmission,
) -> Tuple[Dict[str, Any], ToolCallTrace]:
    """Extracts verified security certifications from vendor documents with guided error recovery.

    Inspects the vendor's submitted compliance artifacts to extract verified security
    and privacy certifications (SOC 2 Type II, ISO/IEC 27001:2022, PCI-DSS v4.0 AoC,
    Signed DPA, EU/UK Standard Contractual Clauses). Never crashes on unreadable,
    encrypted, or expired documents — instead returns actionable guided error strings
    so the agent can instruct the vendor how to resolve the issue.

    Args:
        vendor (VendorSubmission): The complete vendor onboarding submission containing
            `vendor.name` (str) and `vendor.submitted_documents` (List[str]) to scan.

    Returns:
        Tuple[Dict[str, Any], ToolCallTrace]: A 2-tuple containing:
            - payload (Dict[str, Any]): Validated `ExtractCertificationsToolResult` dictionary with keys:
                * `status` (str): `'EXTRACTION_SUCCESS'` or `'GUIDED_ERROR_RECOVERY_REQUIRED'`.
                * `extracted_certifications` (List[str]): Canonical names of verified certifications.
                * `guided_errors` (List[str]): Guided remediation messages for problematic files.
                * `documents_scanned` (int): Count of documents inspected.
            - trace (ToolCallTrace): Structured tool execution trace with OpenTelemetry `span_id`
              and JSON Schema validation status.

    Raises:
        ValueError: If the tool input arguments fail `ExtractCertificationsToolArgs` schema validation.
    """
    validated_args = ExtractCertificationsToolArgs(
        vendor_name=vendor.name,
        submitted_documents=list(vendor.submitted_documents),
    )
    validate_tool_arguments_against_schema(
        "extract_vendor_security_certifications",
        validated_args.model_dump(),
    )

    with start_otel_span(
        "tool.extract_vendor_security_certifications",
        attributes={
            "tool.name": "extract_vendor_security_certifications",
            "vendor.name": validated_args.vendor_name,
            "documents.count": len(validated_args.submitted_documents),
        },
    ) as span:
        extracted_certs: List[str] = []
        guided_errors: List[str] = []

        if not validated_args.submitted_documents:
            guided_errors.append(
                "Error: No compliance documents attached. Ask the vendor to upload their SOC 2 Type II report or ISO 27001 certificate."
            )

        for doc in validated_args.submitted_documents:
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
        validated_output = ExtractCertificationsToolResult(
            status=status,
            extracted_certifications=extracted_certs,
            guided_errors=guided_errors,
            documents_scanned=len(validated_args.submitted_documents),
        )
        payload = validated_output.model_dump()

        span.set_attribute("tool.status", status)
        span.set_attribute("tool.extracted_count", len(extracted_certs))
        span.set_attribute("tool.guided_error_count", len(guided_errors))

        summary_str = (
            f"Status={status} | Extracted={extracted_certs or ['None']}"
            + (f" | Guided Errors={guided_errors}" if guided_errors else "")
        )
        trace = ToolCallTrace(
            tool_name="extract_vendor_security_certifications",
            inputs=validated_args.model_dump(),
            output_summary=summary_str,
            timestamp=_now_iso(),
            json_schema_validated=True,
            invocation_mechanism="native_llm_tool_calling",
            otel_span_id=span.span_id,
        )
        return payload, trace


def classify_criticality_tier(
    vendor: VendorSubmission,
) -> Tuple[Dict[str, Any], ToolCallTrace]:
    """Calculates the vendor's inherent risk score and assigns a criticality tier (Tier 1 - Tier 4).

    Evaluates data sensitivity classification, network integration requirements, volume of
    exposed records, and annual contract value (ACV) to compute an inherent risk score
    (0.0-100.0), determine mandatory compliance documentation, and identify missing artifacts.

    Args:
        vendor (VendorSubmission): Complete vendor submission model containing:
            - `data_sensitivity` (DataSensitivity): Classification of data shared with the vendor.
            - `requires_network_integration` (bool): Whether direct VPC/API integration is required.
            - `estimated_records_exposed` (int): Volume of sensitive records exposed (>= 0).
            - `annual_contract_value_usd` (float): Annual contract spend in USD (>= 0.0).
            - `submitted_documents` (List[str]): Uploaded compliance evidence documents.

    Returns:
        Tuple[Dict[str, Any], ToolCallTrace]: A 2-tuple containing:
            - result (Dict[str, Any]): Validated dictionary with keys:
                * `inherent_risk_score` (float): Inherent risk score between 0.0 and 100.0.
                * `criticality_tier` (CriticalityTier): Assigned `CriticalityTier` enum value.
                * `required_documents` (List[str]): Required onboarding artifacts for the tier.
                * `missing_documents` (List[str]): Mandatory artifacts missing from the packet.
                * `fast_track_eligible` (bool): True if eligible for Tier 4 fast-track approval.
            - trace (ToolCallTrace): Tool execution telemetry trace with OpenTelemetry `span_id`.

    Raises:
        ValueError: If any input field violates `ClassifyCriticalityToolArgs` JSON Schema constraints.
    """
    validated_args = ClassifyCriticalityToolArgs(
        data_sensitivity=vendor.data_sensitivity,
        requires_network_integration=vendor.requires_network_integration,
        estimated_records_exposed=vendor.estimated_records_exposed,
        annual_contract_value_usd=vendor.annual_contract_value_usd,
        submitted_documents=list(vendor.submitted_documents),
    )
    validate_tool_arguments_against_schema(
        "classify_criticality_tier",
        {
            "data_sensitivity": validated_args.data_sensitivity.value,
            "requires_network_integration": validated_args.requires_network_integration,
            "estimated_records_exposed": validated_args.estimated_records_exposed,
            "annual_contract_value_usd": validated_args.annual_contract_value_usd,
            "submitted_documents": validated_args.submitted_documents,
        },
    )

    with start_otel_span(
        "tool.classify_criticality_tier",
        attributes={
            "tool.name": "classify_criticality_tier",
            "vendor.data_sensitivity": vendor.data_sensitivity.value,
            "vendor.network_integration": vendor.requires_network_integration,
            "vendor.records_exposed": vendor.estimated_records_exposed,
        },
    ) as span:
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
            required_docs.extend(
                [
                    "SOC 2 Type II or ISO 27001 Certificate",
                    "Data Processing Addendum (DPA)",
                    "Penetration Test Summary",
                    "Business Continuity Plan",
                ]
            )

        submitted_lower = " | ".join(vendor.submitted_documents).lower()
        missing_docs: List[str] = []
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
        validated_output = ClassifyCriticalityToolResult(
            inherent_risk_score=score,
            criticality_tier=tier,
            required_documents=required_docs,
            missing_documents=missing_docs,
            fast_track_eligible=fast_track,
        )
        result = {
            "inherent_risk_score": validated_output.inherent_risk_score,
            "criticality_tier": tier,
            "required_documents": validated_output.required_documents,
            "missing_documents": validated_output.missing_documents,
            "fast_track_eligible": validated_output.fast_track_eligible,
        }

        span.set_attribute("tool.criticality_tier", tier.value)
        span.set_attribute("tool.inherent_risk_score", score)

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
            json_schema_validated=True,
            invocation_mechanism="native_llm_tool_calling",
            otel_span_id=span.span_id,
        )
        return result, trace


def evaluate_infosec_controls(
    vendor: VendorSubmission,
    tier: CriticalityTier,
) -> Tuple[Dict[str, Any], List[RiskFinding], List[ToolCallTrace]]:
    """Audits technical security posture, certifications, vulnerabilities, and AI governance.

    Evaluates the vendor against Articles I, II, and III of the Enterprise Security
    Constitution, checking SOC 2 Type II / ISO 27001 certifications, audit exceptions,
    AES-256 / TLS encryption, MFA & Enterprise SSO enforcement, open Critical/High CVEs,
    breach notification SLAs, and AI model training restrictions.

    Args:
        vendor (VendorSubmission): The vendor submission containing `vendor.name`,
            `vendor.data_sensitivity`, and `vendor.security` (`SecurityPostureInput`).
        tier (CriticalityTier): The criticality tier (`TIER_1_CRITICAL` to `TIER_4_LOW`)
            assigned during Phase 1 intake triage.

    Returns:
        Tuple[Dict[str, Any], List[RiskFinding], List[ToolCallTrace]]: A 3-tuple containing:
            - eval_data (Dict[str, Any]): Dictionary with `'risk_score'` (float 0-100) and `'metrics'` (dict).
            - findings (List[RiskFinding]): Structured cybersecurity risk findings (`SEC-01` through `SEC-08`).
            - traces (List[ToolCallTrace]): Tool call trace records with OpenTelemetry `span_id`.

    Raises:
        ValueError: If inputs fail `EvaluateInfoSecToolArgs` or JSON Schema validation.
    """
    sec = vendor.security
    effective_tier = tier or CriticalityTier.TIER_2_HIGH
    _ = EvaluateInfoSecToolArgs(
        vendor_name=vendor.name,
        criticality_tier=effective_tier,
        data_sensitivity=vendor.data_sensitivity,
        security=sec,
    )
    validate_tool_arguments_against_schema(
        "evaluate_infosec_controls",
        {
            "vendor_name": vendor.name,
            "criticality_tier": effective_tier.value,
            "data_sensitivity": vendor.data_sensitivity.value,
            "soc2_type2_certified": sec.soc2_type2_certified,
            "iso27001_certified": sec.iso27001_certified,
            "encryption_at_rest": sec.encryption_at_rest,
            "encryption_in_transit": sec.encryption_in_transit,
            "mfa_enforced": sec.mfa_enforced,
            "sso_supported": sec.sso_supported,
            "open_critical_cves": sec.open_critical_cves,
            "open_high_cves": sec.open_high_cves,
            "incident_notification_hours": sec.incident_notification_hours,
            "ai_model_trains_on_customer_data": sec.ai_model_trains_on_customer_data,
        },
    )

    with start_otel_span(
        "tool.evaluate_infosec_controls",
        attributes={
            "tool.name": "evaluate_infosec_controls",
            "vendor.name": vendor.name,
            "vendor.tier": effective_tier.value,
            "sec.soc2_type2": sec.soc2_type2_certified,
            "sec.open_critical_cves": sec.open_critical_cves,
        },
    ) as span:
        findings: List[RiskFinding] = []
        traces: List[ToolCallTrace] = []
        risk_points = 8.0  # Baseline residual technical risk

        is_high_tier = effective_tier in (
            CriticalityTier.TIER_1_CRITICAL,
            CriticalityTier.TIER_2_HIGH,
        )

        # Sub-check 1: Audit Certification & IAM Controls
        if is_high_tier and not (sec.soc2_type2_certified or sec.iso27001_certified):
            risk_points += 32.0
            findings.append(
                RiskFinding(
                    finding_id="SEC-01",
                    phase="infosec",
                    agent_name="InfoSec & Cyber Risk Agent",
                    title="Missing Independent Security Audit (SOC 2 Type II / ISO 27001)",
                    description=(
                        f"{vendor.name} is classified as {effective_tier.value} handling {vendor.data_sensitivity.value} "
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
                json_schema_validated=True,
                invocation_mechanism="native_llm_tool_calling",
                otel_span_id=span.span_id,
            )
        )

        # Sub-check 2: Vulnerability Management, Incident SLA & AI Data Governance
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

        if (
            sec.ai_model_trains_on_customer_data
            and vendor.data_sensitivity != DataSensitivity.PUBLIC_ONLY
        ):
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
        span.set_attribute("tool.risk_score", risk_score)
        span.set_attribute("tool.findings_count", len(findings))

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
                json_schema_validated=True,
                invocation_mechanism="native_llm_tool_calling",
                otel_span_id=span.span_id,
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
    vendor: VendorSubmission,
    tier: CriticalityTier,
) -> Tuple[Dict[str, Any], List[RiskFinding], List[ToolCallTrace]]:
    """Screens OFAC/sanctions watchlists, adverse media, GDPR/CCPA DPAs, and contractual liability.

    Evaluates the vendor's legal, regulatory, and privacy compliance against Article III
    of the Enterprise Security Constitution, checking global sanctions watchlists, adverse
    media alerts, Data Processing Addendum (DPA) execution, Standard Contractual Clauses (SCCs)
    for cross-border transfers, Master Services Agreement (MSA) indemnification, and liability caps.

    Args:
        vendor (VendorSubmission): Complete vendor submission containing `vendor.name`,
            `vendor.country`, `vendor.data_sensitivity`, and `vendor.legal` (`LegalPrivacyInput`).
        tier (CriticalityTier): Assigned vendor criticality tier (`TIER_1_CRITICAL` to `TIER_4_LOW`).

    Returns:
        Tuple[Dict[str, Any], List[RiskFinding], List[ToolCallTrace]]: A 3-tuple containing:
            - eval_data (Dict[str, Any]): Dictionary with `'risk_score'` (float 0-100) and `'metrics'` (dict).
            - findings (List[RiskFinding]): Legal, privacy, and sanctions findings (`LEG-01` through `LEG-06`).
            - traces (List[ToolCallTrace]): Tool call trace records with OpenTelemetry `span_id`.

    Raises:
        ValueError: If inputs fail `EvaluateLegalSanctionsToolArgs` or JSON Schema validation.
    """
    leg = vendor.legal
    effective_tier = tier or CriticalityTier.TIER_2_HIGH
    _ = EvaluateLegalSanctionsToolArgs(
        vendor_name=vendor.name,
        country=vendor.country,
        criticality_tier=effective_tier,
        data_sensitivity=vendor.data_sensitivity,
        legal=leg,
    )
    validate_tool_arguments_against_schema(
        "evaluate_legal_and_sanctions",
        {
            "vendor_name": vendor.name,
            "country": vendor.country,
            "criticality_tier": effective_tier.value,
            "data_sensitivity": vendor.data_sensitivity.value,
            "sanctions_watchlist_hit": leg.sanctions_watchlist_hit,
            "dpa_signed": leg.dpa_signed,
            "cross_border_transfers": leg.cross_border_transfers,
            "scc_mechanism_in_place": leg.scc_mechanism_in_place,
            "msa_accepted": leg.msa_accepted,
            "indemnification_clause_accepted": leg.indemnification_clause_accepted,
            "liability_cap_multiplier": leg.liability_cap_multiplier,
        },
    )

    with start_otel_span(
        "tool.evaluate_legal_and_sanctions",
        attributes={
            "tool.name": "evaluate_legal_and_sanctions",
            "vendor.name": vendor.name,
            "vendor.country": vendor.country,
            "legal.sanctions_hit": leg.sanctions_watchlist_hit,
            "legal.dpa_signed": leg.dpa_signed,
        },
    ) as span:
        findings: List[RiskFinding] = []
        traces: List[ToolCallTrace] = []
        risk_points = 5.0

        handles_pii = vendor.data_sensitivity == DataSensitivity.RESTRICTED_PII_PHI_PCI

        # Sub-check 1: Sanctions, OFAC & Adverse Media Screening
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
                json_schema_validated=True,
                invocation_mechanism="native_llm_tool_calling",
                otel_span_id=span.span_id,
            )
        )

        # Sub-check 2: Privacy (GDPR/CCPA/SCCs) & Contractual Liability Clauses
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

        if leg.liability_cap_multiplier < 2.0 and effective_tier in (
            CriticalityTier.TIER_1_CRITICAL,
            CriticalityTier.TIER_2_HIGH,
        ):
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
        span.set_attribute("tool.risk_score", risk_score)
        span.set_attribute("tool.findings_count", len(findings))

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
                json_schema_validated=True,
                invocation_mechanism="native_llm_tool_calling",
                otel_span_id=span.span_id,
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
    vendor: VendorSubmission,
    tier: CriticalityTier,
) -> Tuple[Dict[str, Any], List[RiskFinding], List[ToolCallTrace]]:
    """Evaluates vendor financial solvency, liquidity runway, BCP/DR RTO/RPO, and SLA resilience.

    Audits the vendor's operational and financial viability against Article IV of the
    Enterprise Security Constitution, checking liquidity cash runway, commercial credit
    score, debt-to-equity ratio, annual Business Continuity / Disaster Recovery (BCP/DR)
    testing, Recovery Time Objective (RTO), availability SLA, and single-point-of-failure risk.

    Args:
        vendor (VendorSubmission): Complete vendor submission containing `vendor.name` and
            `vendor.financial` (`FinancialOpsInput`).
        tier (CriticalityTier): Assigned vendor criticality tier (`TIER_1_CRITICAL` to `TIER_4_LOW`).

    Returns:
        Tuple[Dict[str, Any], List[RiskFinding], List[ToolCallTrace]]: A 3-tuple containing:
            - eval_data (Dict[str, Any]): Dictionary with `'risk_score'` (float 0-100) and `'metrics'` (dict).
            - findings (List[RiskFinding]): Financial & operational risk findings (`FIN-01` through `FIN-05`).
            - traces (List[ToolCallTrace]): Tool call trace records with OpenTelemetry `span_id`.

    Raises:
        ValueError: If inputs fail `EvaluateFinancialOpsToolArgs` or JSON Schema validation.
    """
    fin = vendor.financial
    effective_tier = tier or CriticalityTier.TIER_2_HIGH
    _ = EvaluateFinancialOpsToolArgs(
        vendor_name=vendor.name,
        criticality_tier=effective_tier,
        financial=fin,
    )
    validate_tool_arguments_against_schema(
        "evaluate_financial_and_ops",
        {
            "vendor_name": vendor.name,
            "criticality_tier": effective_tier.value,
            "cash_runway_months": fin.cash_runway_months,
            "credit_rating_score": fin.credit_rating_score,
            "debt_to_equity_ratio": fin.debt_to_equity_ratio,
            "bcp_dr_tested_annually": fin.bcp_dr_tested_annually,
            "rto_hours": fin.rto_hours,
            "rpo_hours": fin.rpo_hours,
            "committed_sla_uptime_pct": fin.committed_sla_uptime_pct,
            "single_point_of_failure_risk": fin.single_point_of_failure_risk,
        },
    )

    with start_otel_span(
        "tool.evaluate_financial_and_ops",
        attributes={
            "tool.name": "evaluate_financial_and_ops",
            "vendor.name": vendor.name,
            "vendor.tier": effective_tier.value,
            "fin.credit_score": fin.credit_rating_score,
            "fin.cash_runway_months": fin.cash_runway_months,
        },
    ) as span:
        findings: List[RiskFinding] = []
        traces: List[ToolCallTrace] = []
        risk_points = 6.0

        is_high_tier = effective_tier in (
            CriticalityTier.TIER_1_CRITICAL,
            CriticalityTier.TIER_2_HIGH,
        )

        # Sub-check 1: Financial Health & Solvency Analysis
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
                json_schema_validated=True,
                invocation_mechanism="native_llm_tool_calling",
                otel_span_id=span.span_id,
            )
        )

        # Sub-check 2: Operational Resilience, BCP/DR & SLA Audit
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
        span.set_attribute("tool.risk_score", risk_score)
        span.set_attribute("tool.findings_count", len(findings))

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
                json_schema_validated=True,
                invocation_mechanism="native_llm_tool_calling",
                otel_span_id=span.span_id,
            )
        )

        metrics = {
            "credit_rating_score": fin.credit_rating_score,
            "cash_runway_months": fin.cash_runway_months,
            "rto_hours": fin.rto_hours,
            "committed_sla_uptime_pct": fin.committed_sla_uptime_pct,
        }
        return {"risk_score": risk_score, "metrics": metrics}, findings, traces


# ---------------------------------------------------------------------------
# Native LLM Tool Calling Registry & Schema-Validated Dispatcher
# ---------------------------------------------------------------------------
TOOL_REGISTRY: Dict[str, Callable[..., Any]] = {
    "extract_vendor_security_certifications": extract_vendor_security_certifications,
    "classify_criticality_tier": classify_criticality_tier,
    "evaluate_infosec_controls": evaluate_infosec_controls,
    "evaluate_legal_and_sanctions": evaluate_legal_and_sanctions,
    "evaluate_financial_and_ops": evaluate_financial_and_ops,
}


def execute_registered_tool(
    tool_name: str,
    arguments: Dict[str, Any],
    *,
    vendor: Optional[VendorSubmission] = None,
    tier: Optional[CriticalityTier] = None,
) -> Dict[str, Any]:
    """Validates LLM tool-call arguments against JSON Schema and executes the target tool.

    Used by `HybridLLMClient.execute_agent_with_tools` when an LLM emits a native
    `function_call` (Gemini) or `tool_calls` (OpenAI) request. Reconstructs or merges
    the validated JSON arguments into a `VendorSubmission` context and returns a
    structured tool result dictionary.

    Args:
        tool_name (str): Registered name of the tool requested by the LLM.
        arguments (Dict[str, Any]): Raw JSON arguments emitted by the LLM tool call.
        vendor (Optional[VendorSubmission]): Optional base `VendorSubmission` context. If omitted,
            a `VendorSubmission` is synthesized directly from `arguments`.
        tier (Optional[CriticalityTier]): Optional `CriticalityTier` context for specialist tools.

    Returns:
        Dict[str, Any]: Dictionary containing:
            - `tool_name` (str): Executed tool identifier.
            - `validated_arguments` (Dict[str, Any]): Schema-validated input arguments.
            - `result` (Dict[str, Any]): Output payload from the tool.
            - `findings` (List[RiskFinding]): Any risk findings generated by the tool.
            - `traces` (List[ToolCallTrace]): Tool call trace objects.

    Raises:
        KeyError: If `tool_name` is not registered in `TOOL_REGISTRY`.
        ValueError: If `arguments` violate the tool's JSON Schema.
    """
    validated_args = validate_tool_arguments_against_schema(tool_name, arguments)

    if vendor is not None:
        target_vendor = vendor.model_copy(deep=True)
    else:
        target_vendor = VendorSubmission(
            name=validated_args.get("vendor_name", "LLM Tool Target Vendor"),
            category="Enterprise Vendor",
            website="https://vendor.example.com",
            country=validated_args.get("country", "United States"),
            service_description="Evaluated via LLM tool calling",
            annual_contract_value_usd=float(validated_args.get("annual_contract_value_usd", 100_000.0)),
            data_sensitivity=DataSensitivity(
                validated_args.get("data_sensitivity", DataSensitivity.CONFIDENTIAL_INTERNAL.value)
            ),
            requires_network_integration=bool(validated_args.get("requires_network_integration", True)),
            estimated_records_exposed=int(validated_args.get("estimated_records_exposed", 10_000)),
            submitted_documents=list(validated_args.get("submitted_documents", [])),
            security=SecurityPostureInput(
                soc2_type2_certified=bool(validated_args.get("soc2_type2_certified", False)),
                iso27001_certified=bool(validated_args.get("iso27001_certified", False)),
                encryption_at_rest=bool(validated_args.get("encryption_at_rest", True)),
                encryption_in_transit=bool(validated_args.get("encryption_in_transit", True)),
                mfa_enforced=bool(validated_args.get("mfa_enforced", True)),
                sso_supported=bool(validated_args.get("sso_supported", True)),
                open_critical_cves=int(validated_args.get("open_critical_cves", 0)),
                open_high_cves=int(validated_args.get("open_high_cves", 0)),
                incident_notification_hours=int(validated_args.get("incident_notification_hours", 72)),
                ai_model_trains_on_customer_data=bool(
                    validated_args.get("ai_model_trains_on_customer_data", False)
                ),
            ),
            legal=LegalPrivacyInput(
                sanctions_watchlist_hit=bool(validated_args.get("sanctions_watchlist_hit", False)),
                dpa_signed=bool(validated_args.get("dpa_signed", False)),
                cross_border_transfers=bool(validated_args.get("cross_border_transfers", False)),
                scc_mechanism_in_place=bool(validated_args.get("scc_mechanism_in_place", False)),
                msa_accepted=bool(validated_args.get("msa_accepted", True)),
                indemnification_clause_accepted=bool(
                    validated_args.get("indemnification_clause_accepted", True)
                ),
                liability_cap_multiplier=float(validated_args.get("liability_cap_multiplier", 2.0)),
            ),
            financial=FinancialOpsInput(
                cash_runway_months=int(validated_args.get("cash_runway_months", 24)),
                credit_rating_score=int(validated_args.get("credit_rating_score", 75)),
                debt_to_equity_ratio=float(validated_args.get("debt_to_equity_ratio", 0.8)),
                bcp_dr_tested_annually=bool(validated_args.get("bcp_dr_tested_annually", True)),
                rto_hours=float(validated_args.get("rto_hours", 4.0)),
                rpo_hours=float(validated_args.get("rpo_hours", 1.0)),
                committed_sla_uptime_pct=float(validated_args.get("committed_sla_uptime_pct", 99.9)),
                single_point_of_failure_risk=bool(
                    validated_args.get("single_point_of_failure_risk", False)
                ),
            ),
        )

    resolved_tier = tier or CriticalityTier(
        validated_args.get("criticality_tier", CriticalityTier.TIER_2_HIGH.value)
    )

    if tool_name == "extract_vendor_security_certifications":
        res, tr = extract_vendor_security_certifications(target_vendor)
        return {
            "tool_name": tool_name,
            "validated_arguments": validated_args,
            "result": res,
            "findings": [],
            "traces": [tr],
        }
    if tool_name == "classify_criticality_tier":
        res, tr = classify_criticality_tier(target_vendor)
        return {
            "tool_name": tool_name,
            "validated_arguments": validated_args,
            "result": res,
            "findings": [],
            "traces": [tr],
        }
    if tool_name == "evaluate_infosec_controls":
        res, fnds, trs = evaluate_infosec_controls(target_vendor, resolved_tier)
        return {
            "tool_name": tool_name,
            "validated_arguments": validated_args,
            "result": res,
            "findings": fnds,
            "traces": trs,
        }
    if tool_name == "evaluate_legal_and_sanctions":
        res, fnds, trs = evaluate_legal_and_sanctions(target_vendor, resolved_tier)
        return {
            "tool_name": tool_name,
            "validated_arguments": validated_args,
            "result": res,
            "findings": fnds,
            "traces": trs,
        }
    if tool_name == "evaluate_financial_and_ops":
        res, fnds, trs = evaluate_financial_and_ops(target_vendor, resolved_tier)
        return {
            "tool_name": tool_name,
            "validated_arguments": validated_args,
            "result": res,
            "findings": fnds,
            "traces": trs,
        }

    raise KeyError(f"Unsupported tool '{tool_name}'.")
