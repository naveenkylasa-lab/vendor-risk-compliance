"""CLI runner supporting Conversational Pattern (--ask), Sequential Pattern (--preset/--all), and Interactive HITL Code Stop (--interactive-hitl)."""

from __future__ import annotations

import argparse
import json
import sys

from app.agents.support_agent import handle_vendor_question
from app.models import HumanReviewDecisionRequest, OnboardingDecision, RiskSeverity
from app.orchestrator import orchestrator
from app.sample_vendors import SAMPLE_VENDORS, get_sample_vendors_map


def print_assessment_report(result, interactive_hitl: bool = False) -> None:
    dec = result.final_decision
    print("=" * 88)
    print(f"VENDOR ONBOARDING ASSESSMENT: {result.vendor.name} ({result.assessment_id})")
    print(f"Engine: {result.orchestrator_engine} | LLM Mode: {result.llm_provider_status}")
    print("=" * 88)
    print(f"Criticality Tier       : {dec.criticality_tier.value}")
    print(f"Composite Risk Score   : {dec.composite_risk_score}/100 ({dec.residual_risk_level.value})")
    print(f"Final Determination    : {dec.decision.value}")
    print("-" * 88)
    print("PHASE BREAKDOWN & STRATEGIC MODEL ROUTING:")
    for phase_id in ("intake", "infosec", "legal", "financial", "compliance_officer"):
        p = result.phase_assessments[phase_id]
        print(
            f"  • [{p.phase_name}] Score: {p.risk_score:5.1f}/100 | "
            f"Findings: {len(p.findings)} | Model: {p.llm_mode_used}"
        )
    print("-" * 88)
    print("EXECUTIVE MEMO:")
    print(f"  {dec.executive_memo}")
    if dec.remediation_plan:
        print("-" * 88)
        print(f"REMEDIATION ACTION PLAN ({len(dec.remediation_plan)} items):")
        for item in dec.remediation_plan:
            block_tag = "[BLOCKS GO-LIVE]" if item.blocking_go_live else "[POST-ONBOARDING]"
            print(f"  • {item.action_id} {block_tag} ({item.owner}): {item.requirement}")

    # Rubric Section 1: Human-in-the-Loop Code Stop when vendor is High/Critical Risk
    if dec.residual_risk_level in (RiskSeverity.HIGH, RiskSeverity.CRITICAL):
        print("-" * 88)
        print("⚠️  [HUMAN-IN-THE-LOOP CODE STOP TRIGGERED]")
        print(
            f"   Policy Checking Agent determined {result.vendor.name} is {dec.residual_risk_level.value} RISK."
        )
        if interactive_hitl and sys.stdin.isatty():
            choice = ""
            while choice not in ("approve", "reject"):
                choice = input("   Compliance Officer Action — Type 'approve' or 'reject' to finalize status: ").strip().lower()
            mapped = OnboardingDecision.APPROVED if choice == "approve" else OnboardingDecision.REJECTED
            orchestrator.apply_human_override(
                result.assessment_id,
                HumanReviewDecisionRequest(
                    decision=mapped,
                    reviewer_name="CLI Compliance Officer",
                    notes=f"Interactive HITL terminal sign-off: '{choice}'",
                ),
            )
            print(f"   -> Finalized Vendor Status: {result.final_decision.decision.value}")
        else:
            print("   Status paused in SQLite session store awaiting Compliance Officer 'approve' or 'reject'.")
    print("=" * 88 + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the Vendor Risk & Compliance Multi-Agent System (Conversational & Sequential Patterns)."
    )
    parser.add_argument(
        "--preset",
        type=str,
        default="VND-1001",
        help="Preset vendor ID to evaluate (VND-1001, VND-1002, VND-1003, VND-1004)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run Sequential pipeline across all 4 sample vendor onboarding packets",
    )
    parser.add_argument(
        "--ask",
        type=str,
        default=None,
        help="Ask a question as the vendor (triggers Conversational Pattern via Flash model + SQLite memory)",
    )
    parser.add_argument(
        "--interactive-hitl",
        action="store_true",
        help="Pause execution when High Risk is detected and prompt for 'approve' or 'reject'",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output full JSON result",
    )
    args = parser.parse_args()

    presets = get_sample_vendors_map()

    if args.ask:
        v = presets.get(args.preset, SAMPLE_VENDORS[0])
        chat_res = handle_vendor_question(
            vendor_id=v.vendor_id or "VND-1001",
            vendor_name=v.name,
            question=args.ask,
        )
        if args.json:
            print(json.dumps(chat_res, indent=2))
        else:
            print("=" * 88)
            print(f"CONVERSATIONAL PATTERN: {chat_res['intent_routing']['pattern']}")
            print(f"Routed Model : {chat_res['model_used']} | PII Redactions: {chat_res['pii_redactions_applied']}")
            print(f"Scrubbed Log : {chat_res['original_question_redacted']}")
            print("-" * 88)
            print(f"Support Agent Reply:\n  {chat_res['reply']}")
            print("=" * 88)
        return 0

    if args.all:
        for v in SAMPLE_VENDORS:
            res = orchestrator.run_pipeline(v.model_copy(deep=True))
            if args.json:
                print(json.dumps(res.model_dump(), indent=2))
            else:
                print_assessment_report(res, interactive_hitl=args.interactive_hitl)
        return 0

    if args.preset not in presets:
        print(f"Error: Unknown preset '{args.preset}'. Available: {list(presets.keys())}", file=sys.stderr)
        return 1

    res = orchestrator.run_pipeline(presets[args.preset].model_copy(deep=True))
    if args.json:
        print(json.dumps(res.model_dump(), indent=2))
    else:
        print_assessment_report(res, interactive_hitl=args.interactive_hitl)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
