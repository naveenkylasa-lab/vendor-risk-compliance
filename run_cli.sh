#!/usr/bin/env bash
# Runs `python3 cli.py "$@"` when Python 3 is available, or falls back to macOS built-in Ruby
# if Xcode Command Line Tools (`xcode-select --install`) have not been installed yet.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if python3 -c "import sys" >/dev/null 2>&1; then
  exec python3 cli.py "$@"
fi

# Fallback when macOS `/usr/bin/python3` stub requires Xcode Command Line Tools
exec /usr/bin/ruby -E UTF-8:UTF-8 - "${1:---all}" <<'RUBY_EOF'
# encoding: UTF-8
require 'json'
require 'securerandom'

arg = ARGV[0] || "--all"

VENDORS = [
  {
    vendor_id: "VND-1001",
    name: "CloudScale AI Inc.",
    category: "Enterprise AI & Cloud Data Platform",
    country: "United States",
    acv: 420_000,
    sensitivity: "RESTRICTED_PII_PHI_PCI",
    network: true,
    records: 250_000,
    docs: ["SOC 2 Type II Report (2026)", "Master Services Agreement (Redlined)", "Data Processing Addendum (DPA)", "Penetration Test Executive Summary"],
    sec: { soc2: true, soc2_exc: ["CC6.2: Quarterly access review for 2 contractor accounts was delayed by 14 days."], iso: false, enc: true, mfa: true, sso: true, crit_cves: 0, high_cves: 1, sla_hrs: 48, ai_train: false },
    leg: { msa: true, dpa: true, cross_border: true, scc: false, cap: 1.5, indemn: true, ofac: false, media: [] },
    fin: { credit: 78, runway: 22, de: 0.65, bcp: true, rto: 4.0, sla: 99.9, spof: false }
  },
  {
    vendor_id: "VND-1002",
    name: "PayStream Global Ltd.",
    category: "Payment Processing & Treasury Infrastructure",
    country: "United Kingdom",
    acv: 650_000,
    sensitivity: "RESTRICTED_PII_PHI_PCI",
    network: true,
    records: 500_000,
    docs: ["SOC 2 Type II Report (2026)", "ISO/IEC 27001:2022 Certificate", "Master Services Agreement (Signed)", "Data Processing Addendum & EU/UK SCCs", "Penetration Test Executive Summary"],
    sec: { soc2: true, soc2_exc: [], iso: true, enc: true, mfa: true, sso: true, crit_cves: 0, high_cves: 0, sla_hrs: 24, ai_train: false },
    leg: { msa: true, dpa: true, cross_border: true, scc: true, cap: 3.0, indemn: true, ofac: false, media: [] },
    fin: { credit: 92, runway: 48, de: 0.4, bcp: true, rto: 1.0, sla: 99.99, spof: false }
  },
  {
    vendor_id: "VND-1003",
    name: "ShadowAnalytics Corp.",
    category: "Customer Telemetry & Behavioral Enrichment",
    country: "Cayman Islands",
    acv: 190_000,
    sensitivity: "RESTRICTED_PII_PHI_PCI",
    network: true,
    records: 1_200_000,
    docs: ["Standard Vendor Terms of Service", "Self-Attested Security Questionnaire"],
    sec: { soc2: false, soc2_exc: [], iso: false, enc: true, mfa: false, sso: false, crit_cves: 2, high_cves: 5, sla_hrs: 168, ai_train: true },
    leg: { msa: false, dpa: false, cross_border: true, scc: false, cap: 0.5, indemn: false, ofac: true, media: ["2025 EU DPA inquiry", "Minority entity flagged on secondary OFAC jurisdiction watchlist"] },
    fin: { credit: 41, runway: 7, de: 2.4, bcp: false, rto: 48.0, sla: 99.0, spof: true }
  },
  {
    vendor_id: "VND-1004",
    name: "OfficePulse Ergonomics LLC",
    category: "Workplace Facilities & Office Equipment",
    country: "United States",
    acv: 35_000,
    sensitivity: "PUBLIC_ONLY",
    network: false,
    records: 0,
    docs: ["Master Services Agreement (Signed)", "W-9 & Vendor Banking Verification"],
    sec: { soc2: false, soc2_exc: [], iso: false, enc: true, mfa: true, sso: false, crit_cves: 0, high_cves: 0, sla_hrs: 72, ai_train: false },
    leg: { msa: true, dpa: false, cross_border: false, scc: false, cap: 2.0, indemn: true, ofac: false, media: [] },
    fin: { credit: 84, runway: 36, de: 0.5, bcp: true, rto: 24.0, sla: 99.5, spof: false }
  }
]

def evaluate_vendor(v)
  asm_id = "ASM-#{SecureRandom.hex(4).upcase}"
  # Phase 1: Intake
  inh = 10.0
  inh += 40.0 if v[:sensitivity] == "RESTRICTED_PII_PHI_PCI"
  inh += 20.0 if v[:network]
  inh += (v[:records] >= 500_000 ? 18.0 : v[:records] >= 100_000 ? 14.0 : v[:records] > 0 ? 8.0 : 0.0)
  inh += (v[:acv] >= 500_000 ? 12.0 : v[:acv] >= 150_000 ? 8.0 : 0.0)
  inh = [100.0, inh].min
  tier = inh >= 75 ? "TIER_1_CRITICAL" : inh >= 50 ? "TIER_2_HIGH" : inh >= 28 ? "TIER_3_MEDIUM" : "TIER_4_LOW"
  high_tier = ["TIER_1_CRITICAL", "TIER_2_HIGH"].include?(tier)

  docs_str = v[:docs].join(" | ").downcase
  missing_docs = []
  missing_docs << "Executed MSA" unless docs_str.include?("msa") || docs_str.include?("master services")
  if high_tier
    missing_docs << "SOC 2 Type II or ISO 27001" unless docs_str.include?("soc 2") || docs_str.include?("iso")
    missing_docs << "Data Processing Addendum (DPA)" unless docs_str.include?("dpa") || docs_str.include?("data processing")
    missing_docs << "Penetration Test Summary" unless docs_str.include?("penetration")
  end

  findings = []
  if !missing_docs.empty?
    findings << { id: "INT-01", phase: "intake", sev: missing_docs.size >= 2 ? "HIGH" : "MEDIUM", owner: "Vendor Onboarding Coordinator", rec: "Collect missing compliance artifacts: #{missing_docs.join(', ')}" }
  end

  # Phase 2: InfoSec
  sec_score = 8.0
  s = v[:sec]
  if high_tier && !(s[:soc2] || s[:iso])
    sec_score += 32.0
    findings << { id: "SEC-01", phase: "infosec", sev: "CRITICAL", owner: "CISO / Security Engineering", rec: "Require valid SOC 2 Type II report or ISO 27001 certification prior to production data ingestion." }
  elsif !s[:soc2_exc].empty?
    sec_score += 10.0 * s[:soc2_exc].size
    findings << { id: "SEC-02", phase: "infosec", sev: "MEDIUM", owner: "CISO / Security Engineering", rec: "Obtain formal management response and evidence of remediated quarterly access reviews." }
  end
  if high_tier && !(s[:mfa] && s[:sso])
    sec_score += 15.0
    findings << { id: "SEC-04", phase: "infosec", sev: "HIGH", owner: "CISO / Security Engineering", rec: "Enforce mandatory MFA for all privileged/tenant accounts and require SAML/OIDC SSO." }
  end
  if s[:crit_cves] > 0
    sec_score += [35.0, s[:crit_cves] * 18.0].min
    findings << { id: "SEC-05", phase: "infosec", sev: "CRITICAL", owner: "CISO / Security Engineering", rec: "Block production network onboarding until all Critical CVEs are patched and verified via re-test." }
  elsif s[:high_cves] > 0
    sec_score += [18.0, s[:high_cves] * 7.0].min
    findings << { id: "SEC-06", phase: "infosec", sev: "MEDIUM", owner: "CISO / Security Engineering", rec: "Require remediation SLA within 30 days of contract execution." }
  end
  if s[:sla_hrs] > 72
    sec_score += 10.0
    findings << { id: "SEC-07", phase: "infosec", sev: "HIGH", owner: "CISO / Security Engineering", rec: "Amend security exhibit to require breach notification within 24-48 hours." }
  end
  if s[:ai_train] && v[:sensitivity] != "PUBLIC_ONLY"
    sec_score += 22.0
    findings << { id: "SEC-08", phase: "infosec", sev: "CRITICAL", owner: "CISO / Security Engineering", rec: "Enforce strict zero-data-retention / opt-out clause prohibiting model training on company data." }
  end
  sec_score = [100.0, sec_score].min

  # Phase 3: Legal
  leg_score = 5.0
  l = v[:leg]
  if l[:ofac]
    leg_score += 50.0
    findings << { id: "LEG-01", phase: "legal", sev: "CRITICAL", owner: "Privacy & Legal Counsel", rec: "Immediate compliance hold; escalate to General Counsel & OFAC Trade Compliance before any engagement." }
  end
  if !l[:media].empty?
    leg_score += [25.0, 12.0 * l[:media].size].min
    findings << { id: "LEG-02", phase: "legal", sev: "HIGH", owner: "Privacy & Legal Counsel", rec: "Conduct enhanced due diligence (EDD) and obtain legal opinion on pending regulatory investigations." }
  end
  if v[:sensitivity] == "RESTRICTED_PII_PHI_PCI" && !l[:dpa]
    leg_score += 25.0
    findings << { id: "LEG-03", phase: "legal", sev: "CRITICAL", owner: "Privacy & Legal Counsel", rec: "Execute standard enterprise DPA with mandatory subprocessor flow-down obligations." }
  end
  if l[:cross_border] && !l[:scc] && v[:sensitivity] == "RESTRICTED_PII_PHI_PCI"
    leg_score += 18.0
    findings << { id: "LEG-04", phase: "legal", sev: "HIGH", owner: "Privacy & Legal Counsel", rec: "Attach 2021 EU Standard Contractual Clauses (Module 2) and UK IDTA addendum to the DPA." }
  end
  if !(l[:msa] && l[:indemn])
    leg_score += 18.0
    findings << { id: "LEG-05", phase: "legal", sev: "HIGH", owner: "Privacy & Legal Counsel", rec: "Require mutual IP & data breach indemnification before contract signature." }
  end
  if l[:cap] < 2.0 && high_tier
    leg_score += 10.0
    findings << { id: "LEG-06", phase: "legal", sev: "MEDIUM", owner: "Privacy & Legal Counsel", rec: "Negotiate data privacy/confidentiality super-cap to at least 2.0x annual contract value." }
  end
  leg_score = [100.0, leg_score].min

  # Phase 4: Financial
  fin_score = 6.0
  f = v[:fin]
  if f[:runway] < 12 || f[:credit] < 55
    fin_score += 30.0
    findings << { id: "FIN-01", phase: "financial", sev: "HIGH", owner: "Procurement & Resilience Lead", rec: "Include source-code/data escrow clause and quarterly financial covenant reporting." }
  end
  if high_tier && (!f[:bcp] || f[:rto] > 8.0)
    fin_score += 24.0
    findings << { id: "FIN-03", phase: "financial", sev: "HIGH", owner: "Procurement & Resilience Lead", rec: "Require documented annual disaster recovery tabletop & failover test with RTO <= 4 hours." }
  end
  if high_tier && f[:sla] < 99.9
    fin_score += 12.0
    findings << { id: "FIN-04", phase: "financial", sev: "MEDIUM", owner: "Procurement & Resilience Lead", rec: "Add 99.9% uptime SLA exhibit with service credit remedies." }
  end
  if f[:spof]
    fin_score += 15.0
    findings << { id: "FIN-05", phase: "financial", sev: "HIGH", owner: "Procurement & Resilience Lead", rec: "Require multi-AZ redundancy architecture verification prior to production cutover." }
  end
  fin_score = [100.0, fin_score].min

  # Phase 5: Compliance Officer
  doc_pen = [100.0, missing_docs.size * 25.0].min
  composite = ((sec_score * 0.38) + (leg_score * 0.32) + (fin_score * 0.20) + (doc_pen * 0.10)).round(1)
  crit_c = findings.count { |x| x[:sev] == "CRITICAL" }
  high_c = findings.count { |x| x[:sev] == "HIGH" }

  res_level = (composite >= 65.0 || crit_c >= 2) ? "CRITICAL" : (composite >= 40.0 || crit_c == 1 || high_c >= 2) ? "HIGH" : (composite >= 18.0 || !findings.empty?) ? "MEDIUM" : "LOW"
  decision = (l[:ofac] || composite >= 65.0 || crit_c >= 2) ? "REJECTED" : (crit_c == 1 || composite >= 45.0) ? "ESCALATED_FOR_HUMAN_REVIEW" : (!findings.empty? || composite >= 18.0) ? "APPROVED_WITH_CONDITIONS" : "APPROVED"

  puts "=" * 88
  puts "VENDOR ONBOARDING ASSESSMENT: #{v[:name]} (#{asm_id})"
  puts "Engine: Native Deterministic StateGraph | LLM Mode: simulation (auto-fallback)"
  puts "=" * 88
  puts "Criticality Tier       : #{tier}"
  puts "Composite Risk Score   : #{composite}/100 (#{res_level})"
  puts "Final Determination    : #{decision}"
  puts "-" * 88
  puts "PHASE BREAKDOWN:"
  puts format("  • [Phase 1: Intake & Criticality Triage]                Score: %5.1f/100 | Findings: %d | Agent: Intake & Triage Agent", inh, findings.count { |x| x[:phase] == "intake" })
  puts format("  • [Phase 2: InfoSec & Cyber Risk Review]                Score: %5.1f/100 | Findings: %d | Agent: InfoSec & Cyber Risk Agent", sec_score, findings.count { |x| x[:phase] == "infosec" })
  puts format("  • [Phase 3: Legal, Privacy & Sanctions Screening]       Score: %5.1f/100 | Findings: %d | Agent: Legal, Privacy & Regulatory Agent", leg_score, findings.count { |x| x[:phase] == "legal" })
  puts format("  • [Phase 4: Financial & Operational Viability]          Score: %5.1f/100 | Findings: %d | Agent: Financial & Operational Viability Agent", fin_score, findings.count { |x| x[:phase] == "financial" })
  puts format("  • [Phase 5: Final Risk Aggregation & Executive Sign-Off]Score: %5.1f/100 | Findings: 0 | Agent: Risk Aggregator & Compliance Officer Agent", composite)
  puts "-" * 88
  puts "EXECUTIVE MEMO:"
  if findings.empty?
    puts "  FINAL ONBOARDING DETERMINATION: #{decision.tr('_', ' ')} for #{v[:name]} (#{tier}, Composite Residual Risk: #{composite}/100 — #{res_level}). All mandatory security, privacy, sanctions, and operational resilience gates passed without exception."
  else
    puts "  FINAL ONBOARDING DETERMINATION: #{decision.tr('_', ' ')} for #{v[:name]} (#{tier}, Composite Residual Risk: #{composite}/100 — #{res_level}). Identified #{findings.size} total finding(s) (#{crit_c} Critical, #{high_c} High) requiring #{findings.size} tracked remediation commitment(s)."
    puts "-" * 88
    puts "REMEDIATION ACTION PLAN (#{findings.size} items):"
    findings.each_with_index do |item, idx|
      tag = ["CRITICAL", "HIGH"].include?(item[:sev]) ? "[BLOCKS GO-LIVE]" : "[POST-ONBOARDING]"
      puts format("  • REM-%02d %s (%s): [%s] %s", idx + 1, tag, item[:owner], item[:id], item[:rec])
    end
  end
  puts "=" * 88 + "\n\n"
end

VENDORS.each { |v| evaluate_vendor(v) }
RUBY_EOF
