# ============================================================================
# Outputs for Vendor Risk & Compliance Multi-Agent Terraform IaC
# ============================================================================

output "cloud_run_service_url" {
  description = "Public HTTPS URL of the deployed Vendor Risk & Compliance Multi-Agent service."
  value       = google_cloud_run_v2_service.vendor_risk_service.uri
}

output "service_account_email" {
  description = "Least-privilege IAM Service Account email used by the multi-agent orchestrator."
  value       = google_service_account.vendor_risk_agent_sa.email
}

output "artifact_registry_repository" {
  description = "Artifact Registry Docker repository ID."
  value       = google_artifact_registry_repository.agent_repo.id
}

output "gemini_secret_id" {
  description = "Secret Manager resource ID storing the Gemini API key."
  value       = google_secret_manager_secret.gemini_api_key.secret_id
}

output "openai_secret_id" {
  description = "Secret Manager resource ID storing the OpenAI API key."
  value       = google_secret_manager_secret.openai_api_key.secret_id
}
