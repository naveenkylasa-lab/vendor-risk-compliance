# ============================================================================
# Input Variables for Vendor Risk & Compliance Multi-Agent Terraform IaC
# ============================================================================

variable "project_id" {
  description = "Google Cloud Project ID where resources will be provisioned."
  type        = string
  default     = "enterprise-tprm-compliance-prod"
}

variable "region" {
  description = "Primary cloud region for Cloud Run and Artifact Registry."
  type        = string
  default     = "us-central1"
}

variable "service_name" {
  description = "Canonical name for the Vendor Risk & Compliance multi-agent service."
  type        = string
  default     = "vendor-risk-compliance-agent"
}

variable "environment" {
  description = "Deployment environment tier (development, staging, production)."
  type        = string
  default     = "production"

  validation {
    condition     = contains(["development", "staging", "production"], var.environment)
    error_message = "environment must be one of: development, staging, production."
  }
}

variable "container_image" {
  description = "Container image URI for the Vendor Risk & Compliance FastAPI application."
  type        = string
  default     = "us-central1-docker.pkg.dev/enterprise-tprm-compliance-prod/vendor-risk-compliance-agent-repo/app:latest"
}

variable "execution_mode" {
  description = "LLM execution mode: 'auto', 'live', or 'simulation'."
  type        = string
  default     = "auto"
}

variable "llm_provider" {
  description = "Primary LLM provider ('gemini' or 'openai')."
  type        = string
  default     = "gemini"
}

variable "gemini_fast_model" {
  description = "Low-latency Gemini model for Coordinator, Intake, and Support agents."
  type        = string
  default     = "gemini-2.5-flash"
}

variable "gemini_pro_model" {
  description = "Reasoning Gemini model for Policy Checking, InfoSec, Legal, and Compliance Officer agents."
  type        = string
  default     = "gemini-2.5-pro"
}

variable "otel_exporter_otlp_endpoint" {
  description = "OTLP collector endpoint for OpenTelemetry distributed traces."
  type        = string
  default     = "http://otel-collector.observability.svc.cluster.local:4317"
}

variable "min_instances" {
  description = "Minimum number of warm Cloud Run container instances."
  type        = number
  default     = 1
}

variable "max_instances" {
  description = "Maximum number of autoscaled Cloud Run container instances."
  type        = number
  default     = 10
}

variable "cpu_limit" {
  description = "CPU allocation per container instance."
  type        = string
  default     = "2"
}

variable "memory_limit" {
  description = "Memory allocation per container instance."
  type        = string
  default     = "2Gi"
}
