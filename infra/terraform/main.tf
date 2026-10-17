# ============================================================================
# Terraform Infrastructure as Code (IaC) — Vendor Risk & Compliance Multi-Agent
# Provisions Cloud Run v2, Secret Manager, Artifact Registry, Least-Privilege IAM,
# Persistent Storage, and OpenTelemetry / Cloud Trace Observability.
# ============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.30"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

# 1. Enable Required Cloud Platform APIs
resource "google_project_service" "enabled_apis" {
  for_each = toset([
    "run.googleapis.com",
    "secretmanager.googleapis.com",
    "artifactregistry.googleapis.com",
    "cloudtrace.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
  ])

  project            = var.project_id
  service            = each.key
  disable_on_destroy = false
}

# 2. Dedicated Least-Privilege Service Account for the Multi-Agent Orchestrator
resource "google_service_account" "vendor_risk_agent_sa" {
  account_id   = "${var.service_name}-sa"
  display_name = "Vendor Risk & Compliance Multi-Agent Service Account"
  description  = "Least-privilege identity for the 5-agent vendor onboarding orchestrator"
}

# Grant Cloud Trace Agent & Structured Log Writer roles for OpenTelemetry
resource "google_project_iam_member" "otel_trace_agent" {
  project = var.project_id
  role    = "roles/cloudtrace.agent"
  member  = "serviceAccount:${google_service_account.vendor_risk_agent_sa.email}"
}

resource "google_project_iam_member" "structured_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.vendor_risk_agent_sa.email}"
}

# 3. Managed Secrets in Google Cloud Secret Manager (No Hardcoded API Keys)
resource "google_secret_manager_secret" "gemini_api_key" {
  secret_id = "${var.service_name}-gemini-api-key"

  labels = {
    app         = var.service_name
    environment = var.environment
    managed_by  = "terraform"
  }

  replication {
    auto {}
  }

  depends_on = [google_project_service.enabled_apis]
}

resource "google_secret_manager_secret" "openai_api_key" {
  secret_id = "${var.service_name}-openai-api-key"

  labels = {
    app         = var.service_name
    environment = var.environment
    managed_by  = "terraform"
  }

  replication {
    auto {}
  }

  depends_on = [google_project_service.enabled_apis]
}

resource "google_secret_manager_secret_iam_member" "gemini_secret_accessor" {
  secret_id = google_secret_manager_secret.gemini_api_key.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.vendor_risk_agent_sa.email}"
}

resource "google_secret_manager_secret_iam_member" "openai_secret_accessor" {
  secret_id = google_secret_manager_secret.openai_api_key.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.vendor_risk_agent_sa.email}"
}

# 4. Artifact Registry Container Repository
resource "google_artifact_registry_repository" "agent_repo" {
  location      = var.region
  repository_id = "${var.service_name}-repo"
  description   = "Container registry for Vendor Risk & Compliance Multi-Agent images"
  format        = "DOCKER"

  depends_on = [google_project_service.enabled_apis]
}

# 5. Cloud Run v2 Service with Autoscaling, Secret Injection & OpenTelemetry
resource "google_cloud_run_v2_service" "vendor_risk_service" {
  name     = var.service_name
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = google_service_account.vendor_risk_agent_sa.email

    scaling {
      min_instance_count = var.min_instances
      max_instance_count = var.max_instances
    }

    volumes {
      name = "session_storage"
      empty_dir {
        medium     = "MEMORY"
        size_limit = "512Mi"
      }
    }

    containers {
      image = var.container_image

      ports {
        container_port = 8000
      }

      resources {
        limits = {
          cpu    = var.cpu_limit
          memory = var.memory_limit
        }
        cpu_idle = true
      }

      env {
        name  = "ENVIRONMENT"
        value = var.environment
      }
      env {
        name  = "EXECUTION_MODE"
        value = var.execution_mode
      }
      env {
        name  = "LLM_PROVIDER"
        value = var.llm_provider
      }
      env {
        name  = "GEMINI_FAST_MODEL"
        value = var.gemini_fast_model
      }
      env {
        name  = "GEMINI_PRO_MODEL"
        value = var.gemini_pro_model
      }
      env {
        name  = "OTEL_ENABLED"
        value = "true"
      }
      env {
        name  = "OTEL_SERVICE_NAME"
        value = var.service_name
      }
      env {
        name  = "OTEL_EXPORTER_OTLP_ENDPOINT"
        value = var.otel_exporter_otlp_endpoint
      }
      env {
        name  = "SQLITE_DB_PATH"
        value = "/var/lib/vendor-sessions/vendor_sessions.db"
      }

      # Inject API keys securely from Secret Manager at runtime
      env {
        name = "GEMINI_API_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.gemini_api_key.secret_id
            version = "latest"
          }
        }
      }
      env {
        name = "OPENAI_API_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.openai_api_key.secret_id
            version = "latest"
          }
        }
      }

      volume_mounts {
        name       = "session_storage"
        mount_path = "/var/lib/vendor-sessions"
      }

      startup_probe {
        http_get {
          path = "/api/health"
          port = 8000
        }
        initial_delay_seconds = 3
        period_seconds        = 5
        failure_threshold     = 6
      }

      liveness_probe {
        http_get {
          path = "/api/health"
          port = 8000
        }
        period_seconds    = 15
        failure_threshold = 3
      }
    }
  }

  depends_on = [
    google_secret_manager_secret_iam_member.gemini_secret_accessor,
    google_secret_manager_secret_iam_member.openai_secret_accessor,
  ]
}
