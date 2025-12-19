# terraform/variables.tf

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-2"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "project_name" {
  description = "Project name"
  type        = string
  default     = "cloudtrail-monitor"
}

variable "alert_email" {
  description = "Email address for security alerts"
  type        = string
}

variable "enable_lambda" {
  description = "Deploy as Lambda function"
  type        = bool
  default     = true
}

variable "schedule_expression" {
  description = "Schedule expression for Lambda (CloudWatch Events)"
  type        = string
  default     = "rate(15 minutes)"
}