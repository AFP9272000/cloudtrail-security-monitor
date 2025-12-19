# terraform/main.tf
# Main infrastructure configuration for CloudTrail Security Monitor

terraform {
  required_version = ">= 1.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Project     = "CloudTrail Security Monitor"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

# Data sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# SNS Topic for Alerts
resource "aws_sns_topic" "security_alerts" {
  name              = "${var.project_name}-security-alerts"
  display_name      = "Security Alerts"
  kms_master_key_id = aws_kms_key.sns_encryption.id
  
  tags = {
    Name = "${var.project_name}-security-alerts"
  }
}

resource "aws_sns_topic_subscription" "email_alert" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# KMS Key for SNS encryption
resource "aws_kms_key" "sns_encryption" {
  description             = "KMS key for SNS topic encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  
  tags = {
    Name = "${var.project_name}-sns-key"
  }
}

resource "aws_kms_alias" "sns_encryption" {
  name          = "alias/${var.project_name}-sns"
  target_key_id = aws_kms_key.sns_encryption.key_id
}

# DynamoDB Table for State Management
resource "aws_dynamodb_table" "state_table" {
  name           = "${var.project_name}-state"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "event_id"
  range_key      = "timestamp"
  
  attribute {
    name = "event_id"
    type = "S"
  }
  
  attribute {
    name = "timestamp"
    type = "N"
  }
  
  attribute {
    name = "processed"
    type = "S"
  }
  
  global_secondary_index {
    name            = "processed-time-index"
    hash_key        = "processed"
    range_key       = "timestamp"
    projection_type = "ALL"
  }
  
  point_in_time_recovery {
    enabled = true
  }
  
  server_side_encryption {
    enabled = true
  }
  
  ttl {
    attribute_name = "ttl"
    enabled        = true
  }
  
  tags = {
    Name = "${var.project_name}-state"
  }
}

# IAM Role for Lambda/EC2
resource "aws_iam_role" "monitor_role" {
  name = "${var.project_name}-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = var.enable_lambda ? "lambda.amazonaws.com" : "ec2.amazonaws.com"
        }
      }
    ]
  })
  
  tags = {
    Name = "${var.project_name}-role"
  }
}

# IAM Policy for CloudTrail monitoring
resource "aws_iam_policy" "monitor_policy" {
  name        = "${var.project_name}-policy"
  description = "Policy for CloudTrail Security Monitor"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CloudTrailReadAccess"
        Effect = "Allow"
        Action = [
          "cloudtrail:LookupEvents",
          "cloudtrail:GetTrail",
          "cloudtrail:GetTrailStatus",
          "cloudtrail:DescribeTrails"
        ]
        Resource = "*"
      },
      {
        Sid    = "SNSPublishAlerts"
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.security_alerts.arn
      },
      {
        Sid    = "DynamoDBStateManagement"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:Query",
          "dynamodb:Scan"
        ]
        Resource = [
          aws_dynamodb_table.state_table.arn,
          "${aws_dynamodb_table.state_table.arn}/index/*"
        ]
      },
      {
        Sid    = "CloudWatchLogsAccess"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/${var.project_name}/*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "monitor_policy_attachment" {
  role       = aws_iam_role.monitor_role.name
  policy_arn = aws_iam_policy.monitor_policy.arn
}

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "monitor_logs" {
  name              = "/aws/${var.project_name}"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.logs_encryption.arn
  
  tags = {
    Name = "${var.project_name}-logs"
  }
}

# KMS Key for CloudWatch Logs encryption
resource "aws_kms_key" "logs_encryption" {
  description             = "KMS key for CloudWatch Logs encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow CloudWatch Logs"
        Effect = "Allow"
        Principal = {
          Service = "logs.${data.aws_region.current.name}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:CreateGrant",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/${var.project_name}"
          }
        }
      }
    ]
  })
  
  tags = {
    Name = "${var.project_name}-logs-key"
  }
}

# Note: Lambda function resources commented out for now
# Uncomment when ready to deploy Lambda