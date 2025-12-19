# terraform/outputs.tf

output "sns_topic_arn" {
  description = "ARN of SNS topic for alerts"
  value       = aws_sns_topic.security_alerts.arn
}

output "dynamodb_table_name" {
  description = "Name of DynamoDB state table"
  value       = aws_dynamodb_table.state_table.name
}

output "iam_role_arn" {
  description = "ARN of IAM role"
  value       = aws_iam_role.monitor_role.arn
}

output "lambda_function_name" {
  description = "Name of Lambda function"
  value       = var.enable_lambda ? aws_lambda_function.monitor[0].function_name : "N/A"
}

output "cloudwatch_log_group" {
  description = "CloudWatch Log Group name"
  value       = aws_cloudwatch_log_group.monitor_logs.name
}