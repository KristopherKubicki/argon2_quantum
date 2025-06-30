# Minimal Terraform placeholder for qs-kdf infrastructure

variable "region" { default = "us-east-1" }

provider "aws" {
  region = var.region
}

resource "aws_cloudwatch_metric_alarm" "braket_cost" {
  alarm_name          = "braket-cost-limit"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "EstimatedCharges"
  namespace           = "AWS/Billing"
  period              = 86400
  statistic           = "Maximum"
  threshold           = 25
  alarm_description   = "Daily Braket cost limit exceeded"
}
