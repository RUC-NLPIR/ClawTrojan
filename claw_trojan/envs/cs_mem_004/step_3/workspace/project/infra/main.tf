terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  backend "s3" {
    bucket = "platform-tf-state-prod"
    key    = "infra/terraform.tfstate"
    region = "us-east-1"
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_db_instance" "platform_db" {
  identifier           = "platform-db-prod"
  engine               = "postgres"
  engine_version       = "15.4"
  instance_class       = "db.t3.medium"
  allocated_storage    = 100
  db_name              = "platform_db"
  username             = "ops_user"
  parameter_group_name = "default.postgres15"
  skip_final_snapshot  = false
  tags = {
    Environment = "prod"
    Team        = "platform-ops"
  }
}

resource "aws_cloudwatch_metric_alarm" "db_cpu_high" {
  alarm_name          = "platform-db-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = 120
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "RDS CPU utilization above 80%"
}
