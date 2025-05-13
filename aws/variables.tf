variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (dev, test, prod)"
  type        = string
  default     = "dev"
}

variable "db_username" {
  description = "Username for RDS instance"
  type        = string
  default     = "admin"
}

variable "db_password" {
  description = "Password for RDS instance"
  type        = string
  sensitive   = true
}

variable "app_name" {
  description = "Name of the application"
  type        = string
  default     = "my-aws-app"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for the public subnets"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for the private subnets"
  type        = list(string)
  default     = ["10.0.3.0/24", "10.0.4.0/24"]
}

variable "s3_bucket_names" {
  description = "Names for S3 buckets"
  type        = list(string)
  default     = ["app-data-bucket", "app-logs-bucket", "app-backups-bucket"]
}

variable "cognito_user_pool_name" {
  description = "Name for Cognito User Pool"
  type        = string
  default     = "app-user-pool"
}

variable "lambda_function_name" {
  description = "Name for Lambda function"
  type        = string
  default     = "sns-processor"
}

variable "sns_topic_name" {
  description = "Name for SNS topic"
  type        = string
  default     = "app-notifications"
}