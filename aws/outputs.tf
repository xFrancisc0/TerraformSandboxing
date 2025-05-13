# VPC y configuración de red
output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.main.id
}

output "public_subnet_ids" {
  description = "IDs of the public subnets"
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "IDs of the private subnets"
  value       = aws_subnet.private[*].id
}

# RDS
output "rds_endpoint" {
  description = "Endpoint of the RDS instance"
  value       = aws_db_instance.mysql.endpoint
}

output "rds_port" {
  description = "Port of the RDS instance"
  value       = aws_db_instance.mysql.port
}

# S3 Buckets
output "s3_bucket_arns" {
  description = "ARNs of the S3 buckets"
  value       = aws_s3_bucket.buckets[*].arn
}

# SNS
output "sns_topic_arn" {
  description = "ARN of the SNS topic"
  value       = aws_sns_topic.app_notifications.arn
}

# Lambda
output "lambda_function_arn" {
  description = "ARN of the Lambda function"
  value       = aws_lambda_function.sns_processor.arn
}

# DynamoDB
output "dynamodb_table_arn" {
  description = "ARN of the DynamoDB table"
  value       = aws_dynamodb_table.app_table.arn
}

# Cognito
output "cognito_user_pool_id" {
  description = "ID of the Cognito User Pool"
  value       = aws_cognito_user_pool.main.id
}

output "cognito_user_pool_client_id" {
  description = "ID of the Cognito User Pool Client"
  value       = aws_cognito_user_pool_client.client.id
}

# EKS
output "eks_cluster_endpoint" {
  description = "Endpoint for EKS control plane"
  value       = aws_eks_cluster.main.endpoint
}

# Elastic Beanstalk
output "eb_environment_endpoint" {
  description = "CNAME of the Elastic Beanstalk environment"
  value       = aws_elastic_beanstalk_environment.frontend.cname
}

output "eb_environment_backend_endpoint" {
  description = "CNAME of the Elastic Beanstalk environment for backend"
  value       = aws_elastic_beanstalk_environment.backend.cname
}

# ECR Repository
output "ecr_repository_url" {
  description = "URL of the ECR repository"
  value       = aws_ecr_repository.app.repository_url
}

# Secrets Manager
output "api_url_secret_arn" {
  description = "ARN of the API URL secret"
  value       = aws_secretsmanager_secret.api_url.arn
}

output "db_connection_secret_arn" {
  description = "ARN of the DB connection secret"
  value       = aws_secretsmanager_secret.db_connection.arn
}