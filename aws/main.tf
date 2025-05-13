# VPC y subredes
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.app_name}-vpc"
  }
}

resource "aws_subnet" "public" {
  count                   = length(var.public_subnet_cidrs)
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.app_name}-public-subnet-${count.index + 1}"
  }
}

resource "aws_subnet" "private" {
  count             = length(var.private_subnet_cidrs)
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "${var.app_name}-private-subnet-${count.index + 1}"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.app_name}-igw"
  }
}

# Tablas de enrutamiento
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "${var.app_name}-public-route-table"
  }
}

resource "aws_route_table_association" "public" {
  count          = length(var.public_subnet_cidrs)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# NAT Gateway para subredes privadas
resource "aws_eip" "nat" {
  domain = "vpc"

  tags = {
    Name = "${var.app_name}-nat-eip"
  }
}

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id

  tags = {
    Name = "${var.app_name}-nat-gateway"
  }

  depends_on = [aws_internet_gateway.igw]
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }

  tags = {
    Name = "${var.app_name}-private-route-table"
  }
}

resource "aws_route_table_association" "private" {
  count          = length(var.private_subnet_cidrs)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# Grupo de seguridad para EC2
resource "aws_security_group" "ec2" {
  name        = "${var.app_name}-ec2-sg"
  description = "Security group for EC2 instances"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.app_name}-ec2-sg"
  }
}

# Grupo de seguridad para RDS
resource "aws_security_group" "rds" {
  name        = "${var.app_name}-rds-sg"
  description = "Security group for RDS instances"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.ec2.id, aws_security_group.lambda.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.app_name}-rds-sg"
  }
}

# Grupo de seguridad para Lambda
resource "aws_security_group" "lambda" {
  name        = "${var.app_name}-lambda-sg"
  description = "Security group for Lambda function"
  vpc_id      = aws_vpc.main.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.app_name}-lambda-sg"
  }
}

# Instancia EC2
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

resource "aws_instance" "app_server" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = "t2.micro"
  key_name               = aws_key_pair.app_key.key_name
  vpc_security_group_ids = [aws_security_group.ec2.id]
  subnet_id              = aws_subnet.public[0].id
  iam_instance_profile   = aws_iam_instance_profile.ec2_profile.name

  user_data = <<-EOF
              #!/bin/bash
              yum update -y
              yum install -y httpd
              systemctl start httpd
              systemctl enable httpd
              echo "<h1>Deployed via Terraform</h1>" > /var/www/html/index.html
              EOF

  tags = {
    Name = "${var.app_name}-ec2-instance"
  }
}

# Clave SSH para EC2
resource "aws_key_pair" "app_key" {
  key_name   = "${var.app_name}-key"
  public_key = file("~/.ssh/id_rsa.pub")  # Asegúrate de tener esta clave o genera una
}

# IAM Role para EC2
resource "aws_iam_role" "ec2_role" {
  name = "${var.app_name}-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ec2_ssm" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "ec2_sns" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSNSFullAccess"
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "${var.app_name}-ec2-profile"
  role = aws_iam_role.ec2_role.name
}

# RDS MySQL
resource "aws_db_subnet_group" "default" {
  name       = "${var.app_name}-db-subnet-group"
  subnet_ids = aws_subnet.private[*].id

  tags = {
    Name = "${var.app_name}-db-subnet-group"
  }
}

resource "aws_db_instance" "mysql" {
  allocated_storage      = 20
  storage_type           = "gp2"
  engine                 = "mysql"
  engine_version         = "8.0"
  instance_class         = "db.t3.micro"
  identifier             = "${var.app_name}-db"
  db_name                = replace(var.app_name, "-", "_")
  username               = var.db_username
  password               = var.db_password
  parameter_group_name   = "default.mysql8.0"
  db_subnet_group_name   = aws_db_subnet_group.default.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  skip_final_snapshot    = true
  multi_az               = false

  tags = {
    Name = "${var.app_name}-rds"
  }
}

# S3 Buckets
resource "aws_s3_bucket" "buckets" {
  count  = length(var.s3_bucket_names)
  bucket = "${var.environment}-${var.s3_bucket_names[count.index]}"

  tags = {
    Name = "${var.environment}-${var.s3_bucket_names[count.index]}"
  }
}

resource "aws_s3_bucket_ownership_controls" "bucket_ownership" {
  count  = length(var.s3_bucket_names)
  bucket = aws_s3_bucket.buckets[count.index].id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "bucket_acl" {
  count      = length(var.s3_bucket_names)
  bucket     = aws_s3_bucket.buckets[count.index].id
  acl        = "private"
  depends_on = [aws_s3_bucket_ownership_controls.bucket_ownership[count.index]]
}

resource "aws_s3_bucket_public_access_block" "block_public_access" {
  count                   = length(var.s3_bucket_names)
  bucket                  = aws_s3_bucket.buckets[count.index].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# SNS Topic
resource "aws_sns_topic" "app_notifications" {
  name = var.sns_topic_name

  tags = {
    Name = var.sns_topic_name
  }
}

# Lambda Function para procesamiento de eventos SNS
resource "aws_iam_role" "lambda_role" {
  name = "${var.app_name}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_policy" "lambda_policy" {
  name        = "${var.app_name}-lambda-policy"
  description = "Policy for Lambda function execution"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "sns:Subscribe",
          "sns:Receive"
        ]
        Resource = aws_sns_topic.app_notifications.arn
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:CreateNetworkInterface",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DeleteNetworkInterface"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = [
          aws_secretsmanager_secret.db_connection.arn
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_policy_attach" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.lambda_policy.arn
}

data "aws_availability_zones" "available" {}

data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "${path.module}/lambda_function.zip"

  source {
    content = <<EOF
import json
import boto3
import os
import mysql.connector
import logging
from datetime import datetime

# Configurar logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def get_db_connection():
    try:
        client = boto3.client('secretsmanager')
        response = client.get_secret_value(SecretId='${aws_secretsmanager_secret.db_connection.name}')
        secret = json.loads(response['SecretString'])
        
        conn = mysql.connector.connect(
            host=secret['host'],
            user=secret['username'],
            password=secret['password'],
            database=secret['dbname']
        )
        return conn
    except Exception as e:
        logger.error(f"Error connecting to database: {e}")
        raise e

def lambda_handler(event, context):
    logger.info(f"Event received: {json.dumps(event)}")

    # Procesar mensaje de SNS
    sns_message = event["Records"][0]["Sns"]["Message"]
    message_id = event["Records"][0]["Sns"]["MessageId"]
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    try:
        # Conexión a la base de datos RDS
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Asegurar que la tabla existe
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS sns_events (
            id VARCHAR(100) PRIMARY KEY,
            message TEXT,
            processed_at TIMESTAMP
        )
        """)
        
        # Insertar el mensaje de SNS
        cursor.execute(
            "INSERT INTO sns_events (id, message, processed_at) VALUES (%s, %s, %s)",
            (message_id, sns_message, timestamp)
        )
        
        conn.commit()
        cursor.close()
        conn.close()
        
        logger.info(f"Successfully processed SNS message: {message_id}")
        return {
            "statusCode": 200,
            "body": json.dumps({
                "message": "Event processed successfully",
                "messageId": message_id
            })
        }
    except Exception as e:
        logger.error(f"Error processing event: {e}")
        return {
            "statusCode": 500,
            "body": json.dumps({
                "message": f"Error processing event: {str(e)}"
            })
        }
EOF
    filename = "lambda_function.py"
  }
}

resource "aws_lambda_function" "sns_processor" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = var.lambda_function_name
  role             = aws_iam_role.lambda_role.arn
  handler          = "lambda_function.lambda_handler"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  runtime          = "python3.9"
  timeout          = 30
  memory_size      = 256

  vpc_config {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.lambda.id]
  }

  environment {
    variables = {
      ENVIRONMENT = var.environment
    }
  }

  depends_on = [aws_secretsmanager_secret.db_connection]

  tags = {
    Name = var.lambda_function_name
  }
}

# Trigger SNS para Lambda
resource "aws_lambda_permission" "sns" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.sns_processor.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.app_notifications.arn
}

resource "aws_sns_topic_subscription" "lambda" {
  topic_arn = aws_sns_topic.app_notifications.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.sns_processor.arn
}

# DynamoDB para datos de la aplicación
resource "aws_dynamodb_table" "app_table" {
  name           = "${var.app_name}-table"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "id"
  range_key      = "timestamp"

  attribute {
    name = "id"
    type = "S"
  }

  attribute {
    name = "timestamp"
    type = "S"
  }

  tags = {
    Name = "${var.app_name}-dynamodb-table"
  }
}

# Cognito User Pool para autenticación
resource "aws_cognito_user_pool" "main" {
  name = var.cognito_user_pool_name
  
  username_attributes      = ["email"]
  auto_verify_attributes   = ["email"]
  
  password_policy {
    minimum_length    = 8
    require_lowercase = true
    require_uppercase = true
    require_numbers   = true
    require_symbols   = true
  }
  
  verification_message_template {
    default_email_option = "CONFIRM_WITH_CODE"
    email_subject        = "Verificación de cuenta para ${var.app_name}"
    email_message        = "Tu código de verificación es {####}"
  }
  
  schema {
    name                = "email"
    attribute_data_type = "String"
    mutable             = true
    required            = true
  }
  
  tags = {
    Name = var.cognito_user_pool_name
  }
}

resource "aws_cognito_user_pool_client" "client" {
  name                = "${var.app_name}-client"
  user_pool_id        = aws_cognito_user_pool.main.id
  generate_secret     = true
  explicit_auth_flows = ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
}

# Elastic Beanstalk para la aplicación frontend
resource "aws_elastic_beanstalk_application" "app" {
  name        = "${var.app_name}-application"
  description = "Application for ${var.app_name}"
}

resource "aws_elastic_beanstalk_environment" "frontend" {
  name                = "${var.app_name}-frontend-env"
  application         = aws_elastic_beanstalk_application.app.name
  solution_stack_name = "64bit Amazon Linux 2 v5.8.0 running Node.js 18"
  
  setting {
    namespace = "aws:autoscaling:launchconfiguration"
    name      = "IamInstanceProfile"
    value     = aws_iam_instance_profile.ec2_profile.name
  }
  
  setting {
    namespace = "aws:ec2:vpc"
    name      = "VPCId"
    value     = aws_vpc.main.id
  }
  
  setting {
    namespace = "aws:ec2:vpc"
    name      = "Subnets"
    value     = join(",", aws_subnet.public[*].id)
  }
  
  setting {
    namespace = "aws:autoscaling:asg"
    name      = "MinSize"
    value     = "1"
  }
  
  setting {
    namespace = "aws:autoscaling:asg"
    name      = "MaxSize"
    value     = "3"
  }
  
  setting {
    namespace = "aws:elasticbeanstalk:environment"
    name      = "EnvironmentType"
    value     = "LoadBalanced"
  }
}

resource "aws_elastic_beanstalk_environment" "backend" {
  name                = "${var.app_name}-backend-env"
  application         = aws_elastic_beanstalk_application.app.name
  solution_stack_name = "64bit Amazon Linux 2 v5.8.0 running Node.js 18"
  
  setting {
    namespace = "aws:autoscaling:launchconfiguration"
    name      = "IamInstanceProfile"
    value     = aws_iam_instance_profile.ec2_profile.name
  }
  
  setting {
    namespace = "aws:ec2:vpc"
    name      = "VPCId"
    value     = aws_vpc.main.id
  }
  
  setting {
    namespace = "aws:ec2:vpc"
    name      = "Subnets"
    value     = join(",", aws_subnet.private[*].id)
  }
  
  setting {
    namespace = "aws:autoscaling:asg"
    name      = "MinSize"
    value     = "1"
  }
  
  setting {
    namespace = "aws:autoscaling:asg"
    name      = "MaxSize"
    value     = "3"
  }
  
  setting {
    namespace = "aws:elasticbeanstalk:environment"
    name      = "EnvironmentType"
    value     = "LoadBalanced"
  }
}

# ECR Repository para imágenes Docker
resource "aws_ecr_repository" "app" {
  name                 = var.app_name
  image_tag_mutability = "MUTABLE"
  
  image_scanning_configuration {
    scan_on_push = true
  }
  
  tags = {
    Name = "${var.app_name}-ecr-repo"
  }
}

# EKS Cluster para Kubernetes
resource "aws_iam_role" "eks_cluster" {
  name = "${var.app_name}-eks-cluster-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "eks.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_cluster.name
}

resource "aws_eks_cluster" "main" {
  name     = "${var.app_name}-cluster"
  role_arn = aws_iam_role.eks_cluster.arn
  
  vpc_config {
    subnet_ids = aws_subnet.private[*].id
  }
  
  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster_policy
  ]
  
  tags = {
    Name = "${var.app_name}-eks-cluster"
  }
}

# Secrets Manager para secretos
resource "aws_secretsmanager_secret" "db_connection" {
  name        = "${var.app_name}-db-connection"
  description = "RDS database connection details"
  
  tags = {
    Name = "${var.app_name}-db-connection-secret"
  }
}

resource "aws_secretsmanager_secret_version" "db_connection" {
  secret_id = aws_secretsmanager_secret.db_connection.id
  secret_string = jsonencode({
    username = var.db_username
    password = var.db_password
    host     = aws_db_instance.mysql.address
    port     = aws_db_instance.mysql.port
    dbname   = aws_db_instance.mysql.db_name
  })
  
  depends_on = [aws_db_instance.mysql]
}

resource "aws_secretsmanager_secret" "api_url" {
  name        = "${var.app_name}-api-url"
  description = "API URL for the application"
  
  tags = {
    Name = "${var.app_name}-api-url-secret"
  }
}

resource "aws_secretsmanager_secret_version" "api_url" {
  secret_id = aws_secretsmanager_secret.api_url.id
  secret_string = jsonencode({
    api_url = "https://${aws_elastic_beanstalk_environment.backend.cname}/api"
  })
  
  depends_on = [aws_elastic_beanstalk_environment.backend]
}