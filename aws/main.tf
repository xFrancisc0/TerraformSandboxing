# ---------------------------------------
# # VPC y subredes
# resource "aws_vpc" "main" {
#   cidr_block           = var.vpc_cidr
#   enable_dns_support   = true
#   enable_dns_hostnames = true

#   tags = {
#     Name = "${var.app_name}-vpc"
#   }
# }

# resource "aws_subnet" "public" {
#   count                   = length(var.public_subnet_cidrs)
#   vpc_id                  = aws_vpc.main.id
#   cidr_block              = var.public_subnet_cidrs[count.index]
#   availability_zone       = data.aws_availability_zones.available.names[count.index]
#   map_public_ip_on_launch = true

#   tags = {
#     Name = "${var.app_name}-public-subnet-${count.index + 1}"
#   }
# }

# (más bloques comentados...)

# ---------------------------------------
# EC2 Instance
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

# SNS
resource "aws_sns_topic" "app_notifications" {
  name = var.sns_topic_name

  tags = {
    Name = var.sns_topic_name
  }
}

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

# Lambda Function
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

# RDS
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

# Cognito
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
