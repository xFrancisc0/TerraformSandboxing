#Se crea rg para abrir puertos 22 (EC2), 80, 443 (frontend), 8080 (backend) y 3066 (db)
resource "aws_security_group" "rg-firewall" {
  name        = "rg-firewall"
  description = "Grupo de seguridad para distintos servicios"
  
  #EC2
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  #AWS Beanstalk Frontend
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

  #AWS Beanstalk backend
  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  #RDS MySQL
  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

#Se crea instancia EC2 con puerto 22 abierto para SSH (sg)
resource "aws_instance" "mi-ec2" {
  ami           = "ami-04fc83311a8d478df"  # Amazon Linux 2 (verifica para tu región)
  instance_type = "t2.micro"

  security_groups = [aws_security_group.rg-firewall.name]

  tags = {
    Name = "FreeTier-EC2"
  }
}

#Se crea un Bucket S3 para posteriormente subir /dev/frontend/frontend.zip
resource "aws_s3_bucket" "my_bucket" {
  bucket = "fmateu-bucket-sandbox-1234" 
  acl    = "private" 
}

resource "aws_s3_bucket_object" "frontend_zip" {
  bucket = aws_s3_bucket.my_bucket.bucket 
  key    = "frontend/frontend.zip"          
  source = "../dev/frontend/frontend.zip"   
  acl    = "private"                      
  depends_on = [aws_s3_bucket.my_bucket]
}

# Se crea la aplicación de Elastic Beanstalk, luego se crea
# Una nueva version de la aplicacion, subiendo el .zip que esta en S3
# Y luego se crea el entorno de la aplicacion
# Crear la aplicación de Elastic Beanstalk
resource "aws_elastic_beanstalk_application" "frontend_app" {
  name        = "frontend-app"
  description = "Aplicación frontend con HTML"
}

resource "aws_elastic_beanstalk_application_version" "frontend_app_version" {
  name        = "frontend-app-version-1"
  application = aws_elastic_beanstalk_application.frontend_app.name
  description = "Versión 1 de la aplicación frontend"
  bucket      = aws_s3_bucket.my_bucket.id
  key         = aws_s3_bucket_object.frontend_zip.key
  
  depends_on = [aws_s3_bucket_object.frontend_zip]
}

resource "aws_elastic_beanstalk_environment" "frontend_env" {
  name                = "frontend-env"
  application         = aws_elastic_beanstalk_application.frontend_app.name
  solution_stack_name = "64bit Amazon Linux 2 v5.8.2 running PHP 8.1"  # Plataforma más común y actualizada

  version_label = aws_elastic_beanstalk_application_version.frontend_app_version.name
  
  setting {
    namespace = "aws:autoscaling:launchconfiguration"
    name      = "SecurityGroups"
    value     = aws_security_group.rg-firewall.name
  }
  
  setting {
    namespace = "aws:autoscaling:launchconfiguration"
    name      = "IamInstanceProfile"
    value     = "aws-elasticbeanstalk-ec2-role"
  }
  
  setting {
    namespace = "aws:elasticbeanstalk:environment"
    name      = "LoadBalancerType"
    value     = "application"
  }
  
  setting {
    namespace = "aws:elasticbeanstalk:environment:process:default"
    name      = "Port"
    value     = "80"
  }
}