resource "aws_security_group" "mi_grupo_seguridad" {
  name        = "mi_grupo_seguridad"
  description = "Grupo de seguridad para EC2 con acceso SSH"
  
  ingress {
    from_port   = 22
    to_port     = 22
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

resource "aws_instance" "mi-ec2" {
  ami           = "ami-0f88e80871fd81e91"  # Amazon Linux 2 (verifica para tu región)
  instance_type = "t2.micro"

  security_groups = [aws_security_group.mi_grupo_seguridad.name]

  tags = {
    Name = "FreeTier-EC2"
  }
}
