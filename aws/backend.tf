terraform {
  backend "s3" {
    bucket         = "terraform-state-bucket-unique-name" # Debes crear este bucket manualmente
    key            = "terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-locks" # Debes crear esta tabla manualmente
  }
}