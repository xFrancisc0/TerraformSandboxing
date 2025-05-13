provider "aws" {
  region = "us-east-1"
  profile = "proyecto1"
  shared_credentials_files = ["${path.module}/../credentials/aws-credentials"]
}