provider "aws" {
  region = "us-west-1"
  profile = "proyecto1"

  shared_credentials_files = ["${path.module}/../credentials/aws-credentials"]
  #Las credenciales vienen con una region, debe hacer match con la ya configurada
}