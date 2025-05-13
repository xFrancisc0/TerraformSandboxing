# Infraestructura AWS con Terraform

Este proyecto define la infraestructura en AWS utilizando Terraform para una aplicación con frontend y backend basada en Elastic Beanstalk.

## Componentes principales

- **VPC y Networking**: Red privada con subredes públicas y privadas
- **Elastic Beanstalk Frontend**: Ambiente web con puertos 80 y 443 habilitados
- **Elastic Beanstalk Backend**: Ambiente de API con puerto 8080 habilitado
- **RDS MySQL**: Base de datos en subredes privadas con puerto 3306 abierto
- **SNS Topic**: Para notificaciones de la aplicación
- **Lambda Function**: Procesa mensajes SNS
- **Cognito User Pool**: Implementa SSO (Single Sign-On)
- **Secrets Manager**: Almacena credenciales de la base de datos
- **S3 Buckets**: Para almacenamiento de la aplicación

## Requisitos previos

1. AWS CLI instalado y configurado
2. Terraform instalado (versión 1.0+)
3. Bucket S3 y tabla DynamoDB para el backend de Terraform (estado remoto)
4. Crear un archivo `aws-credentials` en el directorio raíz

## Pasos para desplegar

1. Inicializar el directorio de trabajo de Terraform:
   ```
   terraform init
   ```

2. Crear un archivo `terraform.tfvars` con las variables requeridas:
   ```
   db_password = "tu-contraseña-segura"
   ssh_public_key = "tu-clave-pública-ssh"
   ssl_certificate_arn = "arn:aws:acm:region:account:certificate/certificate-id"
   ```

3. Revisar el plan de despliegue:
   ```
   terraform plan
   ```

4. Aplicar la configuración:
   ```
   terraform apply
   ```

5. Confirmar la acción cuando se solicite escribiendo `yes`.

## Arquitectura

- El frontend Elastic Beanstalk se ejecuta en subredes públicas con acceso a Internet
- El backend Elastic Beanstalk se ejecuta en subredes privadas
- La base de datos RDS se ejecuta en subredes privadas
- La función Lambda procesa mensajes del tópico SNS
- Cognito gestiona la autenticación de usuarios

## Variables importantes

| Variable | Descripción | Valor por defecto |
|----------|-------------|-------------------|
| app_name | Nombre de la aplicación | my-aws-app |
| environment | Entorno (dev, test, prod) | dev |
| aws_region | Región de AWS | us-east-1 |
| db_username | Usuario de la base de datos | admin |
| db_password | Contraseña de la base de datos | (requerido) |

## Acceso a la aplicación

Una vez desplegada, puedes acceder a los endpoints de la aplicación:

- **Frontend**: `http://<nombre-del-ambiente-frontend>.<region>.elasticbeanstalk.com`
- **Backend**: `http://<nombre-del-ambiente-backend>.<region>.elasticbeanstalk.com:8080`

## Consideraciones de seguridad

- Los recursos están protegidos con grupos de seguridad adecuados
- Las contraseñas se almacenan en AWS Secrets Manager
- Los buckets S3 tienen bloqueado el acceso público
- Las instancias EC2 utilizan perfiles IAM con permisos mínimos necesarios