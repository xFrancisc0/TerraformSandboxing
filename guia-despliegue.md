# Guía de Despliegue para Elastic Beanstalk

Esta guía proporciona instrucciones detalladas para desplegar aplicaciones en los entornos Elastic Beanstalk creados con Terraform.

## Estructura del Proyecto

Los entornos de Elastic Beanstalk que hemos configurado son:

1. **Frontend** (`${var.app_name}-frontend`): 
   - Puertos habilitados: 80 (HTTP), 443 (HTTPS)
   - Stack: Node.js 16 en Amazon Linux 2
   - Ubicación: Subredes públicas

2. **Backend** (`${var.app_name}-backend`): 
   - Puerto habilitado: 8080
   - Stack: Node.js 16 en Amazon Linux 2
   - Ubicación: Subredes privadas

## Requisitos para el Despliegue

### Para el Frontend:

1. Archivos necesarios:
   - `package.json` con las dependencias del frontend
   - Código fuente de la aplicación 
   - Archivo `.ebextensions/` para configuración personalizada

2. Crear un archivo `.ebextensions/nginx-config.config` para configurar el puerto 443:

```yaml
files:
  "/etc/nginx/conf.d/https.conf":
    mode: "000644"
    owner: root
    group: root
    content: |
      # HTTPS server
      server {
        listen 443 ssl;
        server_name localhost;
        
        ssl_certificate /etc/pki/tls/certs/server.crt;
        ssl_certificate_key /etc/pki/tls/certs/server.key;
        
        location / {
          proxy_pass http://localhost:8081;
          proxy_http_version 1.1;
          proxy_set_header Upgrade $http_upgrade;
          proxy_set_header Connection 'upgrade';
          proxy_set_header Host $host;
          proxy_cache_bypass $http_upgrade;
        }
      }
```

### Para el Backend:

1. Archivos necesarios:
   - `package.json` con las dependencias del backend
   - Código fuente de la API
   - Archivo `.ebextensions/` para configuración personalizada

2. Configuración del puerto 8080 en `package.json`:

```json
{
  "scripts": {
    "start": "node app.js"
  }
}
```

3. En tu aplicación Express.js (ejemplo):

```javascript
const express = require('express');
const app = express();
const PORT = process.env.PORT || 8080;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
```

## Pasos para el Despliegue

### 1. Preparar el paquete de despliegue

Para ambos entornos:

```bash
# Crear archivo ZIP para el despliegue
zip -r deploy.zip . -x "node_modules/*" "*.git*"
```

### 2. Despliegue del Frontend

Usando la AWS CLI:

```bash
aws elasticbeanstalk create-application-version \
  --application-name my-aws-app \
  --version-label frontend-v1 \
  --source-bundle S3Bucket="your-deployment-bucket",S3Key="frontend/deploy.zip"

aws elasticbeanstalk update-environment \
  --environment-name my-aws-app-frontend \
  --version-label frontend-v1
```

### 3. Despliegue del Backend

Usando la AWS CLI:

```bash
aws elasticbeanstalk create-application-version \
  --application-name my-aws-app \
  --version-label backend-v1 \
  --source-bundle S3Bucket="your-deployment-bucket",S3Key="backend/deploy.zip"

aws elasticbeanstalk update-environment \
  --environment-name my-aws-app-backend \
  --version-label backend-v1
```

## Variables de Entorno

### Variables configuradas para el Frontend:

- No hay variables de entorno específicas configuradas por defecto

### Variables configuradas para el Backend:

- `DB_SECRET_ARN`: ARN del secreto en Secrets Manager que contiene la información de conexión a la base de datos
- `NODE_ENV`: Entorno de despliegue (dev, test, prod)

## Conexión a la Base de Datos desde el Backend

Para conectarse a la base de datos RDS desde el backend, utilice el siguiente código de ejemplo:

```javascript
const AWS = require('aws-sdk');
const mysql = require('mysql2/promise');

// Recuperar información de la base de datos desde Secrets Manager
async function getDbConnection() {
  const secretsManager = new AWS.SecretsManager();
  const secretData = await secretsManager.getSecretValue({
    SecretId: process.env.DB_SECRET_ARN
  }).promise();
  
  const dbConfig = JSON.parse(secretData.SecretString);
  
  // Crear conexión
  return await mysql.createConnection({
    host: dbConfig.host,
    user: dbConfig.username,
    password: dbConfig.password,
    database: dbConfig.dbInstanceIdentifier.replace(/-/g, '_')
  });
}

// Uso
async function queryDatabase() {
  const connection = await getDbConnection();
  try {
    const [rows] = await connection.execute('SELECT * FROM users');
    return rows;
  } finally {
    connection.end();
  }
}
```

## Verificación del Despliegue

1. Para el Frontend:
   - Acceda a `http://<nombre-ambiente-frontend>.<region>.elasticbeanstalk.com`
   - Verifique que la aplicación carga correctamente
   - Pruebe la autenticación con Cognito

2. Para el Backend:
   - Acceda a `http://<nombre-ambiente-backend>.<region>.elasticbeanstalk.com:8080/health`
   - Verifique que la API responde correctamente
   - Pruebe los endpoints principales

## Solución de Problemas

1. Revisar logs de Elastic Beanstalk:
   ```
   aws elasticbeanstalk request-environment-info --environment-name my-aws-app-frontend --info-type tail
   aws elasticbeanstalk retrieve-environment-info --environment-name my-aws-app-frontend --info-type tail
   ```

2. Problemas comunes:
   - Permisos IAM insuficientes
   - Puerto no configurado correctamente
   - Configuración incorrecta en `.ebextensions`
   - Problema de conectividad con la base de datos