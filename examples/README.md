# MyEncrypt Demo Applications

This directory contains demo applications showcasing different ways to use MyEncrypt ACME server for automatic HTTPS certificate management.

## 🚀 Demo Applications

### 1. Autocert App (Direct HTTPS)
- **Location**: `autocert-app/`
- **Technology**: Go with `golang.org/x/crypto/acme/autocert`
- **Description**: Application that directly obtains and manages certificates from MyEncrypt
- **URL**: https://autocert.local:8443

### 2. Simple HTTP Apps (Reverse Proxy)
- **Location**: `simple-http-app/`
- **Technology**: Go HTTP server
- **Description**: Simple HTTP applications designed to work behind reverse proxies
- **Instances**: Two identical apps with different configurations

### 3. Caddy Reverse Proxy
- **Location**: `caddy/`
- **Technology**: Caddy v2 with automatic HTTPS
- **Description**: Reverse proxy that automatically obtains certificates from MyEncrypt
- **URLs**: 
  - https://app1.local (App 1)
  - https://app2.local (App 2)
  - https://api.local (API Gateway)

### 4. Traefik Reverse Proxy
- **Location**: `traefik/`
- **Technology**: Traefik v3 with ACME support
- **Description**: Dynamic reverse proxy with automatic certificate management
- **URLs**:
  - https://app1-traefik.local:8444 (App 1)
  - https://app2-traefik.local:8444 (App 2)
  - https://traefik.local:8444 (Dashboard)

## 🐳 Quick Start

### Start All Demo Services

```bash
# Start the complete demo environment
docker compose -f docker compose.demo.yml up --build -d

# Check service status
docker compose -f docker compose.demo.yml ps

# View logs
docker compose -f docker compose.demo.yml logs -f
```

### Add Hosts to /etc/hosts

Add these entries to your `/etc/hosts` file:

```
127.0.0.1 autocert.local
127.0.0.1 app1.local
127.0.0.1 app2.local
127.0.0.1 api.local
127.0.0.1 app1-traefik.local
127.0.0.1 app2-traefik.local
127.0.0.1 traefik.local
```

### Access Demo Applications

#### Direct Autocert Application
- **URL**: https://autocert.local:8443
- **Description**: Go application using autocert for direct certificate management

#### Caddy Reverse Proxy (Port 443)
- **App 1**: https://app1.local
- **App 2**: https://app2.local
- **API Gateway**: https://api.local

#### Traefik Reverse Proxy (Port 8444)
- **App 1**: https://app1-traefik.local:8444
- **App 2**: https://app2-traefik.local:8444
- **Dashboard**: https://traefik.local:8444

#### MyEncrypt ACME Server
- **Management Interface**: http://localhost:14000
- **ACME Directory**: http://localhost:14000/acme/directory

## 🔧 Configuration

### Environment Variables

All applications support configuration via environment variables:

#### MyEncrypt Server
```bash
MYENCRYPT_HTTP_PORT=14000
MYENCRYPT_ALLOWED_DOMAINS=localhost,*.localhost,*.local,app1.local,app2.local
MYENCRYPT_CERT_STORE_PATH=/data
MYENCRYPT_DATABASE_PATH=/data/myencrypt.db
```

#### Autocert Application
```bash
DOMAIN=autocert.local
PORT=8443
ACME_DIRECTORY_URL=http://myencrypt:14000/acme/directory
CACHE_DIR=/tmp/autocert-cache
```

#### Simple HTTP Applications
```bash
APP_NAME="Simple HTTP App 1"
PORT=8080
```

### Custom Domains

To add custom domains:

1. Update `MYENCRYPT_ALLOWED_DOMAINS` in docker compose.demo.yml
2. Add domain configurations to Caddy/Traefik configs
3. Add entries to your `/etc/hosts` file
4. Restart the services

## 🧪 Testing Certificate Management

### Check Certificate Details

```bash
# Check autocert application certificate
openssl s_client -connect autocert.local:8443 -servername autocert.local < /dev/null 2>/dev/null | openssl x509 -text -noout

# Check Caddy-proxied application certificate
openssl s_client -connect app1.local:443 -servername app1.local < /dev/null 2>/dev/null | openssl x509 -text -noout

# Check Traefik-proxied application certificate
openssl s_client -connect app1-traefik.local:8444 -servername app1-traefik.local < /dev/null 2>/dev/null | openssl x509 -text -noout
```

### Monitor Certificate Requests

```bash
# Watch MyEncrypt logs
docker compose -f docker compose.demo.yml logs -f myencrypt

# Watch Caddy logs
docker compose -f docker compose.demo.yml logs -f caddy

# Watch Traefik logs
docker compose -f docker compose.demo.yml logs -f traefik
```

## 🛠️ Development

### Build Individual Applications

```bash
# Build autocert app
cd examples/autocert-app
docker build -t myencrypt-autocert-demo .

# Build simple HTTP app
cd examples/simple-http-app
docker build -t myencrypt-simple-http-demo .
```

### Run Individual Services

```bash
# Run only MyEncrypt + Autocert
docker compose -f docker compose.demo.yml up myencrypt autocert-app

# Run only MyEncrypt + Caddy + HTTP apps
docker compose -f docker compose.demo.yml up myencrypt caddy simple-http-app1 simple-http-app2

# Run only MyEncrypt + Traefik + HTTP apps
docker compose -f docker compose.demo.yml up myencrypt traefik simple-http-app1-traefik simple-http-app2-traefik
```

## 🔍 Troubleshooting

### Common Issues

1. **Certificate not issued**: Check MyEncrypt logs and ensure domain is in allowed list
2. **Connection refused**: Verify services are running and ports are not blocked
3. **DNS resolution**: Ensure `/etc/hosts` entries are correct
4. **Port conflicts**: Caddy and Traefik use different ports to avoid conflicts

### Debug Commands

```bash
# Check service health
docker compose -f docker compose.demo.yml exec myencrypt wget -qO- http://localhost:14000/health

# Check certificate store
docker compose -f docker compose.demo.yml exec myencrypt ls -la /data/

# Test ACME directory
curl http://localhost:14000/acme/directory

# Check application connectivity
curl -k https://autocert.local:8443/health
curl -k https://app1.local/health
curl -k https://app1-traefik.local:8444/health

# Check container mode detection
docker compose -f docker compose.demo.yml exec myencrypt ./myencrypt run --dry-run
```

## 📚 Learn More

- [MyEncrypt Documentation](../README.md)
- [Caddy Documentation](https://caddyserver.com/docs/)
- [Traefik Documentation](https://doc.traefik.io/traefik/)
- [Go Autocert Package](https://pkg.go.dev/golang.org/x/crypto/acme/autocert)
