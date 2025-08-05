# MyEncrypt - Local ACME Certificate Authority

MyEncrypt is a local development ACME certificate authority that provides automatic HTTPS certificate management for development environments.

## Project Structure

```
myencrypt/
├── cmd/
│   └── myencrypt/           # Main application entry point
│       └── main.go
├── internal/
│   ├── acme/               # ACME protocol implementation
│   ├── certmanager/        # File-based certificate management
│   ├── config/             # Configuration management
│   │   └── config.go
│   └── logger/             # Logging utilities
│       └── logger.go
├── go.mod
├── go.sum
└── README.md
```

## Configuration

MyEncrypt uses a YAML configuration file located at `~/.myencrypt/config.yaml`. If the file doesn't exist, default values are used.

### Default Configuration

- ACME Port: 14000
- HTTP Management Port: 14001
- Certificate Storage: `~/.myencrypt/`
- Individual Certificate TTL: 24 hours
- CA Certificate TTL: 800 days
- Default Allowed Domains: localhost, *.localhost, *.test, *.example, *.invalid

## Building and Running

```bash
# Build the application
go build -o myencrypt cmd/myencrypt/main.go

# Run in development mode (uses config files + environment variables)
go run cmd/myencrypt/main.go run

# Run in container mode (environment variables only)
go run cmd/myencrypt/main.go run --container

# Docker automatically detects container environment
# Note: MYENCRYPT_EXPOSE_PORT environment variable is required in Docker mode
docker run -p 14000:80 -e MYENCRYPT_EXPOSE_PORT=14000 myencrypt:latest
```

## Docker Configuration

When running in Docker mode, MyEncrypt:
- Listens on port 80 internally (for `http://myencrypt` access within Docker network)
- Requires `MYENCRYPT_EXPOSE_PORT` environment variable to specify the host-accessible port
- Maps the internal port 80 to the host port specified in Docker run/compose configuration

Example Docker run:
```bash
docker run -p 14000:80 \
  -e MYENCRYPT_EXPOSE_PORT=14000 \
  -e MYENCRYPT_ALLOWED_DOMAINS="localhost,*.local" \
  -v myencrypt_data:/data \
  myencrypt:latest
```

## Examples

The project includes several example integrations demonstrating how to use MyEncrypt with different web servers and ACME clients:

### 1. Traefik Integration (`examples/traefik/`)
- **Web Server**: Traefik (reverse proxy)
- **ACME Client**: Built-in Traefik ACME
- **Challenge Type**: TLS-ALPN-01
- **Access**: https://traefik.localhost:8444/
- **Features**: Automatic certificate management, dashboard, load balancing

### 2. Certbot + Nginx Integration (`examples/certbot-nginx/`)
- **Web Server**: Nginx
- **ACME Client**: Certbot (official Let's Encrypt client)
- **Challenge Type**: HTTP-01 (webroot)
- **Access**: https://app-certbot.localhost:8446/
- **Features**: Traditional setup, manual certificate management, high performance

### 3. Go autocert Integration (`examples/autocert/`)
- **Web Server**: Go HTTP server
- **ACME Client**: golang.org/x/crypto/acme/autocert
- **Challenge Type**: TLS-ALPN-01
- **Access**: https://autocert.localhost:8447/
- **Features**: Embedded Go application, automatic certificate caching

## Running Examples

Start all examples:
```bash
docker-compose up -d
```

Start specific examples:
```bash
# Traefik only
docker-compose up -d traefik.localhost

# Certbot + Nginx only
docker-compose up -d app-certbot.localhost

# Go autocert only
docker-compose up -d autocert.localhost
```

## Development Status

This is the initial project structure setup. Core functionality will be implemented in subsequent tasks.