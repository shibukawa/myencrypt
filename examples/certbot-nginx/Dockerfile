FROM nginx:alpine

# Install certbot and openssl
RUN apk add --no-cache \
    certbot \
    certbot-nginx \
    openssl \
    curl \
    bash

# Create directories
RUN mkdir -p /var/www/certbot /var/www/html

# Copy configuration files first
COPY nginx.conf /etc/nginx/nginx.conf
COPY init-letsencrypt.sh /init-letsencrypt.sh

# Create a simple HTML page
COPY <<EOF /var/www/html/index.html
<!DOCTYPE html>
<html>
<head>
    <title>Nginx with MyEncrypt Demo</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { 
            font-family: Arial, sans-serif; 
            max-width: 800px; 
            margin: 50px auto; 
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        .container { 
            background: rgba(255,255,255,0.1); 
            padding: 30px; 
            border-radius: 10px;
            backdrop-filter: blur(10px);
        }
        .status { 
            background: rgba(0,255,0,0.2); 
            padding: 10px; 
            border-radius: 5px; 
            margin: 20px 0;
        }
        .info { 
            background: rgba(255,255,255,0.1); 
            padding: 15px; 
            border-radius: 5px; 
            margin: 10px 0;
        }
        a { color: #ffeb3b; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Nginx with MyEncrypt ACME</h1>
        <div class="status">
            <h2>✅ HTTPS Connection Successful!</h2>
            <p>This page is served over HTTPS using a certificate from MyEncrypt ACME server.</p>
            <p>日本語テスト: このページは正しく表示されるはずです。</p>
        </div>
        
        <div class="info">
            <h3>📋 Configuration Details</h3>
            <ul>
                <li><strong>Web Server:</strong> Nginx</li>
                <li><strong>ACME Client:</strong> Certbot</li>
                <li><strong>Certificate Authority:</strong> MyEncrypt (Local ACME CA)</li>
                <li><strong>Domain:</strong> app-certbot.localhost</li>
                <li><strong>Challenge Type:</strong> HTTP-01 (webroot)</li>
                <li><strong>文字エンコーディング:</strong> UTF-8</li>
            </ul>
        </div>
        
        <div class="info">
            <h3>🔗 Test Links</h3>
            <ul>
                <li><a href="/health">Health Check</a></li>
                <li><a href="/api/">API Proxy Test</a></li>
                <li><a href="https://traefik.localhost:8444/">Traefik Dashboard</a></li>
                <li><a href="https://autocert.localhost:8447/">Autocert Example</a></li>
            </ul>
        </div>
        
        <div class="info">
            <h3>🛡️ Security Features</h3>
            <ul>
                <li>TLS 1.2/1.3 encryption</li>
                <li>HTTP to HTTPS redirect</li>
                <li>Security headers (HSTS, CSP, etc.)</li>
                <li>Rate limiting</li>
                <li>Gzip compression</li>
                <li>UTF-8 character encoding</li>
            </ul>
        </div>
        
        <p><small>Certificate automatically managed by Certbot + MyEncrypt</small></p>
    </div>
</body>
</html>
EOF

# Make script executable
RUN chmod +x /init-letsencrypt.sh

# Expose ports
EXPOSE 80 443

# Start the initialization script
CMD ["/init-letsencrypt.sh"]
