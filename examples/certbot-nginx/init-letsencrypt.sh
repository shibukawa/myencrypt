#!/bin/bash

# MyEncrypt ACME server configuration
ACME_SERVER="http://myencrypt:80/acme/directory"
DOMAIN="nginx.localhost"
EMAIL="admin@example.com"

echo "### Starting certificate initialization for $DOMAIN ###"

# Wait for MyEncrypt server to be ready
echo "Waiting for MyEncrypt ACME server to be ready..."
until curl -f $ACME_SERVER > /dev/null 2>&1; do
    echo "MyEncrypt server not ready, waiting..."
    sleep 5
done
echo "MyEncrypt ACME server is ready!"

# Create dummy certificate to start Nginx
echo "### Creating dummy certificate for $DOMAIN ###"
mkdir -p /etc/letsencrypt/live/$DOMAIN
openssl req -x509 -nodes -newkey rsa:2048 -days 1 \
    -keyout /etc/letsencrypt/live/$DOMAIN/privkey.pem \
    -out /etc/letsencrypt/live/$DOMAIN/fullchain.pem \
    -subj "/CN=$DOMAIN"

# Start Nginx with dummy certificate
echo "### Starting Nginx ###"
nginx -g "daemon off;" &
NGINX_PID=$!

# Wait for Nginx to start
echo "Waiting for Nginx to start..."
sleep 10

# Test Nginx is responding
echo "Testing Nginx HTTP endpoint..."
until curl -f http://localhost/.well-known/acme-challenge/test 2>/dev/null; do
    echo "Nginx not ready for challenges, waiting..."
    sleep 2
done

# Request real certificate from MyEncrypt
echo "### Requesting certificate from MyEncrypt for $DOMAIN ###"
certbot certonly \
    --webroot \
    --webroot-path=/var/www/certbot \
    --server $ACME_SERVER \
    --email $EMAIL \
    --agree-tos \
    --no-eff-email \
    --force-renewal \
    --non-interactive \
    --verbose \
    -d $DOMAIN

if [ $? -eq 0 ]; then
    echo "### Certificate obtained successfully! ###"
    
    # Reload Nginx with real certificate
    echo "### Reloading Nginx with real certificate ###"
    nginx -s reload
    
    echo "### Setup complete! ###"
    echo "You can now access https://nginx.localhost:8446/"
else
    echo "### Certificate request failed! ###"
    echo "### Checking logs for debugging ###"
    cat /var/log/letsencrypt/letsencrypt.log | tail -20
    echo "### Continuing with dummy certificate ###"
fi

# Keep Nginx running
wait $NGINX_PID
