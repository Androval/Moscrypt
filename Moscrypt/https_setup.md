# HTTPS Setup for Moscrypt
This entire document was written by AI, please take what it says with a grain of salt.

This document explains how to set up and enforce HTTPS for the Moscrypt application.

## Overview of Implemented Security Features

1. **HTTP to HTTPS Redirection**
   - All HTTP requests are automatically redirected to HTTPS
   - This is handled by the Flask middleware in `server.py`

2. **HSTS (HTTP Strict Transport Security)**
   - Once a browser receives this header, it will use HTTPS for all future requests
   - Protects against protocol downgrade attacks and cookie hijacking
   - Enabled by default when FORCE_HTTPS is set to true

3. **Secure Cookie Settings**
   - Session cookies are marked as `Secure` and `HttpOnly`
   - Prevents client-side access to cookies and transmission over HTTP

## Configuration

The HTTPS enforcement is controlled by the `FORCE_HTTPS` environment variable:

- In `.env` file: `FORCE_HTTPS=true`
- In Supervisor config: `FORCE_HTTPS="true"`

## Setup with Nginx as Reverse Proxy

For production deployment, we recommend using Nginx as a reverse proxy to handle SSL/TLS termination:

1. **Install Nginx**
   ```
   sudo apt-get install nginx
   ```

2. **Obtain SSL Certificate**
   
   Using Let's Encrypt:
   ```
   sudo apt-get install certbot python3-certbot-nginx
   sudo certbot --nginx -d yourdomain.com
   ```

3. **Configure Nginx**
   
   Create a file `/etc/nginx/sites-available/moscrypt`:
   ```nginx
   server {
       listen 80;
       server_name yourdomain.com;
       
       # Redirect all HTTP to HTTPS
       return 301 https://$host$request_uri;
   }

   server {
       listen 443 ssl;
       server_name yourdomain.com;
       
       ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
       ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
       ssl_protocols TLSv1.2 TLSv1.3;
       ssl_prefer_server_ciphers on;
       ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
       
       # Enable OCSP stapling
       ssl_stapling on;
       ssl_stapling_verify on;
       
       # Add HSTS header with a 1 year max-age
       add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
       
       # Proxy to Gunicorn
       location / {
           proxy_pass http://127.0.0.1:8000;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
       }
   }
   ```

4. **Enable the Site**
   ```
   sudo ln -s /etc/nginx/sites-available/moscrypt /etc/nginx/sites-enabled/
   sudo nginx -t
   sudo systemctl restart nginx
   ```

## Testing HTTPS Configuration

After deployment, use these tools to verify your HTTPS setup:

1. Qualys SSL Labs: https://www.ssllabs.com/ssltest/
2. HSTS Preload check: https://hstspreload.org/
3. Security Headers: https://securityheaders.com/

## Local Development

For local development, you can:

1. Set `FORCE_HTTPS=false` in your local `.env` file
2. Use a self-signed certificate with Flask:
   ```
   openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
   ```
   Then run Flask with:
   ```
   flask run --cert=cert.pem --key=key.pem
   ```

## Notes on Deployment Behind a Load Balancer

If deploying behind a load balancer:

1. Ensure the load balancer forwards the appropriate headers:
   - X-Forwarded-Proto
   - X-Forwarded-For
   - X-Real-IP

2. The application is already configured to handle these headers through the ProxyFix middleware. 