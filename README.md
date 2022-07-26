# passive-fingerprinting
Passive Fingerprinting Project

# Deployment
`docker-compose build`
`docker-compose up -d`

There's some work to be done where you:
1. Comment out SSL certs in the nginx config.
2. Launch everything with docker-compose.
3. Run certbot: `docker-compose run --rm  certbot certonly --webroot --webroot-path /var/www/certbot/ -d <domain>`
4. Modify the nginx config to point to the correct paths (uncomment and change domain).
5. Restart the `webserver` container: `docker-compose restart webserver`
