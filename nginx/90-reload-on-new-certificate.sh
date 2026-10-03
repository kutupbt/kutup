#!/bin/sh
# Run by the nginx image before nginx starts (docker-compose.acme.yml): a
# background loop that reloads nginx when the certificate file changes, so a
# renewed certificate is served without restarting the container.
CERT=/etc/nginx/certs/fullchain.pem
(
  last=$(stat -c %Y "$CERT" 2>/dev/null || echo 0)
  while sleep 30; do
    now=$(stat -c %Y "$CERT" 2>/dev/null || echo 0)
    if [ "$now" != "$last" ]; then
      last=$now
      nginx -s reload 2>/dev/null && echo "nginx: reloaded for a new certificate"
    fi
  done
) &
