# Self-Hosting Guide

This guide covers a production Kutup deployment using Docker Compose.

---

## Prerequisites

- **Docker** 24+ and **Docker Compose** v2 (`docker compose` command, not `docker-compose`)
- A Linux server with at least 1 GB RAM
- A domain name (required for HTTPS and for federation to work correctly)

---

## Step 1: Clone and Configure

```sh
git clone https://github.com/alperen-albayrak/kutup.git
cd kutup
cp .env.example .env
```

Edit `.env` and fill in every value:

```sh
# PostgreSQL — use a strong random password
POSTGRES_PASSWORD=<strong-random-password>

# JWT secret — generate with:
#   openssl rand -hex 64
JWT_SECRET=<64-byte-hex-string>

# SeaweedFS S3 credentials — must match seaweedfs-s3.json
S3_ACCESS_KEY=kutup
S3_SECRET_KEY=<strong-random-secret>
S3_BUCKET=kutup-files

# Public URL — used to build federation invite links
# Must be the address users (and remote servers) reach this instance at
SERVER_URL=https://kutup.example.com

# Admin bootstrap: email:username:password triples, comma-separated
# Accounts are created on first start; admins must complete setup on first login
ADMIN_ACCOUNTS=admin@example.com:admin:<strong-admin-password>
```

---

## Step 2: Configure SeaweedFS S3 Credentials

`seaweedfs-s3.json` must use the **same** access key and secret you set in `.env`:

```json
{
  "identities": [
    {
      "name": "kutup",
      "credentials": [
        {
          "accessKey": "kutup",
          "secretKey": "<same-S3_SECRET_KEY-as-in-.env>"
        }
      ],
      "actions": ["Admin", "Read", "Write"]
    }
  ]
}
```

The file is volume-mounted into the SeaweedFS S3 container at startup.

---

## Step 3: Start the Stack

```sh
docker compose up -d --build
```

This builds the backend and frontend images, then starts all services:

| Service | Role |
|---------|------|
| `postgres` | Database |
| `seaweedfs-master` | SeaweedFS master node |
| `seaweedfs-volume` | SeaweedFS volume server |
| `seaweedfs-filer` | SeaweedFS filer |
| `seaweedfs-s3` | SeaweedFS S3 gateway |
| `seaweedfs-init` | One-shot: creates the S3 bucket |
| `backend` | Go API server (internal port 3000) |
| `frontend` | Compiled React app (served by Nginx) |
| `nginx` | Reverse proxy — listens on port 80; 443 requires the manual TLS setup below |

---

## Step 4: First Login

Find the admin password confirmation in the backend logs:

```sh
docker compose logs backend | grep -i "admin\|bootstrap"
```

Open `http://localhost` (or your domain) and log in. You will be redirected to a first-login setup page where you must:

1. Generate your **recovery phrase** (BIP39 mnemonic) — write it down and store it safely.
2. Optionally configure 2FA.

The recovery phrase is the only way to recover your account if you forget your password. It is never sent to the server.

---

## TLS / HTTPS

The bundled `nginx/nginx.conf` listens on port 80 only. To add HTTPS, add a second server block to `nginx/nginx.conf`:

```nginx
server {
    listen 443 ssl;
    server_name kutup.example.com;

    ssl_certificate     /etc/nginx/certs/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/privkey.pem;

    # copy all location blocks from the port-80 server block here
}
```

Place your certificate files in `./nginx/certs/` (volume-mounted into the container):

```
nginx/certs/
├── fullchain.pem    # Certificate chain
└── privkey.pem      # Private key
```

Then reload Nginx:

```sh
docker compose exec nginx nginx -s reload
```

### Using Certbot (Let's Encrypt)

```sh
# On the host (not inside Docker)
certbot certonly --standalone -d kutup.example.com

# Copy into nginx/certs/
cp /etc/letsencrypt/live/kutup.example.com/fullchain.pem nginx/certs/
cp /etc/letsencrypt/live/kutup.example.com/privkey.pem nginx/certs/
```

---

## SERVER_URL

`SERVER_URL` must be set to the externally reachable base URL of your instance, including the scheme:

```
SERVER_URL=https://kutup.example.com
```

This value is embedded in federation invite links. If it is wrong, cross-server sharing will not work. After changing it, rebuild the backend:

```sh
docker compose up -d --build backend
```

---

## Storage and Backups

All persistent data lives in Docker volumes and bind-mounted directories:

| Data | Location |
|------|----------|
| PostgreSQL database | `postgres_data` (Docker named volume) |
| SeaweedFS master metadata | `./data/seaweedfs-master` |
| SeaweedFS file chunks | `./data/seaweedfs-volume` |

**To back up:**

```sh
# PostgreSQL
docker compose exec postgres pg_dump -U "${POSTGRES_USER:-kutup}" "${POSTGRES_DB:-kutup}" | gzip > backup-$(date +%F).sql.gz

# SeaweedFS data
tar -czf seaweedfs-$(date +%F).tar.gz data/
```

Store backups off-site. The SeaweedFS data directories contain ciphertext only — even a full backup is useless without user keys.

---

## Updating

```sh
git pull
docker compose up -d --build
```

Database migrations run automatically on backend startup.

---

## Running Behind an Existing Reverse Proxy

If you already have Nginx or Caddy on the host, set the stack to not bind port 80 directly. Edit `docker-compose.yml` to change the nginx ports:

```yaml
nginx:
  ports:
    - "127.0.0.1:8080:80"   # bind only locally
```

Then proxy from your host Nginx to `http://127.0.0.1:8080`:

```nginx
server {
    listen 443 ssl;
    server_name kutup.example.com;

    ssl_certificate     /etc/letsencrypt/live/kutup.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/kutup.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        # Required for large file uploads:
        client_max_body_size 0;
        proxy_request_buffering off;
    }
}
```

For **Caddy**:

```
kutup.example.com {
    reverse_proxy localhost:8080
}
```

---

## Security Hardening

- **Change all defaults** in `.env` before first start. The defaults are intentionally weak placeholders.
- **Firewall:** Only expose ports 80 and 443. All other services (PostgreSQL, SeaweedFS) must not be reachable from the internet.
- **JWT_SECRET:** Use `openssl rand -hex 64`. A weak secret allows forging authentication tokens.
- **ADMIN_ACCOUNTS:** Remove or rotate the bootstrap admin credentials after first login.
- **Quotas:** Set default storage quotas in the admin dashboard to prevent abuse.
- **Updates:** Keep Docker images and the application updated.
