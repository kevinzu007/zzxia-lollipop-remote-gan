# Deployment Guide

This project supports two deployment modes: **Docker Container** (Recommended) and **Host Machine** (Systemd).

## 1. Docker Deployment (Recommended)

Quickly bring up the entire stack with Docker Compose. This setup includes:
- **Backend Container**: Runs the Go API, with specific tooling (Docker client, etc.) to executing scripts.
- **Frontend Container**: Nginx serving the static specific files and proxying API requests.
- **Sibling Docker**: The backend container mounts `/var/run/docker.sock`, allowing scripts to control the host's Docker engine.

### Prerequisites
- Docker & Docker Compose installed.

### Steps
1. Navigate to the docker directory:
   ```bash
   cd deploy/docker
   ```

2. **Edit configurations**:
   Before starting, you should edit the configuration files in `deploy/docker/`:
   - `config.yaml`: Backend settings (DB paths, ports, JWT secrets).
   - `config.js`: Frontend settings (Backend URLs, env list).
   
   These files are mounted as volumes, so any changes you make will persist even if the containers are removed and recreated.

3. (Optional) Edit `docker-compose.yaml` to point to your actual script repository.
   By default, it uses the sample scripts in `backend/samples`. For production, you likely want to mount your real `zzxia-op-super-invincible-lollipop` repo.
   
   Open `docker-compose.yaml` and modify the volumes section:
   ```yaml
   volumes:
     - /path/to/your/real/zzxia-op-super-invincible-lollipop:/app/zzxia-op-super-invincible-lollipop
   ```

3. Start the services:
   ```bash
   docker-compose up -d --build
   ```

4. Access the application:
   - Frontend: `http://localhost:80` (or whichever port you mapped)
   - Backend API: `http://localhost:9527`

---

## 2. Host Machine Deployment (Linux/Systemd)

Install as a native system service. Best for environments where you want direct control without container abstraction.

### Prerequisites
- Go 1.21+ installed.
- Nginx installed.
- Root privileges.

### Steps
1. Navigate to the host directory:
   ```bash
   cd deploy/host
   ```

2. Run the install script:
   ```bash
   chmod +x install.sh
   sudo ./install.sh
   ```
   This will:
   - Build the backend binary.
   - Install files to `/opt/lollipop-remote-gan`.
   - Install the Systemd service `lollipop-gan.service`.

3. Configure Nginx:
   ```bash
   sudo cp nginx_host.conf /etc/nginx/conf.d/lollipop-gan.conf
   sudo systemctl restart nginx
   ```

4. Verify service:
   ```bash
   systemctl status lollipop-gan
   ```
