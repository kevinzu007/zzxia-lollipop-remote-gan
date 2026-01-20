#!/bin/bash
set -e

# Define paths
CURRENT_DIR=$(pwd)
PROJECT_ROOT=$(realpath "../../")
BACKEND_DIR="$PROJECT_ROOT/backend"
FRONT_DIR="$PROJECT_ROOT/front"
INSTALL_DIR="/opt/lollipop-remote-gan"
BIN_NAME="lollipop-remote-gan-api"

# Check for root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

echo "=== 1. Building Go Backend ==="
if dependencies_missing=$(! command -v go &> /dev/null); then
    echo "Error: Go is not installed."
    exit 1
fi

cd "$BACKEND_DIR"
# Static build
CGO_ENABLED=0 go build -o "$BIN_NAME" main.go
if [ ! -f "$BIN_NAME" ]; then
    echo "Build failed!"
    exit 1
fi
echo "Build success."

echo "=== 2. Creating Install Directory ($INSTALL_DIR) ==="
mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/log"

echo "=== 3. Copying Files ==="
# Binary
cp "$BACKEND_DIR/$BIN_NAME" "$INSTALL_DIR/"

# Config
if [ -f "$BACKEND_DIR/config.yaml" ]; then
    cp "$BACKEND_DIR/config.yaml" "$INSTALL_DIR/"
else
    cp "$BACKEND_DIR/config.yaml.sample" "$INSTALL_DIR/config.yaml"
    echo "Copied sample config. Please edit $INSTALL_DIR/config.yaml"
fi

# Frontend
rm -rf "$INSTALL_DIR/front"
cp -r "$FRONT_DIR" "$INSTALL_DIR/"

echo "=== 4. Setting up Systemd Service ==="
SERVICE_FILE="$CURRENT_DIR/lollipop-gan.service"
cp "$SERVICE_FILE" /etc/systemd/system/
systemctl daemon-reload

echo "=== Installation Complete ==="
echo "Next steps:"
echo "1. Edit config:  vi $INSTALL_DIR/config.yaml"
echo "   (Ensure GAN_CMD_HOME points to your scripts)"
echo "2. Start Service: systemctl start lollipop-gan"
echo "3. Enable on boot: systemctl enable lollipop-gan"
echo "4. Configure Nginx: Copy $CURRENT_DIR/nginx_host.conf to /etc/nginx/conf.d/"

