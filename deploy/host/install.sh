#!/bin/bash
set -e

# Define paths
CURRENT_DIR=$(pwd)
PROJECT_ROOT=$(realpath "../../")
BACKEND_DIR="$PROJECT_ROOT/backend"
FRONT_DIR="$PROJECT_ROOT/front"
INSTALL_DIR="/opt/lollipop-remote-gan"
BIN_NAME="lollipop-remote-gan-api"
GITEE_REPO="zhf_sy/zzxia-lollipop-remote-gan"

# Check for root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

get_latest_tag() {
    curl -sI https://gitee.com/$GITEE_REPO/releases/latest | grep -i location | awk -F'/' '{print $NF}' | tr -d '\r'
}

setup_config() {
    echo "=== Setting up Configuration ==="
    if [ -f "$INSTALL_DIR/config.yaml" ]; then
        echo "Configuration file already exists in $INSTALL_DIR, skipping..."
    else
        cp "$BACKEND_DIR/config.yaml.sample" "$INSTALL_DIR/config.yaml"
        echo "Copied sample config. Please edit $INSTALL_DIR/config.yaml"
    fi
}

setup_systemd() {
    echo "=== Setting up Systemd Service ==="
    SERVICE_FILE="$CURRENT_DIR/lollipop-gan.service"
    cp "$SERVICE_FILE" /etc/systemd/system/
    systemctl daemon-reload
    echo "Systemd service updated."
}

install_backend_build() {
    echo "=== 1. Building Go Backend ==="
    if ! command -v go &> /dev/null; then
        echo "Error: Go is not installed."
        return 1
    fi

    cd "$BACKEND_DIR"
    # Static build
    CGO_ENABLED=0 go build -o "$BIN_NAME" main.go
    if [ ! -f "$BIN_NAME" ]; then
        echo "Build failed!"
        return 1
    fi
    echo "Build success."

    mkdir -p "$INSTALL_DIR"
    cp "$BACKEND_DIR/$BIN_NAME" "$INSTALL_DIR/"
    cd "$CURRENT_DIR"

    setup_config
    setup_systemd
    
    echo "Backend (Build) Installation Complete."
}

install_backend_download() {
    echo "=== 1. Downloading Backend Binary ==="
    mkdir -p "$INSTALL_DIR"
    
    local tag=$(get_latest_tag)
    if [ -z "$tag" ]; then
        echo "Error: Failed to fetch latest tag from Gitee."
        return 1
    fi
    
    local url="https://gitee.com/$GITEE_REPO/releases/download/$tag/$BIN_NAME"
    echo "Downloading latest binary ($tag) from Gitee..."
    if ! curl -L -o "$INSTALL_DIR/$BIN_NAME" "$url"; then
        echo "Download failed!"
        return 1
    fi
    chmod +x "$INSTALL_DIR/$BIN_NAME"
    echo "Download success."

    setup_config
    setup_systemd

    echo "Backend (Download) Installation Complete."
}

install_front() {
    echo "=== Installing Frontend ==="
    mkdir -p "$INSTALL_DIR"
    rm -rf "$INSTALL_DIR/front"
    cp -r "$FRONT_DIR" "$INSTALL_DIR/"
    echo "Frontend Installation Complete."
}

show_complete_info() {
    echo ""
    echo "=== Installation Summary ==="
    echo "Install Dir: $INSTALL_DIR"
    echo "Next steps:"
    echo "1. Edit config:  vi $INSTALL_DIR/config.yaml"
    echo "   (Ensure GAN_CMD_HOME points to your scripts)"
    echo "2. Start Service: systemctl start lollipop-gan"
    echo "3. Enable on boot: systemctl enable lollipop-gan"
    echo "4. Configure Nginx: Copy $CURRENT_DIR/nginx_host.conf to /etc/nginx/conf.d/"
    echo "=============================="
}

# Main loop
while true; do
    echo ""
    echo "========================================"
    echo "  Lollipop Remote GAN Installation"
    echo "========================================"
    echo "1. Install Backend (Build from source)"
    echo "2. Install Backend (Download from Gitee)"
    echo "3. Install Frontend"
    echo "4. Exit"
    read -p "Select option [1-4]: " choice

    case $choice in
        1) 
            install_backend_build
            show_complete_info
            ;;
        2) 
            install_backend_download
            show_complete_info
            ;;
        3) 
            install_front
            ;;
        4) 
            echo "Exiting..."
            exit 0
            ;;
        *) 
            echo "Invalid option, please try again."
            ;;
    esac
done
