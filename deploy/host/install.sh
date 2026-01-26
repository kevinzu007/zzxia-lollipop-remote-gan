#!/bin/bash
set -e

# Define paths
CURRENT_DIR=$(pwd)
PROJECT_ROOT=$(realpath "../../")
BACKEND_DIR="$PROJECT_ROOT/backend"
FRONT_DIR="$PROJECT_ROOT/front"
INSTALL_DIR="/opt/lollipop-remote-gan"
BACKEND_INSTALL_DIR="$INSTALL_DIR/backend"
FRONT_INSTALL_DIR="$INSTALL_DIR/front"
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
    mkdir -p "$BACKEND_INSTALL_DIR"
    if [ -f "$BACKEND_INSTALL_DIR/config.yaml" ]; then
        echo "Configuration file already exists in $BACKEND_INSTALL_DIR, skipping..."
    else
        cp "$BACKEND_DIR/config.yaml.sample" "$BACKEND_INSTALL_DIR/config.yaml"
        echo "Copied sample config. Please edit $BACKEND_INSTALL_DIR/config.yaml"
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

    mkdir -p "$BACKEND_INSTALL_DIR"
    cp "$BACKEND_DIR/$BIN_NAME" "$BACKEND_INSTALL_DIR/"
    cd "$CURRENT_DIR"

    setup_config
    setup_systemd
    
    echo "Backend (Build) Installation Complete."
}

install_backend_download() {
    echo "=== 1. Downloading Backend Binary ==="
    mkdir -p "$BACKEND_INSTALL_DIR"
    
    local tag=$(get_latest_tag)
    if [ -z "$tag" ]; then
        echo "Error: Failed to fetch latest tag from Gitee."
        return 1
    fi
    
    local url="https://gitee.com/$GITEE_REPO/releases/download/$tag/$BIN_NAME"
    echo "Downloading latest binary ($tag) from Gitee..."
    if ! curl -L -o "$BACKEND_INSTALL_DIR/$BIN_NAME" "$url"; then
        echo "Download failed!"
        return 1
    fi
    chmod +x "$BACKEND_INSTALL_DIR/$BIN_NAME"
    echo "Download success."

    setup_config
    setup_systemd

    echo "Backend (Download) Installation Complete."
}

install_front() {
    echo "=== Installing Frontend ==="
    mkdir -p "$FRONT_INSTALL_DIR"
    
    # Backup existing config to avoid overwrite
    if [ -f "$FRONT_INSTALL_DIR/config.js" ]; then
        mv "$FRONT_INSTALL_DIR/config.js" "$FRONT_INSTALL_DIR/config.js.bak"
    fi

    # Copy files
    cp -rf "$FRONT_DIR"/* "$FRONT_INSTALL_DIR/"

    # Restore or initialize config.js
    if [ -f "$FRONT_INSTALL_DIR/config.js.bak" ]; then
        mv "$FRONT_INSTALL_DIR/config.js.bak" "$FRONT_INSTALL_DIR/config.js"
        echo "Existing frontend config.js preserved."
    else
        # Ensure we start with sample if no previous config existed
        cp "$FRONT_DIR/config.js.sample" "$FRONT_INSTALL_DIR/config.js"
        echo "Created new config.js from sample."
    fi

    echo "Frontend Installation Complete."
    echo ""
    echo "Reminder: Please configure Nginx manually."
    echo "You can use the template at: $CURRENT_DIR/nginx_host.conf"
}

show_complete_info() {
    echo ""
    echo "=== Installation Summary ==="
    echo "Install Dir: $INSTALL_DIR"
    echo "Backend Dir: $BACKEND_INSTALL_DIR"
    echo "Front Dir:   $FRONT_INSTALL_DIR"
    echo "Next steps:"
    echo "1. Edit config:  vi $BACKEND_INSTALL_DIR/config.yaml"
    echo "   (Ensure GAN_CMD_HOME points to your scripts)"
    echo "2. Start Service: systemctl start lollipop-gan"
    echo "3. Enable on boot: systemctl enable lollipop-gan"
    echo "4. Configure Nginx: You can use the template at: $CURRENT_DIR/nginx_host.conf"
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
