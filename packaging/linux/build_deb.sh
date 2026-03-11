#!/bin/bash
# =============================================================================
# NetGuard IDS — Linux .deb Package Build Script
# =============================================================================
# Requires: dpkg-dev, fakeroot, Python 3.10+
#
# Usage:
#   cd packaging/linux
#   chmod +x build_deb.sh && ./build_deb.sh
#
# Output:
#   dist/netguard-ids_2.0.0_amd64.deb
# =============================================================================

set -euo pipefail

VERSION="2.0.0"
PKG_NAME="netguard-ids"
ARCH="amd64"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STAGING="$REPO_ROOT/build/deb-staging"
DIST_DIR="$REPO_ROOT/dist"
DEB_OUT="$DIST_DIR/${PKG_NAME}_${VERSION}_${ARCH}.deb"
INSTALL_PREFIX="/opt/netguard-ids"

echo "==========================================="
echo " NetGuard IDS $VERSION — .deb Build"
echo "==========================================="
echo ""

# ── Step 1: Create staging directory tree ────────────────────────────────────
echo "[1/6] Creating staging directory..."
rm -rf "$STAGING"
mkdir -p "$STAGING/DEBIAN"
mkdir -p "$STAGING$INSTALL_PREFIX"
mkdir -p "$STAGING$INSTALL_PREFIX/rules"
mkdir -p "$STAGING$INSTALL_PREFIX/config"
mkdir -p "$STAGING$INSTALL_PREFIX/logs"
mkdir -p "$STAGING/etc/netguard"
mkdir -p "$STAGING/usr/bin"
mkdir -p "$STAGING/usr/share/doc/$PKG_NAME"
mkdir -p "$STAGING/usr/share/man/man1"
mkdir -p "$STAGING/lib/systemd/system"

# ── Step 2: Install Python package into venv inside staging ──────────────────
echo "[2/6] Installing Python package..."
python3 -m venv "$STAGING$INSTALL_PREFIX/venv"
"$STAGING$INSTALL_PREFIX/venv/bin/pip" install --quiet --upgrade pip
"$STAGING$INSTALL_PREFIX/venv/bin/pip" install --quiet \
    "$REPO_ROOT[api,cli,ml]"

# ── Step 3: Copy application files ───────────────────────────────────────────
echo "[3/6] Copying application files..."
cp "$REPO_ROOT/config.yaml"        "$STAGING/etc/netguard/config.yaml"
cp "$REPO_ROOT/rules/builtin.yaml" "$STAGING$INSTALL_PREFIX/rules/builtin.yaml"
cp -r "$REPO_ROOT/docs"            "$STAGING/usr/share/doc/$PKG_NAME/"
cp "$REPO_ROOT/CHANGELOG.md"       "$STAGING/usr/share/doc/$PKG_NAME/"
cp "$REPO_ROOT/LICENSE"            "$STAGING/usr/share/doc/$PKG_NAME/" 2>/dev/null || \
    echo "MIT License — Copyright 2024 Arman" > "$STAGING/usr/share/doc/$PKG_NAME/copyright"

# ── Step 4: Wrapper scripts in /usr/bin ──────────────────────────────────────
echo "[4/6] Installing wrapper scripts..."
cat > "$STAGING/usr/bin/netguard" << 'EOF'
#!/bin/bash
exec /opt/netguard-ids/venv/bin/python -m main "$@"
EOF
cat > "$STAGING/usr/bin/netguard-cli" << 'EOF'
#!/bin/bash
exec /opt/netguard-ids/venv/bin/python -m cli "$@"
EOF
chmod 755 "$STAGING/usr/bin/netguard" "$STAGING/usr/bin/netguard-cli"

# ── Step 5: systemd service unit ─────────────────────────────────────────────
echo "[5/6] Installing systemd unit..."
cat > "$STAGING/lib/systemd/system/netguard-ids.service" << EOF
[Unit]
Description=NetGuard IDS — Advanced Firewall and Intrusion Detection System
Documentation=https://github.com/Armanrbu/Firewall-Configuration-and-Basic-Intrusion-Detection-System
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/netguard-cli engine start --headless
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=netguard-ids
Environment=NETGUARD_CONFIG=/etc/netguard/config.yaml
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_PTRACE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/etc/netguard /opt/netguard-ids/logs /var/log

[Install]
WantedBy=multi-user.target
EOF

# ── Step 6: DEBIAN control files ─────────────────────────────────────────────
echo "[6/6] Writing DEBIAN control files..."
cp "$REPO_ROOT/packaging/linux/debian/control" "$STAGING/DEBIAN/control"
sed -i "s/^Version: .*/Version: $VERSION/" "$STAGING/DEBIAN/control"

# Compute installed size (in KB)
INST_SIZE=$(du -sk "$STAGING" | awk '{print $1}')
sed -i "s/^Installed-Size: .*/Installed-Size: $INST_SIZE/" "$STAGING/DEBIAN/control"

# postinst
cat > "$STAGING/DEBIAN/postinst" << 'POSTINST'
#!/bin/bash
set -e
# Enable and start the service
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    systemctl enable netguard-ids.service
    echo "NetGuard IDS service enabled. Start with: systemctl start netguard-ids"
fi
# Create log directory
mkdir -p /var/log/netguard
chmod 750 /var/log/netguard
echo "NetGuard IDS v2.0.0 installed successfully."
echo "Config: /etc/netguard/config.yaml"
echo "Docs  : /usr/share/doc/netguard-ids/"
POSTINST
chmod 755 "$STAGING/DEBIAN/postinst"

# prerm
cat > "$STAGING/DEBIAN/prerm" << 'PRERM'
#!/bin/bash
set -e
if command -v systemctl >/dev/null 2>&1; then
    systemctl stop netguard-ids.service  2>/dev/null || true
    systemctl disable netguard-ids.service 2>/dev/null || true
fi
PRERM
chmod 755 "$STAGING/DEBIAN/prerm"

# md5sums
find "$STAGING" -type f ! -path "$STAGING/DEBIAN/*" \
    | xargs md5sum 2>/dev/null \
    | sed "s|$STAGING/||" > "$STAGING/DEBIAN/md5sums"

# ── Build .deb ───────────────────────────────────────────────────────────────
mkdir -p "$DIST_DIR"
fakeroot dpkg-deb --build "$STAGING" "$DEB_OUT"

echo ""
echo "=========================================="
if [ -f "$DEB_OUT" ]; then
    SIZE_MB=$(du -sMh "$DEB_OUT" | awk '{print $1}')
    echo "✅ .deb built: $DEB_OUT ($SIZE_MB)"
    echo ""
    echo "Install with:"
    echo "  sudo dpkg -i $DEB_OUT"
    echo "  sudo apt-get install -f   # fix any missing deps"
else
    echo "❌ Build failed — $DEB_OUT not found"
    exit 1
fi
