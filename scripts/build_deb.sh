#!/usr/bin/env bash
# Debian / Ubuntu .deb package builder for Cloudflare Clean IP Scanner

set -e

VERSION=${1:-"1.0.0"}
ARCH="amd64"
PKG_NAME="cf-clean-ip-scanner"
DIST_DIR="dist"
STAGE_DIR="deb_dist/${PKG_NAME}_${VERSION}_${ARCH}"

echo "[*] Building Debian package: ${PKG_NAME}_${VERSION}_${ARCH}.deb"

# Clean old staging
rm -rf "deb_dist"
mkdir -p "${STAGE_DIR}/DEBIAN"
mkdir -p "${STAGE_DIR}/usr/bin"
mkdir -p "${STAGE_DIR}/usr/share/applications"
mkdir -p "${STAGE_DIR}/usr/share/icons/hicolor/scalable/apps"

# 1. Copy binary
if [ -f "${DIST_DIR}/cf-clean-ip-scanner" ]; then
    cp "${DIST_DIR}/cf-clean-ip-scanner" "${STAGE_DIR}/usr/bin/cf-clean-ip-scanner"
    chmod 755 "${STAGE_DIR}/usr/bin/cf-clean-ip-scanner"
else
    echo "Error: ${DIST_DIR}/cf-clean-ip-scanner binary not found. Build it first with PyInstaller."
    exit 1
fi

# 2. Create Desktop file
cat << 'EOF' > "${STAGE_DIR}/usr/share/applications/cf-clean-ip-scanner.desktop"
[Desktop Entry]
Name=Cloudflare Clean IP Scanner
Comment=High-speed Cloudflare Clean IP Scanner with HE BGP API & RealDelay Test
Exec=/usr/bin/cf-clean-ip-scanner
Icon=cf-clean-ip-scanner
Terminal=false
Type=Application
Categories=Network;Utility;
EOF
chmod 644 "${STAGE_DIR}/usr/share/applications/cf-clean-ip-scanner.desktop"

# 3. Create Control file
cat << EOF > "${STAGE_DIR}/DEBIAN/control"
Package: ${PKG_NAME}
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Maintainer: Cloudflare Clean IP Scanner Team
Description: Cloudflare Clean IP Scanner with Hurricane Electric BGP API & RealDelay testing.
 A cross-platform GUI and CLI scanner for discovering clean, low-latency Cloudflare CDN IPs.
EOF
chmod 644 "${STAGE_DIR}/DEBIAN/control"

# 4. Build .deb package
dpkg-deb --build --root-owner-group "${STAGE_DIR}" "dist/${PKG_NAME}_${VERSION}_${ARCH}.deb"

echo "[✓] Successfully built dist/${PKG_NAME}_${VERSION}_${ARCH}.deb"
