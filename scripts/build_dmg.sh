#!/usr/bin/env bash
# macOS .dmg package builder for Cloudflare Clean IP Scanner

set -e

VERSION=${1:-"1.0.0"}
APP_NAME="cf-clean-ip-scanner"
DIST_DIR="dist"
DMG_NAME="${APP_NAME}-${VERSION}-macos.dmg"

echo "[*] Building macOS DMG: ${DMG_NAME}"

if [ ! -d "${DIST_DIR}/${APP_NAME}.app" ]; then
    echo "Error: ${DIST_DIR}/${APP_NAME}.app not found. Build it with PyInstaller first."
    exit 1
fi

# Create a staging directory
STAGING_DIR="dmg_staging"
rm -rf "${STAGING_DIR}" "${DIST_DIR}/${DMG_NAME}"
mkdir -p "${STAGING_DIR}"

# Copy app bundle
cp -R "${DIST_DIR}/${APP_NAME}.app" "${STAGING_DIR}/"

# Create Applications link
ln -s /Applications "${STAGING_DIR}/Applications"

# Build DMG using hdiutil
hdiutil create -volname "Cloudflare Clean IP Scanner" \
  -srcfolder "${STAGING_DIR}" \
  -ov -format UDZO \
  "${DIST_DIR}/${DMG_NAME}"

rm -rf "${STAGING_DIR}"

echo "[✓] Successfully built ${DIST_DIR}/${DMG_NAME}"
