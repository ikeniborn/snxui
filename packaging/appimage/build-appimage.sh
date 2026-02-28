#!/bin/bash
# AppImage build script
set -e

APPDIR="$(pwd)/AppDir"
VERSION="${1:-0.1.0}"

echo "Building AppImage for snxui v${VERSION}..."

# Create AppDir structure
mkdir -p "${APPDIR}/usr/bin"
mkdir -p "${APPDIR}/usr/share/applications"
mkdir -p "${APPDIR}/usr/share/icons/hicolor/scalable/apps"

# Install application
pip install --prefix="${APPDIR}/usr" --no-deps .

# Copy resources
cp snxui/data/snxui.desktop "${APPDIR}/usr/share/applications/"
cp snxui/data/icons/snxui.svg "${APPDIR}/usr/share/icons/hicolor/scalable/apps/"
cp packaging/appimage/AppRun "${APPDIR}/AppRun"
chmod +x "${APPDIR}/AppRun"

# Symlink for AppImage
ln -sf usr/share/icons/hicolor/scalable/apps/snxui.svg "${APPDIR}/snxui.svg"
cp snxui/data/snxui.desktop "${APPDIR}/snxui.desktop"

echo "AppDir created at ${APPDIR}"
echo "Run: linuxdeploy --appdir ${APPDIR} --output appimage"
