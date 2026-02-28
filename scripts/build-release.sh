#!/usr/bin/env bash
# build-release.sh — Helper script for building Debian package release
# Usage: bash scripts/build-release.sh [VERSION]
#
# Builds snxui DEB package and renames it to snxui_VERSION_all.deb
# Must be run from project root directory.
#
# Requirements:
#   - debhelper, devscripts, python3-setuptools, dh-python installed
#   - packaging/debian/ directory present

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

VERSION="${1:-$(cat "${PROJECT_ROOT}/VERSION" | tr -d '[:space:]')}"

if [ -z "${VERSION}" ]; then
    echo "ERROR: VERSION not specified and VERSION file not found" >&2
    echo "Usage: $0 [VERSION]" >&2
    exit 1
fi

echo "Building DEB package for snxui v${VERSION}..."

# Verify packaging/debian/ exists
if [ ! -d "${PROJECT_ROOT}/packaging/debian" ]; then
    echo "ERROR: packaging/debian/ directory not found" >&2
    exit 1
fi

cd "${PROJECT_ROOT}"

# dpkg-buildpackage requires debian/ at the CWD level
# Following the Makefile pattern: cd packaging && dpkg-buildpackage -us -uc -b
cd packaging
dpkg-buildpackage -us -uc -b

# Go back to project root to find and rename the built package
cd "${PROJECT_ROOT}"

# Find the built .deb (dpkg-buildpackage places output in parent directory)
DEB_FILE=$(find . "${PROJECT_ROOT}/.." -maxdepth 2 -name "snxui_*.deb" 2>/dev/null | head -1)

if [ -z "${DEB_FILE}" ]; then
    echo "ERROR: DEB file not found after build" >&2
    ls -la ../ 2>/dev/null || true
    exit 1
fi

OUTPUT="${PROJECT_ROOT}/snxui_${VERSION}_all.deb"
cp "${DEB_FILE}" "${OUTPUT}"

echo "DEB package built successfully: ${OUTPUT}"
echo "Size: $(du -sh "${OUTPUT}" | cut -f1)"
