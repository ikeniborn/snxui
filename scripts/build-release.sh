#!/usr/bin/env bash
# build-release.sh — Helper script for building the Debian package locally.
#
# Usage: bash scripts/build-release.sh [VERSION]
#
# Must be run from the project root directory.
#
# Requirements:
#   sudo apt-get install debhelper devscripts python3-pip python3-setuptools python3-wheel dh-python

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

VERSION="${1:-$(tr -d '[:space:]' < "${PROJECT_ROOT}/VERSION" 2>/dev/null || true)}"

if [ -z "${VERSION}" ]; then
    echo "ERROR: VERSION not specified and VERSION file not found" >&2
    echo "Usage: $0 [VERSION]" >&2
    exit 1
fi

if [ ! -d "${PROJECT_ROOT}/packaging/debian" ]; then
    echo "ERROR: packaging/debian/ directory not found" >&2
    exit 1
fi

echo "Building DEB package for snxui v${VERSION}..."

cd "${PROJECT_ROOT}"

# dpkg-buildpackage must run from the project root with debian/ as a direct subdirectory.
# packaging/debian/ cannot be used as the source root because debian/rules references
# source files (pyproject.toml, snxui/) relative to the project root.
rm -rf debian
cp -r packaging/debian debian/
# Guarantee cleanup of the temporary debian/ directory even on failure
trap 'rm -rf "${PROJECT_ROOT}/debian"' EXIT

# -us: do not sign the source package
# -uc: do not sign the .changes file
# -b: binary-only build
dpkg-buildpackage -us -uc -b

# dpkg-buildpackage places output in the parent of the project root
PARENT_DIR="$(dirname "${PROJECT_ROOT}")"
DEB_FILE=$(ls "${PARENT_DIR}/snxui_${VERSION}-1_all.deb" 2>/dev/null \
        || ls "${PARENT_DIR}/snxui_${VERSION}_all.deb" 2>/dev/null \
        || find "${PARENT_DIR}" -maxdepth 1 -name "snxui_${VERSION}*_all.deb" -print -quit)

if [ -z "${DEB_FILE}" ]; then
    echo "ERROR: DEB file not found after build in ${PARENT_DIR}" >&2
    ls -la "${PARENT_DIR}/" >&2
    exit 1
fi

OUTPUT="${PROJECT_ROOT}/snxui_${VERSION}_all.deb"
cp "${DEB_FILE}" "${OUTPUT}"

echo "DEB package built successfully: ${OUTPUT}"
echo "Size: $(du -sh "${OUTPUT}" | cut -f1)"
