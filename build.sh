#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR/KeyVault"
BUILD_DIR="$SCRIPT_DIR/build"
APP_NAME="KeyVault.app"
INSTALL_DIR="/Applications"

echo "Building KeyVault..."
xcodebuild \
    -project "$PROJECT_DIR/KeyVault.xcodeproj" \
    -scheme KeyVault \
    -configuration Release \
    -derivedDataPath "$BUILD_DIR"

APP_PATH="$BUILD_DIR/Build/Products/Release/$APP_NAME"

if [ ! -d "$APP_PATH" ]; then
    echo ""
    echo "Build failed."
    exit 1
fi

echo ""
echo "Build successful: $APP_PATH"

INSTALLED="${INSTALL_DIR:?}/${APP_NAME:?}"

# Refuse to quietly replace a released build with a local one. Keychain access
# is granted to an application's code signature, so overwriting the notarized
# KeyVault with a locally-signed build of the same name can leave the installed
# app unable to read the secrets it stored — on the one app where that is the
# whole point. Pass --force when replacing it is what you actually meant.
if [ -d "$INSTALLED" ] && [ "${1:-}" != "--force" ]; then
    if codesign -dvv "$INSTALLED" 2>&1 | grep -q "Authority=Developer ID Application"; then
        echo ""
        echo "$INSTALLED is a signed release build."
        echo "Replacing it with this local build may break its Keychain access."
        echo "Re-run with --force if that is what you want, or run the app from:"
        echo "  $APP_PATH"
        exit 1
    fi
fi

echo "Installing to $INSTALLED..."
rm -rf "$INSTALLED"
cp -R "$APP_PATH" "$INSTALLED"
echo "Installed to $INSTALLED"
