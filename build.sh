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

echo "Installing to $INSTALL_DIR/$APP_NAME..."
rm -rf "$INSTALL_DIR/$APP_NAME"
cp -R "$APP_PATH" "$INSTALL_DIR/$APP_NAME"
echo "Installed to $INSTALL_DIR/$APP_NAME"
