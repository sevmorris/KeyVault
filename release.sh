#!/usr/bin/env zsh
# release.sh — Build, verify, package, and publish a KeyVault release.
#
# Usage: ./release.sh <version>
#   e.g. ./release.sh 1.0
#
# Requires: xcodebuild, hdiutil, gh (GitHub CLI), git

set -euo pipefail

REPO="sevmorris/KeyVault"

# ── Args ──────────────────────────────────────────────────────────────────────
if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <version>"
    echo "  e.g. $0 1.0"
    exit 1
fi

VERSION="$1"
TAG="v${VERSION}"
SCRIPT_DIR="${0:A:h}"
PROJECT_DIR="$SCRIPT_DIR"
PROJECT="$PROJECT_DIR/KeyVault/KeyVault.xcodeproj"
SCHEME="KeyVault"
DERIVED_DATA="/tmp/keyvault_build_${VERSION}"
APP_PATH="$DERIVED_DATA/Build/Products/Release/KeyVault.app"
STAGING="/tmp/keyvault_dmg_${VERSION}"
DMG="/tmp/KeyVault-${TAG}.dmg"
MOUNT="/tmp/keyvault_verify_${VERSION}"

# ── Helpers ───────────────────────────────────────────────────────────────────
step()  { echo "\n▶ $*"; }
ok()    { echo "  ✓ $*"; }
fail()  { echo "\n  ✗ $*" >&2; exit 1; }

cleanup() {
    rm -rf "$STAGING" "$MOUNT" "$DERIVED_DATA"
    rm -f "$DMG"
}

# ── Preflight ─────────────────────────────────────────────────────────────────
step "Preflight checks"
python3 -c "import dmgbuild" 2>/dev/null \
    || fail "python3 module 'dmgbuild' not installed — run: python3 -m pip install dmgbuild"

for cmd in xcodebuild hdiutil gh git python3; do
    command -v $cmd &>/dev/null || fail "'$cmd' not found in PATH"
done
ok "Tools present"

cd "$PROJECT_DIR"

if [[ -n "$(git status --porcelain)" ]]; then
    fail "Working tree is dirty — commit or stash changes before releasing"
fi
ok "Working tree clean"

if git tag | grep -q "^${TAG}$"; then
    fail "Tag $TAG already exists — has this version been released?"
fi
ok "Tag $TAG is available"

# Files marked "Shared verbatim across the sibling app repos" must not drift.
"$PROJECT_DIR/scripts/check-shared.sh" \
    || fail "Shared files have drifted from the sibling repos"

# ── Version bump ──────────────────────────────────────────────────────────────
step "Bumping version to $VERSION"
PBXPROJ="$PROJECT_DIR/KeyVault/KeyVault.xcodeproj/project.pbxproj"
# No Info.plist in this project — the version is a build setting, so the bump
# edits project.pbxproj. Both configurations carry it; sed rewrites both.
CURRENT=$(awk -F' = ' '/MARKETING_VERSION/ {gsub(/;/,"",$2); print $2; exit}' "$PBXPROJ")
if [[ "$CURRENT" == "$VERSION" ]]; then
    ok "Version already $VERSION"
else
    sed -i '' "s/MARKETING_VERSION = ${CURRENT};/MARKETING_VERSION = ${VERSION};/g" "$PBXPROJ"
    NOW=$(awk -F' = ' '/MARKETING_VERSION/ {gsub(/;/,"",$2); print $2; exit}' "$PBXPROJ")
    [[ "$NOW" == "$VERSION" ]] || fail "Version bump did not take: still $NOW"
    git add "$PBXPROJ"
    git commit -m "Bump version to $VERSION"
    ok "Version $CURRENT → $VERSION"
fi

# ── Build ─────────────────────────────────────────────────────────────────────
step "Building (clean, Release)"
rm -rf "$DERIVED_DATA"
rm -rf ~/Library/Caches/com.apple.dt.Xcode/ 2>/dev/null || true
rm -rf ~/Library/Developer/Xcode/DerivedData/ModuleCache* 2>/dev/null || true
ok "Xcode caches cleared"
xcodebuild \
    -project "$PROJECT" \
    -scheme "$SCHEME" \
    -configuration Release \
    -derivedDataPath "$DERIVED_DATA" \
    -quiet
[[ -d "$APP_PATH" ]] || fail "Build did not produce $APP_PATH"
ok "Build complete"

# ── Sign ──────────────────────────────────────────────────────────────────────
step "Codesigning app"
IDENTITY="Developer ID Application: Seven Morris (T9RLNAXPWU)"
ENTITLEMENTS="$PROJECT_DIR/KeyVault/KeyVault/KeyVault.entitlements"

# Sign the app bundle with Hardened Runtime
codesign --force --options runtime --entitlements "$ENTITLEMENTS" --sign "$IDENTITY" "$APP_PATH"
codesign --verify --deep --strict --verbose=2 "$APP_PATH" 2>&1 | tail -3
ok "Codesigning complete"

# ── Verify app version ────────────────────────────────────────────────────────
step "Verifying built app version"
BUILT_VERSION=$(defaults read "$APP_PATH/Contents/Info.plist" CFBundleShortVersionString)
[[ "$BUILT_VERSION" == "$VERSION" ]] || \
    fail "App version mismatch: expected $VERSION, got $BUILT_VERSION"
ok "App reports $BUILT_VERSION"

# ── Create DMG ────────────────────────────────────────────────────────────────
step "Creating DMG"
rm -f "$DMG"
# dmgbuild rather than bare hdiutil so the installer window is laid out:
# background art with an arrow, the app and the Applications alias pinned to its
# endpoints, chrome hidden. Matches the sibling apps.
DMG_BACKGROUND="$PROJECT_DIR/tools/dmg/dmg-background-keyvault.png"
[[ -f "$DMG_BACKGROUND" ]] \
    || fail "Missing DMG background: ${DMG_BACKGROUND#$PROJECT_DIR/} — regenerate with tools/dmg/make-background.py --app-name KeyVault --slug keyvault"

# A python3 that actually has dmgbuild, not Xcode's bundled one; /bin prepended
# because dmgbuild shells out to bare tool names.
PY_BIN=$(command -v python3)
PATH="/bin:/usr/bin:$PATH" "$PY_BIN" -m dmgbuild \
    -s "$PROJECT_DIR/tools/dmg/dmg-settings.py" \
    -D app="$APP_PATH" \
    -D background="$DMG_BACKGROUND" \
    "KeyVault $TAG" "$DMG"
[[ -f "$DMG" ]] || fail "dmgbuild did not produce $DMG"
ok "Created $(du -sh "$DMG" | cut -f1) DMG"

# ── Notarize ──────────────────────────────────────────────────────────────────
step "Notarizing DMG"
# Reusing 'WoWoNotary' profile
xcrun notarytool submit "$DMG" --wait --keychain-profile "WoWoNotary"
xcrun stapler staple "$DMG"
ok "Notarization complete"

# ── Verify DMG ────────────────────────────────────────────────────────────────
step "Verifying DMG contents"
rm -rf "$MOUNT"
mkdir "$MOUNT"
hdiutil attach "$DMG" -mountpoint "$MOUNT" -quiet -nobrowse
DMG_VERSION=$(defaults read "$MOUNT/KeyVault.app/Contents/Info.plist" CFBundleShortVersionString)
hdiutil detach "$MOUNT" -quiet
[[ "$DMG_VERSION" == "$VERSION" ]] || \
    fail "DMG version mismatch: expected $VERSION, got $DMG_VERSION"
ok "DMG contains $DMG_VERSION"

# ── Update docs (README) ─────────────────────────────────────────────────────
step "Updating README to ${TAG}"
sed -i '' "s|KeyVault-v[0-9][0-9.]*\.dmg|KeyVault-${TAG}.dmg|g" README.md
sed -i '' "s|Download v[0-9][0-9.]*|Download ${TAG}|g" README.md

if [[ -n "$(git status --porcelain README.md)" ]]; then
    git add README.md
    git commit -m "docs: update download link to ${TAG}"
    ok "README updated to ${TAG}"
else
    ok "README already up to date"
fi

# ── Tag and push ──────────────────────────────────────────────────────────────
step "Tagging and pushing"
git tag "$TAG"
# Resolve the tracked remote/branch so this works from any branch (e.g. a
# worktree branch whose name differs from its upstream). Fall back to
# `origin` + current branch when no upstream is configured; `-u` sets it
# on first push so subsequent runs resolve cleanly.
if UPSTREAM=$(git rev-parse --abbrev-ref '@{upstream}' 2>/dev/null); then
    REMOTE="${UPSTREAM%%/*}"
    BRANCH="${UPSTREAM#*/}"
else
    REMOTE="origin"
    BRANCH=$(git branch --show-current)
fi
git push -u "$REMOTE" "HEAD:$BRANCH"
git push "$REMOTE" "$TAG"
ok "Pushed $TAG to $REMOTE/$BRANCH"

# ── GitHub release ────────────────────────────────────────────────────────────
step "Creating GitHub release"
PREV_TAG=$(git tag --sort=-creatordate | grep -v "^${TAG}$" | head -1 || true)
if [[ -n "$PREV_TAG" ]]; then
    CHANGES=$(git log "${PREV_TAG}..HEAD" --pretty=format:"- %s" \
        | grep -v "^- Bump version" \
        | grep -v "^- docs: update download link" || true)
else
    CHANGES=$(git log --pretty=format:"- %s" \
        | grep -v "^- Bump version" \
        | grep -v "^- docs: update download link" || true)
fi
[[ -n "$CHANGES" ]] || CHANGES="- Initial release"
RELEASE_NOTES="### Changes
${CHANGES}"
gh release create "$TAG" "$DMG" \
    --repo "$REPO" \
    --title "KeyVault $TAG" \
    --notes "$RELEASE_NOTES"
ok "Release published"

# ── Remove old releases (keep the ${KEEP_RELEASES} most recent) ───────────────
KEEP_RELEASES=5
step "Removing old releases (keeping ${KEEP_RELEASES} most recent)"
# Filtered to v* so non-release tags (build-dependency releases, checkpoints)
# are never in scope for pruning by date alone.
OLD_TAGS=$(gh release list --repo "$REPO" --limit 100 --json tagName \
    --jq '.[].tagName' | grep -E '^v[0-9]' | tail -n +$((KEEP_RELEASES + 1)) || true)
if [[ -z "$OLD_TAGS" ]]; then
    ok "No old releases to remove"
else
    while IFS= read -r old_tag; do
        # Prunes the release page and its asset, NOT the git tag. The tag is the
        # only durable pointer to what shipped: without it a version is
        # unbuildable from a clean clone and unreachable from its own history.
        # A release page is a convenience; a tag is the record.
        gh release delete "$old_tag" --repo "$REPO" --yes 2>/dev/null || true
        ok "Pruned release page for $old_tag (tag kept)"
    done <<< "$OLD_TAGS"
fi

# ── Clean up temp files ───────────────────────────────────────────────────────
step "Cleaning up"
rm -rf "$STAGING" "$MOUNT" "$DERIVED_DATA"
rm -f "$DMG"
ok "Temp files removed"

# ── Open release page ─────────────────────────────────────────────────────────
RELEASE_URL="https://github.com/${REPO}/releases/tag/${TAG}"
echo "\n✓ KeyVault $TAG released successfully."
echo "  $RELEASE_URL"
open "$RELEASE_URL"
