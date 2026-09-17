#!/usr/bin/env zsh
# release.sh — Build, verify, package, and publish a KeyVault release.
#
# Usage: ./release.sh <version> [--generated-notes]
#   e.g. ./release.sh 1.0
#
# Requires: xcodebuild, hdiutil, gh (GitHub CLI), git

set -euo pipefail

REPO="sevmorris/KeyVault"

# notarytool keychain profile, shared by every sibling release script. A profile
# cannot be exported, so a new Mac needs it created again under this name:
#   xcrun notarytool store-credentials notarytool --apple-id <email> --team-id T9RLNAXPWU
# Set NOTARY_PROFILE to use another (a Mac still holding the old WoWoNotary one).
NOTARY_PROFILE="${NOTARY_PROFILE:-notarytool}"

# ── Args ──────────────────────────────────────────────────────────────────────
# One positional argument (the version) plus optional flags in any position.
# Anything else — including no arguments, or a second positional that isn't a
# flag — still fails with usage, as it did before the flags existed.
ALLOW_GENERATED_NOTES=0
ARGS=()
for arg in "$@"; do
    case "$arg" in
        --generated-notes) ALLOW_GENERATED_NOTES=1 ;;
        *)                 ARGS+=("$arg") ;;
    esac
done

if [[ ${#ARGS[@]} -ne 1 ]]; then
    echo "Usage: $0 <version> [--generated-notes]"
    echo "  e.g. $0 1.0"
    echo ""
    echo "  --generated-notes  Release without a curated release-notes file,"
    echo "                     generating notes from commit subjects instead."
    exit 1
fi

VERSION="${ARGS[1]}"
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
PBXPROJ="$PROJECT/project.pbxproj"
README_MD="$PROJECT_DIR/README.md"
MANUAL_IDX="$PROJECT_DIR/docs/manual/index.html"
NOTES_FILE="$PROJECT_DIR/release-notes/${TAG}.md"

# Set while project.pbxproj carries an uncommitted version bump, and cleared
# once that rewrite is committed. The EXIT trap reverts it in between.
BUMP_ACTIVE=0

# The same contract for the docs rewrite, one window later. A separate flag
# because the two windows are disjoint and they revert different files.
DOCS_ACTIVE=0

# ── Helpers ───────────────────────────────────────────────────────────────────
step()  { echo "\n▶ $*"; }
ok()    { echo "  ✓ $*"; }
fail()  { echo "\n  ✗ $*" >&2; exit 1; }
warn()  { echo "  ! $*" >&2; }

cleanup() {
    # ${VAR:-} throughout so the trap fires cleanly even when the script exits
    # before these are defined — an argument error, say. A bare (( BUMP_ACTIVE ))
    # would trip `set -u` on exactly those early exits.
    #
    # The version bump is written to project.pbxproj before it is committed, so
    # a failure in that window would otherwise strand it in the working tree,
    # and the dirty-tree preflight then blocks the next run until someone
    # reverts it by hand. Reverting the whole file is safe precisely because
    # preflight proved the tree clean on entry: this script's own seds are the
    # only changes present, so there is nothing else here to discard.
    if (( ${BUMP_ACTIVE:-0} )); then
        git -C "${PROJECT_DIR:-.}" checkout -- "${PBXPROJ:-}" 2>/dev/null || true
    fi
    if (( ${DOCS_ACTIVE:-0} )); then
        git -C "${PROJECT_DIR:-.}" checkout -- \
            "${README_MD:-}" "${MANUAL_IDX:-}" 2>/dev/null || true
    fi
    [[ -d "${STAGING:-}" ]]      && rm -rf -- "$STAGING"      || true
    [[ -d "${MOUNT:-}" ]]        && rm -rf -- "$MOUNT"        || true
    [[ -d "${DERIVED_DATA:-}" ]] && rm -rf -- "$DERIVED_DATA" || true
    [[ -f "${DMG:-}" ]]          && rm -f  -- "$DMG"          || true
}
# A zsh EXIT trap does not fire on a signal, so Ctrl-C or a closed terminal
# during the long notarization wait used to leave the version bump sitting in
# the working tree — the same stranded-bump state that blocked two releases on
# 2026-09-16, which the deferred commit only fixed for an ordinary failure.
# These handlers exit and let the EXIT trap do the cleanup, exactly once.
trap 'exit 130' INT
trap 'exit 143' TERM
trap cleanup EXIT

# ── Preflight ─────────────────────────────────────────────────────────────────
step "Preflight checks"
python3 -c "import dmgbuild" 2>/dev/null \
    || fail "python3 module 'dmgbuild' not installed — run: python3 -m pip install dmgbuild"

# Importing dmgbuild does not prove it can run. On 2026-09-16 a pyenv Python
# built against Xcode 27's macOS 27 SDK, on macOS 26.7, imported it and then
# segfaulted on its first subprocess — dmgbuild's hdiutil call.
python3 -c "import subprocess; subprocess.run(['/usr/bin/true'], check=True)" &>/dev/null \
    || fail "$(command -v python3) cannot start a subprocess, so dmgbuild would crash — rebuild that Python against an SDK no newer than this macOS"

for cmd in xcodebuild hdiutil gh git python3; do
    command -v $cmd &>/dev/null || fail "'$cmd' not found in PATH"
done
ok "Tools present"

# A missing profile used to surface at the notarization step, after a clean
# build — which is how a new Mac found out. Asking costs one API call.
xcrun notarytool history --keychain-profile "$NOTARY_PROFILE" &>/dev/null \
    || fail "notarytool profile '$NOTARY_PROFILE' is missing, rejected or unreachable — create it with: xcrun notarytool store-credentials $NOTARY_PROFILE --apple-id <email> --team-id T9RLNAXPWU"
ok "notarytool profile '$NOTARY_PROFILE' works"

cd "$PROJECT_DIR"

if [[ -n "$(git status --porcelain)" ]]; then
    fail "Working tree is dirty — commit or stash changes before releasing"
fi
ok "Working tree clean"

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

# The remote's tags are the record, not this clone's. A clone that has not seen
# a release — made on another Mac, or one whose tag push failed — passes a
# local-only check, then builds, notarizes and pushes the branch before the tag
# is refused, as re-runs of ClipHack and WaxOnWaxOff did on 2026-09-16. Fetching
# first lets the checks below see every published tag, and a local tag that
# disagrees with the remote makes the fetch itself fail.
git fetch --tags "$REMOTE" \
    || fail "Could not fetch tags from $REMOTE — a tag reported as rejected above points at different commits here and on $REMOTE"
if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
    fail "Tag $TAG already exists — has this version been released?"
fi
ok "Tag $TAG is available"

# The push at the end is a fast-forward or nothing, so a remote branch with
# commits this one lacks would fail it after the notarization. Stop now instead.
if git rev-parse -q --verify "refs/remotes/$REMOTE/$BRANCH" >/dev/null \
        && ! git merge-base --is-ancestor "$REMOTE/$BRANCH" HEAD; then
    fail "$REMOTE/$BRANCH has commits that HEAD lacks — pull before releasing"
fi
ok "HEAD contains everything on $REMOTE/$BRANCH"

# ── Version ordering ────────────────────────────────────────────────────────────────────────
# Nothing here stopped a release going backwards. On 2026-09-03 Magic Backup
# Machine published v1.3.9 on top of v1.4.2 — two sessions releasing from one
# clone, neither aware of the other. GitHub served the older build as "latest"
# from that moment, and because the update checker compares numerically, every
# client already on 1.4.2 read 1.3.9 as older and reported itself up to date.
# The release could not reach anyone.
#
# Tags are the record of what is actually published, and what "latest" keys on,
# so they are what this compares against. Set ALLOW_DOWNGRADE=1 to override.
step "Checking version ordering"
version_core() { printf '%s' "${1%%[-+]*}"; }
HIGHEST_TAG=$(git tag --sort=-v:refname | head -1 | sed 's/^v//')
if [[ -n "$HIGHEST_TAG" ]]; then
    NEW_CORE=$(version_core "$VERSION")
    REF_CORE=$(version_core "$HIGHEST_TAG")
    # Numeric cores only: `sort -V` places 1.7.0 ahead of 1.7.0-rc.1, backwards
    # from semver, and comparing raw strings would block any release that
    # follows its own release candidate.
    if [[ "$NEW_CORE" != "$REF_CORE" ]] \
       && [[ "$(printf '%s\n%s\n' "$NEW_CORE" "$REF_CORE" | sort -V | head -1)" == "$NEW_CORE" ]]; then
        if [[ "${ALLOW_DOWNGRADE:-0}" != "0" ]]; then
            warn "$VERSION sorts below tag v$HIGHEST_TAG — continuing, ALLOW_DOWNGRADE is set"
        else
            fail "$VERSION sorts below the highest tag v$HIGHEST_TAG. Publishing it would leave GitHub serving an older build as 'latest', and clients on $HIGHEST_TAG would be told they are up to date. Set ALLOW_DOWNGRADE=1 to override."
        fi
    fi
fi
ok "Version $VERSION does not go backwards"


# Absent siblings are not drift — a fresh clone or a CI checkout has none, and
# the check passes quietly. Only a content mismatch stops the release.
#
# Worded to avoid quoting the registration marker itself: check-shared.sh finds
# shared files by grepping for that phrase, so spelling it here would enrol this
# script — which is app-specific and must never be compared across repos.
step "Checking shared files against sibling repos"
"$PROJECT_DIR/scripts/check-shared.sh" \
    || fail "Shared files have drifted from the sibling repos"

# ── Release-notes gate ────────────────────────────────────────────────────────
# The notes are read much later, at the GitHub-release step — by which point the
# branch and the tag have both been pushed. Failing there would strand a pushed
# tag with no release behind it, so the absence has to be caught here, while
# nothing has been mutated and nothing has left the machine.
#
# Without this, a forgotten notes file is invisible: the curated path announces
# itself, the generated path says nothing, and both end on the same "Release
# published" line. Shipping auto-generated notes becomes a silent default rather
# than a decision.
if [[ -f "$NOTES_FILE" ]]; then
    ok "Curated notes present: release-notes/${TAG}.md"
elif (( ALLOW_GENERATED_NOTES )); then
    echo "\n  ⚠ --generated-notes — publishing $TAG without curated notes" >&2
    echo "      expected:  release-notes/${TAG}.md" >&2
    echo "      notes will be generated from commit subjects since the last tag" >&2
    ok "Generated notes accepted"
else
    echo "      expected:  release-notes/${TAG}.md" >&2
    fail "No curated notes for $TAG — write that file, or re-run with --generated-notes"
fi

# ── Version bump ──────────────────────────────────────────────────────────────
step "Bumping version to $VERSION"
# No Info.plist in this project — the version is a build setting, so the bump
# edits project.pbxproj. Both configurations carry it; sed rewrites both.
CURRENT=$(awk -F' = ' '/MARKETING_VERSION/ {gsub(/;/,"",$2); print $2; exit}' "$PBXPROJ")
# Armed before the first mutation rather than after the last: the build-number
# bump below reads through a pipeline that can abort under `set -o pipefail`
# with the marketing-version sed already on disk.
BUMP_ACTIVE=1
if [[ "$CURRENT" == "$VERSION" ]]; then
    ok "Version already $VERSION"
else
    # Escape regex metacharacters so a version like 1.7.0-rc.1 cannot make the
    # dots match arbitrary characters.
    ESC_CURRENT=$(printf '%s' "$CURRENT" | sed 's/[.[\*^$]/\\&/g')
    ESC_VERSION=$(printf '%s' "$VERSION" | sed 's/[.[\*^$]/\\&/g')
    sed -i '' "s/MARKETING_VERSION = ${ESC_CURRENT};/MARKETING_VERSION = ${ESC_VERSION};/g" "$PBXPROJ"
    NOW=$(awk -F' = ' '/MARKETING_VERSION/ {gsub(/;/,"",$2); print $2; exit}' "$PBXPROJ")
    [[ "$NOW" == "$VERSION" ]] || fail "Version bump did not take: still $NOW"
    ok "Version $CURRENT → $VERSION"
fi

# CFBundleVersion has to increase for every build submitted under one marketing
# version, and it had been pinned at 1 since the first release — so every
# KeyVault ever shipped claimed to be build 1.
BUILD_NUM=$(grep 'CURRENT_PROJECT_VERSION = ' "$PBXPROJ" | head -1 | grep -o '[0-9][0-9]*')
NEXT_BUILD=$((BUILD_NUM + 1))
sed -i '' "s/CURRENT_PROJECT_VERSION = ${BUILD_NUM};/CURRENT_PROJECT_VERSION = ${NEXT_BUILD};/g" "$PBXPROJ"
ok "Build number ${BUILD_NUM} → ${NEXT_BUILD}"

if [[ -n "$(git status --porcelain "$PBXPROJ")" ]]; then
    git add "$PBXPROJ"
    git commit -m "Bump version to $VERSION"
    ok "Version bump committed"
else
    ok "Version already committed"
fi
BUMP_ACTIVE=0

# ── Build ─────────────────────────────────────────────────────────────────────
step "Building (clean, Release)"
rm -rf "$DERIVED_DATA"
rm -rf ~/Library/Caches/com.apple.dt.Xcode/ 2>/dev/null || true
rm -rf ~/Library/Developer/Xcode/DerivedData/ModuleCache* 2>/dev/null || true
ok "Xcode caches cleared"
# -destination: without it xcodebuild warns and builds only the first matching
# destination's architecture; with it, ARCHS in the project decides.
xcodebuild \
    -project "$PROJECT" \
    -scheme "$SCHEME" \
    -configuration Release \
    -destination 'generic/platform=macOS' \
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
# NOTARY_PROFILE is defined at the top and proven usable in preflight.
xcrun notarytool submit "$DMG" --wait --keychain-profile "$NOTARY_PROFILE"
xcrun stapler staple "$DMG"
ok "Notarization complete"

# ── Verify DMG ────────────────────────────────────────────────────────────────
step "Verifying DMG contents"
rm -rf "$MOUNT"
mkdir "$MOUNT"
hdiutil attach "$DMG" -mountpoint "$MOUNT" -quiet -nobrowse
DMG_VERSION=$(defaults read "$MOUNT/KeyVault.app/Contents/Info.plist" CFBundleShortVersionString)
# The installer window is these two files: the .DS_Store carrying the layout and
# the background art it points at. Without them the image opens as a plain
# folder — which is how ClipHack 1.25.2 and 1.25.3 shipped, undetected, because
# nothing looked inside the image it had just built.
DMG_DSSTORE=( "$MOUNT"/.DS_Store(N) )
DMG_BGART=( "$MOUNT"/.background.*(N) )
hdiutil detach "$MOUNT" -quiet
[[ "$DMG_VERSION" == "$VERSION" ]] || \
    fail "DMG version mismatch: expected $VERSION, got $DMG_VERSION"
(( ${#DMG_DSSTORE} && ${#DMG_BGART} )) || \
    fail "DMG has no installer window layout (.DS_Store and .background.* are not both present)"
ok "DMG contains $DMG_VERSION, with its installer window layout"

# ── Update docs (README + manual) ─────────────────────────────────────────────
step "Updating docs to ${TAG}"
# Armed before the first sed, so a failure part-way through reverts the whole
# set rather than leaving the README rewritten and the manual stale.
DOCS_ACTIVE=1

# README: the download hyperlink, and the version label under the title. That
# label was previously left behind — the link said v1.2.0 while the line above
# it still said 1.1.0.
sed -i '' "s|KeyVault-v[0-9][0-9.]*\.dmg|KeyVault-${TAG}.dmg|g" "$README_MD"
sed -i '' "s|Download v[0-9][0-9.]*|Download ${TAG}|g" "$README_MD"
sed -i '' "s|<strong>Version:</strong> [0-9][0-9.]*|<strong>Version:</strong> ${VERSION}|g" "$README_MD"
sed -i '' "s|\*\*Version:\*\* [0-9][0-9.]*|**Version:** ${VERSION}|g" "$README_MD"

# Manual: the version badge in the footer. docs/index.html is a bare redirect
# to the manual and carries no version, so there is nothing to rewrite there.
sed -i '' "s|Manual — v[0-9][0-9.]*|Manual — ${TAG}|g" "$MANUAL_IDX"

# Nothing published should still name an older version.
if grep -E "KeyVault-v[0-9]+\.[0-9]+[0-9.]*\.dmg" "$README_MD" "$MANUAL_IDX" \
        | grep -v "${TAG}\.dmg" >/dev/null; then
    fail "Stale version references remain after rewrite — check the sed patterns"
fi

if [[ -n "$(git status --porcelain "$README_MD" "$MANUAL_IDX")" ]]; then
    git add "$README_MD" "$MANUAL_IDX"
    git commit -m "docs: update download link to ${TAG}"
    ok "Docs point to ${TAG}"
else
    ok "Docs already up to date"
fi
DOCS_ACTIVE=0

# ── Tag and push ──────────────────────────────────────────────────────────────
step "Tagging and pushing"
git tag "$TAG"
# One atomic push: the branch and the tag land together or not at all. As two
# pushes, a refused tag left the release commit on the branch with nothing
# tagging it — which is how ClipHack put a 1.25.2 commit on main with no tag
# behind it on 2026-09-16. On failure nothing has been published, so the tag
# made above is removed and a re-run starts clean.
if ! git push --atomic -u "$REMOTE" "HEAD:refs/heads/$BRANCH" "refs/tags/$TAG"; then
    git tag -d "$TAG" >/dev/null
    fail "Push to $REMOTE failed and nothing was published — the local $TAG tag has been removed"
fi
ok "Pushed $TAG to $REMOTE/$BRANCH"

# ── GitHub release ────────────────────────────────────────────────────────────
step "Creating GitHub release"
# A curated description at release-notes/v<version>.md wins over the generated
# commit list. Use it when the release needs prose the log can't produce —
# licensing notes, a known-gap disclosure, an explanation of what changed and
# what deliberately didn't. Without one, fall back to subjects since the last tag.
#
# NOTES_FILE is defined with the other paths and its absence is gated in
# preflight, so reaching the generated branch here means --generated-notes was
# passed deliberately.
if [[ -f "$NOTES_FILE" ]]; then
    ok "Using curated notes: release-notes/${TAG}.md"
    gh release create "$TAG" "$DMG" \
        --repo "$REPO" \
        --title "KeyVault $TAG" \
        --notes-file "$NOTES_FILE"
else
    PREV_TAG=$(git tag --list 'v[0-9]*' --sort=-creatordate | grep -v "^${TAG}$" | head -1 || true)
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
fi
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
