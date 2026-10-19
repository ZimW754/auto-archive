#!/bin/bash
# 构建「自动归档.app」
set -euo pipefail
cd "$(dirname "$0")"

APP="自动归档.app"
BIN="AutoArchive"

echo "==> 清理"
rm -rf "$APP" icon.png
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

echo "==> 编译主程序"
clang -fobjc-arc -O2 -Wall \
      -framework Cocoa -framework ImageIO \
      -mmacosx-version-min=11.0 \
      -o "$APP/Contents/MacOS/$BIN" src/main.m

echo "==> 生成图标"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
clang -fobjc-arc -O1 -framework Cocoa -mmacosx-version-min=11.0 \
      -o "$TMP/make_icon" tools/make_icon.m
"$TMP/make_icon" "$TMP/icon.png"
mkdir -p "$TMP/icon.iconset"
for spec in "16 icon_16x16" "32 icon_16x16@2x" "32 icon_32x32" "64 icon_32x32@2x" \
            "128 icon_128x128" "256 icon_128x128@2x" "256 icon_256x256" \
            "512 icon_256x256@2x" "512 icon_512x512" "1024 icon_512x512@2x"; do
    set -- $spec
    sips -z "$1" "$1" "$TMP/icon.png" --out "$TMP/icon.iconset/$2.png" >/dev/null
done
iconutil -c icns "$TMP/icon.iconset" -o "$APP/Contents/Resources/AppIcon.icns"

echo "==> 写入 Info.plist"
cp src/Info.plist "$APP/Contents/Info.plist"
cp CHANGELOG.md FEATURES.md "$APP/Contents/Resources/"
printf 'APPL????' > "$APP/Contents/PkgInfo"

echo "==> 临时签名"
codesign --force --sign - "$APP" >/dev/null 2>&1 || echo "（跳过签名，不影响本机运行）"

echo "==> 完成：$PWD/$APP"
