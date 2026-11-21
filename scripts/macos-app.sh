#!/usr/bin/env bash
# 把 corplink-desktop 二进制包成 macOS .app。
#
# 用法: scripts/macos-app.sh <binary> <out.app>
# 可用 VERSION 覆盖 Info.plist 里的版本号。
set -euo pipefail

binary=${1:?用法: macos-app.sh <binary> <out.app>}
app=${2:?用法: macos-app.sh <binary> <out.app>}
name=$(basename "$app" .app)
version=${VERSION:-0.1.0}

if [ ! -f "$binary" ]; then
  echo "找不到二进制: $binary" >&2
  exit 1
fi

rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp "$binary" "$app/Contents/MacOS/$name"
chmod +x "$app/Contents/MacOS/$name"

cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleName</key>
	<string>$name</string>
	<key>CFBundleDisplayName</key>
	<string>Corplink Go</string>
	<key>CFBundleIdentifier</key>
	<string>dev.corplink.desktop</string>
	<key>CFBundleExecutable</key>
	<string>$name</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleShortVersionString</key>
	<string>$version</string>
	<key>CFBundleVersion</key>
	<string>$version</string>
	<key>LSMinimumSystemVersion</key>
	<string>11.0</string>
	<key>NSHighResolutionCapable</key>
	<true/>
</dict>
</plist>
PLIST

echo "已生成 $app"
