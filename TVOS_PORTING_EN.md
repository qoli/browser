# Lightpanda tvOS Porting Notes

This document records the work done to run Lightpanda as a Zig-based tvOS app in the tvOS Simulator, the changes made, build and test steps, and maintenance guidance. The goal is to make future development and adjustments easy to reproduce without needing historical context.

## Goals and Constraints
- Goal: Run Lightpanda in the tvOS Simulator as a single app that exposes a CDP server.
- Constraints: No Docker; final runtime environment is tvOS.
- Testing: Drive via CDP (WebSocket) using Puppeteer.

## Environment and Versions
- Zig: 0.15.2 (used in this build)
- tvOS Simulator: tvOS 26.1
- Xcode: must include the matching tvOS Simulator SDK

## Architecture Overview
### App Startup Flow
1) ObjC `main.m` starts UIApplication
2) `SceneDelegate` calls `lightpanda_start()` in `scene:willConnectToSession:`
3) `lightpanda_start()` runs Zig `main()` on a background thread
4) Zig `main()` initializes the app and enters `serve` mode, starting the CDP server (default `127.0.0.1:9222`)

### CDP Behavior
Lightpanda’s CDP server is single-connection oriented:
- `GET /json/version` returns JSON and closes the connection (avoids blocking on concurrent upgrade)
- WebSocket upgrade allows only one active connection

## Key Changes

### 1) tvOS App Entry and Lifecycle
- Added tvOS entry `src/tvos_entry.zig`, called from ObjC `main.m` via `lightpanda_start()`.
- Disabled signal handling on tvOS/ios to avoid `sigprocmask`-related crashes.
- Added `AppDelegate` / `SceneDelegate` under `tvos/` using UIScene lifecycle.
- Updated `tvos/Info.plist` to include `UIApplicationSceneManifest`.

### 2) Zig Build and tvOS Target
- `build.zig` adds the tvOS app target (`LightpandaTV`) and includes `System/Library/SubFrameworks`.
- `deps/zig-v8-fork/build.zig`: when building for tvOS simulator, GN args set `target_environment = "simulator"`.
- `deps/boringssl-zig/build.zig`: adjusted for Zig 0.15 ArrayList behavior and filtered incompatible sources for tvOS simulator.

### 3) CA Certificates (TLS) Fix
The tvOS Simulator lacks system certificates, resulting in:
`SslCacertBadfile` / `No system certificates`.

Mitigation:
- In `src/http/Http.zig`, if `bundle.rescan()` finds no system certs, fall back to an embedded CA bundle.
- Added `src/data/ca-bundle.pem` (copied from macOS `/etc/ssl/cert.pem`).

Note: This CA bundle is a snapshot from the dev machine. Real devices should provide an appropriate CA bundle or load it from app resources.

### 4) Xcode Test Project
Added `xcode/LightpandaTVTest` (xcodegen):
- `project.yml` preBuild runs Zig to produce the binary.
- PATH includes `~/.cargo/bin` to avoid `rustup not found`.
- postBuild replaces the app bundle executable with the Zig output.

## Important Files and Entry Map
- `src/tvos_entry.zig`: tvOS entry, sets argv/env, calls Zig `main()`
- `tvos/main.m`: UIApplication entry
- `tvos/SceneDelegate.m`: UIScene lifecycle and `lightpanda_start()` call site
- `tvos/Info.plist`: app config and UIScene manifest
- `src/main.zig`: Lightpanda CLI entry for `serve`/`fetch`
- `src/Server.zig`: CDP server (HTTP + WebSocket)
- `src/http/Http.zig`: TLS/CA bundle loading and libcurl config
- `xcode/LightpandaTVTest/project.yml`: Xcode generation and build scripts

## Build and Install (tvOS Simulator)

```sh
SDKROOT=$(xcrun --sdk appletvsimulator --show-sdk-path)
cat > /tmp/tvos-sim.libc <<EOF
include_dir=$SDKROOT/usr/include
sys_include_dir=$SDKROOT/usr/include
crt_dir=$SDKROOT/usr/lib
msvc_lib_dir=
kernel32_lib_dir=
gcc_dir=
EOF

/tmp/zig-0.15.2/zig build \
  --sysroot "$SDKROOT" \
  --libc /tmp/tvos-sim.libc \
  -Dtarget=aarch64-tvos-simulator \
  -Doptimize=ReleaseFast \
  -Dtvos_app
```

Create and install the app bundle:
```sh
APPDIR=zig-out/tvos-simulator/LightpandaTV.app
mkdir -p "$APPDIR"
cp zig-out/bin/LightpandaTV "$APPDIR/LightpandaTV"
cp tvos/Info.plist "$APPDIR/Info.plist"

xcrun simctl install <BOOTED_UDID> "$APPDIR"
xcrun simctl launch <BOOTED_UDID> io.lightpanda.tvos
```

## Full Test Flow

### 1) Launch the App
```sh
xcrun simctl launch <BOOTED_UDID> io.lightpanda.tvos
```

### 2) Verify CDP is reachable
```sh
curl -v http://127.0.0.1:9222/json/version
```

### 3) Puppeteer Test
```sh
node /Volumes/Data/Github/runLightpanda/app.js https://example.com
```

Expected:
- WebSocket connects successfully
- `page.goto` succeeds
- `console.log(mainText)` prints page content

## CDP Endpoint
`app.js` connects to:
```
ws://127.0.0.1:9222/
```

## Logs
Use Xcode Console or:
```sh
xcrun simctl launch --console <BOOTED_UDID> io.lightpanda.tvos
```

## TLS / CA Bundle Maintenance
### Background
The tvOS Simulator has no system certificates; `bundle.rescan()` returns empty, causing TLS failures.

### Current Solution
Fallback to embedded `src/data/ca-bundle.pem`.

### Update CA Bundle
1) Replace the CA bundle:
```sh
cp /etc/ssl/cert.pem /Volumes/Data/Github/lightpanda/src/data/ca-bundle.pem
```
2) Rebuild the tvOS app.

### Possible Improvements
- Load CA bundle from app resources to avoid rebuilding
- Provide a configurable CA path or embed via a pipeline

## Common Issues and Troubleshooting

### 1) `SslCacertBadfile`
- Cause: missing system certs or CA bundle not embedded
- Fix: ensure `src/data/ca-bundle.pem` exists and is embedded

### 2) `Navigating frame was detached`
- Usually indicates CDP lifecycle mismatch or interrupted navigation
- Check Lightpanda logs around `page.goto`
- Try `waitUntil: 'domcontentloaded'` to reduce load

### 3) `connect ETIMEDOUT 127.0.0.1:9222`
- CDP server did not start, or app is not running
- Check `lsof -nP -iTCP:9222`
- Verify with `curl /json/version`

### 4) `MODULE_TYPELESS_PACKAGE_JSON`
- Node ES module warning (not fatal)
- Fix: add `"type":"module"` to `runLightpanda`’s package.json

## Build and Deployment Notes
- Ensure the tvOS simulator sysroot is correct (`xcrun --sdk appletvsimulator`)
- `zig build` requires V8 toolchain; PATH must include `~/.cargo/bin`
- GN warning about `v8_enable_jitless` can be ignored

## Next Steps (Suggested)
1) Make CA bundle configurable (avoid rebuilds).
2) Improve CDP stability around `page.goto` / lifecycle.
3) Add a one-shot script to build + install + run + Puppeteer verify.
4) Test on real tvOS hardware (host binding and network policy changes).

## Known Issues / Follow-ups
- tvOS system certs are missing; embedded CA bundle used as workaround.
- Real device deployment needs a CA distribution/update plan.
- CDP lifecycle edge cases may still cause frame detach errors.
