# Lightpanda tvOS 移植說明

本文件記錄本次將 Lightpanda 以 Zig + tvOS App 形式運行於 tvOS Simulator 的工作內容、修改點、建置與測試方式，以及後續維護的注意事項。目標是讓後續開發者能在不了解歷史細節的情況下，仍可順利重現、調整與擴充。

## 目標與約束
- 目標：在 tvOS Simulator 以單一 App 啟動 Lightpanda（CDP server）。
- 限制：不使用 Docker；最終運行環境為 tvOS。
- 測試：透過 CDP（WebSocket）驅動，使用 Puppeteer 連線。

## 環境與版本
- Zig：0.15.2（本次建置使用版本）
- tvOS Simulator：tvOS 26.1
- Xcode：需包含對應 tvOS Simulator SDK

## 架構概覽
### App 啟動流程
1) ObjC `main.m` 啟動 UIApplication
2) `SceneDelegate` 在 `scene:willConnectToSession:` 中呼叫 `lightpanda_start()`
3) `lightpanda_start()` 在背景執行 Zig 的 `main()`（避免阻塞 UI）
4) Zig `main()` 初始化 App，進入 `serve` 模式啟動 CDP server（預設 `127.0.0.1:9222`）

### CDP 行為
Lightpanda 的 CDP server 使用單連線設計：
- `GET /json/version` 回傳 JSON 並關閉連線（避免併發造成阻塞）
- WebSocket upgrade 只允許一條 active 連線

## 主要改動摘要

### 1) tvOS App 入口與生命週期
- 新增 tvOS 入口 `src/tvos_entry.zig`，由 ObjC `main.m` 呼叫 `lightpanda_start()` 啟動 Zig 主流程。
- 在 tvOS/ios 上停用訊號處理（`SigHandler`），避免 `sigprocmask` 等 API 造成崩潰。
- 在 `tvos/` 內加入 `AppDelegate` / `SceneDelegate`，採用 UIScene lifecycle。
- 更新 `tvos/Info.plist` 增加 `UIApplicationSceneManifest`。

### 2) Zig build 與 tvOS 目標
- `build.zig` 增加 tvOS app target（`LightpandaTV`），並加上 `System/Library/SubFrameworks` framework path。
- `deps/zig-v8-fork/build.zig`：tvOS simulator 目標時，GN args 指定 `target_environment = "simulator"`。
- `deps/boringssl-zig/build.zig`：調整 Zig 0.15 的 ArrayList 行為，並在 tvOS simulator 內過濾不相容來源。

### 3) CA 憑證（TLS）修正
tvOS Simulator 內無系統憑證，導致：
`SslCacertBadfile` / `No system certificates`。

處理方式：
- 在 `src/http/Http.zig` 中，當 `bundle.rescan()` 找不到系統憑證時，回退使用內嵌的 CA bundle。
- 新增檔案 `src/data/ca-bundle.pem`（由 macOS `/etc/ssl/cert.pem` 複製）。

注意：這個 CA bundle 是目前開發機的系統憑證快照，實機需提供合適的 CA bundle 或改為從資源載入。

### 4) Xcode 測試專案
新增 `xcode/LightpandaTVTest` 測試專案（xcodegen）：
- `project.yml` 內建 preBuild 會呼叫 Zig 產出二進位。
- 修正 PATH 以包含 `~/.cargo/bin`，避免 `rustup not found`。
- postBuild 用 Zig 輸出替換 App bundle 內 executable。

## 重要檔案與入口對照表
- `src/tvos_entry.zig`：tvOS 入口，封裝 argv/env，呼叫 Zig `main()`
- `tvos/main.m`：UIApplication 入口
- `tvos/SceneDelegate.m`：UIScene 生命週期與 `lightpanda_start()` 呼叫點
- `tvos/Info.plist`：App 設定與 UIScene manifest
- `src/main.zig`：Lightpanda CLI entry，負責 `serve`/`fetch`
- `src/Server.zig`：CDP server (HTTP + WebSocket)
- `src/http/Http.zig`：TLS/CA bundle 載入、libcurl 設定
- `xcode/LightpandaTVTest/project.yml`：Xcode 生成規格與 build script

## 建置與安裝（tvOS Simulator）

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

建立 App bundle 並安裝：
```sh
APPDIR=zig-out/tvos-simulator/LightpandaTV.app
mkdir -p "$APPDIR"
cp zig-out/bin/LightpandaTV "$APPDIR/LightpandaTV"
cp tvos/Info.plist "$APPDIR/Info.plist"

xcrun simctl install <BOOTED_UDID> "$APPDIR"
xcrun simctl launch <BOOTED_UDID> io.lightpanda.tvos
```

## 測試流程（完整）

### 1) 啟動 App
```sh
xcrun simctl launch <BOOTED_UDID> io.lightpanda.tvos
```

### 2) 確認 CDP 是否可用
```sh
curl -v http://127.0.0.1:9222/json/version
```

### 3) Puppeteer 測試
```sh
node /Volumes/Data/Github/runLightpanda/app.js https://example.com
```

預期行為：
- 能成功連線 WebSocket
- `page.goto` 成功
- `console.log(mainText)` 輸出頁面內容

## 測試方式（CDP）

`app.js` 會透過：
```
ws://127.0.0.1:9222/
```
連到 Lightpanda CDP server。

## 觀察日誌
在 Xcode Console 或：
```sh
xcrun simctl launch --console <BOOTED_UDID> io.lightpanda.tvos
```

## TLS / CA Bundle 維護指引
### 問題背景
 tvOS Simulator 沒有系統憑證，`bundle.rescan()` 會回傳空集合，導致：
- `SslCacertBadfile`
- 無法載入 HTTPS 網頁（`page.goto` 失敗）

### 目前解法
使用內嵌 `src/data/ca-bundle.pem` 作為 fallback。

### 如何更新 CA bundle
1) 更新本機憑證來源：
```sh
cp /etc/ssl/cert.pem /Volumes/Data/Github/lightpanda/src/data/ca-bundle.pem
```
2) 重新 build tvOS app。

### 後續可改進方向
- 改為從 app bundle 讀取 CA 文件（避免重新編譯）
- 提供可配置的 CA path 或 binary embedding pipeline

## 常見問題與排錯

### 1) `SslCacertBadfile`
- 原因：沒有系統憑證或 CA bundle 不可用
- 解法：確保 `src/data/ca-bundle.pem` 存在且被內嵌

### 2) `Navigating frame was detached`
- 通常是 CDP 的 page lifecycle 事件不同步或導航中斷
- 先檢查 `page.goto` 前後的 Lightpanda log
- 可改用 `waitUntil: 'domcontentloaded'` 減少負擔

### 3) `connect ETIMEDOUT 127.0.0.1:9222`
- CDP server 沒有成功啟動，或 app 其實未啟動
- 用 `lsof -nP -iTCP:9222` 確認是否在 listen
- 用 `curl /json/version` 驗證是否能回應

### 4) `MODULE_TYPELESS_PACKAGE_JSON`
- Node 對 ES module 警告，不影響功能
- 解法：在 `runLightpanda` 專案加 `"type":"module"`

## 編譯與部署的注意事項
- tvOS simulator 的 sysroot 必須正確（`xcrun --sdk appletvsimulator`）
- `zig build` 需要 V8 工具鏈，PATH 必須包含 `~/.cargo/bin`
- 目前 Zig build 仍會輸出 GN warning（`v8_enable_jitless`），可忽略

## 後續調整清單（建議）
1) 改為可配置 CA bundle，避免每次 rebuild。
2) 改善 CDP 穩定性：補齊 `page.goto` / lifecycle 事件。
3) 建立自動化測試腳本：一鍵完成 build + install + run + Puppeteer 驗證。
4) tvOS 真機測試：需調整 host 綁定與網路策略。

## 已知問題 / 後續工作
- tvOS 系統憑證來源不足，已用內嵌 CA bundle 避免 HTTPS 失敗。
- 若要實機部署，需決定 CA bundle 分發與更新策略。
- CDP 仍可能有 frame detach 或事件同步問題，需持續觀察 log。
