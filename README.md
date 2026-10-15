# pico2w_adblock_blacklist_gen

替 pico2w-adblock 韌體（v1.2.0 以上）每週自動產生黑名單。GitHub 的雲端主機會下載你選的名單，合併、去重、去掉多餘子網域、壓縮，再發布到固定網址。Pico 只需要定時下載這一個檔案。

## Pico 要填的網址

儀表板 *BLOCKLIST — REMOTE AUTO-UPDATE* 填入：

```
https://github.com/slashxzero/pico2w_adblock_blacklist_gen/releases/download/blocklist/blocklist2.bin
```

間隔維持 `24` 小時，按 **Save** 再按 **Fetch now**。

同一個 Release 裡如果有 `blocklist.bin`，那是同一份名單的舊格式，給 v1.2.0 以前的韌體用。名單超過 39.2 萬筆時舊格式放不下，就不會發布 `blocklist.bin`。

## 第一次使用

1. 到 **Actions** 分頁。如果看到要你啟用 workflow 的按鈕，按下去。
2. 點左側的 **blocklist** → 右邊的 **Run workflow** → **Run workflow**。
3. 大約 1–2 分鐘後完成。到 **Releases** 會看到 `blocklist`，裡面有 `blocklist2.bin`。
4. 把上面的網址填進 Pico。

之後每週一 12:17（台灣時間）會自動重新產生。

## 換名單組合

兩種方法擇一：

- **用選單：** 在 **Actions → blocklist → Run workflow** 挑選。選了 `(keep)` 的項目維持原設定。你的選擇會自動存進 `lists.conf`，之後每週照這個組合產生。
- **改設定檔：** 在 GitHub 網頁上打開 `lists.conf`，按鉛筆圖示編輯，再按 **Commit changes**。下次執行就會套用。想立刻生效的話，再手動 Run workflow 一次。

| 項目 | 選項 |
|---|---|
| `HAGEZI` | `light` / `pro`（預設，官方推薦）/ `pro.plus` / `ultimate` / `none` |
| `TIF` | `none` / `tif.mini`（釣魚、惡意軟體的威脅情報） |
| `STEVENBLACK` | `yes` / `no` |
| `EXTRA` | 其他名單網址，可填多個，以空白分隔。只接受 `https://`。選單裡填 `-` 會清空 |

參考大小（2026-10 實測，已去掉多餘子網域；百分比是佔 Pico 名單空間的比例）：

| 組合 | 筆數 | 佔用 |
|---|---|---|
| StevenBlack + Light | 8.9 萬 | 15% |
| StevenBlack + Pro（預設） | 21.6 萬 | 34% |
| StevenBlack + Pro++ | 23.1 萬 | 37% |
| StevenBlack + Ultimate | 25.7 萬 | 40% |
| StevenBlack + Pro + TIF mini | 36.2 萬 | 55% |
| StevenBlack + Pro++ + TIF mini | 37.5 萬 | 57% |
| StevenBlack + Ultimate + TIF mini | 40.0 萬 | 62% |

組合太大、超過 Pico 的容量（約 68 萬筆）時，這次執行會失敗，Release 裡的舊名單保持不變。

## 自動行為

- 任何一個來源下載失敗，整次執行就失敗，不會發布一份悄悄變小的名單。名單少於 5 萬筆也視為失敗。
- GitHub 會在公開倉庫 60 天沒有活動時停用排程。為了避免這件事，workflow 會在最後一次 commit 超過 50 天時，自動補一個空的 commit。
- 執行失敗時，GitHub 會寄信通知你。

## 檔案

| 檔案 | 用途 |
|---|---|
| `lists.conf` | 名單組合設定 |
| `.github/workflows/blocklist.yml` | 每週排程與手動執行的流程 |
| `tools/lists.py` | 把 `lists.conf` 和選單的選擇轉成下載網址 |
| `tools/build_blocklist.py` | 產生名單（取自 pico2w-adblock 的 `tools/`，兩邊要保持一致） |
| `tools/test_build_blocklist.py` | 產生器的測試，每次執行前會先跑 |

## 疑難排解

| 狀況 | 處理方式 |
|---|---|
| 執行失敗，log 出現 `403` 或 `Resource not accessible by integration` | 到 **Settings → Actions → General → Workflow permissions**，選 **Read and write permissions** 後儲存 |
| `!! HAGEZI=...: must be one of ...` | `lists.conf` 的值打錯了，照上表修正 |
| `too large for the device` | 組合超過容量，少選一份 |
| Pico 顯示 `HTTP 404` | 還沒成功執行過，Release 不存在。先手動 Run workflow |
