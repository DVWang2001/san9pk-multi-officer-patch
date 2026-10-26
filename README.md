# 三國志9 威力加強版：多人指令補丁 (san9pk-multi-officer-patch)

Steam 版《三國志IX with 威力加強版》(San9WPK.exe **v1.2.0.0**，繁體中文) 的非官方補丁。
讓同一個指令可以一次派多名武將，並把「軍師說可以」的武將排在最前面、預先勾選。

> English: unofficial patch for Steam *Romance of the Three Kingdoms IX with Power Up Kit* (v1.2.0.0, Traditional Chinese).
> One command can dispatch several officers at once; officers the advisor says will succeed are sorted first and pre-checked.

## 功能

| 功能 | 說明 |
|---|---|
| 多人探索、登庸 | 選執行武將時改成多選列表，一次派多人 |
| 多人計謀：離間、燒夷、奪取、流言 | 同上 |
| 多人外交：贈與、請求、勸降 | 同上（贈與每人各送一份同額禮物） |
| 軍師說可以的排最前面 | 軍師預估「可成」的武將自動排在列表最前、預先打勾 |
| ◎ 醒目提示 | 探索地域、登庸/離間對象、各指令執行武將中，軍師說可成者名字後面加 ◎ |
| 顯示相性 | 武將情報標題顯示「相性NN」；選擇武將的「個人」分頁最後一欄改為相性 |

## 重要限制

- **軍師說可以 ≠ 一定成功。** 遊戲是下令時用一次亂數預估，武將到場後才重新擲骰。實測登庸被軍師說可成的人到場後仍可能被拒絕。
- 「全派」會連君主一起派出，因為遊戲本身允許。
- 只支援 **Steam 版 San9WPK.exe v1.2.0.0**。補丁會檢查程式碼位址，不符就不安裝（日誌會寫 mismatch），但仍請先備份存檔。
- 第 1 次使用請在不重要的存檔上試。目前沒有「交涉」的多人版（該指令需要特定條件才可用）。
- 與「優化伴侶」等其他補丁不相容，請勿同時使用。

## 安裝

1. 到遊戲資料夾（`...\steamapps\common\San9WPK`）。
2. 把原本的 `MyDoc.dll` 改名為 `MyDoc_orig.dll`。
3. 把本補丁編譯出的 `MyDoc.dll` 放進同一個資料夾。
4. 從 Steam 啟動遊戲。

## 移除

刪除補丁版 `MyDoc.dll`，把 `MyDoc_orig.dll` 改回 `MyDoc.dll`。補丁不改任何遊戲原檔。

## 編譯

需要 32 位元 MinGW gcc（遊戲是 32 位元）：

```
build.bat
```

## 運作原理（簡述）

遊戲載入時會讀取 `MyDoc.dll`（只匯出一個取得「我的文件」路徑的函式）。本補丁是它的代理 DLL：
轉發原函式，並在遊戲視窗出現後（Steam DRM 已解密程式碼）：

- 以記憶體內 inline hook / 呼叫點改寫，攔截各指令的「選擇執行武將」對話框，改呼叫遊戲自己的多選列表。
- 用遊戲自己的軍師判斷函式（以暫時的指令物件、不顯示訊息的方式呼叫）決定哪些人要預選。
- 額外的指令透過遊戲的「指令佇列」（城市選單反覆呼叫 CreateCommand）依序建立。

所有位址都寫死在 `src/patch.c`，僅對應 v1.2.0.0。

## 免責聲明

- 非官方作品，與 KOEI TECMO 無關。三國志是其商標。
- 本倉庫不含任何遊戲檔案、程式碼傾印或存檔，只有原始碼。
- 使用風險自負；請先備份存檔。

## 授權

MIT
