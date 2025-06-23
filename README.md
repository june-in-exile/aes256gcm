# AES-256-GCM TypeScript Implementation

這是一個用於零知識證明電路驗證的 AES-256-GCM 參考實作，使用 TypeScript 編寫，支援完整的加密和認證功能。

## 🚀 快速開始

```bash
# 運行基本驗證測試
pnpm dev

# 運行完整測試套件
pnpm test
```

## 📚 API 文檔

### 基礎工具類

#### `AESUtils`

- `bytesToHex(bytes)` - 字節數組轉十六進制字符串
- `hexToBytes(hex)` - 十六進制字符串轉字節數組
- `xor(a, b)` - 兩個字節數組的 XOR 運算
- `randomBytes(length)` - 生成隨機字節數組

#### `AES256`

- `encryptBlock(plaintext, key)` - 單區塊 AES-256 加密

#### `AES256GCM`

- `encrypt(plaintext, key, iv, additionalData?)` - 完整的 AES-256-GCM 加密

## 🔧 使用範例

### 基本加密

```typescript
import { AES256GCM, AESUtils } from "./src/aes256gcm.js";

// 生成密鑰和 IV
const key = AESUtils.randomBytes(32); // 256 位密鑰
const iv = AESUtils.randomBytes(12); // 96 位 IV

// 準備明文
const plaintext = new TextEncoder().encode("Hello, World!");

// 加密
const result = AES256GCM.encrypt(plaintext, key, iv);

console.log("密文:", AESUtils.bytesToHex(result.ciphertext));
console.log("認證標籤:", AESUtils.bytesToHex(result.tag));
```

### 單區塊 AES-256

```typescript
import { AES256, AESUtils } from "./src/aes256gcm.js";

const key = AESUtils.hexToBytes(
  "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
);
const plaintext = AESUtils.hexToBytes("6bc1bee22e409f96e93d7e117393172a");

const ciphertext = AES256.encryptBlock(plaintext, key);
console.log("密文:", AESUtils.bytesToHex(ciphertext));
```

### 驗證實作正確性

```typescript
import { AESVerification } from "./src/aes256gcm.js";

// 運行所有驗證測試
const allPassed = AESVerification.runAllTests();
console.log("測試結果:", allPassed ? "通過" : "失敗");
```

## 🏗️ 架構說明

### 核心組件

1. **基礎運算層**

   - `AESUtils` - 工具函數
   - `GaloisField` - GF(2^8) 域運算
   - `AESSbox` - S-box 替換

2. **AES 變換層**

   - `AESTransforms` - 四大變換（SubBytes, ShiftRows, MixColumns, AddRoundKey）
   - `AESKeyExpansion` - 密鑰擴展

3. **加密層**

   - `AES256` - AES-256 區塊加密
   - `AES256GCM` - GCM 模式實作

4. **驗證層**
   - `AESVerification` - 與標準實作對比驗證

### 實作特點

- ✅ 完整的 AES-256 實作（14 輪）
- ✅ 標準 S-box 和 Galois 域運算
- ✅ 優化的預計算表
- ✅ GCM 模式支援（CTR + GHASH）
- ✅ 與 Node.js crypto 模組驗證
- ✅ NIST 標準測試向量驗證

## 🧪 測試

### 運行測試

```bash
# 基本驗證
pnpm tsx src/aes256gcm.ts

# 完整測試套件
pnpm tsx src/test.ts
```

### 測試內容

1. **正確性驗證**

   - Node.js crypto 模組對比
   - NIST 標準測試向量
   - 中間步驟驗證

2. **功能測試**

   - 單區塊加密
   - GCM 模式加密
   - 錯誤處理

3. **性能測試**
   - 吞吐量測試
   - 與原生實作比較

## 🎯 用於 ZKP 電路

這個實作的主要目的是為零知識證明電路提供參考：

1. **驗證電路正確性** - 使用此實作生成測試向量
2. **理解算法步驟** - 每個變換都有清晰的實作
3. **調試電路** - 可以逐步對比中間結果

### 建議的 ZKP 實作流程

1. 使用此 TypeScript 實作生成測試案例
2. 在 Circom 中實作對應的約束
3. 使用測試案例驗證電路正確性
4. 逐步優化電路效率

## 📝 注意事項

### 安全性

⚠️ **此實作僅用於教育和驗證目的，不建議用於生產環境：**

- 未針對側信道攻擊進行防護
- 沒有實作時間常數運算
- GCM 實作為簡化版本

### 性能

- 此實作優先考慮可讀性和正確性
- 性能約為 Node.js crypto 的 1/10
- 適合小規模測試和驗證

### 限制

- 目前僅支援加密，未實作解密
- GCM 的 GHASH 為簡化實作
- 未支援流式處理

## 🤝 貢獻

歡迎提交 Issue 和 Pull Request 來改進這個實作！

## 📄 授權

MIT License
