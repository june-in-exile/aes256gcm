/**
 * AES-256-GCM TypeScript Implementation
 * 用於 ZKP 電路驗證的參考實作
 */

import { createCipheriv } from 'crypto';

// 基礎工具函數
export class AESUtils {
  // 將字節轉換為十六進制字符串 (調試用)
  static bytesToHex(bytes: Buffer): string {
    return bytes.toString('hex');
  }

  // 十六進制字符串轉字節
  static hexToBytes(hex: string): Buffer {
    return Buffer.from(hex, 'hex');
  }

  // XOR 兩個字節數組
  static xor(a: Buffer, b: Buffer): Buffer {
    const result = Buffer.alloc(Math.min(a.length, b.length));
    for (let i = 0; i < result.length; i++) {
      result[i] = a[i] ^ b[i];
    }
    return result;
  }

  // 將 32 位整數轉換為字節數組 (大端序)
  static u32ToBytes(value: number): Buffer {
    const buffer = Buffer.alloc(4);
    buffer.writeUInt32BE(value, 0);
    return buffer;
  }

  // 將字節數組轉換為 32 位整數 (大端序)
  static bytesToU32(bytes: Buffer, offset: number = 0): number {
    return bytes.readUInt32BE(offset);
  }

  // 生成隨機字節
  static randomBytes(length: number): Buffer {
    return Buffer.from(crypto.getRandomValues(new Uint8Array(length)));
  }

  // 字節數組轉 base64
  static bytesToBase64(bytes: Buffer): string {
    return bytes.toString('base64');
  }

  // base64 轉字節數組
  static base64ToBytes(base64: string): Buffer {
    return Buffer.from(base64, 'base64');
  }

  // 字符串轉字節數組 (UTF-8)
  static stringToBytes(str: string): Buffer {
    return Buffer.from(str, 'utf8');
  }

  // 字節數組轉字符串 (UTF-8)
  static bytesToString(bytes: Buffer): string {
    return bytes.toString('utf8');
  }
}

// AES S-box 和逆 S-box
export class AESSbox {
  // AES S-box 查找表
  static readonly SBOX = Buffer.from([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
  ]);

  // 應用 S-box 變換
  static substitute(input: number): number {
    return this.SBOX[input];
  }

  // 對字節數組應用 S-box
  static substituteBytes(bytes: Buffer): Buffer {
    const result = Buffer.alloc(bytes.length);
    for (let i = 0; i < bytes.length; i++) {
      result[i] = this.SBOX[bytes[i]];
    }
    return result;
  }
}

// Galois 域 GF(2^8) 運算
export class GaloisField {
  // GF(2^8) 乘法，使用不可約多項式 0x11b
  static multiply(a: number, b: number): number {
    let result = 0;
    let temp_a = a;
    let temp_b = b;

    for (let i = 0; i < 8; i++) {
      if (temp_b & 1) {
        result ^= temp_a;
      }

      // 檢查是否需要減去不可約多項式
      const carry = temp_a & 0x80;
      temp_a <<= 1;
      temp_a &= 0xff; // 保持在 8 位範圍內

      if (carry) {
        temp_a ^= 0x1b; // 不可約多項式 x^8 + x^4 + x^3 + x + 1
      }

      temp_b >>= 1;
    }

    return result;
  }

  // 預計算的 2, 3 倍數表 (優化用)
  static readonly MUL2 = Buffer.alloc(256);
  static readonly MUL3 = Buffer.alloc(256);

  // 初始化倍數表
  static initMultiplicationTables() {
    for (let i = 0; i < 256; i++) {
      this.MUL2[i] = this.multiply(i, 2);
      this.MUL3[i] = this.multiply(i, 3);
    }
  }

  // 快速乘法 (使用預計算表)
  static fastMul2(x: number): number {
    return this.MUL2[x];
  }

  static fastMul3(x: number): number {
    return this.MUL3[x];
  }
}

// 初始化 Galois 域倍數表
GaloisField.initMultiplicationTables();

// AES 核心變換
export class AESTransforms {
  // SubBytes 變換 - 對狀態矩陣的每個字節應用 S-box
  static subBytes(state: Buffer): Buffer {
    return AESSbox.substituteBytes(state);
  }

  // ShiftRows 變換 - 對狀態矩陣的行進行循環左移
  static shiftRows(state: Buffer): Buffer {
    const result = Buffer.alloc(16);

    // 第一行不變 (索引 0, 4, 8, 12)
    result[0] = state[0]; result[4] = state[4];
    result[8] = state[8]; result[12] = state[12];

    // 第二行左移 1 位 (索引 1, 5, 9, 13)
    result[1] = state[5]; result[5] = state[9];
    result[9] = state[13]; result[13] = state[1];

    // 第三行左移 2 位 (索引 2, 6, 10, 14)
    result[2] = state[10]; result[6] = state[14];
    result[10] = state[2]; result[14] = state[6];

    // 第四行左移 3 位 (索引 3, 7, 11, 15)
    result[3] = state[15]; result[7] = state[3];
    result[11] = state[7]; result[15] = state[11];

    return result;
  }

  // MixColumns 變換 - 在 GF(2^8) 中進行列混合
  static mixColumns(state: Buffer): Buffer {
    const result = Buffer.alloc(16);

    // 對每一列進行變換
    for (let col = 0; col < 4; col++) {
      const offset = col * 4;

      // 獲取當前列的四個字節
      const s0 = state[offset];
      const s1 = state[offset + 1];
      const s2 = state[offset + 2];
      const s3 = state[offset + 3];

      // 應用 MixColumns 矩陣:
      // [2 3 1 1]   [s0]
      // [1 2 3 1] × [s1]
      // [1 1 2 3]   [s2]
      // [3 1 1 2]   [s3]

      result[offset] = GaloisField.fastMul2(s0) ^ GaloisField.fastMul3(s1) ^ s2 ^ s3;
      result[offset + 1] = s0 ^ GaloisField.fastMul2(s1) ^ GaloisField.fastMul3(s2) ^ s3;
      result[offset + 2] = s0 ^ s1 ^ GaloisField.fastMul2(s2) ^ GaloisField.fastMul3(s3);
      result[offset + 3] = GaloisField.fastMul3(s0) ^ s1 ^ s2 ^ GaloisField.fastMul2(s3);
    }

    return result;
  }

  // AddRoundKey 變換 - 將輪密鑰與狀態進行 XOR
  static addRoundKey(state: Buffer, roundKey: Buffer): Buffer {
    return AESUtils.xor(state, roundKey);
  }
}

// AES 密鑰擴展
export class AESKeyExpansion {
  // AES-256 的輪常數
  static readonly RCON = Buffer.from([
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
    0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f
  ]);

  // 將 4 字節字進行循環左移
  static rotWord(word: Buffer): Buffer {
    return Buffer.from([word[1], word[2], word[3], word[0]]);
  }

  // 對 4 字節字應用 S-box
  static subWord(word: Buffer): Buffer {
    return AESSbox.substituteBytes(word);
  }

  // AES-256 密鑰擴展 (生成 15 輪密鑰，每輪 16 字節)
  static expandKey(key: Buffer): Buffer[] {
    if (key.length !== 32) {
      throw new Error('AES-256 requires a 32-byte key');
    }

    const roundKeys: Buffer[] = [];
    const expandedKey = Buffer.alloc(240); // 15 輪 × 16 字節

    // 前兩輪密鑰直接來自原始密鑰
    key.copy(expandedKey, 0);

    // 擴展剩餘的密鑰
    for (let i = 32; i < 240; i += 4) {
      // 獲取前一個字
      const prevWord = expandedKey.subarray(i - 4, i);
      let newWord: Buffer;

      if (i % 32 === 0) {
        // 每 8 個字 (32 字節) 進行 RotWord + SubWord + Rcon
        const rotated = this.rotWord(prevWord);
        const substituted = this.subWord(rotated);
        const rconValue = Buffer.from([this.RCON[(i / 32) - 1], 0, 0, 0]);
        newWord = AESUtils.xor(substituted, rconValue);
      } else if (i % 32 === 16) {
        // AES-256 特殊情況：第 4 個字需要 SubWord
        newWord = this.subWord(prevWord);
      } else {
        newWord = Buffer.from(prevWord);
      }

      // 與 8 個字之前的字進行 XOR
      const prevRoundWord = expandedKey.subarray(i - 32, i - 28);
      const finalWord = AESUtils.xor(newWord, prevRoundWord);
      finalWord.copy(expandedKey, i);
    }

    // 將擴展密鑰分割為輪密鑰
    for (let round = 0; round < 15; round++) {
      roundKeys.push(expandedKey.subarray(round * 16, (round + 1) * 16));
    }

    return roundKeys;
  }
}

// AES-256 加密實作
export class AES256 {
  // AES-256 加密單個區塊
  static encryptBlock(plaintext: Buffer, key: Buffer): Buffer {
    if (plaintext.length !== 16) {
      throw new Error('Plaintext must be exactly 16 bytes');
    }

    // 密鑰擴展
    const roundKeys = AESKeyExpansion.expandKey(key);

    // 初始狀態
    let state = Buffer.from(plaintext);

    // 初始 AddRoundKey
    state = AESTransforms.addRoundKey(state, roundKeys[0]);

    // 13 輪標準變換 (AES-256 有 14 輪，最後一輪特殊)
    for (let round = 1; round <= 13; round++) {
      state = AESTransforms.subBytes(state);
      state = AESTransforms.shiftRows(state);
      state = AESTransforms.mixColumns(state);
      state = AESTransforms.addRoundKey(state, roundKeys[round]);
    }

    // 最後一輪 (沒有 MixColumns)
    state = AESTransforms.subBytes(state);
    state = AESTransforms.shiftRows(state);
    state = AESTransforms.addRoundKey(state, roundKeys[14]);

    return state;
  }
}

// AES-256-GCM 實作
export class AES256GCM {
  // 計數器模式加密
  static ctrEncrypt(plaintext: Buffer, key: Buffer, iv: Buffer): Buffer {
    const numBlocks = Math.ceil(plaintext.length / 16);
    const ciphertext = Buffer.alloc(plaintext.length);

    // 初始計數器
    const counter = Buffer.alloc(16);
    iv.subarray(0, 12).copy(counter, 0); // IV 的前 12 字節

    for (let i = 0; i < numBlocks; i++) {
      // 設置計數器值 (後 4 字節)
      const counterValue = i + 1;
      const counterBytes = AESUtils.u32ToBytes(counterValue);
      counterBytes.copy(counter, 12);

      // 加密計數器
      const keystream = AES256.encryptBlock(counter, key);

      // 與明文進行 XOR
      const blockStart = i * 16;
      const blockEnd = Math.min(blockStart + 16, plaintext.length);
      const plaintextBlock = plaintext.subarray(blockStart, blockEnd);

      for (let j = 0; j < plaintextBlock.length; j++) {
        ciphertext[blockStart + j] = plaintextBlock[j] ^ keystream[j];
      }
    }

    return ciphertext;
  }

  // GHASH 認證標籤計算 (簡化版)
  static ghash(data: Buffer, hashKey: Buffer): Buffer {
    // 這是 GHASH 的簡化實作
    // 完整實作需要 GF(2^128) 運算
    const result = Buffer.alloc(16);

    // 處理每 16 字節區塊
    for (let i = 0; i < data.length; i += 16) {
      const block = Buffer.alloc(16);
      const blockData = data.subarray(i, Math.min(i + 16, data.length));
      blockData.copy(block);

      // XOR 與前一個結果
      for (let j = 0; j < 16; j++) {
        result[j] ^= block[j];
      }

      // 在實際實作中，這裡需要與 hashKey 進行 GF(2^128) 乘法
      // 現在使用簡化版本
    }

    return result;
  }

  // 完整的 AES-256-GCM 加密
  static encrypt(
    plaintext: Buffer,
    key: Buffer,
    iv: Buffer,
    additionalData: Buffer = Buffer.alloc(0)
  ): { ciphertext: Buffer; tag: Buffer } {

    if (key.length !== 32) {
      throw new Error('AES-256-GCM requires a 32-byte key');
    }

    // 生成 hash 子密鑰
    const zeroBlock = Buffer.alloc(16);
    const hashKey = AES256.encryptBlock(zeroBlock, key);

    // CTR 模式加密
    const ciphertext = this.ctrEncrypt(plaintext, key, iv);

    // 計算認證標籤
    const authData = Buffer.alloc(additionalData.length + ciphertext.length);
    additionalData.copy(authData, 0);
    ciphertext.copy(authData, additionalData.length);

    let tag = this.ghash(authData, hashKey);

    // 生成最終標籤
    const tagCounter = Buffer.alloc(16);
    iv.subarray(0, 12).copy(tagCounter, 0);
    AESUtils.u32ToBytes(1).copy(tagCounter, 12);

    const tagMask = AES256.encryptBlock(tagCounter, key);
    tag = AESUtils.xor(tag, tagMask);

    return { ciphertext, tag };
  }
}

// 便利的 API 函數，直接使用 base64 和字符串
export class AES256GCMEasy {
  // 簡化的加密 API - 輸入和輸出都使用 base64/string 格式
  static encrypt(
    plaintext: string,
    keyBase64?: string,
    ivBase64?: string
  ): { key: string; iv: string; ciphertext: string; authTag: string } {
    // 如果沒有提供密鑰，生成隨機密鑰
    const keyBytes = keyBase64 ? AESUtils.base64ToBytes(keyBase64) : AESUtils.randomBytes(32);

    // 如果沒有提供 IV，生成隨機 IV
    const ivBytes = ivBase64 ? AESUtils.base64ToBytes(ivBase64) : AESUtils.randomBytes(12);

    // 轉換明文為字節
    const plaintextBytes = AESUtils.stringToBytes(plaintext);

    // 執行加密
    const result = AES256GCM.encrypt(plaintextBytes, keyBytes, ivBytes);

    // 返回 base64 格式的結果
    return {
      key: AESUtils.bytesToBase64(keyBytes),
      iv: AESUtils.bytesToBase64(ivBytes),
      ciphertext: AESUtils.bytesToBase64(result.ciphertext),
      authTag: AESUtils.bytesToBase64(result.tag)
    };
  }

  // 單區塊加密 API
  static encryptBlock(
    plaintext: string,
    keyBase64: string
  ): { key: string; plaintext: string; ciphertext: string } {
    const keyBytes = AESUtils.base64ToBytes(keyBase64);
    const plaintextBytes = AESUtils.stringToBytes(plaintext);

    // 確保明文剛好 16 字節
    const paddedPlaintext = Buffer.alloc(16);
    plaintextBytes.subarray(0, 16).copy(paddedPlaintext);

    // 執行單區塊加密
    const ciphertext = AES256.encryptBlock(paddedPlaintext, keyBytes);

    return {
      key: keyBase64,
      plaintext: plaintext,
      ciphertext: AESUtils.bytesToBase64(ciphertext)
    };
  }

  // 生成測試向量
  static generateTestVector(
    plaintext: string,
    keyBase64?: string
  ): { key: string; plaintext: string; expected: string } {
    const keyBytes = keyBase64 ? AESUtils.base64ToBytes(keyBase64) : AESUtils.randomBytes(32);
    const result = this.encryptBlock(plaintext, AESUtils.bytesToBase64(keyBytes));

    return {
      key: result.key,
      plaintext: result.plaintext,
      expected: result.ciphertext
    };
  }
}

// 驗證函數
export class AESVerification {
  // 使用 Node.js crypto 模組驗證
  static testECBModeWithNodeCrypto(): boolean {
    console.log('\n=== Node.js crypto 模組驗證 AES-256-ECB ===');

    // 測試向量
    const key = AESUtils.base64ToBytes('qmpEWRQQ+w1hp6xFYkoXFUHZA8Os71XTWxDZIdNAS7o=');
    // 明文必須是 16 bytes
    const plaintext = AESUtils.stringToBytes('This is a secret');

    // 我們的實作
    const ourCiphertext = AES256.encryptBlock(plaintext, key);
    console.log('我們的實作:', AESUtils.bytesToBase64(ourCiphertext));

    // Node.js crypto 模組 (ECB 模式，無填充)
    const cipher = createCipheriv('aes-256-ecb', key, null);
    cipher.setAutoPadding(false);

    let nodeCiphertext = cipher.update(plaintext);
    nodeCiphertext = Buffer.concat([nodeCiphertext, cipher.final()]);
    console.log('Node.js crypto:', nodeCiphertext.toString('base64'));

    // 比較結果
    const isEqual = AESUtils.bytesToHex(ourCiphertext) === nodeCiphertext.toString('hex');
    console.log('結果一致:', isEqual ? '✅ 是' : '❌ 否');

    return isEqual;
  }

  // 使用 Node.js crypto 模組驗證
  static testGCMModeWithNodeCrypto(): boolean {
    console.log('\n=== Node.js crypto 模組驗證 AES-256-GCM ===');

    // 測試向量
    const key = AESUtils.base64ToBytes('qmpEWRQQ+w1hp6xFYkoXFUHZA8Os71XTWxDZIdNAS7o=');
    const iv = AESUtils.base64ToBytes('YjgZJzfIXjAYvwt/');
    // 明文可以是任意長度
    const plaintext = AESUtils.stringToBytes('Text');

    // 我們的實作
    const result = AES256GCM.encrypt(plaintext, key, iv);
    console.log('我們的實作:');
    console.log('密文 (base64):', AESUtils.bytesToBase64(result.ciphertext));
    console.log('認證標籤 (base64):', AESUtils.bytesToBase64(result.tag));

    // Node.js crypto 模組 (GCM 模式)
    const cipher = createCipheriv('aes-256-gcm', key, iv);

    let nodeCiphertext = cipher.update(plaintext);
    nodeCiphertext = Buffer.concat([nodeCiphertext, cipher.final()]);
    const authTag = cipher.getAuthTag();

    console.log('\nNode.js crypto:');
    console.log('密文 (base64):', nodeCiphertext.toString('base64'));
    console.log('認證標籤 (base64):', authTag.toString('base64'));

    // 比較結果
    const ciphertextMatches = AESUtils.bytesToBase64(result.ciphertext) === nodeCiphertext.toString('base64');
    const authTagMatches = AESUtils.bytesToBase64(result.tag) === authTag.toString('base64');

    const isEqual = ciphertextMatches && authTagMatches;
    console.log('結果一致:', isEqual ? '✅ 是' : '❌ 否');

    return isEqual;
  }

  // 測試 GCM 模式
  static testGCMModeWithVector(): boolean {
    console.log('\n=== AES-256-GCM 測試 ===');

    const testVectors = [
      {
        plaintext: 'Text',
        key: 'qmpEWRQQ+w1hp6xFYkoXFUHZA8Os71XTWxDZIdNAS7o=',
        iv: 'YjgZJzfIXjAYvwt/',
        ciphertext: 'PgG52g==',
        authTag: 'u1NxL5uXKyM/8qbZiBtUvQ==',
      },
    ];

    let allPassed = true;

    testVectors.forEach((vector, index) => {
      console.log(`\n測試向量 ${index + 1}:`);

      console.log('明文:', vector.plaintext);
      console.log('密鑰 (base64):', vector.key);
      console.log('IV (base64):', vector.iv);

      const plaintext = AESUtils.stringToBytes(vector.plaintext);
      const key = AESUtils.base64ToBytes(vector.key);
      const iv = AESUtils.base64ToBytes(vector.iv);

      console.log("\nplaintext:", plaintext);
      console.log("key:", key);
      console.log("iv:", iv);

      const result = AES256GCM.encrypt(plaintext, key, iv);

      console.log('\n預期結果:');
      console.log('密文 (base64):', vector.ciphertext);
      console.log('認證標籤 (base64):', vector.authTag);

      const ciphertextPassed = AESUtils.bytesToBase64(result.ciphertext) === vector.ciphertext;
      const authTagPassed = AESUtils.bytesToBase64(result.tag) === vector.authTag;

      console.log('\n實際結果:');
      console.log('密文 (base64):', AESUtils.bytesToBase64(result.ciphertext), ciphertextPassed ? '✅' : '❌');
      console.log('認證標籤 (base64):', AESUtils.bytesToBase64(result.tag), authTagPassed ? '✅' : '❌');

      if (!ciphertextPassed || !authTagPassed) allPassed = false;
    });

    return allPassed;
  }

  // 測試中間步驟
  static testIntermediateSteps(): void {
    console.log('\n=== 中間步驟驗證 ===');

    // 可以手動驗證的簡單例子
    const testByte = 0x53;
    const sboxResult = AESSbox.substitute(testByte);
    console.log(`S-box(0x${testByte.toString(16)}) = 0x${sboxResult.toString(16)} (預期: 0xed)`);

    // Galois 域乘法測試
    const gf2 = GaloisField.multiply(0x53, 0x02);
    const gf3 = GaloisField.multiply(0x53, 0x03);
    console.log(`GF(0x53 * 0x02) = 0x${gf2.toString(16)} (預期: 0xa6)`);
    console.log(`GF(0x53 * 0x03) = 0x${gf3.toString(16)} (預期: 0xf5)`);

    // 驗證快速乘法表
    const fast2 = GaloisField.fastMul2(0x53);
    const fast3 = GaloisField.fastMul3(0x53);
    console.log(`快速表 2x: 0x${fast2.toString(16)}, 直接計算: 0x${gf2.toString(16)}, 一致: ${fast2 === gf2}`);
    console.log(`快速表 3x: 0x${fast3.toString(16)}, 直接計算: 0x${gf3.toString(16)}, 一致: ${fast3 === gf3}`);
  }

  // 執行所有測試
  static runAllTests(): boolean {
    console.log('🧪 開始 AES-256-GCM 實作驗證...\n');

    this.testIntermediateSteps();

    const cryptoECBMatches = this.testECBModeWithNodeCrypto();
    const cryptoGCNMatches = this.testGCMModeWithNodeCrypto();
    const gcmPassed = this.testGCMModeWithVector();

    const allPass = cryptoECBMatches && cryptoGCNMatches && gcmPassed;

    console.log('\n📊 測試總結:');
    console.log('Node.js crypto ECB 一致性:', cryptoECBMatches ? '✅' : '❌');
    console.log('Node.js crypto GCM 一致性:', cryptoGCNMatches ? '✅' : '❌');
    console.log('GCM 測試向量:', gcmPassed ? '✅' : '❌');
    console.log('整體狀態:', allPass ? '🎉 所有測試通過！' : '⚠️  存在問題，需要修正');

    return allPass;
  }
}

// 如果這個文件被直接執行，運行測試
if (import.meta.url === `file://${process.argv[1]}`) {
  AESVerification.runAllTests();
}