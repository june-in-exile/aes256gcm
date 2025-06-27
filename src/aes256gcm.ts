/**
 * AES-256-GCM TypeScript 實作 (修正版 - 支援任意長度 IV)
 */

import { createCipheriv } from 'crypto';

export class AESUtils {
  static bytesToHex(bytes: Buffer): string {
    return bytes.toString('hex');
  }

  static hexToBytes(hex: string): Buffer {
    return Buffer.from(hex, 'hex');
  }

  static xor(a: Buffer, b: Buffer): Buffer {
    const result = Buffer.alloc(Math.min(a.length, b.length));
    for (let i = 0; i < result.length; i++) {
      result[i] = a[i] ^ b[i];
    }
    return result;
  }

  static u32ToBytes(value: number): Buffer {
    const buffer = Buffer.alloc(4);
    buffer.writeUInt32BE(value, 0);
    return buffer;
  }

  static bytesToU32(bytes: Buffer, offset: number = 0): number {
    return bytes.readUInt32BE(offset);
  }

  static randomBytes(length: number): Buffer {
    return Buffer.from(crypto.getRandomValues(new Uint8Array(length)));
  }

  static bytesToBase64(bytes: Buffer): string {
    return bytes.toString('base64');
  }

  static base64ToBytes(base64: string): Buffer {
    return Buffer.from(base64, 'base64');
  }

  static stringToBytes(str: string): Buffer {
    return Buffer.from(str, 'utf8');
  }

  static bytesToString(bytes: Buffer): string {
    return bytes.toString('utf8');
  }
}

export class AESSbox {
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

  static substitute(input: number): number {
    return this.SBOX[input];
  }

  static substituteBytes(bytes: Buffer): Buffer {
    const result = Buffer.alloc(bytes.length);
    for (let i = 0; i < bytes.length; i++) {
      result[i] = this.SBOX[bytes[i]];
    }
    return result;
  }
}

export class GaloisField {
  static multiply(a: number, b: number): number {
    let result = 0;
    let temp_a = a;
    let temp_b = b;

    for (let i = 0; i < 8; i++) {
      if (temp_b & 1) {
        result ^= temp_a;
      }

      const carry = temp_a & 0x80;
      temp_a <<= 1;
      temp_a &= 0xff;

      if (carry) {
        temp_a ^= 0x1b;
      }

      temp_b >>= 1;
    }

    return result;
  }

  static readonly MUL2 = Buffer.alloc(256);
  static readonly MUL3 = Buffer.alloc(256);

  static initMultiplicationTables() {
    for (let i = 0; i < 256; i++) {
      this.MUL2[i] = this.multiply(i, 2);
      this.MUL3[i] = this.multiply(i, 3);
    }
  }

  static fastMul2(x: number): number {
    return this.MUL2[x];
  }

  static fastMul3(x: number): number {
    return this.MUL3[x];
  }
}

GaloisField.initMultiplicationTables();

export class AESTransforms {
  static subBytes(state: Buffer): Buffer {
    return AESSbox.substituteBytes(state);
  }

  static shiftRows(state: Buffer): Buffer {
    const result = Buffer.alloc(16);

    result[0] = state[0]; result[4] = state[4];
    result[8] = state[8]; result[12] = state[12];

    result[1] = state[5]; result[5] = state[9];
    result[9] = state[13]; result[13] = state[1];

    result[2] = state[10]; result[6] = state[14];
    result[10] = state[2]; result[14] = state[6];

    result[3] = state[15]; result[7] = state[3];
    result[11] = state[7]; result[15] = state[11];

    return result;
  }

  static mixColumns(state: Buffer): Buffer {
    const result = Buffer.alloc(16);

    for (let col = 0; col < 4; col++) {
      const offset = col * 4;

      const s0 = state[offset];
      const s1 = state[offset + 1];
      const s2 = state[offset + 2];
      const s3 = state[offset + 3];

      result[offset] = GaloisField.fastMul2(s0) ^ GaloisField.fastMul3(s1) ^ s2 ^ s3;
      result[offset + 1] = s0 ^ GaloisField.fastMul2(s1) ^ GaloisField.fastMul3(s2) ^ s3;
      result[offset + 2] = s0 ^ s1 ^ GaloisField.fastMul2(s2) ^ GaloisField.fastMul3(s3);
      result[offset + 3] = GaloisField.fastMul3(s0) ^ s1 ^ s2 ^ GaloisField.fastMul2(s3);
    }

    return result;
  }

  static addRoundKey(state: Buffer, roundKey: Buffer): Buffer {
    return AESUtils.xor(state, roundKey);
  }
}

export class AESKeyExpansion {
  static readonly RCON = Buffer.from([
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
    0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f
  ]);

  static rotWord(word: Buffer): Buffer {
    return Buffer.from([word[1], word[2], word[3], word[0]]);
  }

  static subWord(word: Buffer): Buffer {
    return AESSbox.substituteBytes(word);
  }

  static expandKey(key: Buffer): Buffer[] {
    if (key.length !== 32) {
      throw new Error('AES-256 requires a 32-byte key');
    }

    const roundKeys: Buffer[] = [];
    const expandedKey = Buffer.alloc(240);

    key.copy(expandedKey, 0);

    for (let i = 32; i < 240; i += 4) {
      const prevWord = expandedKey.subarray(i - 4, i);
      let newWord: Buffer;

      if (i % 32 === 0) {
        const rotated = this.rotWord(prevWord);
        const substituted = this.subWord(rotated);
        const rconValue = Buffer.from([this.RCON[(i / 32) - 1], 0, 0, 0]);
        newWord = AESUtils.xor(substituted, rconValue);
      } else if (i % 32 === 16) {
        newWord = this.subWord(prevWord);
      } else {
        newWord = Buffer.from(prevWord);
      }

      const prevRoundWord = expandedKey.subarray(i - 32, i - 28);
      const finalWord = AESUtils.xor(newWord, prevRoundWord);
      finalWord.copy(expandedKey, i);
    }

    for (let round = 0; round < 15; round++) {
      roundKeys.push(expandedKey.subarray(round * 16, (round + 1) * 16));
    }

    return roundKeys;
  }
}

export class AES256 {
  static encryptBlock(plaintext: Buffer, key: Buffer): Buffer {
    if (plaintext.length !== 16) {
      throw new Error('Plaintext must be exactly 16 bytes');
    }

    const roundKeys = AESKeyExpansion.expandKey(key);
    let state = Buffer.from(plaintext);

    state = AESTransforms.addRoundKey(state, roundKeys[0]);

    for (let round = 1; round <= 13; round++) {
      state = AESTransforms.subBytes(state);
      state = AESTransforms.shiftRows(state);
      state = AESTransforms.mixColumns(state);
      state = AESTransforms.addRoundKey(state, roundKeys[round]);
    }

    state = AESTransforms.subBytes(state);
    state = AESTransforms.shiftRows(state);
    state = AESTransforms.addRoundKey(state, roundKeys[14]);

    return state;
  }
}

// GF(2^128) 運算
export class GF128 {
  // GF(2^128) 乘法運算，使用約化多項式 f(x) = x^128 + x^7 + x^2 + x + 1
  static multiply(x: Buffer, y: Buffer): Buffer {
    const result = Buffer.alloc(16);
    const v = Buffer.from(y);

    // 對 x 的每一位進行處理
    for (let i = 0; i < 128; i++) {
      const byteIndex = Math.floor(i / 8);
      const bitIndex = 7 - (i % 8);

      // 如果 x 的當前位是 1，則將 v 加到結果中
      if ((x[byteIndex] >> bitIndex) & 1) {
        for (let j = 0; j < 16; j++) {
          result[j] ^= v[j];
        }
      }

      // v 右移一位
      let carry = 0;
      for (let j = 0; j < 16; j++) {
        const newCarry = v[j] & 1;
        v[j] = (v[j] >> 1) | (carry << 7);
        carry = newCarry;
      }

      // 如果有進位，需要減去約化多項式
      // f(x) = x^128 + x^7 + x^2 + x + 1 對應 11100001 00000000 ... 00000000
      if (carry) {
        v[0] ^= 0xe1;
      }
    }

    return result;
  }
}

export class AES256GCM {
  static incrementCounter(counter: Buffer): void {
    let carry = 1;
    for (let j = 15; j >= 12 && carry; j--) {
      const sum = counter[j] + carry;
      counter[j] = sum & 0xff;
      carry = sum >> 8;
    }
  }

  static ctrEncrypt(plaintext: Buffer, key: Buffer, j0: Buffer): Buffer {
    const numBlocks = Math.ceil(plaintext.length / 16);
    const ciphertext = Buffer.alloc(plaintext.length);

    const counter = Buffer.from(j0);

    for (let i = 0; i < numBlocks; i++) {
      // 遞增計數器（只遞增最後 4 個字節）
      this.incrementCounter(counter);

      // 加密當前計數器
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

  static ghash(data: Buffer, hashKey: Buffer): Buffer {
    let result = Buffer.alloc(16);

    // 處理每 16 字節塊
    for (let i = 0; i < data.length; i += 16) {
      const block = Buffer.alloc(16);
      const actualLength = Math.min(16, data.length - i);
      data.subarray(i, i + actualLength).copy(block, 0);

      // GHASH 運算：result = (result ⊕ block) × H
      for (let j = 0; j < 16; j++) {
        result[j] ^= block[j];
      }

      result = GF128.multiply(result, hashKey);
    }

    return result;
  }

  /**
   * 計算 J0 值，支援任意長度的 IV
   * 根據 NIST SP 800-38D 標準：
   * - 如果 IV 長度為 96 位 (12 字節)：J0 = IV || 0x00000001
   * - 否則：J0 = GHASH_H(IV || 0^(s+64) || [len(IV)]64)
   */
  static computeJ0(iv: Buffer, hashKey: Buffer): Buffer {
    if (iv.length === 12) {
      // 標準情況：IV 為 12 字節
      const j0 = Buffer.alloc(16);
      iv.copy(j0, 0, 0, 12);
      j0.writeUInt32BE(1, 12); // J0 = IV || 0x00000001
      return j0;
    } else {
      // 非標準情況：使用 GHASH 計算 J0
      // 計算需要的 padding
      const s = (128 - (iv.length * 8) % 128) % 128; // padding 到 128 位邊界
      const paddingBytes = Math.floor(s / 8);

      // 構建 GHASH 輸入：IV || 0^(s+64) || [len(IV)]64
      const ghashInputLength = iv.length + paddingBytes + 8 + 8; // +8 for zero padding, +8 for length
      const ghashInput = Buffer.alloc(ghashInputLength);

      let offset = 0;

      // 複製 IV
      iv.copy(ghashInput, offset);
      offset += iv.length;

      // 添加 padding 到 128 位邊界 + 額外 64 位零
      offset += paddingBytes + 8; // 跳過零填充部分

      // 添加 IV 長度（以位為單位，64位大端序）
      const ivLengthBits = iv.length * 8;
      ghashInput.writeUInt32BE(Math.floor(ivLengthBits / 0x100000000), offset);
      ghashInput.writeUInt32BE(ivLengthBits & 0xffffffff, offset + 4);

      // 使用 GHASH 計算 J0
      return this.ghash(ghashInput, hashKey);
    }
  }

  static encrypt(
    plaintext: Buffer,
    key: Buffer,
    iv: Buffer,
    additionalData: Buffer = Buffer.alloc(0)
  ): { ciphertext: Buffer; authTag: Buffer } {
    if (key.length !== 32) {
      throw new Error('AES-256-GCM requires a 32-byte key');
    }

    // 1. 生成 hash subkey: H = CIPH_K(0^128)
    const zeroBlock = Buffer.alloc(16);
    const hashKey = AES256.encryptBlock(zeroBlock, key);

    // 2. 計算 J0（支援任意長度 IV）
    const j0 = this.computeJ0(iv, hashKey);

    // 3. CTR 模式加密
    const ciphertext = this.ctrEncrypt(plaintext, key, j0);

    // 4. 計算 padding v(aadPadding), u(ciphertextPadding)
    const aadPadding = (16 - (additionalData.length % 16)) % 16;
    const ciphertextPadding = (16 - (ciphertext.length % 16)) % 16;

    // 5. S = GHASH_H(AAD || 0^v || C || 0^u || [len(AAD)]64 || [len(C)]64)
    const authDataLength = additionalData.length + aadPadding +
      ciphertext.length + ciphertextPadding + 16;
    const authData = Buffer.alloc(authDataLength);

    let offset = 0;

    // 添加 AAD
    additionalData.copy(authData, offset);
    offset += additionalData.length + aadPadding;

    // 添加密文
    ciphertext.copy(authData, offset);
    offset += ciphertext.length + ciphertextPadding;

    // 添加長度信息（64位大端序）
    const aadLengthBits = additionalData.length * 8;
    const ciphertextLengthBits = ciphertext.length * 8;

    authData.writeUInt32BE(Math.floor(aadLengthBits / 0x100000000), offset);
    authData.writeUInt32BE(aadLengthBits & 0xffffffff, offset + 4);
    authData.writeUInt32BE(Math.floor(ciphertextLengthBits / 0x100000000), offset + 8);
    authData.writeUInt32BE(ciphertextLengthBits & 0xffffffff, offset + 12);

    // 計算 GHASH
    let S = this.ghash(authData, hashKey);

    // 6. 最終標籤計算：T = GCTR_K(J0, S) = S xor CIPH_K(J0)
    const tagMask = AES256.encryptBlock(j0, key);
    S = AESUtils.xor(S, tagMask);

    // 7. 返回密文及標籤
    return { ciphertext, authTag: S };
  }
}

export class AES256GCMEasy {
  static encrypt(
    plaintext: string,
    keyBase64?: string,
    ivBase64?: string
  ): { key: string; iv: string; ciphertext: string; authTag: string } {
    const keyBytes = keyBase64 ? AESUtils.base64ToBytes(keyBase64) : AESUtils.randomBytes(32);
    const ivBytes = ivBase64 ? AESUtils.base64ToBytes(ivBase64) : AESUtils.randomBytes(12);
    const plaintextBytes = AESUtils.stringToBytes(plaintext);

    const result = AES256GCM.encrypt(plaintextBytes, keyBytes, ivBytes);

    return {
      key: AESUtils.bytesToBase64(keyBytes),
      iv: AESUtils.bytesToBase64(ivBytes),
      ciphertext: AESUtils.bytesToBase64(result.ciphertext),
      authTag: AESUtils.bytesToBase64(result.authTag)
    };
  }

  static encryptBlock(
    plaintext: string,
    keyBase64: string
  ): { key: string; plaintext: string; ciphertext: string } {
    const keyBytes = AESUtils.base64ToBytes(keyBase64);
    const plaintextBytes = AESUtils.stringToBytes(plaintext);

    const paddedPlaintext = Buffer.alloc(16);
    plaintextBytes.subarray(0, 16).copy(paddedPlaintext);

    const ciphertext = AES256.encryptBlock(paddedPlaintext, keyBytes);

    return {
      key: keyBase64,
      plaintext: plaintext,
      ciphertext: AESUtils.bytesToBase64(ciphertext)
    };
  }
}

export class AESVerification {
  static testECBMode(): boolean {
    console.log('\n=== Node.js crypto 模組驗證 AES-256-ECB ===');

    const plaintext = AESUtils.stringToBytes('This is a secret');
    const key = AESUtils.base64ToBytes('qmpEWRQQ+w1hp6xFYkoXFUHZA8Os71XTWxDZIdNAS7o=');

    const cipher = createCipheriv('aes-256-ecb', key, null);
    cipher.setAutoPadding(false);

    let expectedCiphertext = cipher.update(plaintext);
    expectedCiphertext = Buffer.concat([expectedCiphertext, cipher.final()]);
    console.log('Node.js crypto:', AESUtils.bytesToBase64(expectedCiphertext));

    const ourCiphertext = AES256.encryptBlock(plaintext, key);
    const isEqual = ourCiphertext.equals(expectedCiphertext);

    console.log('我們的實作:', AESUtils.bytesToBase64(ourCiphertext), isEqual ? '✅' : '❌');

    return isEqual;
  }

  static testGCMMode(): boolean {
    console.log('\n=== Node.js crypto 模組驗證 AES-256-GCM (12 字節 IV) ===');

    const plaintext = AESUtils.stringToBytes('Text');
    const key = AESUtils.base64ToBytes('qmpEWRQQ+w1hp6xFYkoXFUHZA8Os71XTWxDZIdNAS7o=');
    const iv = AESUtils.base64ToBytes('YjgZJzfIXjAYvwt/');

    const cipher = createCipheriv('aes-256-gcm', key, iv);

    let expectedCiphertext = cipher.update(plaintext);
    expectedCiphertext = Buffer.concat([expectedCiphertext, cipher.final()]);
    const expectedAuthTag = cipher.getAuthTag();

    console.log('\nNode.js crypto:');
    console.log('密文 (base64):', AESUtils.bytesToBase64(expectedCiphertext));
    console.log('認證標籤 (base64):', AESUtils.bytesToBase64(expectedAuthTag));

    const result = AES256GCM.encrypt(plaintext, key, iv);
    const ciphertextMatches = result.ciphertext.equals(expectedCiphertext);
    const authTagMatches = result.authTag.equals(expectedAuthTag);

    console.log('\n我們的實作:');
    console.log('密文 (base64):', AESUtils.bytesToBase64(result.ciphertext), ciphertextMatches ? '✅' : '❌');
    console.log('認證標籤 (base64):', AESUtils.bytesToBase64(result.authTag), authTagMatches ? '✅' : '❌');

    return ciphertextMatches && authTagMatches;
  }

  static runAllTests(): boolean {
    console.log('🧪 開始 AES-256-GCM 驗證...\n');

    const ecbPassed = this.testECBMode();
    const gcm12BytePassed = this.testGCMMode();

    console.log('\n📊 測試總結:');
    console.log('ECB 模式:', ecbPassed ? '✅' : '❌');
    console.log('GCM 模式:', gcm12BytePassed ? '✅' : '❌');
    console.log('整體狀態:', (ecbPassed && gcm12BytePassed) ?
      '🎉 所有測試通過！' : '⚠️  仍有問題需要調試');

    return ecbPassed && gcm12BytePassed;
  }
}

// 運行測試
if (import.meta.url === `file://${process.argv[1]}`) {
  AESVerification.runAllTests();
}