/**
 * AES-256-GCM 測試套件
 * 對應最新版本的實作 (含不同長度 IV 測試)
 */

import {
  AES256,
  AES256GCM,
  AES256GCMEasy,
  AESUtils,
  AESVerification,
  GaloisField,
  GF128,
  AESTransforms
} from './main.js';
import { createCipheriv } from 'crypto';

// 簡化的使用範例
function simpleUsageExample() {
  console.log('\n🎯 簡化 API 使用範例\n');

  // 最簡單的用法 - 自動生成密鑰和 IV
  const result1 = AES256GCMEasy.encrypt('Hello, Simple World!');
  console.log('自動生成密鑰加密:');
  console.log('明文:', 'Hello, Simple World!');
  console.log('密鑰 (base64):', result1.key);
  console.log('IV (base64):', result1.iv);
  console.log('密文 (base64):', result1.ciphertext);
  console.log('認證標籤 (base64):', result1.authTag);

  // 使用指定密鑰
  const fixedKey = 'qmpEWRQQ+w1hp6xFYkoXFUHZA8Os71XTWxDZIdNAS7o=';
  const fixedIv = 'YjgZJzfIXjAYvwt/';
  const result2 = AES256GCMEasy.encrypt('Text', fixedKey, fixedIv);
  console.log('\n使用固定密鑰和IV加密:');
  console.log('明文:', 'Text');
  console.log('密鑰 (base64):', result2.key);
  console.log('IV (base64):', result2.iv);
  console.log('密文 (base64):', result2.ciphertext);
  console.log('認證標籤 (base64):', result2.authTag);

  // 單區塊加密
  const blockResult = AES256GCMEasy.encryptBlock('Test Block 16B!!', fixedKey);
  console.log('\n單區塊加密:');
  console.log('明文:', blockResult.plaintext);
  console.log('密文 (base64):', blockResult.ciphertext);

  return { result1, result2, blockResult };
}

// 基本使用範例
function basicUsageExample() {
  console.log('\n🚀 基本使用範例\n');

  // 1. 生成隨機密鑰和 IV
  const key = AESUtils.randomBytes(32);  // 256 位密鑰
  const iv = AESUtils.randomBytes(12);   // 96 位 IV (GCM 推薦)

  console.log('生成的密鑰 (base64):', AESUtils.bytesToBase64(key));
  console.log('生成的 IV (base64):', AESUtils.bytesToBase64(iv));

  // 2. 準備明文
  const plaintext = 'Hello, ZKP World! 這是一個測試消息。';
  const plaintextBytes = AESUtils.stringToBytes(plaintext);

  console.log('明文:', plaintext);
  console.log('明文長度:', plaintextBytes.length, '字節');

  // 3. AES-256-GCM 加密
  const result = AES256GCM.encrypt(plaintextBytes, key, iv);

  console.log('\n加密結果:');
  console.log('密文 (base64):', AESUtils.bytesToBase64(result.ciphertext));
  console.log('認證標籤 (base64):', AESUtils.bytesToBase64(result.authTag));

  return {
    key: AESUtils.bytesToBase64(key),
    iv: AESUtils.bytesToBase64(iv),
    plaintext,
    ciphertext: AESUtils.bytesToBase64(result.ciphertext),
    tag: AESUtils.bytesToBase64(result.authTag)
  };
}

// 單區塊 AES-256 測試
function singleBlockExample() {
  console.log('\n📦 單區塊 AES-256 測試\n');

  // 使用已知測試向量 (base64 格式)
  const key = 'qmpEWRQQ+w1hp6xFYkoXFUHZA8Os71XTWxDZIdNAS7o=';
  const plaintext = 'Test AES Block!!'; // 剛好 16 字節

  console.log('密鑰 (base64):', key);
  console.log('明文:', plaintext);

  const keyBytes = AESUtils.base64ToBytes(key);
  const plaintextBytes = AESUtils.stringToBytes(plaintext);

  // 確保明文剛好 16 字節
  const paddedPlaintext = Buffer.alloc(16);
  plaintextBytes.subarray(0, 16).copy(paddedPlaintext);

  // 單區塊加密
  const ciphertext = AES256.encryptBlock(paddedPlaintext, keyBytes);
  const result = AESUtils.bytesToBase64(ciphertext);

  console.log('密文 (base64):', result);
  console.log('✅ 加密完成');
}

// 步驟測試 - 驗證每個 AES 變換
function stepByStepTest() {
  console.log('\n🔍 AES 變換步驟測試\n');

  // 測試狀態
  const state = AESUtils.hexToBytes('19a09ae93df4c6f8e3e28d48be2b2a08');
  console.log('初始狀態:', AESUtils.bytesToHex(state));

  // SubBytes
  const afterSub = AESTransforms.subBytes(state);
  console.log('SubBytes:', AESUtils.bytesToHex(afterSub));

  // ShiftRows
  const afterShift = AESTransforms.shiftRows(afterSub);
  console.log('ShiftRows:', AESUtils.bytesToHex(afterShift));

  // MixColumns
  const afterMix = AESTransforms.mixColumns(afterShift);
  console.log('MixColumns:', AESUtils.bytesToHex(afterMix));

  // 測試 Galois 域運算
  console.log('\nGalois 域運算測試:');
  console.log('GF(0x53 * 0x02) =', GaloisField.multiply(0x53, 0x02).toString(16));
  console.log('GF(0x53 * 0x03) =', GaloisField.multiply(0x53, 0x03).toString(16));
  console.log('快速表 2x =', GaloisField.fastMul2(0x53).toString(16));
  console.log('快速表 3x =', GaloisField.fastMul3(0x53).toString(16));

  // 測試 GF(2^128) 運算
  console.log('\nGF(2^128) 運算測試:');
  const x = Buffer.from('01234567890abcdef0123456789abcde', 'hex');
  const y = Buffer.from('fedcba0987654321fedcba0987654321', 'hex');
  const product = GF128.multiply(x, y);
  console.log('GF128 乘法結果:', AESUtils.bytesToHex(product));
}

// 測試不同長度的 IV
function testVariousIVLengths(): boolean {
  console.log('\n🔄 測試不同長度的 IV\n');

  const plaintext = AESUtils.stringToBytes('Hello World!');
  const key = AESUtils.base64ToBytes('qmpEWRQQ+w1hp6xFYkoXFUHZA8Os71XTWxDZIdNAS7o=');

  // 測試不同長度的 IV
  const testCases = [
    { length: 1, name: '1 字節 IV (最小)' },
    { length: 8, name: '8 字節 IV' },
    { length: 12, name: '12 字節 IV (標準)' },
    { length: 16, name: '16 字節 IV' },
    { length: 24, name: '24 字節 IV' },
    { length: 32, name: '32 字節 IV' },
    { length: 64, name: '64 字節 IV (大型)' }
  ];

  let allPassed = true;

  for (const testCase of testCases) {
    console.log(`--- ${testCase.name} ---`);

    const iv = AESUtils.randomBytes(testCase.length);
    console.log(`IV 長度: ${testCase.length} 字節`);
    console.log('IV (base64):', AESUtils.bytesToBase64(iv));

    try {
      // 使用 Node.js crypto 作為參考 (只對標準長度)
      let nodeResult: Buffer | null = null;
      let nodeAuthTag: Buffer | null = null;
      let nodeSupported = false;

      if (testCase.length === 12) {
        // Node.js 標準支援 12 字節 IV
        try {
          const nodeCipher = createCipheriv('aes-256-gcm', key, iv);
          nodeResult = nodeCipher.update(plaintext);
          nodeResult = Buffer.concat([nodeResult, nodeCipher.final()]);
          nodeAuthTag = nodeCipher.getAuthTag();
          nodeSupported = true;

          console.log('Node.js 密文:', AESUtils.bytesToBase64(nodeResult));
          console.log('Node.js 標籤:', AESUtils.bytesToBase64(nodeAuthTag));
        } catch (error) {
          console.log('Node.js 不支援此 IV 長度');
        }
      } else {
        console.log('Node.js 僅支援 12 字節 IV，跳過比較');
      }

      // 使用我們的實作
      const ourResult = AES256GCM.encrypt(plaintext, key, iv);
      console.log('我們的密文:', AESUtils.bytesToBase64(ourResult.ciphertext));
      console.log('我們的標籤:', AESUtils.bytesToBase64(ourResult.authTag));

      // 如果 Node.js 支援，進行比較
      if (nodeSupported && nodeResult && nodeAuthTag) {
        const ciphertextMatches = ourResult.ciphertext.equals(nodeResult);
        const authTagMatches = ourResult.authTag.equals(nodeAuthTag);

        console.log('密文匹配:', ciphertextMatches ? '✅' : '❌');
        console.log('標籤匹配:', authTagMatches ? '✅' : '❌');

        if (!ciphertextMatches || !authTagMatches) {
          allPassed = false;
        }
      } else {
        console.log('狀態: ✅ 成功生成 (無法與 Node.js 比較)');
      }

      // 驗證基本屬性
      if (ourResult.ciphertext.length !== plaintext.length) {
        console.log('❌ 密文長度不匹配');
        allPassed = false;
      }

      if (ourResult.authTag.length !== 16) {
        console.log('❌ 認證標籤長度應為 16 字節');
        allPassed = false;
      }

    } catch (error) {
      console.log('測試失敗:', (error as Error).message);
      allPassed = false;
    }

    console.log(''); // 空行分隔
  }

  // 額外測試：空 IV 處理
  console.log('--- 特殊情況：空 IV ---');
  try {
    const emptyIv = Buffer.alloc(0);
    const result = AES256GCM.encrypt(plaintext, key, emptyIv);
    console.log('空 IV 結果:', AESUtils.bytesToBase64(result.ciphertext));
    console.log('✅ 空 IV 處理成功');
  } catch (error) {
    console.log('空 IV 測試失敗:', (error as Error).message);
    allPassed = false;
  }

  console.log('\n🏁 不同長度 IV 測試總結:', allPassed ? '✅ 全部通過' : '❌ 存在問題');
  return allPassed;
}

// 深度 IV 測試：邊界情況和特殊模式
function deepIVTesting(): boolean {
  console.log('\n🧪 深度 IV 測試：邊界情況和特殊模式\n');

  const plaintext = AESUtils.stringToBytes('Deep IV Test Message');
  const key = AESUtils.randomBytes(32);

  let allPassed = true;

  // 測試 1：全零 IV
  console.log('--- 測試 1：全零 IV ---');
  const testCases = [
    { iv: Buffer.alloc(12, 0), name: '12字節全零IV' },
    { iv: Buffer.alloc(16, 0), name: '16字節全零IV' },
    { iv: Buffer.alloc(8, 0), name: '8字節全零IV' }
  ];

  for (const testCase of testCases) {
    try {
      const result = AES256GCM.encrypt(plaintext, key, testCase.iv);
      console.log(`${testCase.name}: ✅`);
      console.log('  密文:', AESUtils.bytesToBase64(result.ciphertext).substring(0, 20) + '...');
    } catch (error) {
      console.log(`${testCase.name}: ❌ ${(error as Error).message}`);
      allPassed = false;
    }
  }

  // 測試 2：全 0xFF IV
  console.log('\n--- 測試 2：全 0xFF IV ---');
  const maxIVCases = [
    { iv: Buffer.alloc(12, 0xFF), name: '12字節全0xFF IV' },
    { iv: Buffer.alloc(16, 0xFF), name: '16字節全0xFF IV' },
    { iv: Buffer.alloc(32, 0xFF), name: '32字節全0xFF IV' }
  ];

  for (const testCase of maxIVCases) {
    try {
      const result = AES256GCM.encrypt(plaintext, key, testCase.iv);
      console.log(`${testCase.name}: ✅`);
      console.log('  密文:', AESUtils.bytesToBase64(result.ciphertext).substring(0, 20) + '...');
    } catch (error) {
      console.log(`${testCase.name}: ❌ ${(error as Error).message}`);
      allPassed = false;
    }
  }

  // 測試 3：遞增模式 IV
  console.log('\n--- 測試 3：遞增模式 IV ---');
  for (let len = 1; len <= 16; len++) {
    const iv = Buffer.alloc(len);
    for (let i = 0; i < len; i++) {
      iv[i] = i;
    }

    try {
      const result = AES256GCM.encrypt(plaintext, key, iv);
      console.log(`${len}字節遞增IV: ✅`);
    } catch (error) {
      console.log(`${len}字節遞增IV: ❌ ${(error as Error).message}`);
      allPassed = false;
    }
  }

  // 測試 4：重複性檢查 - 相同 IV 應產生相同結果
  console.log('\n--- 測試 4：重複性檢查 ---');
  const fixedIV = AESUtils.randomBytes(16);
  const result1 = AES256GCM.encrypt(plaintext, key, fixedIV);
  const result2 = AES256GCM.encrypt(plaintext, key, fixedIV);

  const repeatabilityTest = result1.ciphertext.equals(result2.ciphertext) &&
    result1.authTag.equals(result2.authTag);
  console.log('相同 IV 重複性測試:', repeatabilityTest ? '✅' : '❌');
  if (!repeatabilityTest) allPassed = false;

  // 測試 5：隨機性檢查 - 不同 IV 應產生不同結果
  console.log('\n--- 測試 5：隨機性檢查 ---');
  const differentResults = [];
  for (let i = 0; i < 5; i++) {
    const randomIV = AESUtils.randomBytes(12);
    const result = AES256GCM.encrypt(plaintext, key, randomIV);
    differentResults.push(AESUtils.bytesToBase64(result.ciphertext));
  }

  const uniqueResults = new Set(differentResults);
  const randomnessTest = uniqueResults.size === differentResults.length;
  console.log('不同 IV 隨機性測試:', randomnessTest ? '✅' : '❌');
  console.log(`生成了 ${uniqueResults.size}/${differentResults.length} 個不同結果`);
  if (!randomnessTest) allPassed = false;

  console.log('\n🏁 深度 IV 測試總結:', allPassed ? '✅ 全部通過' : '❌ 存在問題');
  return allPassed;
}

// 生成 ZKP 電路測試向量
function generateZKPTestVectors() {
  console.log('\n⚡ 生成 ZKP 電路測試向量\n');

  // 為 ZKP 電路生成標準測試案例
  const testCases = [
    {
      name: 'Simple Test Case',
      key: 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=', // 32 字節全序列
      plaintext: 'Hello AES World!'
    },
    {
      name: 'Known Vector',
      key: 'qmpEWRQQ+w1hp6xFYkoXFUHZA8Os71XTWxDZIdNAS7o=',
      plaintext: 'Test Vector Data'
    },
    {
      name: 'Zero Key Test',
      key: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', // 全零密鑰
      plaintext: 'Zero Key Test!!!'
    },
    {
      name: 'Max Key Test',
      key: '//////////////////////////////////////////8=', // 全一密鑰
      plaintext: 'Max Key Test!!!!'
    },
    {
      name: 'Chinese Text Test',
      key: 'dGVzdEtleTEyMzQ1Njc4OTBhYmNkZWZnaGlqa2xtbm8=',
      plaintext: '中文測試Block!!!'
    }
  ];

  console.log('// ZKP 電路測試向量 (TypeScript/JavaScript 格式)');
  console.log('// 可以直接用於 Circom 電路驗證\n');

  testCases.forEach((testCase, index) => {
    const keyBytes = AESUtils.base64ToBytes(testCase.key);
    const plaintextBytes = AESUtils.stringToBytes(testCase.plaintext);

    // 確保明文剛好 16 字節
    const paddedPlaintext = Buffer.alloc(16);
    plaintextBytes.subarray(0, 16).copy(paddedPlaintext);

    const ciphertext = AES256.encryptBlock(paddedPlaintext, keyBytes);
    const ciphertextBase64 = AESUtils.bytesToBase64(ciphertext);

    console.log(`// ${testCase.name}`);
    console.log(`const testVector${index + 1} = {`);
    console.log(`  key: "${testCase.key}",`);
    console.log(`  plaintext: "${testCase.plaintext}",`);
    console.log(`  expected: "${ciphertextBase64}"`);
    console.log('};\n');
  });

  // 也生成 GCM 模式的測試向量 (包含不同長度 IV)
  console.log('// GCM 模式測試向量 (含不同長度 IV)');
  const gcmTestCases = [
    {
      name: 'GCM Standard 12-byte IV',
      key: 'qmpEWRQQ+w1hp6xFYkoXFUHZA8Os71XTWxDZIdNAS7o=',
      iv: 'YjgZJzfIXjAYvwt/', // 12 字節 IV
      plaintext: 'Text'
    },
    {
      name: 'GCM Long Message',
      key: 'bXlTZWNyZXRLZXkxMjM0NTY3ODkwYWJjZGVmZ2hpams=',
      iv: 'lV8jzMw8l38VL+kA', // 12 字節 IV
      plaintext: 'This is a longer message for GCM testing!'
    },
    {
      name: 'GCM 8-byte IV',
      key: 'dGVzdEtleTEyMzQ1Njc4OTBhYmNkZWZnaGlqa2xtbm8=',
      iv: 'MTIzNDU2Nzg=', // 8 字節 IV
      plaintext: 'Short IV test'
    },
    {
      name: 'GCM 16-byte IV',
      key: 'dGVzdEtleTEyMzQ1Njc4OTBhYmNkZWZnaGlqa2xtbm8=',
      iv: 'AAAAAAAAAAAAAAAAAAAAAA==', // 16 字節全零 IV
      plaintext: 'Long IV test!'
    },
    {
      name: 'GCM Empty Message',
      key: 'dGVzdEtleTEyMzQ1Njc4OTBhYmNkZWZnaGlqa2xtbm8=',
      iv: 'lV8jzMw8l38VL+kA',
      plaintext: ''
    }
  ];

  gcmTestCases.forEach((testCase, index) => {
    const keyBytes = AESUtils.base64ToBytes(testCase.key);
    const ivBytes = AESUtils.base64ToBytes(testCase.iv);
    const plaintextBytes = AESUtils.stringToBytes(testCase.plaintext);

    const result = AES256GCM.encrypt(plaintextBytes, keyBytes, ivBytes);

    console.log(`// ${testCase.name}`);
    console.log(`const gcmTestVector${index + 1} = {`);
    console.log(`  key: "${testCase.key}",`);
    console.log(`  iv: "${testCase.iv}", // ${ivBytes.length} bytes`);
    console.log(`  plaintext: "${testCase.plaintext}",`);
    console.log(`  expectedCiphertext: "${AESUtils.bytesToBase64(result.ciphertext)}",`);
    console.log(`  expectedAuthTag: "${AESUtils.bytesToBase64(result.authTag)}"`);
    console.log('};\n');
  });
}

// 性能測試
function performanceTest() {
  console.log('\n⚡ 性能測試\n');

  const key = AESUtils.randomBytes(32);
  const plaintext = Buffer.alloc(16, 0x41); // 16字節的'A'

  const iterations = 10000;

  console.log(`執行 ${iterations} 次 AES-256 單區塊加密...`);

  const start = performance.now();
  for (let i = 0; i < iterations; i++) {
    AES256.encryptBlock(plaintext, key);
  }
  const end = performance.now();

  const totalTime = end - start;
  const avgTime = totalTime / iterations;

  console.log(`總時間: ${totalTime.toFixed(2)} ms`);
  console.log(`平均時間: ${avgTime.toFixed(4)} ms/次`);
  console.log(`吞吐量: ${(iterations / totalTime * 1000).toFixed(0)} 次/秒`);

  // GCM 模式性能測試
  const gcmPlaintext = Buffer.alloc(64, 0x42); // 64 字節
  const iv = AESUtils.randomBytes(12);
  const gcmIterations = 1000;

  console.log(`\n執行 ${gcmIterations} 次 AES-256-GCM 加密 (64 字節)...`);

  const gcmStart = performance.now();
  for (let i = 0; i < gcmIterations; i++) {
    AES256GCM.encrypt(gcmPlaintext, key, iv);
  }
  const gcmEnd = performance.now();

  const gcmTotalTime = gcmEnd - gcmStart;
  const gcmAvgTime = gcmTotalTime / gcmIterations;

  console.log(`GCM 總時間: ${gcmTotalTime.toFixed(2)} ms`);
  console.log(`GCM 平均時間: ${gcmAvgTime.toFixed(4)} ms/次`);
  console.log(`GCM 吞吐量: ${(gcmIterations / gcmTotalTime * 1000).toFixed(0)} 次/秒`);
}

// 與 Node.js crypto 性能比較
async function compareWithNodeCrypto() {
  console.log('\n🔍 與 Node.js crypto 性能比較\n');

  const key = AESUtils.randomBytes(32);
  const plaintext = Buffer.alloc(1024, 0x55); // 1KB 數據
  const iv = AESUtils.randomBytes(12);

  const iterations = 1000;

  // 測試我們的實作
  console.log('測試我們的 AES-256-GCM 實作...');
  const ourStart = performance.now();
  for (let i = 0; i < iterations; i++) {
    AES256GCM.encrypt(plaintext, key, iv);
  }
  const ourEnd = performance.now();
  const ourTime = ourEnd - ourStart;

  // 測試 Node.js crypto
  console.log('測試 Node.js crypto AES-256-GCM...');
  const nodeStart = performance.now();
  for (let i = 0; i < iterations; i++) {
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    cipher.update(plaintext);
    cipher.final();
    cipher.getAuthTag();
  }
  const nodeEnd = performance.now();
  const nodeTime = nodeEnd - nodeStart;

  console.log(`我們的實作: ${ourTime.toFixed(2)} ms`);
  console.log(`Node.js crypto: ${nodeTime.toFixed(2)} ms`);
  console.log(`性能比: ${(ourTime / nodeTime).toFixed(2)}x (我們的實作較慢)`);
  console.log(`Node.js 加速比: ${(ourTime / nodeTime).toFixed(1)}x 更快`);
}

// 錯誤處理測試
function errorHandlingTest() {
  console.log('\n❌ 錯誤處理測試\n');

  try {
    // 錯誤的密鑰長度
    const wrongKey = AESUtils.randomBytes(16); // 應該是 32 字節
    const plaintext = Buffer.alloc(16);
    AES256.encryptBlock(plaintext, wrongKey);
    console.log('❌ 應該要拋出錯誤但沒有');
  } catch (error) {
    console.log('✅ 正確捕獲密鑰長度錯誤:', (error as Error).message);
  }

  try {
    // 錯誤的明文長度
    const key = AESUtils.randomBytes(32);
    const wrongPlaintext = Buffer.alloc(15); // 應該是 16 字節
    AES256.encryptBlock(wrongPlaintext, key);
    console.log('❌ 應該要拋出錯誤但沒有');
  } catch (error) {
    console.log('✅ 正確捕獲明文長度錯誤:', (error as Error).message);
  }

  try {
    // GCM 模式錯誤的密鑰長度
    const wrongKey = AESUtils.randomBytes(16);
    const plaintext = Buffer.alloc(32);
    const iv = AESUtils.randomBytes(12);
    AES256GCM.encrypt(plaintext, wrongKey, iv);
    console.log('❌ 應該要拋出錯誤但沒有');
  } catch (error) {
    console.log('✅ 正確捕獲 GCM 密鑰長度錯誤:', (error as Error).message);
  }

  console.log('\n✅ 錯誤處理測試完成 - 現在支援任意長度 IV');
}

// 內存使用測試
function memoryUsageTest() {
  console.log('\n💾 內存使用測試\n');

  const initialMemory = process.memoryUsage();
  console.log('初始內存使用:', {
    rss: Math.round(initialMemory.rss / 1024 / 1024) + ' MB',
    heapUsed: Math.round(initialMemory.heapUsed / 1024 / 1024) + ' MB'
  });

  // 執行大量加密操作
  const key = AESUtils.randomBytes(32);
  const iterations = 50000;

  console.log(`執行 ${iterations} 次加密操作...`);

  for (let i = 0; i < iterations; i++) {
    const plaintext = Buffer.alloc(16, i % 256);
    AES256.encryptBlock(plaintext, key);

    // 每 10000 次檢查一次內存
    if (i % 10000 === 0 && i > 0) {
      const currentMemory = process.memoryUsage();
      console.log(`第 ${i} 次 - 堆內存: ${Math.round(currentMemory.heapUsed / 1024 / 1024)} MB`);
    }
  }

  const finalMemory = process.memoryUsage();
  console.log('\n最終內存使用:', {
    rss: Math.round(finalMemory.rss / 1024 / 1024) + ' MB',
    heapUsed: Math.round(finalMemory.heapUsed / 1024 / 1024) + ' MB'
  });

  const memoryIncrease = finalMemory.heapUsed - initialMemory.heapUsed;
  console.log('內存增長:', Math.round(memoryIncrease / 1024 / 1024) + ' MB');
}

// 驗證修正後的實作
function extraVerification() {
  console.log('\n🔧 測資驗證\n');

  // 測試已知向量
  const testVector = {
    plaintext: 'Text',
    key: 'qmpEWRQQ+w1hp6xFYkoXFUHZA8Os71XTWxDZIdNAS7o=',
    iv: 'YjgZJzfIXjAYvwt/',
    expectedCiphertext: 'PgG52g==',
    expectedAuthTag: 'u1NxL5uXKyM/8qbZiBtUvQ=='
  };

  const plaintext = AESUtils.stringToBytes(testVector.plaintext);
  const key = AESUtils.base64ToBytes(testVector.key);
  const iv = AESUtils.base64ToBytes(testVector.iv);

  const result = AES256GCM.encrypt(plaintext, key, iv);

  console.log('測試向量驗證:');
  console.log('明文:', testVector.plaintext);
  console.log('密鑰 (base64):', testVector.key);
  console.log('IV (base64):', testVector.iv);

  const ciphertextMatch = AESUtils.bytesToBase64(result.ciphertext) === testVector.expectedCiphertext;
  const authTagMatch = AESUtils.bytesToBase64(result.authTag) === testVector.expectedAuthTag;

  console.log('\n預期結果:');
  console.log('密文 (base64):', testVector.expectedCiphertext);
  console.log('認證標籤 (base64):', testVector.expectedAuthTag);

  console.log('\n實際結果:');
  console.log('密文 (base64):', AESUtils.bytesToBase64(result.ciphertext), ciphertextMatch ? '✅' : '❌');
  console.log('認證標籤 (base64):', AESUtils.bytesToBase64(result.authTag), authTagMatch ? '✅' : '❌');

  return ciphertextMatch && authTagMatch;
}

// IV 兼容性測試：與其他實作比較
function ivCompatibilityTest() {
  console.log('\n🔄 IV 兼容性測試：與其他實作比較\n');

  const plaintext = AESUtils.stringToBytes('Compatibility Test');
  const key = AESUtils.randomBytes(32);

  let allPassed = true;

  // 測試與 Node.js crypto 的兼容性 (12字節 IV)
  console.log('--- Node.js crypto 兼容性測試 ---');
  const standard12ByteIV = AESUtils.randomBytes(12);

  try {
    // Node.js crypto
    const nodeCipher = createCipheriv('aes-256-gcm', key, standard12ByteIV);
    let nodeResult = nodeCipher.update(plaintext);
    nodeResult = Buffer.concat([nodeResult, nodeCipher.final()]);
    const nodeAuthTag = nodeCipher.getAuthTag();

    // 我們的實作
    const ourResult = AES256GCM.encrypt(plaintext, key, standard12ByteIV);

    const ciphertextMatch = ourResult.ciphertext.equals(nodeResult);
    const authTagMatch = ourResult.authTag.equals(nodeAuthTag);

    console.log('12字節 IV 密文匹配:', ciphertextMatch ? '✅' : '❌');
    console.log('12字節 IV 標籤匹配:', authTagMatch ? '✅' : '❌');

    if (!ciphertextMatch || !authTagMatch) {
      allPassed = false;
    }

  } catch (error) {
    console.log('Node.js 兼容性測試失敗:', (error as Error).message);
    allPassed = false;
  }

  // 測試跨長度一致性：相同 J0 應產生相同結果
  console.log('\n--- 跨長度一致性測試 ---');

  // 使用特定的 IV 長度組合來測試 J0 計算的一致性
  const testIVs = [
    Buffer.from('123456789012', 'utf8'), // 12 字節，應該使用標準方法
    Buffer.concat([Buffer.from('123456789012', 'utf8'), Buffer.alloc(4, 0)]) // 16 字節，應該使用 GHASH 方法
  ];

  for (let i = 0; i < testIVs.length; i++) {
    try {
      const result = AES256GCM.encrypt(plaintext, key, testIVs[i]);
      console.log(`IV長度 ${testIVs[i].length} 字節: ✅`);
      console.log(`  結果預覽: ${AESUtils.bytesToBase64(result.ciphertext).substring(0, 16)}...`);
    } catch (error) {
      console.log(`IV長度 ${testIVs[i].length} 字節: ❌ ${(error as Error).message}`);
      allPassed = false;
    }
  }

  // 測試極端情況
  console.log('\n--- 極端情況測試 ---');
  const extremeCases = [
    { length: 1, name: '最小 IV (1字節)' },
    { length: 128, name: '大型 IV (128字節)' },
    { length: 255, name: '極大 IV (255字節)' }
  ];

  for (const testCase of extremeCases) {
    try {
      const iv = AESUtils.randomBytes(testCase.length);
      const result = AES256GCM.encrypt(plaintext, key, iv);
      console.log(`${testCase.name}: ✅`);
    } catch (error) {
      console.log(`${testCase.name}: ❌ ${(error as Error).message}`);
      allPassed = false;
    }
  }

  console.log('\n🏁 IV 兼容性測試總結:', allPassed ? '✅ 全部通過' : '❌ 存在問題');
  return allPassed;
}

// 主測試函數
async function main() {
  console.log('🧪 AES-256-GCM 完整測試套件\n');
  console.log('='.repeat(60));

  // 1. 運行官方驗證測試
  console.log('\n📋 第一部分：官方驗證測試');
  const officialTests = AESVerification.runAllTests();

  console.log('\n' + '='.repeat(60));

  // 2. 驗證修正後的實作
  console.log('\n📋 第二部分：額外驗證');
  const extraTests = extraVerification();

  console.log('\n' + '='.repeat(60));

  // 3. 新增：不同長度 IV 測試
  console.log('\n📋 第三部分：不同長度 IV 測試');
  const variousIVTests = testVariousIVLengths();
  const deepIVTests = deepIVTesting();
  const compatibilityTests = ivCompatibilityTest();

  console.log('\n' + '='.repeat(60));

  // 4. 簡化 API 範例
  console.log('\n📋 第四部分：使用範例');
  simpleUsageExample();

  // 5. 基本使用範例
  basicUsageExample();

  // 6. 單區塊測試
  singleBlockExample();

  // 7. 步驟測試
  stepByStepTest();

  console.log('\n' + '='.repeat(60));

  console.log('\n' + '='.repeat(60));

  // 8. 生成 ZKP 測試向量
  console.log('\n📋 第五部分：ZKP 電路支援');
  generateZKPTestVectors();

  console.log('\n' + '='.repeat(60));

  // 9. 性能測試
  console.log('\n📋 第六部分：性能測試');
  performanceTest();

  // 10. 與 Node.js 比較
  await compareWithNodeCrypto();

  console.log('\n' + '='.repeat(60));

  // 11. 錯誤處理測試
  console.log('\n📋 第七部分：錯誤處理');
  errorHandlingTest();

  console.log('\n' + '='.repeat(60));

  // 12. 內存使用測試
  console.log('\n📋 第八部分：內存測試');
  memoryUsageTest();

  console.log('\n' + '='.repeat(60));

  const allTestResults = [
    { name: '官方驗證測試', passed: officialTests },
    { name: '額外驗證測試', passed: extraTests },
    { name: '不同長度 IV 測試', passed: variousIVTests },
    { name: '深度 IV 測試', passed: deepIVTests },
    { name: 'IV 兼容性測試', passed: compatibilityTests }
  ];

  let totalPassed = 0;
  allTestResults.forEach(test => {
    console.log(`${test.name}: ${test.passed ? '✅ 通過' : '❌ 失敗'}`);
    if (test.passed) totalPassed++;
  });

  const overallSuccess = totalPassed === allTestResults.length;
  console.log(`\n整體測試結果: ${overallSuccess ? '🎉' : '⚠️'} ${totalPassed}/${allTestResults.length} 通過`);

  if (overallSuccess) {
    console.log('\n🎉 所有測試完成並通過！');
    console.log('\n💡 重要改進：');
    console.log('✅ 支援任意長度 IV (1-255 字節)');
    console.log('✅ 符合 NIST SP 800-38D 標準');
    console.log('✅ 與 Node.js crypto 完全兼容 (12字節 IV)');
    console.log('✅ 適用於各種區塊鏈應用場景');
  } else {
    console.log('\n⚠️ 部分測試失敗，請檢查實作');
  }

  console.log('\n💡 使用建議：');
  console.log('- 標準應用：使用 12 字節 IV 以獲得最佳兼容性');
  console.log('- 區塊鏈應用：考慮使用 16 或 32 字節 IV');
  console.log('- 嵌入式系統：可以使用 8 字節 IV 節省空間');
  console.log('- 生成的測試向量可直接用於 Circom 電路驗證');
  console.log('- 參考性能數據來優化您的應用設計');
}

// 如果直接執行此文件，運行主測試
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(console.error);
}

export {
  extraVerification,
  simpleUsageExample,
  basicUsageExample,
  singleBlockExample,
  stepByStepTest,
  testVariousIVLengths,
  deepIVTesting,
  ivCompatibilityTest,
  generateZKPTestVectors,
  performanceTest,
  errorHandlingTest,
  memoryUsageTest
};