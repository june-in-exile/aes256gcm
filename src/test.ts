/**
 * AES-256-GCM 使用範例和測試
 */

import {
  AES256,
  AES256GCM,
  AES256GCMEasy,
  AESUtils,
  AESVerification,
  GaloisField,
  AESTransforms
} from './aes256gcm.js';
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
  console.log('標籤 (base64):', result1.tag);

  // 使用指定密鑰
  const fixedKey = 'dGVzdEtleTEyMzQ1Njc4OTBhYmNkZWZnaGlqa2xtbm8=';
  const result2 = AES256GCMEasy.encrypt('Hello, Fixed Key!', fixedKey);
  console.log('\n使用固定密鑰加密:');
  console.log('明文:', 'Hello, Fixed Key!');
  console.log('密鑰 (base64):', result2.key);
  console.log('密文 (base64):', result2.ciphertext);

  // 單區塊加密
  const blockResult = AES256GCMEasy.encryptBlock('Test Block 16B!!', fixedKey);
  console.log('\n單區塊加密:');
  console.log('明文:', blockResult.plaintext);
  console.log('密文 (base64):', blockResult.ciphertext);

  // 生成測試向量
  const testVector = AES256GCMEasy.generateTestVector('ZKP Test Block!!');
  console.log('\n生成的測試向量:');
  console.log('測試向量:', JSON.stringify(testVector, null, 2));

  return { result1, result2, blockResult, testVector };
}
function basicUsageExample() {
  console.log('🚀 基本使用範例\n');

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
  console.log('認證標籤 (base64):', AESUtils.bytesToBase64(result.tag));

  return {
    key: AESUtils.bytesToBase64(key),
    iv: AESUtils.bytesToBase64(iv),
    plaintext,
    ciphertext: AESUtils.bytesToBase64(result.ciphertext),
    tag: AESUtils.bytesToBase64(result.tag)
  };
}

// 單區塊 AES-256 測試
function singleBlockExample() {
  console.log('\n📦 單區塊 AES-256 測試\n');

  // 使用已知測試向量 (base64 格式)
  const key = 'YD3rEBXKcb4rc67whX13gR8zLAc7YQjXLZgQowkU3/Q='; // 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
  const plaintext = 'Test AES Block!!'; // 剛好 16 字節

  console.log('密鑰 (base64):', key);
  console.log('明文:', plaintext);

  const keyBytes = AESUtils.base64ToBytes(key);
  const plaintextBytes = AESUtils.stringToBytes(plaintext);

  // 確保明文剛好 16 字節
  const paddedPlaintext = new Uint8Array(16);
  paddedPlaintext.set(plaintextBytes.slice(0, 16));

  // 單區塊加密
  const ciphertext = AES256.encryptBlock(paddedPlaintext, keyBytes);
  const result = AESUtils.bytesToBase64(ciphertext);

  console.log('密文 (base64):', result);

  // 這裡可以記錄預期結果用於後續驗證
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
      name: 'NIST Test Vector',
      key: 'YD3rEBXKcb4rc67whX13gR8zLAc7YQjXLZgQowkU3/Q=',
      plaintext: 'NIST Test Block!'
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
    const paddedPlaintext = new Uint8Array(16);
    paddedPlaintext.set(plaintextBytes.slice(0, 16));

    const ciphertext = AES256.encryptBlock(paddedPlaintext, keyBytes);
    const ciphertextBase64 = AESUtils.bytesToBase64(ciphertext);

    console.log(`// ${testCase.name}`);
    console.log(`const testVector${index + 1} = {`);
    console.log(`  key: "${testCase.key}",`);
    console.log(`  plaintext: "${testCase.plaintext}",`);
    console.log(`  expected: "${ciphertextBase64}"`);
    console.log('};\n');
  });

  // 也生成 GCM 模式的測試向量
  console.log('// GCM 模式測試向量');
  const gcmTestCases = [
    {
      name: 'GCM Simple Test',
      key: 'dGVzdEtleTEyMzQ1Njc4OTBhYmNkZWZnaGlqa2xtbm8=',
      iv: 'dGVzdEl2MTIzNA==', // 12 字節 IV
      plaintext: 'Hello GCM World!'
    },
    {
      name: 'GCM Long Message',
      key: 'bXlTZWNyZXRLZXkxMjM0NTY3ODkwYWJjZGVmZ2hpams=',
      iv: 'cmFuZG9tSXZAIyQ=',
      plaintext: 'This is a longer message for GCM testing!'
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
    console.log(`  iv: "${testCase.iv}",`);
    console.log(`  plaintext: "${testCase.plaintext}",`);
    console.log(`  expectedCiphertext: "${AESUtils.bytesToBase64(result.ciphertext)}",`);
    console.log(`  expectedTag: "${AESUtils.bytesToBase64(result.tag)}"`);
    console.log('};\n');
  });
}

// 性能測試
function performanceTest() {
  console.log('\n⚡ 性能測試\n');

  const key = AESUtils.randomBytes(32);
  const plaintext = AESUtils.randomBytes(16);

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
  const gcmPlaintext = AESUtils.randomBytes(64); // 64 字節
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

// 與 Node.js crypto 比較
async function compareWithNodeCrypto() {
  console.log('\n🔍 與 Node.js crypto 性能比較\n');

  const key = AESUtils.randomBytes(32);
  const plaintext = AESUtils.randomBytes(1024); // 1KB 數據
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
    const plaintext = AESUtils.randomBytes(16);
    AES256.encryptBlock(plaintext, wrongKey);
    console.log('❌ 應該要拋出錯誤但沒有');
  } catch (error) {
    console.log('✅ 正確捕獲密鑰長度錯誤:', (error as Error).message);
  }

  try {
    // 錯誤的明文長度
    const key = AESUtils.randomBytes(32);
    const wrongPlaintext = AESUtils.randomBytes(15); // 應該是 16 字節
    AES256.encryptBlock(wrongPlaintext, key);
    console.log('❌ 應該要拋出錯誤但沒有');
  } catch (error) {
    console.log('✅ 正確捕獲明文長度錯誤:', (error as Error).message);
  }

  try {
    // GCM 模式錯誤的密鑰長度
    const wrongKey = AESUtils.randomBytes(16);
    const plaintext = AESUtils.randomBytes(32);
    const iv = AESUtils.randomBytes(12);
    AES256GCM.encrypt(plaintext, wrongKey, iv);
    console.log('❌ 應該要拋出錯誤但沒有');
  } catch (error) {
    console.log('✅ 正確捕獲 GCM 密鑰長度錯誤:', (error as Error).message);
  }
}

// 實際使用案例演示
function realWorldExample() {
  console.log('\n🌍 實際使用案例演示\n');

  // 模擬一個需要加密的敏感數據
  const sensitiveData = {
    userId: '12345',
    email: 'user@example.com',
    balance: 1000.50,
    timestamp: Date.now()
  };

  const dataString = JSON.stringify(sensitiveData);
  const plaintext = dataString;
  const plaintextBytes = AESUtils.stringToBytes(plaintext);

  // 生成密鑰和 IV
  const key = AESUtils.randomBytes(32);
  const iv = AESUtils.randomBytes(12);

  console.log('原始數據:', dataString);
  console.log('數據大小:', plaintextBytes.length, '字節');

  // 加密
  const encrypted = AES256GCM.encrypt(plaintextBytes, key, iv);

  console.log('\n加密結果:');
  console.log('密鑰 (base64):', AESUtils.bytesToBase64(key));
  console.log('IV (base64):', AESUtils.bytesToBase64(iv));
  console.log('密文 (base64):', AESUtils.bytesToBase64(encrypted.ciphertext));
  console.log('認證標籤 (base64):', AESUtils.bytesToBase64(encrypted.tag));

  // 顯示壓縮比
  const originalSize = plaintextBytes.length;
  const encryptedSize = encrypted.ciphertext.length + encrypted.tag.length;
  console.log(`\n大小比較: 原始 ${originalSize} 字節 -> 加密 ${encryptedSize} 字節 (不含密鑰和IV)`);

  // 返回 base64 格式的結果
  return {
    key: AESUtils.bytesToBase64(key),
    iv: AESUtils.bytesToBase64(iv),
    plaintext: dataString,
    ciphertext: AESUtils.bytesToBase64(encrypted.ciphertext),
    tag: AESUtils.bytesToBase64(encrypted.tag)
  };
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
    const plaintext = AESUtils.randomBytes(16);
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

// 主測試函數
async function main() {
  console.log('🧪 AES-256-GCM 完整測試套件\n');
  console.log('='.repeat(60));

  // 1. 運行驗證測試
  console.log('\n📋 第一部分：驗證測試');
  AESVerification.runAllTests();

  console.log('\n' + '='.repeat(60));

  // 2. 簡化 API 範例
  simpleUsageExample();

  // 3. 基本使用範例
  console.log('\n📋 第二部分：使用範例');
  basicUsageExample();

  // 4. 單區塊測試
  singleBlockExample();

  // 5. 步驟測試
  stepByStepTest();

  console.log('\n' + '='.repeat(60));

  // 6. 生成 ZKP 測試向量
  console.log('\n📋 第三部分：ZKP 電路支援');
  generateZKPTestVectors();

  console.log('\n' + '='.repeat(60));

  // 7. 性能測試
  console.log('\n📋 第四部分：性能測試');
  performanceTest();

  // 8. 與 Node.js 比較
  await compareWithNodeCrypto();

  console.log('\n' + '='.repeat(60));

  // 9. 實際使用案例
  console.log('\n📋 第五部分：實際應用');
  realWorldExample();

  console.log('\n' + '='.repeat(60));

  // 10. 錯誤處理測試
  console.log('\n📋 第六部分：錯誤處理');
  errorHandlingTest();

  console.log('\n' + '='.repeat(60));

  // 11. 內存使用測試
  console.log('\n📋 第七部分：內存測試');
  memoryUsageTest();

  console.log('\n🎉 所有測試完成！');
  console.log('\n💡 提示：');
  console.log('- 使用生成的測試向量來驗證您的 Circom 電路');
  console.log('- 參考性能數據來優化電路設計');
  console.log('- 確保錯誤處理在電路中也有對應的約束');
}

// 如果直接執行此文件，運行主測試
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(console.error);
}

export {
  simpleUsageExample,
  basicUsageExample,
  singleBlockExample,
  stepByStepTest,
  generateZKPTestVectors,
  performanceTest,
  errorHandlingTest,
  realWorldExample,
  memoryUsageTest
};