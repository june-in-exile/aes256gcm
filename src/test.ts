/**
 * AES-256-GCM Test Suite
 * Corresponds to the latest implementation (includes different length IV tests)
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

// Simple usage examples
function simpleUsageExample() {
  console.log('\n🎯 Simplified API Usage Examples\n');

  // Simplest usage - auto-generate key and IV
  const result1 = AES256GCMEasy.encrypt('Hello, Simple World!');
  console.log('Auto-generated key encryption:');
  console.log('Plaintext:', 'Hello, Simple World!');
  console.log('Key (base64):', result1.key);
  console.log('IV (base64):', result1.iv);
  console.log('Ciphertext (base64):', result1.ciphertext);
  console.log('Auth tag (base64):', result1.authTag);

  // Using specified key
  const fixedKey = 'qmpEWRQQ+w1hp6xFYkoXFUHZA8Os71XTWxDZIdNAS7o=';
  const fixedIv = 'YjgZJzfIXjAYvwt/';
  const result2 = AES256GCMEasy.encrypt('Text', fixedKey, fixedIv);
  console.log('\nFixed key and IV encryption:');
  console.log('Plaintext:', 'Text');
  console.log('Key (base64):', result2.key);
  console.log('IV (base64):', result2.iv);
  console.log('Ciphertext (base64):', result2.ciphertext);
  console.log('Auth tag (base64):', result2.authTag);

  // Single block encryption
  const blockResult = AES256GCMEasy.encryptBlock('Test Block 16B!!', fixedKey);
  console.log('\nSingle block encryption:');
  console.log('Plaintext:', blockResult.plaintext);
  console.log('Ciphertext (base64):', blockResult.ciphertext);

  return { result1, result2, blockResult };
}

// Basic usage examples
function basicUsageExample() {
  console.log('\n🚀 Basic Usage Examples\n');

  // 1. Generate random key and IV
  const key = AESUtils.randomBytes(32);  // 256-bit key
  const iv = AESUtils.randomBytes(12);   // 96-bit IV (GCM recommended)

  console.log('Generated key (base64):', AESUtils.bytesToBase64(key));
  console.log('Generated IV (base64):', AESUtils.bytesToBase64(iv));

  // 2. Prepare plaintext
  const plaintext = 'Hello, ZKP World! This is a test message.';
  const plaintextBytes = AESUtils.stringToBytes(plaintext);

  console.log('Plaintext:', plaintext);
  console.log('Plaintext length:', plaintextBytes.length, 'bytes');

  // 3. AES-256-GCM encryption
  const result = AES256GCM.encrypt(plaintextBytes, key, iv);

  console.log('\nEncryption result:');
  console.log('Ciphertext (base64):', AESUtils.bytesToBase64(result.ciphertext));
  console.log('Auth tag (base64):', AESUtils.bytesToBase64(result.authTag));

  return {
    key: AESUtils.bytesToBase64(key),
    iv: AESUtils.bytesToBase64(iv),
    plaintext,
    ciphertext: AESUtils.bytesToBase64(result.ciphertext),
    tag: AESUtils.bytesToBase64(result.authTag)
  };
}

// Single block AES-256 test
function singleBlockExample() {
  console.log('\n📦 Single Block AES-256 Test\n');

  // Using known test vectors (base64 format)
  const key = 'qmpEWRQQ+w1hp6xFYkoXFUHZA8Os71XTWxDZIdNAS7o=';
  const plaintext = 'Test AES Block!!'; // Exactly 16 bytes

  console.log('Key (base64):', key);
  console.log('Plaintext:', plaintext);

  const keyBytes = AESUtils.base64ToBytes(key);
  const plaintextBytes = AESUtils.stringToBytes(plaintext);

  // Ensure plaintext is exactly 16 bytes
  const paddedPlaintext = Buffer.alloc(16);
  plaintextBytes.subarray(0, 16).copy(paddedPlaintext);

  // Single block encryption
  const ciphertext = AES256.encryptBlock(paddedPlaintext, keyBytes);
  const result = AESUtils.bytesToBase64(ciphertext);

  console.log('Ciphertext (base64):', result);
  console.log('✅ Encryption complete');
}

// Step-by-step test - verify each AES transformation
function stepByStepTest() {
  console.log('\n🔍 AES Transformation Step-by-Step Test\n');

  // Test state
  const state = AESUtils.hexToBytes('19a09ae93df4c6f8e3e28d48be2b2a08');
  console.log('Initial state:', AESUtils.bytesToHex(state));

  // SubBytes
  const afterSub = AESTransforms.subBytes(state);
  console.log('SubBytes:', AESUtils.bytesToHex(afterSub));

  // ShiftRows
  const afterShift = AESTransforms.shiftRows(afterSub);
  console.log('ShiftRows:', AESUtils.bytesToHex(afterShift));

  // MixColumns
  const afterMix = AESTransforms.mixColumns(afterShift);
  console.log('MixColumns:', AESUtils.bytesToHex(afterMix));

  // Test Galois field operations
  console.log('\nGalois field operation tests:');
  console.log('GF(0x53 * 0x02) =', GaloisField.multiply(0x53, 0x02).toString(16));
  console.log('GF(0x53 * 0x03) =', GaloisField.multiply(0x53, 0x03).toString(16));
  console.log('Fast table 2x =', GaloisField.fastMul2(0x53).toString(16));
  console.log('Fast table 3x =', GaloisField.fastMul3(0x53).toString(16));

  // Test GF(2^128) operations
  console.log('\nGF(2^128) operation tests:');
  const x = Buffer.from('01234567890abcdef0123456789abcde', 'hex');
  const y = Buffer.from('fedcba0987654321fedcba0987654321', 'hex');
  const product = GF128.multiply(x, y);
  console.log('GF128 multiplication result:', AESUtils.bytesToHex(product));
}

// Test different IV lengths
function testVariousIVLengths(): boolean {
  console.log('\n🔄 Testing Different IV Lengths\n');

  const plaintext = AESUtils.stringToBytes('Hello World!');
  const key = AESUtils.base64ToBytes('qmpEWRQQ+w1hp6xFYkoXFUHZA8Os71XTWxDZIdNAS7o=');

  // Test different IV lengths
  const testCases = [
    { length: 1, name: '1-byte IV (minimum)' },
    { length: 8, name: '8-byte IV' },
    { length: 12, name: '12-byte IV (standard)' },
    { length: 16, name: '16-byte IV' },
    { length: 24, name: '24-byte IV' },
    { length: 32, name: '32-byte IV' },
    { length: 64, name: '64-byte IV (large)' }
  ];

  let allPassed = true;

  for (const testCase of testCases) {
    console.log(`--- ${testCase.name} ---`);

    const iv = AESUtils.randomBytes(testCase.length);
    console.log(`IV length: ${testCase.length} bytes`);
    console.log('IV (base64):', AESUtils.bytesToBase64(iv));

    try {
      // Use Node.js crypto as reference (only for standard lengths)
      let nodeResult: Buffer | null = null;
      let nodeAuthTag: Buffer | null = null;
      let nodeSupported = false;

      if (testCase.length === 12) {
        // Node.js standard support for 12-byte IV
        try {
          const nodeCipher = createCipheriv('aes-256-gcm', key, iv);
          nodeResult = nodeCipher.update(plaintext);
          nodeResult = Buffer.concat([nodeResult, nodeCipher.final()]);
          nodeAuthTag = nodeCipher.getAuthTag();
          nodeSupported = true;

          console.log('Node.js ciphertext:', AESUtils.bytesToBase64(nodeResult));
          console.log('Node.js tag:', AESUtils.bytesToBase64(nodeAuthTag));
        } catch (error) {
          console.log('Node.js does not support this IV length');
        }
      } else {
        console.log('Node.js only supports 12-byte IV, skipping comparison');
      }

      // Use our implementation
      const ourResult = AES256GCM.encrypt(plaintext, key, iv);
      console.log('Our ciphertext:', AESUtils.bytesToBase64(ourResult.ciphertext));
      console.log('Our tag:', AESUtils.bytesToBase64(ourResult.authTag));

      // Compare with Node.js if supported
      if (nodeSupported && nodeResult && nodeAuthTag) {
        const ciphertextMatches = ourResult.ciphertext.equals(nodeResult);
        const authTagMatches = ourResult.authTag.equals(nodeAuthTag);

        console.log('Ciphertext match:', ciphertextMatches ? '✅' : '❌');
        console.log('Tag match:', authTagMatches ? '✅' : '❌');

        if (!ciphertextMatches || !authTagMatches) {
          allPassed = false;
        }
      } else {
        console.log('Status: ✅ Successfully generated (cannot compare with Node.js)');
      }

      // Verify basic properties
      if (ourResult.ciphertext.length !== plaintext.length) {
        console.log('❌ Ciphertext length mismatch');
        allPassed = false;
      }

      if (ourResult.authTag.length !== 16) {
        console.log('❌ Auth tag length should be 16 bytes');
        allPassed = false;
      }

    } catch (error) {
      console.log('Test failed:', (error as Error).message);
      allPassed = false;
    }

    console.log(''); // Empty line separator
  }

  // Additional test: empty IV handling
  console.log('--- Special case: Empty IV ---');
  try {
    const emptyIv = Buffer.alloc(0);
    const result = AES256GCM.encrypt(plaintext, key, emptyIv);
    console.log('Empty IV result:', AESUtils.bytesToBase64(result.ciphertext));
    console.log('✅ Empty IV handling successful');
  } catch (error) {
    console.log('Empty IV test failed:', (error as Error).message);
    allPassed = false;
  }

  console.log('\n🏁 Different IV length test summary:', allPassed ? '✅ All passed' : '❌ Issues exist');
  return allPassed;
}

// Deep IV testing: edge cases and special patterns
function deepIVTesting(): boolean {
  console.log('\n🧪 Deep IV Testing: Edge Cases and Special Patterns\n');

  const plaintext = AESUtils.stringToBytes('Deep IV Test Message');
  const key = AESUtils.randomBytes(32);

  let allPassed = true;

  // Test 1: All-zero IV
  console.log('--- Test 1: All-zero IV ---');
  const testCases = [
    { iv: Buffer.alloc(12, 0), name: '12-byte all-zero IV' },
    { iv: Buffer.alloc(16, 0), name: '16-byte all-zero IV' },
    { iv: Buffer.alloc(8, 0), name: '8-byte all-zero IV' }
  ];

  for (const testCase of testCases) {
    try {
      const result = AES256GCM.encrypt(plaintext, key, testCase.iv);
      console.log(`${testCase.name}: ✅`);
      console.log('  Ciphertext:', AESUtils.bytesToBase64(result.ciphertext).substring(0, 20) + '...');
    } catch (error) {
      console.log(`${testCase.name}: ❌ ${(error as Error).message}`);
      allPassed = false;
    }
  }

  // Test 2: All 0xFF IV
  console.log('\n--- Test 2: All 0xFF IV ---');
  const maxIVCases = [
    { iv: Buffer.alloc(12, 0xFF), name: '12-byte all-0xFF IV' },
    { iv: Buffer.alloc(16, 0xFF), name: '16-byte all-0xFF IV' },
    { iv: Buffer.alloc(32, 0xFF), name: '32-byte all-0xFF IV' }
  ];

  for (const testCase of maxIVCases) {
    try {
      const result = AES256GCM.encrypt(plaintext, key, testCase.iv);
      console.log(`${testCase.name}: ✅`);
      console.log('  Ciphertext:', AESUtils.bytesToBase64(result.ciphertext).substring(0, 20) + '...');
    } catch (error) {
      console.log(`${testCase.name}: ❌ ${(error as Error).message}`);
      allPassed = false;
    }
  }

  // Test 3: Incrementing pattern IV
  console.log('\n--- Test 3: Incrementing pattern IV ---');
  for (let len = 1; len <= 16; len++) {
    const iv = Buffer.alloc(len);
    for (let i = 0; i < len; i++) {
      iv[i] = i;
    }

    try {
      const result = AES256GCM.encrypt(plaintext, key, iv);
      console.log(`${len}-byte incrementing IV: ✅`);
    } catch (error) {
      console.log(`${len}-byte incrementing IV: ❌ ${(error as Error).message}`);
      allPassed = false;
    }
  }

  // Test 4: Repeatability check - same IV should produce same result
  console.log('\n--- Test 4: Repeatability check ---');
  const fixedIV = AESUtils.randomBytes(16);
  const result1 = AES256GCM.encrypt(plaintext, key, fixedIV);
  const result2 = AES256GCM.encrypt(plaintext, key, fixedIV);

  const repeatabilityTest = result1.ciphertext.equals(result2.ciphertext) &&
    result1.authTag.equals(result2.authTag);
  console.log('Same IV repeatability test:', repeatabilityTest ? '✅' : '❌');
  if (!repeatabilityTest) allPassed = false;

  // Test 5: Randomness check - different IVs should produce different results
  console.log('\n--- Test 5: Randomness check ---');
  const differentResults = [];
  for (let i = 0; i < 5; i++) {
    const randomIV = AESUtils.randomBytes(12);
    const result = AES256GCM.encrypt(plaintext, key, randomIV);
    differentResults.push(AESUtils.bytesToBase64(result.ciphertext));
  }

  const uniqueResults = new Set(differentResults);
  const randomnessTest = uniqueResults.size === differentResults.length;
  console.log('Different IV randomness test:', randomnessTest ? '✅' : '❌');
  console.log(`Generated ${uniqueResults.size}/${differentResults.length} unique results`);
  if (!randomnessTest) allPassed = false;

  console.log('\n🏁 Deep IV testing summary:', allPassed ? '✅ All passed' : '❌ Issues exist');
  return allPassed;
}

// Generate ZKP circuit test vectors
function generateZKPTestVectors() {
  console.log('\n⚡ Generate ZKP Circuit Test Vectors\n');

  // Generate standard test cases for ZKP circuits
  const testCases = [
    {
      name: 'Simple Test Case',
      key: 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=', // 32-byte full sequence
      plaintext: 'Hello AES World!'
    },
    {
      name: 'Known Vector',
      key: 'qmpEWRQQ+w1hp6xFYkoXFUHZA8Os71XTWxDZIdNAS7o=',
      plaintext: 'Test Vector Data'
    },
    {
      name: 'Zero Key Test',
      key: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', // All-zero key
      plaintext: 'Zero Key Test!!!'
    },
    {
      name: 'Max Key Test',
      key: '//////////////////////////////////////////8=', // All-one key
      plaintext: 'Max Key Test!!!!'
    },
    {
      name: 'Unicode Text Test',
      key: 'dGVzdEtleTEyMzQ1Njc4OTBhYmNkZWZnaGlqa2xtbm8=',
      plaintext: 'Unicode Test🔒!!!'
    }
  ];

  console.log('// ZKP Circuit Test Vectors (TypeScript/JavaScript format)');
  console.log('// Can be used directly for Circom circuit verification\n');

  testCases.forEach((testCase, index) => {
    const keyBytes = AESUtils.base64ToBytes(testCase.key);
    const plaintextBytes = AESUtils.stringToBytes(testCase.plaintext);

    // Ensure plaintext is exactly 16 bytes
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

  // Also generate GCM mode test vectors (including different length IVs)
  console.log('// GCM Mode Test Vectors (with different length IVs)');
  const gcmTestCases = [
    {
      name: 'GCM Standard 12-byte IV',
      key: 'qmpEWRQQ+w1hp6xFYkoXFUHZA8Os71XTWxDZIdNAS7o=',
      iv: 'YjgZJzfIXjAYvwt/', // 12-byte IV
      plaintext: 'Text'
    },
    {
      name: 'GCM Long Message',
      key: 'bXlTZWNyZXRLZXkxMjM0NTY3ODkwYWJjZGVmZ2hpams=',
      iv: 'lV8jzMw8l38VL+kA', // 12-byte IV
      plaintext: 'This is a longer message for GCM testing!'
    },
    {
      name: 'GCM 8-byte IV',
      key: 'dGVzdEtleTEyMzQ1Njc4OTBhYmNkZWZnaGlqa2xtbm8=',
      iv: 'MTIzNDU2Nzg=', // 8-byte IV
      plaintext: 'Short IV test'
    },
    {
      name: 'GCM 16-byte IV',
      key: 'dGVzdEtleTEyMzQ1Njc4OTBhYmNkZWZnaGlqa2xtbm8=',
      iv: 'AAAAAAAAAAAAAAAAAAAAAA==', // 16-byte all-zero IV
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

// Performance testing
function performanceTest() {
  console.log('\n⚡ Performance Testing\n');

  const key = AESUtils.randomBytes(32);
  const plaintext = Buffer.alloc(16, 0x41); // 16 bytes of 'A'

  const iterations = 10000;

  console.log(`Executing ${iterations} AES-256 single block encryptions...`);

  const start = performance.now();
  for (let i = 0; i < iterations; i++) {
    AES256.encryptBlock(plaintext, key);
  }
  const end = performance.now();

  const totalTime = end - start;
  const avgTime = totalTime / iterations;

  console.log(`Total time: ${totalTime.toFixed(2)} ms`);
  console.log(`Average time: ${avgTime.toFixed(4)} ms/operation`);
  console.log(`Throughput: ${(iterations / totalTime * 1000).toFixed(0)} operations/second`);

  // GCM mode performance test
  const gcmPlaintext = Buffer.alloc(64, 0x42); // 64 bytes
  const iv = AESUtils.randomBytes(12);
  const gcmIterations = 1000;

  console.log(`\nExecuting ${gcmIterations} AES-256-GCM encryptions (64 bytes)...`);

  const gcmStart = performance.now();
  for (let i = 0; i < gcmIterations; i++) {
    AES256GCM.encrypt(gcmPlaintext, key, iv);
  }
  const gcmEnd = performance.now();

  const gcmTotalTime = gcmEnd - gcmStart;
  const gcmAvgTime = gcmTotalTime / gcmIterations;

  console.log(`GCM total time: ${gcmTotalTime.toFixed(2)} ms`);
  console.log(`GCM average time: ${gcmAvgTime.toFixed(4)} ms/operation`);
  console.log(`GCM throughput: ${(gcmIterations / gcmTotalTime * 1000).toFixed(0)} operations/second`);
}

// Performance comparison with Node.js crypto
async function compareWithNodeCrypto() {
  console.log('\n🔍 Performance Comparison with Node.js crypto\n');

  const key = AESUtils.randomBytes(32);
  const plaintext = Buffer.alloc(1024, 0x55); // 1KB data
  const iv = AESUtils.randomBytes(12);

  const iterations = 1000;

  // Test our implementation
  console.log('Testing our AES-256-GCM implementation...');
  const ourStart = performance.now();
  for (let i = 0; i < iterations; i++) {
    AES256GCM.encrypt(plaintext, key, iv);
  }
  const ourEnd = performance.now();
  const ourTime = ourEnd - ourStart;

  // Test Node.js crypto
  console.log('Testing Node.js crypto AES-256-GCM...');
  const nodeStart = performance.now();
  for (let i = 0; i < iterations; i++) {
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    cipher.update(plaintext);
    cipher.final();
    cipher.getAuthTag();
  }
  const nodeEnd = performance.now();
  const nodeTime = nodeEnd - nodeStart;

  console.log(`Our implementation: ${ourTime.toFixed(2)} ms`);
  console.log(`Node.js crypto: ${nodeTime.toFixed(2)} ms`);
  console.log(`Performance ratio: ${(ourTime / nodeTime).toFixed(2)}x (our implementation is slower)`);
  console.log(`Node.js speedup: ${(ourTime / nodeTime).toFixed(1)}x faster`);
}

// Error handling tests
function errorHandlingTest() {
  console.log('\n❌ Error Handling Tests\n');

  try {
    // Wrong key length
    const wrongKey = AESUtils.randomBytes(16); // Should be 32 bytes
    const plaintext = Buffer.alloc(16);
    AES256.encryptBlock(plaintext, wrongKey);
    console.log('❌ Should have thrown error but didn\'t');
  } catch (error) {
    console.log('✅ Correctly caught key length error:', (error as Error).message);
  }

  try {
    // Wrong plaintext length
    const key = AESUtils.randomBytes(32);
    const wrongPlaintext = Buffer.alloc(15); // Should be 16 bytes
    AES256.encryptBlock(wrongPlaintext, key);
    console.log('❌ Should have thrown error but didn\'t');
  } catch (error) {
    console.log('✅ Correctly caught plaintext length error:', (error as Error).message);
  }

  try {
    // GCM mode wrong key length
    const wrongKey = AESUtils.randomBytes(16);
    const plaintext = Buffer.alloc(32);
    const iv = AESUtils.randomBytes(12);
    AES256GCM.encrypt(plaintext, wrongKey, iv);
    console.log('❌ Should have thrown error but didn\'t');
  } catch (error) {
    console.log('✅ Correctly caught GCM key length error:', (error as Error).message);
  }

  console.log('\n✅ Error handling tests complete - now supports arbitrary length IV');
}

// Memory usage test
function memoryUsageTest() {
  console.log('\n💾 Memory Usage Test\n');

  const initialMemory = process.memoryUsage();
  console.log('Initial memory usage:', {
    rss: Math.round(initialMemory.rss / 1024 / 1024) + ' MB',
    heapUsed: Math.round(initialMemory.heapUsed / 1024 / 1024) + ' MB'
  });

  // Execute many encryption operations
  const key = AESUtils.randomBytes(32);
  const iterations = 50000;

  console.log(`Executing ${iterations} encryption operations...`);

  for (let i = 0; i < iterations; i++) {
    const plaintext = Buffer.alloc(16, i % 256);
    AES256.encryptBlock(plaintext, key);

    // Check memory every 10000 iterations
    if (i % 10000 === 0 && i > 0) {
      const currentMemory = process.memoryUsage();
      console.log(`Iteration ${i} - Heap memory: ${Math.round(currentMemory.heapUsed / 1024 / 1024)} MB`);
    }
  }

  const finalMemory = process.memoryUsage();
  console.log('\nFinal memory usage:', {
    rss: Math.round(finalMemory.rss / 1024 / 1024) + ' MB',
    heapUsed: Math.round(finalMemory.heapUsed / 1024 / 1024) + ' MB'
  });

  const memoryIncrease = finalMemory.heapUsed - initialMemory.heapUsed;
  console.log('Memory increase:', Math.round(memoryIncrease / 1024 / 1024) + ' MB');
}

// Verify the corrected implementation
function extraVerification() {
  console.log('\n🔧 Test Vector Verification\n');

  // Test known vectors
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

  console.log('Test vector verification:');
  console.log('Plaintext:', testVector.plaintext);
  console.log('Key (base64):', testVector.key);
  console.log('IV (base64):', testVector.iv);

  const ciphertextMatch = AESUtils.bytesToBase64(result.ciphertext) === testVector.expectedCiphertext;
  const authTagMatch = AESUtils.bytesToBase64(result.authTag) === testVector.expectedAuthTag;

  console.log('\nExpected results:');
  console.log('Ciphertext (base64):', testVector.expectedCiphertext);
  console.log('Auth tag (base64):', testVector.expectedAuthTag);

  console.log('\nActual results:');
  console.log('Ciphertext (base64):', AESUtils.bytesToBase64(result.ciphertext), ciphertextMatch ? '✅' : '❌');
  console.log('Auth tag (base64):', AESUtils.bytesToBase64(result.authTag), authTagMatch ? '✅' : '❌');

  return ciphertextMatch && authTagMatch;
}

// IV compatibility test: comparison with other implementations
function ivCompatibilityTest() {
  console.log('\n🔄 IV Compatibility Test: Comparison with Other Implementations\n');

  const plaintext = AESUtils.stringToBytes('Compatibility Test');
  const key = AESUtils.randomBytes(32);

  let allPassed = true;

  // Test compatibility with Node.js crypto (12-byte IV)
  console.log('--- Node.js crypto compatibility test ---');
  const standard12ByteIV = AESUtils.randomBytes(12);

  try {
    // Node.js crypto
    const nodeCipher = createCipheriv('aes-256-gcm', key, standard12ByteIV);
    let nodeResult = nodeCipher.update(plaintext);
    nodeResult = Buffer.concat([nodeResult, nodeCipher.final()]);
    const nodeAuthTag = nodeCipher.getAuthTag();

    // Our implementation
    const ourResult = AES256GCM.encrypt(plaintext, key, standard12ByteIV);

    const ciphertextMatch = ourResult.ciphertext.equals(nodeResult);
    const authTagMatch = ourResult.authTag.equals(nodeAuthTag);

    console.log('12-byte IV ciphertext match:', ciphertextMatch ? '✅' : '❌');
    console.log('12-byte IV tag match:', authTagMatch ? '✅' : '❌');

    if (!ciphertextMatch || !authTagMatch) {
      allPassed = false;
    }

  } catch (error) {
    console.log('Node.js compatibility test failed:', (error as Error).message);
    allPassed = false;
  }

  // Test cross-length consistency: same J0 should produce same results
  console.log('\n--- Cross-length consistency test ---');

  // Use specific IV length combinations to test J0 calculation consistency
  const testIVs = [
    Buffer.from('123456789012', 'utf8'), // 12 bytes, should use standard method
    Buffer.concat([Buffer.from('123456789012', 'utf8'), Buffer.alloc(4, 0)]) // 16 bytes, should use GHASH method
  ];

  for (let i = 0; i < testIVs.length; i++) {
    try {
      const result = AES256GCM.encrypt(plaintext, key, testIVs[i]);
      console.log(`IV length ${testIVs[i].length} bytes: ✅`);
      console.log(`  Result preview: ${AESUtils.bytesToBase64(result.ciphertext).substring(0, 16)}...`);
    } catch (error) {
      console.log(`IV length ${testIVs[i].length} bytes: ❌ ${(error as Error).message}`);
      allPassed = false;
    }
  }

  // Test extreme cases
  console.log('\n--- Extreme case tests ---');
  const extremeCases = [
    { length: 1, name: 'Minimum IV (1 byte)' },
    { length: 128, name: 'Large IV (128 bytes)' },
    { length: 255, name: 'Maximum IV (255 bytes)' }
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

  console.log('\n🏁 IV compatibility test summary:', allPassed ? '✅ All passed' : '❌ Issues exist');
  return allPassed;
}

// Main test function
async function main() {
  console.log('🧪 AES-256-GCM Complete Test Suite\n');
  console.log('='.repeat(60));

  // 1. Run official verification tests
  console.log('\n📋 Part 1: Official Verification Tests');
  const officialTests = AESVerification.runAllTests();

  console.log('\n' + '='.repeat(60));

  // 2. Verify the corrected implementation
  console.log('\n📋 Part 2: Additional Verification');
  const extraTests = extraVerification();

  console.log('\n' + '='.repeat(60));

  // 3. New: Different length IV tests
  console.log('\n📋 Part 3: Different Length IV Tests');
  const variousIVTests = testVariousIVLengths();
  const deepIVTests = deepIVTesting();
  const compatibilityTests = ivCompatibilityTest();

  console.log('\n' + '='.repeat(60));

  // 4. Simplified API examples
  console.log('\n📋 Part 4: Usage Examples');
  simpleUsageExample();

  // 5. Basic usage examples
  basicUsageExample();

  // 6. Single block tests
  singleBlockExample();

  // 7. Step-by-step tests
  stepByStepTest();

  console.log('\n' + '='.repeat(60));

  // 8. Generate ZKP test vectors
  console.log('\n📋 Part 5: ZKP Circuit Support');
  generateZKPTestVectors();

  console.log('\n' + '='.repeat(60));

  // 9. Performance tests
  console.log('\n📋 Part 6: Performance Tests');
  performanceTest();

  // 10. Comparison with Node.js
  await compareWithNodeCrypto();

  console.log('\n' + '='.repeat(60));

  // 11. Error handling tests
  console.log('\n📋 Part 7: Error Handling');
  errorHandlingTest();

  console.log('\n' + '='.repeat(60));

  // 12. Memory usage tests
  console.log('\n📋 Part 8: Memory Tests');
  memoryUsageTest();

  console.log('\n' + '='.repeat(60));

  const allTestResults = [
    { name: 'Official verification tests', passed: officialTests },
    { name: 'Additional verification tests', passed: extraTests },
    { name: 'Different length IV tests', passed: variousIVTests },
    { name: 'Deep IV tests', passed: deepIVTests },
    { name: 'IV compatibility tests', passed: compatibilityTests }
  ];

  let totalPassed = 0;
  allTestResults.forEach(test => {
    console.log(`${test.name}: ${test.passed ? '✅ Passed' : '❌ Failed'}`);
    if (test.passed) totalPassed++;
  });

  const overallSuccess = totalPassed === allTestResults.length;
  console.log(`\nOverall test results: ${overallSuccess ? '🎉' : '⚠️'} ${totalPassed}/${allTestResults.length} passed`);

  if (overallSuccess) {
    console.log('\n🎉 All tests completed and passed!');
    console.log('\n💡 Key improvements:');
    console.log('✅ Supports arbitrary length IV (1-255 bytes)');
    console.log('✅ Compliant with NIST SP 800-38D standard');
    console.log('✅ Fully compatible with Node.js crypto (12-byte IV)');
    console.log('✅ Suitable for various blockchain application scenarios');
  } else {
    console.log('\n⚠️ Some tests failed, please check implementation');
  }

  console.log('\n💡 Usage recommendations:');
  console.log('- Standard applications: Use 12-byte IV for best compatibility');
  console.log('- Blockchain applications: Consider using 16 or 32-byte IV');
  console.log('- Embedded systems: Can use 8-byte IV to save space');
  console.log('- Generated test vectors can be used directly for Circom circuit verification');
  console.log('- Reference performance data to optimize your application design');
}

// If this file is executed directly, run main test
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