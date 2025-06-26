/**
 * GCM 測試驗證工具
 * 用於驗證修正後的 AES-256-GCM 實作
 */

import { createCipheriv } from 'crypto';
import { AES256, AES256GCM, AES256GCMEasy, AESUtils, GF128 } from './aes256gcm'

// 測試工具類
export class GCMTestSuite {

    // 測試 1: 基本功能測試
    static testBasicGCM() {
        console.log('\n=== 基本 GCM 功能測試 ===');

        const plaintext = 'Hello, World!';
        const result = AES256GCMEasy.encrypt(plaintext);

        console.log('明文:', plaintext);
        console.log('密鑰:', result.key);
        console.log('IV:', result.iv);
        console.log('密文:', result.ciphertext);
        console.log('認證標籤:', result.authTag);

        return result;
    }

    // 測試 2: 與 Node.js crypto 對比（固定測試向量）
    static testAgainstNodeCrypto() {
        console.log('\n=== 與 Node.js crypto 對比測試 ===');

        // 使用固定的測試向量
        const plaintext = Buffer.from('The quick brown fox jumps over the lazy dog');
        const key = Buffer.from('2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe', 'hex');
        const iv = Buffer.from('cafebabefacedbaddecaf888', 'hex');
        const aad = Buffer.from('feedfacedeadbeeffeedfacedeadbeef', 'hex');

        console.log('測試參數:');
        console.log('明文:', plaintext.toString('utf8'));
        console.log('密鑰 (hex):', key.toString('hex'));
        console.log('IV (hex):', iv.toString('hex'));
        console.log('AAD (hex):', aad.toString('hex'));

        try {
            // Node.js crypto 結果
            const cipher = createCipheriv('aes-256-gcm', key, iv);
            cipher.setAAD(aad);
            let nodeCiphertext = cipher.update(plaintext);
            nodeCiphertext = Buffer.concat([nodeCiphertext, cipher.final()]);
            const nodeAuthTag = cipher.getAuthTag();

            console.log('\nNode.js crypto 結果:');
            console.log('密文 (hex):', nodeCiphertext.toString('hex'));
            console.log('認證標籤 (hex):', nodeAuthTag.toString('hex'));

            // 我們的實作結果
            const ourResult = AES256GCM.encrypt(plaintext, key, iv, aad);

            console.log('\n我們的實作結果:');
            console.log('密文 (hex):', ourResult.ciphertext.toString('hex'));
            console.log('認證標籤 (hex):', ourResult.tag.toString('hex'));

            // 比較結果
            const ciphertextMatch = nodeCiphertext.equals(ourResult.ciphertext);
            const authTagMatch = nodeAuthTag.equals(ourResult.tag);

            console.log('\n比較結果:');
            console.log('密文一致:', ciphertextMatch ? '✅' : '❌');
            console.log('認證標籤一致:', authTagMatch ? '✅' : '❌');

            return ciphertextMatch && authTagMatch;

        } catch (error) {
            console.error('測試過程中發生錯誤:', error);
            return false;
        }
    }

    // 測試 3: NIST 標準測試向量
    static testNISTVectors() {
        console.log('\n=== NIST 標準測試向量 ===');

        // NIST SP 800-38D 測試向量 (簡化版)
        const testCases = [
            {
                name: 'Test Case 1',
                key: '00000000000000000000000000000000000000000000000000000000000000000',
                iv: '000000000000000000000000',
                plaintext: '',
                aad: '',
                expectedCiphertext: '',
                expectedTag: '530f8afbc74536b9a963b4f1c4cb738b'
            },
            {
                name: 'Test Case 2',
                key: '00000000000000000000000000000000000000000000000000000000000000000',
                iv: '000000000000000000000000',
                plaintext: '00000000000000000000000000000000',
                aad: '',
                expectedCiphertext: 'cea7403d4d606b6e074ec5d3baf39d18',
                expectedTag: 'd0d1c8a799996bf0265b98b5d48ab919'
            }
        ];

        let allPassed = true;

        testCases.forEach((testCase, index) => {
            console.log(`\n--- ${testCase.name} ---`);

            try {
                const key = Buffer.from(testCase.key, 'hex');
                const iv = Buffer.from(testCase.iv, 'hex');
                const plaintext = Buffer.from(testCase.plaintext, 'hex');
                const aad = Buffer.from(testCase.aad, 'hex');

                const result = AES256GCM.encrypt(plaintext, key, iv, aad);

                const ciphertextMatch = result.ciphertext.toString('hex') === testCase.expectedCiphertext;
                const tagMatch = result.tag.toString('hex') === testCase.expectedTag;

                console.log('預期密文:', testCase.expectedCiphertext);
                console.log('實際密文:', result.ciphertext.toString('hex'));
                console.log('密文匹配:', ciphertextMatch ? '✅' : '❌');

                console.log('預期標籤:', testCase.expectedTag);
                console.log('實際標籤:', result.tag.toString('hex'));
                console.log('標籤匹配:', tagMatch ? '✅' : '❌');

                if (!ciphertextMatch || !tagMatch) {
                    allPassed = false;
                }

            } catch (error) {
                console.error(`${testCase.name} 執行失敗:`, error);
                allPassed = false;
            }
        });

        return allPassed;
    }

    // 測試 4: 中間步驟驗證
    static testIntermediateSteps() {
        console.log('\n=== 中間步驟驗證 ===');

        const key = Buffer.from('2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe', 'hex');
        const iv = Buffer.from('cafebabefacedbad', 'hex');

        // 測試 Hash subkey 生成
        const zeroBlock = Buffer.alloc(16);
        const hashKey = AES256.encryptBlock(zeroBlock, key);
        console.log('Hash subkey H:', hashKey.toString('hex'));

        // 測試計數器生成
        const counter = Buffer.alloc(16);
        iv.copy(counter, 0, 0, 12);
        counter.writeUInt32BE(1, 12);
        console.log('初始計數器:', counter.toString('hex'));

        // 測試 GF(2^128) 乘法
        const a = Buffer.from('00000000000000000000000000000001', 'hex');
        const b = Buffer.from('00000000000000000000000000000002', 'hex');
        const product = GF128.multiply(a, b);
        console.log('GF(2^128) 測試: 1 × 2 =', product.toString('hex'));
        console.log('預期結果: 00000000000000000000000000000002');

        // 測試更複雜的 GF 乘法
        const x = Buffer.from('0388dace60b6a392f328c2b971b2fe78', 'hex');
        const y = Buffer.from('66e94bd4ef8a2c3b884cfa59ca342b2e', 'hex');
        const complexProduct = GF128.multiply(x, y);
        console.log('複雜 GF 乘法結果:', complexProduct.toString('hex'));
    }

    // 測試 5: 邊界條件測試
    static testEdgeCases() {
        console.log('\n=== 邊界條件測試 ===');

        const key = AESUtils.randomBytes(32);
        const iv = AESUtils.randomBytes(12);

        // 空明文
        try {
            const result1 = AES256GCM.encrypt(Buffer.alloc(0), key, iv);
            console.log('空明文測試: ✅ (密文長度:', result1.ciphertext.length, ')');
        } catch (error) {
            console.log('空明文測試: ❌', String(error));
        }

        // 單字節明文
        try {
            const result2 = AES256GCM.encrypt(Buffer.from([0x42]), key, iv);
            console.log('單字節明文測試: ✅ (密文長度:', result2.ciphertext.length, ')');
        } catch (error) {
            console.log('空明文測試: ❌', String(error));
        }

        // 大明文 (多個區塊)
        try {
            const largePlaintext = Buffer.alloc(1000, 0x41); // 1000 個 'A'
            const result3 = AES256GCM.encrypt(largePlaintext, key, iv);
            console.log('大明文測試: ✅ (密文長度:', result3.ciphertext.length, ')');
        } catch (error) {
            console.log('空明文測試: ❌', String(error));
        }

        // 有 AAD 的測試
        try {
            const aad = Buffer.from('Additional Authenticated Data');
            const result4 = AES256GCM.encrypt(Buffer.from('Hello'), key, iv, aad);
            console.log('AAD 測試: ✅');
        } catch (error) {
            console.log('空明文測試: ❌', String(error));
        }
    }

    // 測試 6: 性能測試
    static performanceTest() {
        console.log('\n=== 性能測試 ===');

        const key = AESUtils.randomBytes(32);
        const iv = AESUtils.randomBytes(12);
        const plaintext = Buffer.alloc(1024, 0x41); // 1KB 數據

        const iterations = 100;

        console.log(`測試 ${iterations} 次 1KB 數據加密...`);

        const startTime = Date.now();

        for (let i = 0; i < iterations; i++) {
            AES256GCM.encrypt(plaintext, key, iv);
        }

        const endTime = Date.now();
        const totalTime = endTime - startTime;
        const avgTime = totalTime / iterations;

        console.log(`總時間: ${totalTime}ms`);
        console.log(`平均時間: ${avgTime.toFixed(2)}ms/次`);
        console.log(`吞吐量: ${(1024 * iterations / totalTime * 1000 / 1024 / 1024).toFixed(2)} MB/s`);
    }

    // 執行所有測試
    static runAllTests() {
        console.log('🧪 開始完整的 GCM 測試套件...\n');

        const results = {
            basic: false,
            crypto: false,
            nist: false,
            edge: true // 邊界測試不返回布爾值
        };

        try {
            // 基本測試
            this.testBasicGCM();
            results.basic = true;

            // 與 Node.js 對比
            results.crypto = this.testAgainstNodeCrypto();

            // NIST 測試向量
            results.nist = this.testNISTVectors();

            // 中間步驟驗證
            this.testIntermediateSteps();

            // 邊界條件
            this.testEdgeCases();

            // 性能測試
            this.performanceTest();

        } catch (error) {
            console.error('測試過程中發生錯誤:', error);
        }

        // 總結
        console.log('\n📊 測試結果總結:');
        console.log('基本功能測試:', results.basic ? '✅' : '❌');
        console.log('與 Node.js 一致性:', results.crypto ? '✅' : '❌');
        console.log('NIST 測試向量:', results.nist ? '✅' : '❌');
        console.log('邊界條件測試: 已執行');
        console.log('性能測試: 已執行');

        const overallSuccess = results.basic && results.crypto && results.nist;
        console.log('\n🎯 整體狀態:', overallSuccess ? '🎉 所有核心測試通過！' : '⚠️ 仍需調試');

        if (!overallSuccess) {
            console.log('\n🔧 調試建議:');
            if (!results.basic) console.log('- 檢查基本 GCM 流程');
            if (!results.crypto) console.log('- 對比 Node.js crypto 的中間結果');
            if (!results.nist) console.log('- 使用 NIST 測試向量調試具體步驟');
        }

        return overallSuccess;
    }
}

// 使用說明
console.log(`
🔍 GCM 測試工具使用說明:

單個測試:
- GCMTestSuite.testBasicGCM()           // 基本功能
- GCMTestSuite.testAgainstNodeCrypto()  // 與 Node.js 對比  
- GCMTestSuite.testNISTVectors()        // NIST 標準測試
- GCMTestSuite.testIntermediateSteps()  // 中間步驟驗證
- GCMTestSuite.testEdgeCases()          // 邊界條件
- GCMTestSuite.performanceTest()        // 性能測試

完整測試:
- GCMTestSuite.runAllTests()            // 執行所有測試

這個測試套件會幫助你驗證修正後的實作是否正確！
`);

// 執行測試 (如果直接運行此文件)
if (typeof process !== 'undefined' && import.meta.url === `file://${process.argv[1]}`) {
    GCMTestSuite.runAllTests();
}