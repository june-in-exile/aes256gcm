/**
 * GCM 調試測試工具
 * 分步驗證 AES-256-GCM 的各個組件
 */

import { createCipheriv } from 'crypto';
import { AES256 } from './aes256gcm';

// 測試工具類
export class GCMDebugger {

    // 1. 測試 CTR 模式的計數器生成
    static testCounterGeneration() {
        console.log('\n=== CTR 計數器生成測試 ===');

        const iv = Buffer.from('YjgZJzfIXjAYvwt/', 'base64'); // 12 bytes
        console.log('IV (hex):', iv.toString('hex'));
        console.log('IV 長度:', iv.length);

        // 正確的計數器初始化
        const counter = Buffer.alloc(16);
        iv.copy(counter, 0, 0, 12);
        counter.writeUInt32BE(1, 12); // GCM 標準：從 1 開始

        console.log('初始計數器 (hex):', counter.toString('hex'));
        console.log('初始計數器 (base64):', counter.toString('base64'));

        // 生成後續幾個計數器
        for (let i = 0; i < 3; i++) {
            console.log(`計數器 ${i + 1}:`, counter.toString('hex'));

            // 遞增計數器（只遞增最後 4 個字節）
            let carry = 1;
            for (let j = 15; j >= 12 && carry; j--) {
                const sum = counter[j] + carry;
                counter[j] = sum & 0xff;
                carry = sum >> 8;
            }
        }
    }

    // 2. 測試你的 CTR 模式 vs Node.js
    static async testCTRModeOnly() {
        console.log('\n=== CTR 模式對比測試 ===');

        const key = Buffer.from('qmpEWRQQ+w1hp6xFYkoXFUHZA8Os71XTWxDZIdNAS7o=', 'base64');
        const iv = Buffer.from('YjgZJzfIXjAYvwt/', 'base64');
        const plaintext = Buffer.from('ABCDEFGHIJKLMNOP');

        console.log('密鑰 (hex):', key.toString('hex'));
        console.log('IV (hex):', iv.toString('hex'));
        console.log('明文 (hex):', plaintext.toString('hex'));

        // 手動實作 CTR 模式
        const counter = Buffer.alloc(16);
        iv.copy(counter, 0, 0, 12);
        counter.writeUInt32BE(1, 12);

        console.log('\n手動 CTR 實作:');
        console.log('初始計數器:', counter.toString('hex'));

        // 使用你的 AES256.encryptBlock 加密計數器
        const keystream = AES256.encryptBlock(counter, key);
        console.log('密鑰流:', keystream.toString('hex'));

        // 與 Node.js crypto 對比
        const cipher = createCipheriv('aes-256-ctr', key, iv);
        const nodeCiphertext = cipher.update(plaintext);
        console.log('\nNode.js CTR 結果:', nodeCiphertext.toString('hex'));

        return { nodeCiphertext };
    }

    // 3. 測試 Hash subkey 生成
    static testHashSubkeyGeneration() {
        console.log('\n=== Hash Subkey 生成測試 ===');

        const key = Buffer.from('qmpEWRQQ+w1hp6xFYkoXFUHZA8Os71XTWxDZIdNAS7o=', 'base64');
        const zeroBlock = Buffer.alloc(16);

        console.log('零塊 (hex):', zeroBlock.toString('hex'));

        // 生成 Hash subkey: H = E_K(0^128)
        const hashKey = AES256.encryptBlock(zeroBlock, key);
        console.log('Hash subkey H (hex):', hashKey.toString('hex'));

        // 用 Node.js 驗證
        const cipher = createCipheriv('aes-256-ecb', key, null);
        cipher.setAutoPadding(false);
        const nodeHashKey = cipher.update(zeroBlock);
        console.log('Node.js Hash subkey:', nodeHashKey.toString('hex'));

        return nodeHashKey;
    }

    // 4. 簡化的 GF(2^128) 乘法測試
    static testGF128Multiplication() {
        console.log('\n=== GF(2^128) 乘法測試 ===');

        // 簡單測試案例
        const a = Buffer.from('00000000000000000000000000000001', 'hex'); // 1
        const b = Buffer.from('00000000000000000000000000000002', 'hex'); // 2

        console.log('a:', a.toString('hex'));
        console.log('b:', b.toString('hex'));

        // 實作 GF(2^128) 乘法
        const result = this.gf128Multiply(a, b);
        console.log('a × b =', result.toString('hex'));
        console.log('預期: 00000000000000000000000000000002');
    }

    // GF(2^128) 乘法實作（供參考）
    static gf128Multiply(x: Buffer, y: Buffer): Buffer {
        const result = Buffer.alloc(16);
        const v = Buffer.from(y);

        for (let i = 0; i < 128; i++) {
            const byteIndex = Math.floor(i / 8);
            const bitIndex = 7 - (i % 8);

            if ((x[byteIndex] >> bitIndex) & 1) {
                for (let j = 0; j < 16; j++) {
                    result[j] ^= v[j];
                }
            }

            // 右移 v
            let carry = 0;
            for (let j = 0; j < 16; j++) {
                const newCarry = v[j] & 1;
                v[j] = (v[j] >> 1) | (carry << 7);
                carry = newCarry;
            }

            // 如果進位，減去歸約多項式 R = 11100001 || 0^120
            if (carry) {
                v[0] ^= 0xe1;
            }
        }

        return result;
    }

    // 5. 完整的 GHASH 測試
    static testGHASH() {
        console.log('\n=== GHASH 函數測試 ===');

        const hashKey = Buffer.from('66e94bd4ef8a2c3b884cfa59ca342b2e', 'hex'); // 示例
        const data = Buffer.from('hello world', 'utf8');

        console.log('Hash key:', hashKey.toString('hex'));
        console.log('數據:', data.toString('hex'));

        // 實作 GHASH
        let result = Buffer.alloc(16);

        // 將數據按 16 字節分塊
        for (let i = 0; i < data.length; i += 16) {
            const block = Buffer.alloc(16);
            const blockData = data.subarray(i, Math.min(i + 16, data.length));
            blockData.copy(block);

            console.log(`塊 ${Math.floor(i / 16) + 1}:`, block.toString('hex'));

            // GHASH: result = (result ⊕ block) × H
            for (let j = 0; j < 16; j++) {
                result[j] ^= block[j];
            }
            console.log('XOR 後:', result.toString('hex'));

            result = this.gf128Multiply(result, hashKey);
            console.log('乘法後:', result.toString('hex'));
        }

        console.log('最終 GHASH 結果:', result.toString('hex'));
    }

    // 6. 與標準 GCM 實作對比
    static compareWithStandardGCM() {
        console.log('\n=== 與標準 GCM 對比 ===');

        const key = Buffer.from('qmpEWRQQ+w1hp6xFYkoXFUHZA8Os71XTWxDZIdNAS7o=', 'base64');
        const iv = Buffer.from('YjgZJzfIXjAYvwt/', 'base64');
        const plaintext = Buffer.from('ABCDEFGHIJKLMNOP');

        // Node.js GCM 實作
        const cipher = createCipheriv('aes-256-gcm', key, iv);
        const ciphertext = cipher.update(plaintext);
        cipher.final();
        const authTag = cipher.getAuthTag();

        console.log('標準 GCM 結果:');
        console.log('密文:', ciphertext.toString('hex'));
        console.log('認證標籤:', authTag.toString('hex'));

        // 這裡你可以對比你的實作結果
        console.log('\n你的實作結果:');
        console.log('密文: [將你的結果放在這裡]');
        console.log('認證標籤: [將你的結果放在這裡]');
    }

    // 7. 運行所有測試
    static runAllDebugTests() {
        console.log('🔧 開始 GCM 調試測試...\n');

        this.testCounterGeneration();
        this.testCTRModeOnly();
        this.testHashSubkeyGeneration();
        this.testGF128Multiplication();
        this.testGHASH();
        this.compareWithStandardGCM();

        console.log('\n✅ 調試測試完成！');
        console.log('\n💡 建議：');
        console.log('1. 先確保你的 CTR 計數器生成正確');
        console.log('2. 實作並測試 GF(2^128) 乘法');
        console.log('3. 重新實作 GHASH 函數');
        console.log('4. 修正 GCM 整體流程');
    }
}

// 運行調試測試
if (typeof window === 'undefined') {
    GCMDebugger.runAllDebugTests();
}