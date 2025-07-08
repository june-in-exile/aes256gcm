import {
    AESUtils,
    AESKeyExpansion
} from './main.js';

async function main() {
    // const key = AESUtils.randomBytes(32);
    // const keyBase64 = AESUtils.bytesToBase64(key);
    
    const keyBase64 = "gqngitQZdS6ihWF34xmxSkwN9fPhteFwvMrpDG6G5gY";

    console.log("keyBase64:", keyBase64);
    const key = AESUtils.base64ToBytes(keyBase64);

    const roundKeys = AESKeyExpansion.expandKey(key);
    const roundKeysBuffer = Buffer.concat(roundKeys);
    const roundKeysBase64 = AESUtils.bytesToBase64(roundKeysBuffer);
    console.log("roundKeysBase64:", roundKeysBase64);
}

// 如果直接執行此文件，運行主測試
if (import.meta.url === `file://${process.argv[1]}`) {
    main().catch(console.error);
  }