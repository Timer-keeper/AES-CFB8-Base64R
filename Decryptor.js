function unshiftBase64R(base64Str) {
    // URL安全型Base64还原（按需修改替换规则）
    return base64Str.replace(/-/g, '+').replace(/_/g, '/');
}

function decrypt(encryptedMessage) {
    // 1. Base64R反向替换
    const base64Standard = unshiftBase64R(encryptedMessage);
    
    // 2. Base64解码
    const rawData = CryptoJS.enc.Base64.parse(base64Standard);
    const bytes = new Uint8Array(rawData.words.buffer);
    
    // 3. 分离IV（前16字节）
    if (bytes.length < 16) throw new Error("Invalid encrypted message");
    const iv = bytes.slice(0, 16);
    const ciphertext = bytes.slice(16);
    
    // 4. AES解密配置
    const key = CryptoJS.enc.Utf8.parse("YOUR_SECRET_KEY"); // 替换为实际密钥
    const decrypted = CryptoJS.AES.decrypt(
        { ciphertext: CryptoJS.lib.WordArray.create(ciphertext) },
        key,
        {
            iv: CryptoJS.lib.WordArray.create(iv),
            mode: CryptoJS.mode.CFB,
            padding: CryptoJS.pad.NoPadding,
            blockSize: 8 // CFB8模式
        }
    );
    
    return decrypted.toString(CryptoJS.enc.Utf8);
}