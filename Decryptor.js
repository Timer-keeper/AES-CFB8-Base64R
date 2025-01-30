class JavaRandom {
    constructor(seed) {
        this.seed = (seed ^ 0x0005DEECE66Dn) & ((1n << 48n) - 1n);
    }

    next(bits) {
        this.seed = (this.seed * 0x5DEECE66Dn + 0xBn) & ((1n << 48n) - 1n);
        return Number(this.seed >> (48n - BigInt(bits)));
    }

    nextBytes(bytes) {
        let i = 0;
        while (i < bytes.length) {
            const rnd = this.next(32);
            bytes[i++] = (rnd >>> 24) & 0xFF;
            if (i >= bytes.length) break;
            bytes[i++] = (rnd >>> 16) & 0xFF;
            if (i >= bytes.length) break;
            bytes[i++] = (rnd >>> 8) & 0xFF;
            if (i >= bytes.length) break;
            bytes[i++] = rnd & 0xFF;
        }
    }
}

// Base64R反向映射表
const base64ReverseMap = {
    '!': 'A', '"': 'B', '#': 'C', '$': 'D', '%': 'E', '¼': 'F', '\'': 'G',
    '(': 'H', ')': 'I', ',': 'J', '-': 'K', '.': 'L', ':': 'M', ';': 'N',
    '<': 'O', '=': 'P', '>': 'Q', '?': 'R', '@': 'S', '[': 'T', '\\': 'U',
    ']': 'V', '^': 'W', '_': 'X', '`': 'Y', '{': 'Z', '|': 'a', '}': 'b',
    '~': 'c', '¡': 'd', '¢': 'e', '£': 'f', '¤': 'g', '¥': 'h', '¦': 'i',
    '¨': 'j', '©': 'k', 'ª': 'l', '«': 'm', '¬': 'n', '®': 'o', '¯': 'p',
    '°': 'q', '±': 'r', '²': 's', '³': 't', 'µ': 'u', '¶': 'v', '·': 'w',
    '×': 'x', '¹': 'y', 'º': 'z', '0': '0', '1': '1', '2': '2', '3': '3',
    '4': '4', '5': '5', '6': '6', '7': '7', '8': '8', '9': '9', '+': '+',
    '»': '/', '¿': '='
};

function unshiftBase64R(base64Str) {
    return Array.from(base64Str).map(c => base64ReverseMap[c] || c).join('');
}

function javaRandomBytes(nonce, length) {
    const bytes = new Uint8Array(length);
    const random = new JavaRandom(BigInt(nonce));
    random.nextBytes(bytes);
    return bytes;
}

function bytesToLong(bytes) {
    if (bytes.length !== 8) throw new Error("Invalid nonce length");
    const buffer = new DataView(bytes.buffer);
    return buffer.getBigInt64(0, false); // 大端序
}

// 新增：Uint8Array转WordArray
function uint8ArrayToWordArray(u8Array) {
    const words = [];
    for (let i = 0; i < u8Array.length; i += 4) {
        let word = 0;
        for (let j = 0; j < 4; j++) {
            word |= (u8Array[i + j] || 0) << (24 - j * 8);
        }
        words.push(word);
    }
    return CryptoJS.lib.WordArray.create(words, u8Array.length);
}

function decrypt(encryptedMessage, keyStr) {
    console.log("原始加密消息:", encryptedMessage);

    // 1. Base64R反转
    const base64Standard = unshiftBase64R(encryptedMessage);
    console.log("Base64标准字符串:", base64Standard);

    // 2. Base64解码原始数据
    const rawData = CryptoJS.enc.Base64.parse(base64Standard);
    console.log("Base64解码后的WordArray:", rawData); // 调试输出

    // 修复字节转换：手动处理WordArray的字节
    const bytes = new Uint8Array(rawData.sigBytes);
    for (let i = 0; i < rawData.sigBytes; i++) {
        bytes[i] = (rawData.words[Math.floor(i / 4)] >>> (24 - (i % 4) * 8)) & 0xFF;
    }
    console.log("解码后字节数组:", bytes);
    console.log("解码后字节长度:", bytes.length);

    // 3. 提取nonce和加密数据
    if (bytes.length < 8) throw new Error("消息格式错误");
    const nonceBytes = bytes.slice(0, 8);
    const encryptedBytes = bytes.slice(8);
    console.log("Nonce字节:", nonceBytes);
    console.log("加密数据字节:", encryptedBytes);

    // 4. 生成IV
    const nonce = bytesToLong(nonceBytes);
    console.log("Nonce值:", nonce.toString());
    const iv = javaRandomBytes(nonce, 16);
    console.log("IV字节:", iv);

    // 转换IV和加密数据为WordArray
    const ivWA = uint8ArrayToWordArray(iv);
    const ciphertext = uint8ArrayToWordArray(encryptedBytes);

    // 5. 解密参数
    const decodedKey = CryptoJS.enc.Base64.parse(keyStr); // 确保密钥解析正确
    console.log("密钥字节长度:", decodedKey.sigBytes); // 检查是否为16/24/32字节
    const key = decodedKey;

    // 6. 执行解密
    const decrypted = CryptoJS.AES.decrypt(
        { ciphertext: ciphertext },
        key,
        {
            iv: ivWA,
            mode: CryptoJS.mode.CFB,
            padding: CryptoJS.pad.NoPadding,
            segmentSize: 8
        }
    );

    // 7. 返回UTF8字符串
    return decrypted.toString(CryptoJS.enc.Utf8);
}