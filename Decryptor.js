class JavaRandom {
    constructor(seed) {
        this.seed = (seed ^ 0x5DEECE66Dn) & ((1n << 48n) - 1n);
    }
    
    next(bits) {
        this.seed = (this.seed * 0x5DEECE66Dn + 0xBn) & ((1n << 48n) - 1n);
        return Number(this.seed >> (48n - BigInt(bits)));
    }
    
    nextBytes(bytes) {
        for (let i = 0; i < bytes.length; i++) {
            if (i % 4 === 0) {
                const rnd = this.next(32);
                bytes[i] = rnd >>> 24;
                if (++i >= bytes.length) break;
                bytes[i] = (rnd >>> 16) & 0xFF;
                if (++i >= bytes.length) break;
                bytes[i] = (rnd >>> 8) & 0xFF;
                if (++i >= bytes.length) break;
                bytes[i] = rnd & 0xFF;
            }
        }
    }
}

// 完整Base64R反向映射
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

function decrypt(encryptedMessage, keyStr) {
    // Decode the Base64 encoded key
    const decodedKey = CryptoJS.enc.Base64.parse(keyStr);

    // 1. Base64R处理
    const base64Standard = unshiftBase64R(encryptedMessage);
    
    // 2. Base64解码
    const rawData = CryptoJS.enc.Base64.parse(base64Standard);
    const bytes = new Uint8Array(rawData.words.buffer);
    
    // 3. 提取nonce（前8字节）
    if (bytes.length < 8) throw new Error("消息格式错误");
    const nonceBytes = bytes.slice(0, 8);
    const encryptedBytes = bytes.slice(8);
    
    // 4. 生成IV
    const nonce = bytesToLong(nonceBytes);
    const iv = javaRandomBytes(nonce, 16);

    // 5. 准备解密参数
    const key = CryptoJS.lib.WordArray.create(decodedKey.words);
    const ciphertext = CryptoJS.lib.WordArray.create(encryptedBytes);
    
    // 6. 执行解密
    const decrypted = CryptoJS.AES.decrypt(
        { ciphertext: ciphertext },
        key,
        {
            iv: CryptoJS.lib.WordArray.create(iv),
            mode: CryptoJS.mode.CFB,
            padding: CryptoJS.pad.NoPadding,
            blockSize: 8 // CFB8模式
        }
    );
    
    // 7. 返回UTF8字符串
    return decrypted.toString(CryptoJS.enc.Utf8);
}