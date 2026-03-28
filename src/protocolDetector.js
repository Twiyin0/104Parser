// protocolDetector.js
// 自动识别报文属于 IEC 104 还是 IEC 101
//
// 识别规则：
//   104: 首字节 68H，最后无 16H 结束字符（TCP帧，无FT1.2封装）
//   101 固定帧: 首字节 10H，共6字节，末字节 16H
//   101 可变帧: 首字节 68H，且末字节 16H，第2/3字节相同（L），第4字节 68H
//   手动标注:  行首 [101] 或 [104] 前缀强制指定协议
//
// 优先级：手动标注 > 自动识别

'use strict';
const Buffer = require('buffer').Buffer;

/**
 * @param {string} hexLine  一行十六进制字符串（可含空格，可含[101]/[104]前缀）
 * @returns {{ protocol: '104'|'101', hexData: string }}
 */
function detectProtocol(hexLine) {
    let line     = hexLine.trim();
    let protocol = null;

    // 1. 检查手动标注前缀
    const prefixMatch = line.match(/^\[(101|104)\]\s*/i);
    if (prefixMatch) {
        protocol = prefixMatch[1];
        line     = line.slice(prefixMatch[0].length).trim();
    }

    if (protocol) return { protocol, hexData: line };

    // 2. 自动识别
    const clean = line.replace(/\s+/g, '');
    if (clean.length < 2) return { protocol: '104', hexData: line };

    const firstByte = parseInt(clean.slice(0, 2), 16);
    const lastByte  = parseInt(clean.slice(-2), 16);

    // 101 固定帧: 10H 开头，16H 结尾，恰好 12 个十六进制字符（6字节）
    if (firstByte === 0x10 && lastByte === 0x16 && clean.length === 12) {
        return { protocol: '101', hexData: line };
    }

    // 101 可变帧: 68H 开头，16H 结尾，且第4字节也是 68H，且两个L字节相同
    if (firstByte === 0x68 && lastByte === 0x16 && clean.length >= 16) {
        const L1     = parseInt(clean.slice(2, 4), 16);
        const L2     = parseInt(clean.slice(4, 6), 16);
        const byte4  = parseInt(clean.slice(6, 8), 16);
        const expect = (L1 + 6) * 2; // 总字节数 = L+6，每字节2个十六进制字符
        if (L1 === L2 && byte4 === 0x68 && clean.length === expect) {
            return { protocol: '101', hexData: line };
        }
    }

    // 104 可变帧: 68H 开头，无 16H 结尾（TCP封装）
    if (firstByte === 0x68) {
        return { protocol: '104', hexData: line };
    }

    // 默认尝试104
    return { protocol: '104', hexData: line };
}

module.exports = { detectProtocol };
