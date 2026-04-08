// 101ParserClass.js
// DL/T634.5101-2002 规约解析器
//
// 链路层：FT1.2帧格式
//   固定帧长：10H C A1 A2 CS 16H          (6字节)
//   可变帧长：68H L L 68H C A1 A2 [ASDU] CS 16H
//
// 与104规约的关键差异：
//   [D-01] 链路层完全不同，需要先剥除FT1.2帧头/帧尾，再解析ASDU
//   [D-02] 信息对象地址(IOA)为2字节，104为3字节
//   [D-03] 链路层含控制域C（PRM/FCB/FCV/ACD/DFC/FC）和地址域A（2字节链路地址）
//   [D-04] 新增 TI=104 测试命令，TI=105 复位进程命令
//   [D-05] TI=210 私有扩展文件服务（与104共用相同ASDU结构）
//   [D-06] ASDU结构（TI/VSQ/COT/公共地址/信息对象）与104完全相同，复用104的ASDU解析逻辑

'use strict';
const Buffer = require('buffer').Buffer;

// ── 常量表 ───────────────────────────────────────────────────────────────────

const DOW_MAP   = ['', '一', '二', '三', '四', '五', '六', '日'];
const DP_STATE  = { 0: '中间态', 1: '分', 2: '合', 3: '故障' };
const QOC_MAP   = { 0: '无附加定义', 1: '短脉冲', 2: '长脉冲', 3: '持续输出' };
const COT_NAME  = {
    1: 'per/cyc', 2: 'back', 3: 'spont', 4: 'init', 5: 'req',
    6: 'act', 7: 'actcon', 8: 'deact', 9: 'deactcon', 10: 'actterm',
    13: 'file', 20: 'introgen', 37: 'reqcogen',
    44: '未知TI', 45: '未知COT', 46: '未知公共地址', 47: '未知IOA',
    48: '软压板状态错', 49: '时间戳错', 50: '数字签名错',
};

// 链路功能码
const FC_NAME_DOWN = {
    0: '复位远方链路', 1: '复位用户进程', 2: '链路测试', 3: '发送/确认用户数据',
    4: '发送/无回答用户数据', 9: '请求链路状态', 10: '请求1级用户数据', 11: '请求2级用户数据',
};
const FC_NAME_UP = {
    0: '认可(ACK)', 1: '否定认可(NACK)', 8: '以用户数据响应', 9: '无所请求的用户数据',
    11: '链路状态/访问请求',
};

// ── 主类 ─────────────────────────────────────────────────────────────────────
class Parser101 {

    // ========== 工具函数（与104共用逻辑）==========

    static hexStringToBuffer(hex) {
        if (typeof hex !== 'string') return hex;
        const clean = hex.replace(/\s+/g, '');
        if (clean.length % 2 !== 0) throw new Error('Invalid hex string length');
        return Buffer.from(clean, 'hex');
    }

    /** CP56Time2a（7字节）解析 */
    static parseCP56Time2a(buf, offset) {
        if (buf.length < offset + 7) throw new Error('Insufficient buffer for CP56Time2a');
        const msRaw    = buf.readUInt16LE(offset);
        const minByte  = buf.readUInt8(offset + 2);
        const hourByte = buf.readUInt8(offset + 3);
        const dayByte  = buf.readUInt8(offset + 4);
        const monByte  = buf.readUInt8(offset + 5);
        const yearByte = buf.readUInt8(offset + 6);
        const ms   = msRaw % 1000;
        const sec  = Math.floor(msRaw / 1000);
        const min  = minByte & 0x3F;
        const hour = hourByte & 0x1F;
        const dow  = (hourByte >> 5) & 0x07;
        const day  = dayByte & 0x1F;
        const month= monByte & 0x0F;
        const year = (yearByte & 0x7F) + 2000;
        const pad2 = n => String(n).padStart(2, '0');
        const pad3 = n => String(n).padStart(3, '0');
        const dowStr = dow >= 1 && dow <= 7 ? `(周${DOW_MAP[dow]})` : '';
        return `${year}-${pad2(month)}-${pad2(day)} ${pad2(hour)}:${pad2(min)}:${pad2(sec)}.${pad3(ms)}${dowStr}`;
    }

    static _readUInt32LE(buf, off) { return buf.readUInt32LE(off); }
    static _sum8(buf) { let sum = 0; for (const b of buf) sum = (sum + b) & 0xFF; return sum; }
    static _resultDesc(code, map) { return map[code] ?? `未知(${code})`; }
    static _readAscii(buf, offset, len) { return buf.slice(offset, offset + len).toString('ascii'); }

    /** TLV值解析 */
    static parseTLVValue(tag, dataBuf) {
        const tagMap = {
            1:'布尔', 43:'小整形', 32:'无符号小整形', 33:'短整形', 45:'无符号短整形',
            2:'整形', 35:'无符号整形', 36:'长整形', 37:'无符号长整形',
            38:'单精度浮点', 39:'双精度浮点', 4:'字符串/八位位串',
        };
        const type = tagMap[tag] || '未知';
        const len  = dataBuf.length;
        try {
            switch (type) {
                case '布尔':          return { tag: type, value: dataBuf.readUInt8(0) !== 0 };
                case '小整形':        return { tag: type, value: dataBuf.readInt8(0) };
                case '无符号小整形':  return { tag: type, value: dataBuf.readUInt8(0) };
                case '短整形':        return { tag: type, value: len >= 2 ? dataBuf.readInt16LE(0) : 0 };
                case '无符号短整形':  return { tag: type, value: len >= 2 ? dataBuf.readUInt16LE(0) : 0 };
                case '整形':          return { tag: type, value: len >= 4 ? dataBuf.readInt32LE(0) : 0 };
                case '无符号整形':    return { tag: type, value: len >= 4 ? dataBuf.readUInt32LE(0) : 0 };
                case '长整形':        return { tag: type, value: len >= 8 ? dataBuf.readBigInt64LE(0) : 0n };
                case '无符号长整形':  return { tag: type, value: len >= 8 ? dataBuf.readBigUInt64LE(0) : 0n };
                case '单精度浮点':    return { tag: type, value: len >= 4 ? dataBuf.readFloatLE(0) : 0 };
                case '双精度浮点':    return { tag: type, value: len >= 8 ? dataBuf.readDoubleLE(0) : 0 };
                case '字符串/八位位串': {
                    const str = dataBuf.toString('ascii');
                    const ni  = str.indexOf('\0');
                    return ni >= 0
                        ? { tag: '字符串', value: str.substring(0, ni) }
                        : { tag: '八位位串', value: dataBuf.toString('hex') };
                }
                default: return { tag: '未知', value: dataBuf.toString('hex') };
            }
        } catch { return { tag: '未知', value: dataBuf.toString('hex') }; }
    }

    /** 参数特征标识PI */
    static parsePI(pi) {
        return {
            raw : `0x${pi.toString(16).padStart(2, '0')}`,
            cont: (pi & 0x01) !== 0 ? '有后续' : '无后续',
            cr  : (pi & 0x40) !== 0 ? '取消预置' : '不取消预置',
            se  : (pi & 0x80) !== 0 ? '预置' : '固化',
        };
    }

    // ========== 链路层解析 [D-01] ==========

    /**
     * 解析控制域C（1字节）
     * 非平衡模式：
     *   启动方向(PRM=1): D7=RES D6=PRM D5=FCB D4=FCV D3..D0=FC
     *   从动方向(PRM=0): D7=RES D6=PRM D5=ACD D4=DFC D3..D0=FC
     * 平衡模式：
     *   启动方向(PRM=1): D7=DIR D6=PRM D5=FCB D4=FCV D3..D0=FC
     *   从动方向(PRM=0): D7=DIR D6=PRM D5=RES D4=DFC D3..D0=FC
     */
    static parseControlByte(c) {
        const prm = (c >> 6) & 0x01;
        const dir = (c >> 7) & 0x01;   // 平衡模式下有效，非平衡模式此位为RES
        const fc  = c & 0x0F;
        let result = { raw: `0x${c.toString(16).padStart(2,'0')}`, prm, dir, fc };
        if (prm === 1) {
            // 启动方向（主站→终端）
            result.fcb = (c >> 5) & 0x01;
            result.fcv = (c >> 4) & 0x01;
            result.fcName = FC_NAME_DOWN[fc] ?? `FC=${fc}`;
            result.direction = dir ? '↑上行(平衡)' : '↓下行';
        } else {
            // 从动方向（终端→主站）
            result.acd = (c >> 5) & 0x01;  // ACD：有1级数据待访问
            result.dfc = (c >> 4) & 0x01;  // DFC：数据流控，缓冲区满
            result.fcName = FC_NAME_UP[fc] ?? `FC=${fc}`;
            result.direction = dir ? '↓下行(平衡)' : '↑上行';
        }
        return result;
    }

    /**
     * 识别帧类型：
     *   固定帧: 10H ... 16H (6字节)
     *   可变帧: 68H L L 68H C A1 A2 [ASDU] CS 16H
     * 返回: { frameType, ctrl, linkAddr, asdu, cs, valid, error }
     */
    static parseFrame(buf) {
        if (!Buffer.isBuffer(buf)) buf = Parser101.hexStringToBuffer(buf);

        if (buf.length < 1) return { frameType: 'error', error: 'Empty buffer' };

        // ── 固定帧长格式 ──────────────────────────────────────────────
        if (buf[0] === 0x10) {
            if (buf.length < 6) return { frameType: 'error', error: '固定帧长度不足6字节' };
            if (buf[buf.length - 1] !== 0x16) return { frameType: 'error', error: '固定帧结束字符不是16H' };
            const c        = buf[1];
            const linkAddr = buf.readUInt16LE(2);
            const cs       = buf[4];
            const csCalc   = (c + buf[2] + buf[3]) & 0xFF;
            const ctrl     = Parser101.parseControlByte(c);
            return {
                frameType: 'fixed',
                ctrl, linkAddr,
                cs, csCalc,
                csValid  : cs === csCalc,
                asdu     : null,          // 固定帧无ASDU
            };
        }

        // ── 可变帧长格式 ──────────────────────────────────────────────
        if (buf[0] === 0x68) {
            if (buf.length < 6) return { frameType: 'error', error: '可变帧最小长度不足' };
            const L1 = buf[1];
            const L2 = buf[2];
            if (L1 !== L2) return { frameType: 'error', error: `可变帧两个L不一致: L1=${L1} L2=${L2}` };
            if (buf[3] !== 0x68) return { frameType: 'error', error: '可变帧第4字节不是68H' };
            const totalLen = L1 + 6;  // 68 L L 68 + L字节内容(C+A+ASDU) + CS + 16
            if (buf.length < totalLen) return { frameType: 'error', error: `可变帧实际长度${buf.length}不足，需要${totalLen}` };
            if (buf[totalLen - 1] !== 0x16) return { frameType: 'error', error: '可变帧结束字符不是16H' };

            const c        = buf[4];
            const linkAddr = buf.readUInt16LE(5);   // A：2字节链路地址 [D-03]
            const cs       = buf[totalLen - 2];

            // CS = (C + A1 + A2 + ASDU各字节) mod 256
            let csCalc = 0;
            for (let i = 4; i < totalLen - 2; i++) csCalc = (csCalc + buf[i]) & 0xFF;

            const asduBuf = buf.slice(7, totalLen - 2);  // 从ASDU开始到CS之前
            const ctrl    = Parser101.parseControlByte(c);
            return {
                frameType: 'variable',
                ctrl, linkAddr,
                cs, csCalc,
                csValid  : cs === csCalc,
                asduBuf,
            };
        }

        return { frameType: 'error', error: `未知帧起始字节: 0x${buf[0].toString(16)}` };
    }

    // ========== ASDU层解析（[D-02] IOA为2字节）==========

    static _dpState(val) {
        return DP_STATE[val & 0x03] ?? String(val & 0x03);
    }

    // ── 遥信 TI=1/3 [D-02] IOA=2字节 ──
    static parseYX(ti, asdu, offset, cot, addr, sq, num) {
        const results    = [];
        const isSingle   = (ti === 1);

        if (sq === 0) {
            for (let i = 0; i < num; i++) {
                if (asdu.length - offset < 3) throw new Error('YX item too short');
                const objAddr = asdu.readUInt16LE(offset); offset += 2;  // [D-02] 2字节IOA
                const val     = asdu.readUInt8(offset);    offset += 1;
                const state   = isSingle
                    ? ((val & 0x01) ? '合(1)' : '分(0)')
                    : Parser101._dpState(val);
                results.push({ slot: i + 1, addr: objAddr, addrDec: objAddr, state, qds: val >> (isSingle ? 1 : 2) });
            }
        } else {
            if (asdu.length - offset < 2) throw new Error('YX base addr missing');
            const baseAddr = asdu.readUInt16LE(offset); offset += 2;  // [D-02]
            for (let j = 0; j < num; j++) {
                if (asdu.length - offset < 1) throw new Error('YX seq item too short');
                const val   = asdu.readUInt8(offset); offset += 1;
                const state = isSingle ? ((val & 0x01) ? '合(1)' : '分(0)') : Parser101._dpState(val);
                results.push({ slot: j + 1, addr: baseAddr + j, addrDec: baseAddr + j, state });
            }
        }
        return { type: 'yx', data: results };
    }

    // ── 带时标遥信 TI=30/31 [D-02] ──
    static parseSOE(ti, asdu, offset, cot, addr, sq, num) {
        const results  = [];
        const isSingle = (ti === 30);

        if (sq === 0) {
            for (let i = 0; i < num; i++) {
                if (asdu.length - offset < 10) throw new Error('SOE item too short');
                const objAddr = asdu.readUInt16LE(offset); offset += 2;  // [D-02]
                const val     = asdu.readUInt8(offset);    offset += 1;
                const timeStr = Parser101.parseCP56Time2a(asdu, offset); offset += 7;
                const state   = isSingle ? ((val & 0x01) ? '合(1)' : '分(0)') : Parser101._dpState(val);
                results.push({ slot: i + 1, addr: objAddr, addrDec: objAddr, state, time: timeStr });
            }
        } else {
            if (asdu.length - offset < 2) throw new Error('SOE base addr missing');
            const baseAddr = asdu.readUInt16LE(offset); offset += 2;  // [D-02]
            for (let j = 0; j < num; j++) {
                if (asdu.length - offset < 8) throw new Error('SOE seq item too short');
                const val     = asdu.readUInt8(offset);    offset += 1;
                const timeStr = Parser101.parseCP56Time2a(asdu, offset); offset += 7;
                const state   = isSingle ? ((val & 0x01) ? '合(1)' : '分(0)') : Parser101._dpState(val);
                results.push({ slot: j + 1, addr: baseAddr + j, addrDec: baseAddr + j, state, time: timeStr });
            }
        }
        return { type: 'soe', data: results };
    }

    // ── 遥测 TI=9/11/13 [D-02] ──
    static parseYC(ti, asdu, offset, cot, addr, sq, num) {
        const results   = [];
        const isFloat   = (ti === 13);
        const isNorm    = (ti === 9);
        const valueSize = isFloat ? 4 : 2;

        const readValue = (buf, off) => {
            if (isFloat) return buf.readFloatLE(off);
            const raw = buf.readInt16LE(off);
            if (isNorm) return { raw, eng: parseFloat((raw / 32767.0).toFixed(6)) };
            return raw;
        };
        const typeLabel = isFloat ? 'float(短浮点)' : isNorm ? 'NVA(归一化)' : 'SVA(标度化)';

        if (sq === 0) {
            for (let i = 0; i < num; i++) {
                if (asdu.length - offset < 2 + valueSize + 1) throw new Error('YC item too short');
                const objAddr = asdu.readUInt16LE(offset); offset += 2;  // [D-02]
                const val     = readValue(asdu, offset);   offset += valueSize;
                const qds     = asdu.readUInt8(offset);    offset += 1;
                results.push({ slot: i + 1, addr: objAddr, value: val, valueType: typeLabel, qds });
            }
        } else {
            if (asdu.length - offset < 2) throw new Error('YC base addr missing');
            const baseAddr = asdu.readUInt16LE(offset); offset += 2;  // [D-02]
            for (let j = 0; j < num; j++) {
                if (asdu.length - offset < valueSize + 1) throw new Error('YC seq item too short');
                const val = readValue(asdu, offset); offset += valueSize;
                const qds = asdu.readUInt8(offset);  offset += 1;
                results.push({ slot: j + 1, addr: baseAddr + j, value: val, valueType: typeLabel, qds });
            }
        }
        return { type: 'yc', data: results };
    }

    // ── 遥控 TI=45/46 [D-02] ──
    static parseRemoteControl(ti, asdu, offset, cot, addr, sq, num, pn) {
        const results  = [];
        const isSingle = (ti === 45);
        const ptType   = isSingle ? 'single(单点)' : 'double(双点)';

        const parseOne = (objAddr, rawByte) => {
            const s_e    = (rawByte >> 7) & 0x01;
            const qoc    = (rawByte >> 2) & 0x1F;
            const qocStr = QOC_MAP[qoc] ?? `QOC=${qoc}`;
            let cmdState;
            if (isSingle) {
                cmdState = (rawByte & 0x01) ? '控合' : '控分';
            } else {
                const dcs = rawByte & 0x03;
                cmdState  = dcs === 1 ? '控分' : dcs === 2 ? '控合' : '不确定';
            }
            let operation;
            switch (cot & 0x3F) {
                case 6:  operation = s_e ? '选择' : '执行';       break;
                case 7:  operation = s_e ? '选择确认' : '执行确认'; break;
                case 8:  operation = '撤销';                        break;
                case 9:  operation = '撤销确认';                    break;
                case 10: operation = '执行结束';                    break;
                default: operation = `COT=${cot}`;
            }
            if (pn) operation += '(否定)';
            const cause     = cot & 0x3F;
            const isSuccess = (cause === 7 || cause === 9 || cause === 10) && !pn;
            const isFail    = ((cause >= 44 && cause <= 50) || pn);
            return {
                addr: `0x${objAddr.toString(16).padStart(4, '0')}`,  // [D-02] 4位hex
                state: cmdState, operation, qoc: qocStr,
                return: isSuccess ? 'success' : isFail ? 'failed' : '',
                pointType: ptType,
            };
        };

        if (sq === 0) {
            for (let i = 0; i < num; i++) {
                if (asdu.length - offset < 3) throw new Error('Control item too short');
                const objAddr = asdu.readUInt16LE(offset); offset += 2;  // [D-02]
                const raw     = asdu.readUInt8(offset);    offset += 1;
                results.push({ slot: i + 1, ...parseOne(objAddr, raw) });
            }
        } else {
            if (asdu.length - offset < 2) throw new Error('Control base addr missing');
            const baseAddr = asdu.readUInt16LE(offset); offset += 2;  // [D-02]
            for (let j = 0; j < num; j++) {
                const raw = asdu.readUInt8(offset); offset += 1;
                results.push({ slot: j + 1, ...parseOne(baseAddr + j, raw) });
            }
        }
        return { type: 'control', data: results };
    }

    // ── 总召唤 TI=100 [D-02] IOA=2字节 ──
    static parseTotalCall(asdu, offset, cot, addr) {
        if (asdu.length - offset < 3) throw new Error('Total call too short');
        offset += 2;  // [D-02] 跳过2字节IOA（固定=0）
        const qoi     = asdu.readUInt8(offset);
        const isTotal = (qoi === 20);
        return { type: 'total_call', command: isTotal ? 'total' : 'group', group: isTotal ? undefined : qoi, cot, addr };
    }

    // ── 初始化结束 TI=70 [D-02] ──
    static parseInitEnd(asdu, offset, cot, addr) {
        if (asdu.length - offset < 3) return { type: 'init_end', cot, addr, coi: null };
        offset += 2;  // [D-02]
        const coi    = asdu.readUInt8(offset);
        const coiMap = { 0: '当地电源合上', 1: '当地手动复位', 2: '远方复位' };
        return { type: 'init_end', cot, addr, coi, coiDesc: coiMap[coi] ?? `COI=${coi}` };
    }

    // ── 电能量召唤 TI=101 [D-02] ──
    static parseEnergyCall(asdu, offset, cot, addr) {
        if (asdu.length - offset < 3) return { type: 'energy_call', cot, addr, qcc: null };
        offset += 2;  // [D-02]
        const qcc = asdu.readUInt8(offset);
        return { type: 'energy_call', cot, addr, qcc, qccDesc: qcc === 5 ? '总的请求电能量' : `QCC=${qcc}` };
    }

    // ── 时钟同步/读取 TI=103 [D-02] ──
    static parseClockSync(asdu, offset, cot, addr) {
        if (asdu.length - offset < 2) return { type: 'clock_sync', cot, addr, time: null };
        offset += 2;  // [D-02]
        let time = null;
        if (asdu.length - offset >= 7) time = Parser101.parseCP56Time2a(asdu, offset);
        const cause = cot & 0x3F;
        const desc  = cause === 6 ? '时钟同步命令' : cause === 7 ? '时钟同步确认' : cause === 5 ? '时钟读取' : `COT=${cot}`;
        return { type: 'clock_sync', cot, addr, time, desc };
    }

    // ── [D-04] 测试命令 TI=104 ──
    static parseTestCmd(asdu, offset, cot, addr) {
        if (asdu.length - offset < 4) return { type: 'test_cmd', cot, addr, fbp: null };
        offset += 2;  // [D-02] IOA=0
        const fbp = asdu.readUInt16LE(offset);
        const cause = cot & 0x3F;
        const desc  = cause === 6 ? '测试命令' : cause === 7 ? '测试命令确认' : `COT=${cot}`;
        return {
            type: 'test_cmd', cot, addr,
            fbp, fbpHex: `0x${fbp.toString(16).padStart(4,'0')}`,
            fbpValid: fbp === 0x55AA,
            desc,
        };
    }

    // ── [D-04] 复位进程命令 TI=105 ──
    static parseResetProcess(asdu, offset, cot, addr) {
        if (asdu.length - offset < 3) return { type: 'reset_process', cot, addr, qrp: null };
        offset += 2;  // [D-02]
        const qrp = asdu.readUInt8(offset);
        const cause = cot & 0x3F;
        const desc  = cause === 6 ? '复位进程命令' : cause === 7 ? '复位进程确认' : `COT=${cot}`;
        return { type: 'reset_process', cot, addr, qrp, qrpDesc: qrp === 1 ? '进程的总复位' : `QRP=${qrp}`, desc };
    }

    // ── 电能量 TI=206/207 [D-02] ──
    static parseEnergy(ti, asdu, offset, cot, addr, sq, num) {
        const results  = [];
        const hasTime  = (ti === 207);
        const itemSize = 4 + 1 + (hasTime ? 7 : 0);

        if (sq === 0) {
            for (let i = 0; i < num; i++) {
                if (asdu.length - offset < 2 + itemSize) break;
                const objAddr = asdu.readUInt16LE(offset); offset += 2;  // [D-02]
                const value   = asdu.readFloatLE(offset);  offset += 4;
                const qds     = asdu.readUInt8(offset);    offset += 1;
                let time = null;
                if (hasTime && asdu.length - offset >= 7) { time = Parser101.parseCP56Time2a(asdu, offset); offset += 7; }
                results.push({ slot: i + 1, addr: objAddr, value, qds, time });
            }
        } else {
            if (asdu.length - offset < 2) throw new Error('Energy base addr missing');
            const baseAddr = asdu.readUInt16LE(offset); offset += 2;  // [D-02]
            for (let j = 0; j < num; j++) {
                if (asdu.length - offset < itemSize) break;
                const value = asdu.readFloatLE(offset); offset += 4;
                const qds   = asdu.readUInt8(offset);  offset += 1;
                let time = null;
                if (hasTime && asdu.length - offset >= 7) { time = Parser101.parseCP56Time2a(asdu, offset); offset += 7; }
                results.push({ slot: j + 1, addr: baseAddr + j, value, qds, time });
            }
        }
        return { type: 'energy', hasTime, data: results };
    }

    // ── 故障事件 TI=42 [D-02] IOA=2字节，遥信地址2字节，遥测地址2字节 ──
    static parseFault(asdu, offset, cot, addr) {
        const result = { type: 'fault', cot, addr, yx: [], yc: [] };
        try {
            if (asdu.length - offset < 1) return result;
            const yxCount = asdu.readUInt8(offset); offset += 1;

            // IOA (2字节) + 故障时刻时标CP56Time2a (7字节) -- 根据规约7.5格式
            // 遥信：类型(1)+点号(2)+值(1)+时标(7) = 11字节/条
            for (let i = 0; i < yxCount; i++) {
                if (asdu.length - offset < 11) break;
                const yxType  = asdu.readUInt8(offset);                    offset += 1;
                const yxPoint = asdu.readUInt16LE(offset);                 offset += 2;  // [D-02] 2字节
                const yxVal   = asdu.readUInt8(offset);                    offset += 1;
                const yxTime  = Parser101.parseCP56Time2a(asdu, offset);   offset += 7;
                let state;
                if (yxType === 1 || yxType === 0x1e) {
                    state = (yxVal & 0x01) ? '合(1)' : '分(0)';
                } else if (yxType === 3 || yxType === 0x1f) {
                    state = Parser101._dpState(yxVal);
                } else {
                    state = `0x${yxVal.toString(16)}`;
                }
                result.yx.push({
                    type: yxType, typeHex: `0x${yxType.toString(16).padStart(2,'0')}`,
                    point: yxPoint, pointHex: `0x${yxPoint.toString(16).padStart(4,'0')}`,
                    state, time: yxTime, stateHex: `0x${yxVal.toString(16).padStart(2,'0')}`,
                });
            }

            // 保留字节+遥测个数+遥测类型
            if (asdu.length - offset < 3) return result;
            offset += 1;  // 保留字节
            const ycCount = asdu.readUInt8(offset); offset += 1;
            const ycType  = asdu.readUInt8(offset); offset += 1;
            result.ycCount   = ycCount;
            result.ycType    = ycType;
            result.ycTypeHex = `0x${ycType.toString(16).padStart(2,'0')}`;

            const valueSize = (ycType === 9 || ycType === 11) ? 2 : 4;
            const isNorm    = (ycType === 9);

            for (let i = 0; i < ycCount; i++) {
                if (asdu.length - offset < 2 + valueSize) break;  // [D-02] 2字节地址
                const lo = asdu.readUInt8(offset), hi = asdu.readUInt8(offset + 1); offset += 2;
                const ycAddr = (hi << 8) | lo;
                let raw, eng;
                if (valueSize === 4) {
                    eng = asdu.readFloatLE(offset);
                } else {
                    raw = asdu.readInt16LE(offset);
                    eng = isNorm ? parseFloat((raw / 32767.0).toFixed(6)) : raw;
                }
                offset += valueSize;
                const valueTypeMap = { 0x0d: 'float', 0x09: 'NVA(归一化)', 0x0b: 'SVA(标度化)' };
                result.yc.push({
                    addr: ycAddr, hexAddr: `0x${ycAddr.toString(16).padStart(4,'0')}`,
                    value: eng, rawValue: raw,
                    valueType: valueTypeMap[ycType] ?? `type=0x${ycType.toString(16)}`,
                });
            }
            result.description = `故障事件: ${result.yx.length}个遥信, ${result.yc.length}个遥测`;
        } catch (e) { result.error = e.message; }
        return result;
    }

    // ── 参数读写 TI=200~203 [D-02] IOA=2字节 ──
    static parseParamCommand(ti, asdu, offset, cot, addr, sq, num) {
        const results = [];
        const cause   = cot & 0x3F;

        if (ti === 200) {
            // 切换定值区：IOA(2) + SN(2)
            if (asdu.length - offset < 4) throw new Error('Missing IOA/SN (TI=200)');
            offset += 2;  // [D-02]
            const sn   = asdu.readUInt16LE(offset);
            const opMap = { 6: '切换请求', 7: '切换确认', 8: '切换撤销', 9: '切换撤销确认' };
            results.push({ type: 'Para_switch', operation: opMap[cause] ?? `COT=${cot}`, sn });
        }

        else if (ti === 201) {
            // 读定值区号：IOA(2) [+ SN1(2)+SN2(2)+SN3(2) 仅响应]
            if (asdu.length - offset < 2) throw new Error('Missing IOA (TI=201)');
            const objAddr = asdu.readUInt16LE(offset); offset += 2;  // [D-02]
            if (cause === 7 && asdu.length - offset >= 6) {
                const current = asdu.readUInt16LE(offset); offset += 2;
                const min     = asdu.readUInt16LE(offset); offset += 2;
                const max     = asdu.readUInt16LE(offset); offset += 2;
                results.push({ type: 'SNNum', operation: '读区号响应', current, min, max });
            } else {
                const opMap = { 6: '读区号请求', 8: '读区号撤销', 9: '读区号撤销确认' };
                results.push({ type: 'SNNum', operation: opMap[cause] ?? `COT=${cot}`,
                    addr: `0x${objAddr.toString(16).padStart(4,'0')}` });
            }
        }

        else if (ti === 202) {
            // 读参数和定值：SN(2) [+ PI(1) + N×(地址(2)+Tag(1)+Len(1)+Value)]
            if (asdu.length - offset < 2) throw new Error('Missing SN (TI=202)');
            const sn = asdu.readUInt16LE(offset); offset += 2;

            if (cause === 6) {
                const addrs = [];
                for (let i = 0; i < num; i++) {
                    if (asdu.length - offset < 2) break;
                    const a = asdu.readUInt16LE(offset); offset += 2;  // [D-02]
                    addrs.push(`0x${a.toString(16).padStart(4,'0')}`);
                }
                results.push({ type: 'Para_read', operation: '读请求', sn, addrs });
            } else if (cause === 7) {
                if (asdu.length - offset < 1) {
                    results.push({ type: 'Para_read', operation: '读响应(数据不足)', sn });
                } else {
                    const pi      = asdu.readUInt8(offset); offset += 1;
                    const piFlags = Parser101.parsePI(pi);
                    let isFirst = true;
                    while (offset + 4 <= asdu.length) {   // addr(2)+tag(1)+len(1)
                        const a   = asdu.readUInt16LE(offset); offset += 2;  // [D-02]
                        const tag = asdu.readUInt8(offset);    offset += 1;
                        const len = asdu.readUInt8(offset);    offset += 1;
                        if (asdu.length - offset < len) break;
                        const vBuf  = asdu.slice(offset, offset + len); offset += len;
                        const parsed = Parser101.parseTLVValue(tag, vBuf);
                        results.push({
                            type: 'Para_read', operation: '读响应', sn,
                            addr: `0x${a.toString(16).padStart(4,'0')}`,
                            tag: parsed.tag, value: parsed.value,
                            pi: isFirst ? pi : null, piFlags: isFirst ? piFlags : null,
                        });
                        isFirst = false;
                    }
                    if (!results.length) results.push({ type: 'Para_read', operation: '读响应(空)', sn, pi, piFlags });
                }
            } else {
                const opMap = { 8: '读撤销', 9: '读撤销确认' };
                results.push({ type: 'Para_read', operation: opMap[cause] ?? `COT=${cot}`, sn });
            }
        }

        else if (ti === 203) {
            // 写参数和定值：SN(2) + PI(1) + N×(地址(2)+Tag(1)+Len(1)+Value)
            if (asdu.length - offset < 2) throw new Error('Missing SN (TI=203)');
            const sn = asdu.readUInt16LE(offset); offset += 2;

            if (cause === 6) {
                if (asdu.length - offset < 1) {
                    results.push({ type: 'Para_write', operation: '写预置(PI缺失)', sn });
                } else {
                    const pi      = asdu.readUInt8(offset); offset += 1;
                    const piFlags = Parser101.parsePI(pi);
                    for (let i = 0; i < num; i++) {
                        if (asdu.length - offset < 4) break;
                        const a   = asdu.readUInt16LE(offset); offset += 2;  // [D-02]
                        const tag = asdu.readUInt8(offset);    offset += 1;
                        const len = asdu.readUInt8(offset);    offset += 1;
                        const vBuf = asdu.length - offset >= len ? asdu.slice(offset, offset + len) : asdu.slice(offset);
                        offset += Math.min(len, asdu.length - offset);
                        const parsed = Parser101.parseTLVValue(tag, vBuf);
                        results.push({
                            type: 'Para_write', operation: '写预置', sn, pi, piFlags,
                            addr: `0x${a.toString(16).padStart(4,'0')}`,
                            tag: parsed.tag, value: parsed.value,
                        });
                    }
                }
            } else if (cause === 7) {
                let pi = null, piFlags = null;
                if (asdu.length - offset >= 1) { pi = asdu.readUInt8(offset); piFlags = Parser101.parsePI(pi); offset += 1; }
                const values = [];
                while (offset + 4 <= asdu.length) {
                    const a   = asdu.readUInt16LE(offset); offset += 2;  // [D-02]
                    const tag = asdu.readUInt8(offset);    offset += 1;
                    const len = asdu.readUInt8(offset);    offset += 1;
                    if (asdu.length - offset < len) break;
                    const vBuf  = asdu.slice(offset, offset + len); offset += len;
                    const parsed = Parser101.parseTLVValue(tag, vBuf);
                    values.push({ addr: `0x${a.toString(16).padStart(4,'0')}`, tag: parsed.tag, value: parsed.value });
                }
                results.push({ type: 'Para_write', operation: values.length ? '写确认(带回显)' : '写确认', sn, pi, piFlags, values });
            } else {
                const opMap = { 8: '撤销', 9: '撤销确认', 10: '激活终止' };
                let pi = null, piFlags = null;
                if (asdu.length - offset >= 1) { pi = asdu.readUInt8(offset); piFlags = Parser101.parsePI(pi); offset += 1; }
                results.push({ type: 'Para_write', operation: opMap[cause] ?? `COT=${cot}`, sn, pi, piFlags });
            }
        }

        return { type: 'param', data: results };
    }

    // ── 私有文件目录服务 TI=210 [D-05] ──
    // 结构同104 TI=210，IOA=2字节
    static parsePrivateFileDir(asdu, offset, cot, addr) {
        const subTypeMap   = { 0x01: '按条数查询', 0x02: '按时间范围查询', 0x03: '按序号查询' };
        const fileTypeMap  = { 0x00: '无时间过滤', 0x01: '按时间段过滤' };
        const fileNameTypeMap = {
            'HISTORY/COMTRADE': '录波文件', 'COMTRADE': '录波文件',
            'HISTORY/SOE': 'SOE事件记录', 'SOE': 'SOE事件记录',
            'HISTORY/CTRL': '遥控操作记录', 'CTRL': '遥控操作记录',
            'HISTORY/EXTREME': '极值记录', 'EXTREME': '极值记录',
            'HISTORY/FIXED': '定点记录', 'FIXED': '定点记录',
            'HISTORY/LOG': '日志记录', 'LOG': '日志记录',
        };
        if (asdu.length - offset < 2 + 6) throw new Error('TI=0xD2 too short');
        offset += 2;  // [D-02] skip IOA

        const subType   = asdu.readUInt8(offset); offset += 1;
        const fileCount = asdu.readUInt8(offset); offset += 1;
        offset += 4;  // reserved

        const files = [];
        for (let i = 0; i < fileCount; i++) {
            if (asdu.length - offset < 1) break;
            const nLen = asdu.readUInt8(offset); offset += 1;
            if (asdu.length - offset < nLen + 1 + 14) break;
            const name     = asdu.slice(offset, offset + nLen).toString('ascii'); offset += nLen;
            const fileType = asdu.readUInt8(offset); offset += 1;
            const startTime= Parser101.parseCP56Time2a(asdu, offset); offset += 7;
            const endTime  = Parser101.parseCP56Time2a(asdu, offset); offset += 7;
            files.push({
                name, fileType,
                fileTypeName: fileTypeMap[fileType] ?? `类型0x${fileType.toString(16)}`,
                fileCategory: fileNameTypeMap[name.toUpperCase()] ?? name,
                startTime, endTime,
            });
        }
        const cause = cot & 0x3F;
        const isRequest = (cause === 5 || cause === 6);
        const allCat = [...new Set(files.map(f => f.fileCategory))].join('、') || '文件';
        return {
            type: 'file_service', service: 'PRIV_DIR',
            desc: isRequest ? `召唤文件目录请求(${allCat})` : `文件目录响应(${files.length}个文件)`,
            subType, subTypeName: subTypeMap[subType] ?? `SubType=0x${subType.toString(16)}`,
            fileCount, files, cot, addr,
        };
    }

    static parseFileService210(asdu, offset, cot, addr) {
        const packetTypeMap = { 1:'备用', 2:'文件传输', 3:'备用', 4:'备用' };
        const opMap = {
            1:'文件目录召唤',
            2:'目录召唤确认',
            3:'读文件激活',
            4:'读文件激活确认',
            5:'读文件数据传输',
            6:'读文件数据传输确认',
            7:'写文件激活',
            8:'写文件激活确认',
            9:'写文件数据传输',
            10:'写文件数据传输确认',
        };
        const dirResultMap = { 0:'成功', 1:'失败' };
        const readActivateResultMap = { 0:'成功', 1:'失败' };
        const writeActivateResultMap = { 0:'成功', 1:'未知错误', 2:'文件名不支持', 3:'长度超范围' };
        const transferConfirmMap = {
            0:'成功/无后续',
            1:'有后续/未知错误',
            2:'校验和错误',
            3:'文件长度不对应',
            4:'文件ID与激活ID不一致',
        };

        if (asdu.length - offset < 4) throw new Error('TI=210 file service too short');
        const infoObjAddr = asdu.readUInt16LE(offset) | (asdu.readUInt8(offset + 2) << 16); offset += 3;
        const packetType = asdu.readUInt8(offset); offset += 1;
        const packetTypeName = packetTypeMap[packetType] ?? `未知(${packetType})`;
        const base = {
            type: 'file_service',
            service: 'F_FR_NA_1',
            tiName: 'F_FR_NA_1',
            infoObjAddr,
            packetType,
            packetTypeName,
            cot,
            addr,
        };

        if (packetType !== 2) {
            return {
                ...base,
                desc: `文件服务附加包类型${packetTypeName}`,
                rawHex: asdu.slice(offset).toString('hex').toUpperCase(),
            };
        }
        if (asdu.length - offset < 1) throw new Error('TI=210 missing operation code');

        const op = asdu.readUInt8(offset); offset += 1;
        const opName = opMap[op] ?? `未知操作(${op})`;
        const result = { ...base, op, opName, desc: opName };

        switch (op) {
            case 1: {
                if (asdu.length - offset < 4 + 1) throw new Error('目录召唤报文长度不足');
                const directoryId = Parser101._readUInt32LE(asdu, offset); offset += 4;
                const dirNameLen = asdu.readUInt8(offset); offset += 1;
                if (asdu.length - offset < dirNameLen + 1 + 7 + 7) throw new Error('目录召唤目录名/时间长度不足');
                const directoryName = Parser101._readAscii(asdu, offset, dirNameLen); offset += dirNameLen;
                const queryFlag = asdu.readUInt8(offset); offset += 1;
                const queryFlagName = queryFlag === 0 ? '目录下所有文件' : queryFlag === 1 ? '目录下满足搜索时间段的文件' : `未知(${queryFlag})`;
                const startTime = Parser101.parseCP56Time2a(asdu, offset); offset += 7;
                const endTime = Parser101.parseCP56Time2a(asdu, offset); offset += 7;
                Object.assign(result, { directoryId, directoryName, dirNameLen, queryFlag, queryFlagName, startTime, endTime });
                break;
            }
            case 2: {
                if (asdu.length - offset < 1 + 4 + 1 + 1) throw new Error('目录召唤确认长度不足');
                const resultCode = asdu.readUInt8(offset); offset += 1;
                const directoryId = Parser101._readUInt32LE(asdu, offset); offset += 4;
                const hasMore = asdu.readUInt8(offset); offset += 1;
                const fileCount = asdu.readUInt8(offset); offset += 1;
                const entries = [];
                for (let i = 0; i < fileCount; i++) {
                    if (asdu.length - offset < 1) throw new Error('目录文件名长度缺失');
                    const nameLen = asdu.readUInt8(offset); offset += 1;
                    if (asdu.length - offset < nameLen + 1 + 4 + 7) throw new Error('目录文件项长度不足');
                    const fileName = Parser101._readAscii(asdu, offset, nameLen); offset += nameLen;
                    const fileAttr = asdu.readUInt8(offset); offset += 1;
                    const fileSize = Parser101._readUInt32LE(asdu, offset); offset += 4;
                    const fileTime = Parser101.parseCP56Time2a(asdu, offset); offset += 7;
                    entries.push({ fileName, fileAttr, fileSize, fileTime });
                }
                Object.assign(result, {
                    resultCode,
                    resultDesc: Parser101._resultDesc(resultCode, dirResultMap),
                    directoryId,
                    hasMore,
                    hasMoreDesc: hasMore ? '有后续' : '无后续',
                    fileCount,
                    entries,
                });
                break;
            }
            case 3: {
                if (asdu.length - offset < 1) throw new Error('读文件激活长度不足');
                const fileNameLen = asdu.readUInt8(offset); offset += 1;
                if (asdu.length - offset < fileNameLen) throw new Error('读文件激活文件名长度不足');
                const fileName = Parser101._readAscii(asdu, offset, fileNameLen); offset += fileNameLen;
                Object.assign(result, { fileNameLen, fileName });
                break;
            }
            case 4: {
                if (asdu.length - offset < 1 + 1) throw new Error('读文件激活确认长度不足');
                const resultCode = asdu.readUInt8(offset); offset += 1;
                const fileNameLen = asdu.readUInt8(offset); offset += 1;
                if (asdu.length - offset < fileNameLen + 4 + 4) throw new Error('读文件激活确认内容长度不足');
                const fileName = Parser101._readAscii(asdu, offset, fileNameLen); offset += fileNameLen;
                const fileId = Parser101._readUInt32LE(asdu, offset); offset += 4;
                const fileSize = Parser101._readUInt32LE(asdu, offset); offset += 4;
                Object.assign(result, {
                    resultCode,
                    resultDesc: Parser101._resultDesc(resultCode, readActivateResultMap),
                    fileNameLen,
                    fileName,
                    fileId,
                    fileSize,
                });
                break;
            }
            case 5:
            case 9: {
                if (asdu.length - offset < 4 + 4 + 1 + 1) throw new Error('文件数据传输长度不足');
                const fileId = Parser101._readUInt32LE(asdu, offset); offset += 4;
                const segmentNo = Parser101._readUInt32LE(asdu, offset); offset += 4;
                const hasMore = asdu.readUInt8(offset); offset += 1;
                const dataLen = asdu.length - offset - 1;
                if (dataLen < 0) throw new Error('文件数据传输校验码缺失');
                const fileData = asdu.slice(offset, offset + dataLen); offset += dataLen;
                const checksum = asdu.readUInt8(offset); offset += 1;
                const checksumCalc = Parser101._sum8(fileData);
                Object.assign(result, {
                    fileId,
                    segmentNo,
                    hasMore,
                    hasMoreDesc: hasMore ? '有后续' : '无后续',
                    dataLen,
                    dataHex: fileData.toString('hex').toUpperCase().replace(/(.{64})/g, '$1\n').trim(),
                    checksum,
                    checksumHex: `0x${checksum.toString(16).padStart(2, '0')}`,
                    checksumCalc,
                    checksumCalcHex: `0x${checksumCalc.toString(16).padStart(2, '0')}`,
                    checksumValid: checksumCalc === checksum,
                });
                break;
            }
            case 6:
            case 10: {
                if (asdu.length - offset < 4 + 4 + 1) throw new Error('文件数据传输确认长度不足');
                const fileId = Parser101._readUInt32LE(asdu, offset); offset += 4;
                const segmentNo = Parser101._readUInt32LE(asdu, offset); offset += 4;
                const resultCode = asdu.readUInt8(offset); offset += 1;
                const resultMap = op === 6 ? { 0:'无后续', 1:'有后续' } : transferConfirmMap;
                Object.assign(result, {
                    fileId,
                    segmentNo,
                    resultCode,
                    resultDesc: Parser101._resultDesc(resultCode, resultMap),
                });
                break;
            }
            case 7: {
                if (asdu.length - offset < 1) throw new Error('写文件激活长度不足');
                const fileNameLen = asdu.readUInt8(offset); offset += 1;
                if (asdu.length - offset < fileNameLen + 4 + 4) throw new Error('写文件激活内容长度不足');
                const fileName = Parser101._readAscii(asdu, offset, fileNameLen); offset += fileNameLen;
                const fileId = Parser101._readUInt32LE(asdu, offset); offset += 4;
                const fileSize = Parser101._readUInt32LE(asdu, offset); offset += 4;
                Object.assign(result, { fileNameLen, fileName, fileId, fileSize });
                break;
            }
            case 8: {
                if (asdu.length - offset < 1 + 1) throw new Error('写文件激活确认长度不足');
                const resultCode = asdu.readUInt8(offset); offset += 1;
                const fileNameLen = asdu.readUInt8(offset); offset += 1;
                if (asdu.length - offset < fileNameLen + 4 + 4) throw new Error('写文件激活确认内容长度不足');
                const fileName = Parser101._readAscii(asdu, offset, fileNameLen); offset += fileNameLen;
                const fileId = Parser101._readUInt32LE(asdu, offset); offset += 4;
                const fileSize = Parser101._readUInt32LE(asdu, offset); offset += 4;
                Object.assign(result, {
                    resultCode,
                    resultDesc: Parser101._resultDesc(resultCode, writeActivateResultMap),
                    fileNameLen,
                    fileName,
                    fileId,
                    fileSize,
                });
                break;
            }
            default:
                Object.assign(result, { rawHex: asdu.slice(offset).toString('hex').toUpperCase() });
                break;
        }

        return result;
    }

    // ========== ASDU主解析（IOA=2字节版本）==========
    static parseASdu(asduBuf, linkAddr, ctrl) {
        if (asduBuf.length < 6) return { type: 'error', error: 'ASDU too short' };

        let offset  = 0;
        const ti    = asduBuf[offset++];
        const vsq   = asduBuf[offset++];
        const cotRaw= asduBuf.readUInt16LE(offset); offset += 2;
        const addr  = asduBuf.readUInt16LE(offset); offset += 2;  // 公共地址2字节

        const cot   = cotRaw & 0x3F;
        const pn    = (cotRaw >> 6) & 0x01;
        const test  = (cotRaw >> 7) & 0x01;
        const cotDesc = COT_NAME[cot] ?? `cot=${cot}`;
        const sq    = (vsq >> 7) & 0x01;
        const num   = vsq & 0x7F;

        // 附加链路层信息
        const linkInfo = {
            linkAddr,
            fc     : ctrl?.fc,
            fcName : ctrl?.fcName,
            prm    : ctrl?.prm,
            acd    : ctrl?.acd,
            dfc    : ctrl?.dfc,
            direction: ctrl?.direction,
        };

        try {
            let result;
            switch (ti) {
                case 1: case 3:
                    result = Parser101.parseYX(ti, asduBuf, offset, cotRaw, addr, sq, num); break;
                case 9: case 11: case 13:
                    result = Parser101.parseYC(ti, asduBuf, offset, cotRaw, addr, sq, num); break;
                case 30: case 31:
                    result = Parser101.parseSOE(ti, asduBuf, offset, cotRaw, addr, sq, num); break;
                case 42:
                    result = Parser101.parseFault(asduBuf, offset, cotRaw, addr); break;
                case 45: case 46:
                    result = Parser101.parseRemoteControl(ti, asduBuf, offset, cotRaw, addr, sq, num, pn); break;
                case 70:
                    result = Parser101.parseInitEnd(asduBuf, offset, cotRaw, addr); break;
                case 100:
                    result = Parser101.parseTotalCall(asduBuf, offset, cotRaw, addr); break;
                case 101:
                    result = Parser101.parseEnergyCall(asduBuf, offset, cotRaw, addr); break;
                case 103:
                    result = Parser101.parseClockSync(asduBuf, offset, cotRaw, addr); break;
                case 104:  // [D-04]
                    result = Parser101.parseTestCmd(asduBuf, offset, cotRaw, addr); break;
                case 105:  // [D-04]
                    result = Parser101.parseResetProcess(asduBuf, offset, cotRaw, addr); break;
                case 200: case 201: case 202: case 203:
                    result = Parser101.parseParamCommand(ti, asduBuf, offset, cotRaw, addr, sq, num); break;
                case 206: case 207:
                    result = Parser101.parseEnergy(ti, asduBuf, offset, cotRaw, addr, sq, num); break;
                case 210:
                    result = Parser101.parseFileService210(asduBuf, offset, cotRaw, addr); break;
                default:
                    result = { type: 'unknown', ti, tiHex: `0x${ti.toString(16).padStart(2,'0')}`, cot: cotRaw, cotDesc, addr };
            }
            return { ...result, pn, test, cotDesc, linkInfo, protocol: '101' };
        } catch (e) {
            return { type: 'error', error: e.message, ti, cot: cotRaw, linkInfo, protocol: '101' };
        }
    }

    // ========== 对外主解析入口 ==========

    /**
     * 解析一帧101报文（十六进制字符串或Buffer）
     * 返回完整解析结果，包含链路层信息
     */
    static parseFrame101(input) {
        try {
            const buf  = Buffer.isBuffer(input) ? input : Parser101.hexStringToBuffer(input);
            const frame = Parser101.parseFrame(buf);

            if (frame.frameType === 'error') return { ...frame, protocol: '101' };

            // 固定帧：无ASDU，只返回链路层信息
            if (frame.frameType === 'fixed') {
                return {
                    type    : 'link_frame',
                    protocol: '101',
                    frameType: 'fixed',
                    linkAddr : frame.linkAddr,
                    ctrl     : frame.ctrl,
                    fcName   : frame.ctrl.fcName,
                    prm      : frame.ctrl.prm,
                    acd      : frame.ctrl.acd,
                    dfc      : frame.ctrl.dfc,
                    fc       : frame.ctrl.fc,
                    direction: frame.ctrl.direction,
                    csValid  : frame.csValid,
                };
            }

            // 可变帧：解析ASDU
            if (!frame.asduBuf || frame.asduBuf.length === 0) {
                return {
                    type    : 'link_frame',
                    protocol: '101',
                    frameType: 'variable_noasdu',
                    linkAddr : frame.linkAddr,
                    ctrl     : frame.ctrl,
                    csValid  : frame.csValid,
                };
            }

            const asduResult = Parser101.parseASdu(frame.asduBuf, frame.linkAddr, frame.ctrl);
            return {
                ...asduResult,
                frameType: 'variable',
                csValid  : frame.csValid,
                protocol : '101',
            };
        } catch (e) {
            return { type: 'error', error: e.message, protocol: '101' };
        }
    }

    /** 批量解析接口，与104 parser.parse() 签名一致 */
    parse(input) {
        const toBuffer = item => {
            if (Buffer.isBuffer(item)) return item;
            if (typeof item === 'string') return Parser101.hexStringToBuffer(item);
            throw new Error('Invalid input type');
        };
        const buffers = Array.isArray(input) ? input.map(toBuffer) : [toBuffer(input)];
        return buffers.map(buf => Parser101.parseFrame101(buf));
    }
}

module.exports = Parser101;
