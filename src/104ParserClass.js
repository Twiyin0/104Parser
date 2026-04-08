// 104ParserClass.js
// IEC 60870-5-104 / DL/T634.5104 规约解析器（完整修复版）
// 修复记录：
//   [FIX-01] parseTotalCall: offset 未+3导致 QOI 读到 objAddr 低字节，总召唤永远识别为分组召唤
//   [FIX-02] parseFault: 遥信结束后多跳一个不存在的"保留字节"，导致遥测偏移错乱
//   [FIX-03] parseYC: TI=9 归一化值需除以32767得到工程值(-1~+1)，原代码直接用原始整数
//   [FIX-04] parseYX/SOE: 双点状态 0/1/2/3 增加文字说明（分/合/中间/故障）
//   [FIX-05] parseCP56Time2a: 补充解析 DOW（星期）位并附加到时标字符串
//   [FIX-06] parseAPDU: 移除无效的 TI=0 容错分支；解析 COT 的 T 位和 P/N 位
//   [FIX-07] parseRemoteControl: 解析 QOC 命令限定词；拼写 "faild"->"failed"；P/N=1 时标注否定确认
//   [FIX-08] 新增 TI=70  初始化结束解析
//   [FIX-09] 新增 TI=101 电能量召唤命令解析
//   [FIX-10] 新增 TI=103 时钟同步/读取解析
//   [FIX-11] 新增 TI=206 累计量短浮点数解析
//   [FIX-12] 新增 TI=207 带时标累计量短浮点数解析
//   [FIX-13] parseParamCommand TI=202 COT=7: 修正读响应结构，统一 PI 在首位读取

'use strict';
const Buffer = require('buffer').Buffer;

// ── 常量表 ───────────────────────────────────────────────────────────────────

// DOW 星期映射
const DOW_MAP = ['', '一', '二', '三', '四', '五', '六', '日'];

// 双点状态映射
const DP_STATE = { 0: '中间态', 1: '分', 2: '合', 3: '故障' };

// QOC 命令限定词
const QOC_MAP = {
    0: '无附加定义',
    1: '短脉冲',
    2: '长脉冲',
    3: '持续输出',
};

// COT 传送原因文字
const COT_NAME = {
    1: 'per/cyc', 2: 'back', 3: 'spont', 4: 'init', 5: 'req',
    6: 'act', 7: 'actcon', 8: 'deact', 9: 'deactcon', 10: 'actterm',
    13: 'file', 20: 'introgen',
    37: 'reqcogen',
    44: '未知TI', 45: '未知COT', 46: '未知公共地址', 47: '未知IOA',
    48: '软压板状态错', 49: '时间戳错', 50: '数字签名错',
};

// ── 主类 ─────────────────────────────────────────────────────────────────────
class Parser104 {

    // ========== 工具函数 ==========

    static hexStringToBuffer(hex) {
        if (typeof hex !== 'string') return hex;
        const clean = hex.replace(/\s+/g, '');
        if (clean.length % 2 !== 0) throw new Error('Invalid hex string length');
        return Buffer.from(clean, 'hex');
    }

    /** 解析 CP56Time2a（7字节二进制时间），返回格式化字符串 + DOW */
    static parseCP56Time2a(buf, offset) {
        if (buf.length < offset + 7) throw new Error('Insufficient buffer for CP56Time2a');
        const msRaw   = buf.readUInt16LE(offset);       // ms + sec: [0..59999]
        const minByte = buf.readUInt8(offset + 2);
        const hourByte= buf.readUInt8(offset + 3);
        const dayByte = buf.readUInt8(offset + 4);
        const monByte = buf.readUInt8(offset + 5);
        const yearByte= buf.readUInt8(offset + 6);

        const ms   = msRaw % 1000;
        const sec  = Math.floor(msRaw / 1000);
        const min  = minByte & 0x3F;
        const hour = hourByte & 0x1F;
        const dow  = (hourByte >> 5) & 0x07;            // [FIX-05] 星期
        const day  = dayByte & 0x1F;
        const month= monByte & 0x0F;
        const year = (yearByte & 0x7F) + 2000;

        const pad2 = n => String(n).padStart(2, '0');
        const pad3 = n => String(n).padStart(3, '0');
        const dowStr = dow >= 1 && dow <= 7 ? `(周${DOW_MAP[dow]})` : '';

        return `${year}-${pad2(month)}-${pad2(day)} ${pad2(hour)}:${pad2(min)}:${pad2(sec)}.${pad3(ms)}${dowStr}`;
    }

    /** 解析 TLV 值（附录D） */
    static parseTLVValue(tag, dataBuf) {
        const tagMap = {
            1: '布尔', 43: '小整形', 32: '无符号小整形',
            33: '短整形', 45: '无符号短整形',
            2: '整形', 35: '无符号整形',
            36: '长整形', 37: '无符号长整形',
            38: '单精度浮点', 39: '双精度浮点',
            4: '字符串/八位位串',
        };
        const type = tagMap[tag] || '未知';
        const len  = dataBuf.length;
        try {
            switch (type) {
                case '布尔':              return { tag: type, value: dataBuf.readUInt8(0) !== 0 };
                case '小整形':            return { tag: type, value: dataBuf.readInt8(0) };
                case '无符号小整形':      return { tag: type, value: dataBuf.readUInt8(0) };
                case '短整形':            return { tag: type, value: len >= 2 ? dataBuf.readInt16LE(0) : 0 };
                case '无符号短整形':      return { tag: type, value: len >= 2 ? dataBuf.readUInt16LE(0) : 0 };
                case '整形':              return { tag: type, value: len >= 4 ? dataBuf.readInt32LE(0) : 0 };
                case '无符号整形':        return { tag: type, value: len >= 4 ? dataBuf.readUInt32LE(0) : 0 };
                case '长整形':            return { tag: type, value: len >= 8 ? dataBuf.readBigInt64LE(0) : 0n };
                case '无符号长整形':      return { tag: type, value: len >= 8 ? dataBuf.readBigUInt64LE(0) : 0n };
                case '单精度浮点':        return { tag: type, value: len >= 4 ? dataBuf.readFloatLE(0) : 0 };
                case '双精度浮点':        return { tag: type, value: len >= 8 ? dataBuf.readDoubleLE(0) : 0 };
                case '字符串/八位位串': {
                    const str = dataBuf.toString('ascii');
                    const ni  = str.indexOf('\0');
                    return ni >= 0
                        ? { tag: '字符串', value: str.substring(0, ni) }
                        : { tag: '八位位串', value: dataBuf.toString('hex') };
                }
                default: return { tag: '未知', value: dataBuf.toString('hex') };
            }
        } catch (e) {
            return { tag: '未知', value: dataBuf.toString('hex') };
        }
    }

    /** 解析参数特征标识 PI（7.9.5） */
    static parsePI(pi) {
        return {
            raw : `0x${pi.toString(16).padStart(2, '0')}`,
            cont: (pi & 0x01) !== 0 ? '有后续' : '无后续',
            cr  : (pi & 0x40) !== 0 ? '取消预置' : '不取消预置',
            se  : (pi & 0x80) !== 0 ? '预置' : '固化',
        };
    }

    // ========== 各类型解析 ==========

    // [FIX-01] 修复 QOI 读取位置
    static parseTotalCall(asdu, offset, ti, cot, addr) {
        if (asdu.length - offset < 4) throw new Error('Total call ASDU too short');
        // 信息对象地址（3字节，规定为0，跳过）
        offset += 3;                                        // [FIX-01] 必须先跳过 3 字节
        const qoi = asdu.readUInt8(offset);
        const isTotal = (qoi === 20);
        return {
            type   : 'total_call',
            command: isTotal ? 'total' : 'group',
            group  : isTotal ? undefined : qoi,
            cot, addr,
        };
    }

    // [FIX-04] 双点状态文字化
    static _dpState(val) {
        return DP_STATE[val & 0x03] ?? String(val & 0x03);
    }

    static parseYX(ti, asdu, offset, cot, addr, sq, num) {
        const results = [];
        const isSingle = (ti === 1);

        if (sq === 0) {
            for (let i = 0; i < num; i++) {
                if (asdu.length - offset < 4) throw new Error('YX item too short');
                const objAddr = asdu.readUInt16LE(offset) | (asdu.readUInt8(offset + 2) << 16); offset += 3;
                const val = asdu.readUInt8(offset); offset += 1;
                const siq = val;
                const state = isSingle
                    ? ((val & 0x01) ? '合(1)' : '分(0)')
                    : Parser104._dpState(val);
                const qds = isSingle ? (val >> 1) : (val >> 2);
                results.push({ slot: i + 1, addr: objAddr, addrDec: objAddr, state, qds, invalid: !!(qds & 0x10) });
            }
        } else {
            if (asdu.length - offset < 3) throw new Error('YX base addr missing');
            const baseAddr = asdu.readUInt16LE(offset) | (asdu.readUInt8(offset + 2) << 16); offset += 3;
            for (let j = 0; j < num; j++) {
                if (asdu.length - offset < 1) throw new Error('YX seq item too short');
                const val = asdu.readUInt8(offset); offset += 1;
                const state = isSingle
                    ? ((val & 0x01) ? '合(1)' : '分(0)')
                    : Parser104._dpState(val);
                results.push({ slot: j + 1, addr: baseAddr + j, addrDec: baseAddr + j, state });
            }
        }
        return { type: 'yx', data: results };
    }

    static parseSOE(ti, asdu, offset, cot, addr, sq, num) {
        const results = [];
        const isSingle = (ti === 30);

        if (sq === 0) {
            for (let i = 0; i < num; i++) {
                if (asdu.length - offset < 11) throw new Error('SOE item too short');
                const objAddr = asdu.readUInt16LE(offset) | (asdu.readUInt8(offset + 2) << 16); offset += 3;
                const val = asdu.readUInt8(offset); offset += 1;
                const timeStr = Parser104.parseCP56Time2a(asdu, offset); offset += 7;
                const state = isSingle
                    ? ((val & 0x01) ? '合(1)' : '分(0)')
                    : Parser104._dpState(val);
                results.push({ slot: i + 1, addr: objAddr, addrDec: objAddr, state, time: timeStr });
            }
        } else {
            if (asdu.length - offset < 3) throw new Error('SOE base addr missing');
            const baseAddr = asdu.readUInt16LE(offset) | (asdu.readUInt8(offset + 2) << 16); offset += 3;
            for (let j = 0; j < num; j++) {
                if (asdu.length - offset < 8) throw new Error('SOE seq item too short');
                const val = asdu.readUInt8(offset); offset += 1;
                const timeStr = Parser104.parseCP56Time2a(asdu, offset); offset += 7;
                const state = isSingle
                    ? ((val & 0x01) ? '合(1)' : '分(0)')
                    : Parser104._dpState(val);
                results.push({ slot: j + 1, addr: baseAddr + j, addrDec: baseAddr + j, state, time: timeStr });
            }
        }
        return { type: 'soe', data: results };
    }

    // [FIX-07] 解析 QOC；修正 "faild" 拼写；P/N=1 时标注否定确认
    static parseRemoteControl(ti, asdu, offset, cot, addr, sq, num, pn) {
        const results = [];
        const isSingle = (ti === 45);
        const pointType = isSingle ? 'single(单点)' : 'double(双点)';

        const parseOne = (objAddr, rawByte) => {
            const s_e = (rawByte >> 7) & 0x01;
            const qoc = (rawByte >> 2) & 0x1F;             // [FIX-07] QOC
            const qocStr = QOC_MAP[qoc] ?? `QOC=${qoc}`;

            let cmdState;
            if (isSingle) {
                cmdState = (rawByte & 0x01) ? '控合' : '控分';
            } else {
                const dcs = rawByte & 0x03;
                cmdState = dcs === 1 ? '控分' : dcs === 2 ? '控合' : '不确定';
            }

            let operation;
            switch (cot & 0x3F) {                          // 低6位才是原因
                case 6:  operation = s_e ? '选择' : '执行'; break;
                case 7:  operation = s_e ? '选择确认' : '执行确认'; break;
                case 8:  operation = '撤销'; break;
                case 9:  operation = '撤销确认'; break;
                case 10: operation = '执行结束'; break;
                default: operation = `COT=${cot}`;
            }
            if (pn) operation += '(否定)';                 // [FIX-07] 否定确认标注

            const cause = cot & 0x3F;
            const isSuccess = (cause === 7 || cause === 9 || cause === 10) && !pn;
            const isFail    = ((cause >= 44 && cause <= 50) || pn);

            return {
                addr     : `0x${objAddr.toString(16).padStart(6, '0')}`,
                state    : cmdState,
                operation,
                qoc      : qocStr,
                return   : isSuccess ? 'success' : isFail ? 'failed' : '',  // [FIX-07] 拼写
                pointType,
            };
        };

        if (sq === 0) {
            for (let i = 0; i < num; i++) {
                if (asdu.length - offset < 4) throw new Error('Control item too short');
                const objAddr = asdu.readUInt16LE(offset) | (asdu.readUInt8(offset + 2) << 16); offset += 3;
                const raw = asdu.readUInt8(offset); offset += 1;
                results.push({ slot: i + 1, ...parseOne(objAddr, raw) });
            }
        } else {
            if (asdu.length - offset < 3) throw new Error('Control base addr missing');
            const baseAddr = asdu.readUInt16LE(offset) | (asdu.readUInt8(offset + 2) << 16); offset += 3;
            for (let j = 0; j < num; j++) {
                if (asdu.length - offset < 1) throw new Error('Control seq item too short');
                const raw = asdu.readUInt8(offset); offset += 1;
                results.push({ slot: j + 1, ...parseOne(baseAddr + j, raw) });
            }
        }
        return { type: 'control', data: results };
    }

    // [FIX-03] TI=9 归一化值工程换算
    static parseYC(ti, asdu, offset, cot, addr, sq, num) {
        const results = [];
        const isFloat = (ti === 13);
        const isNorm  = (ti === 9);                         // [FIX-03]
        const valueSize = isFloat ? 4 : 2;

        const readValue = (buf, off) => {
            if (isFloat) return buf.readFloatLE(off);
            const raw = buf.readInt16LE(off);
            if (isNorm) {
                // [FIX-03] NVA: 真实值 = raw / 32767.0，范围 -1~+1
                return { raw, eng: parseFloat((raw / 32767.0).toFixed(6)) };
            }
            return raw; // SVA 直接返回整数
        };

        const typeLabel = isFloat ? 'float(短浮点)' : isNorm ? 'NVA(归一化)' : 'SVA(标度化)';

        if (sq === 0) {
            for (let i = 0; i < num; i++) {
                if (asdu.length - offset < 3 + valueSize + 1) throw new Error('YC item too short');
                const objAddr = asdu.readUInt16LE(offset) | (asdu.readUInt8(offset + 2) << 16); offset += 3;
                const val = readValue(asdu, offset); offset += valueSize;
                const qds = asdu.readUInt8(offset); offset += 1;
                results.push({ slot: i + 1, addr: objAddr, value: val, valueType: typeLabel, qds });
            }
        } else {
            if (asdu.length - offset < 3) throw new Error('YC base addr missing');
            const baseAddr = asdu.readUInt16LE(offset) | (asdu.readUInt8(offset + 2) << 16); offset += 3;
            for (let j = 0; j < num; j++) {
                if (asdu.length - offset < valueSize + 1) throw new Error('YC seq item too short');
                const val = readValue(asdu, offset); offset += valueSize;
                const qds = asdu.readUInt8(offset); offset += 1;
                results.push({ slot: j + 1, addr: baseAddr + j, value: val, valueType: typeLabel, qds });
            }
        }
        return { type: 'yc', data: results };
    }

    // [FIX-08] TI=70 初始化结束
    static parseInitEnd(asdu, offset, cot, addr) {
        if (asdu.length - offset < 4) return { type: 'init_end', cot, addr, coi: null };
        offset += 3; // skip IOA (=0)
        const coi = asdu.readUInt8(offset);
        const coiMap = { 0: '当地电源合上', 1: '当地手动复位', 2: '远方复位' };
        return { type: 'init_end', cot, addr, coi, coiDesc: coiMap[coi] ?? `COI=${coi}` };
    }

    // [FIX-09] TI=101 电能量召唤命令
    static parseEnergyCall(asdu, offset, cot, addr) {
        if (asdu.length - offset < 4) return { type: 'energy_call', cot, addr, qcc: null };
        offset += 3;
        const qcc = asdu.readUInt8(offset);
        return { type: 'energy_call', cot, addr, qcc, qccDesc: qcc === 5 ? '总请求电能量' : `QCC=${qcc}` };
    }

    // [FIX-10] TI=103 时钟同步/读取
    static parseClockSync(asdu, offset, cot, addr) {
        if (asdu.length - offset < 3) return { type: 'clock_sync', cot, addr, time: null };
        offset += 3; // skip IOA
        let time = null;
        if (asdu.length - offset >= 7) {
            time = Parser104.parseCP56Time2a(asdu, offset);
        }
        const cause = cot & 0x3F;
        const desc  = cause === 6 ? '时钟同步命令' : cause === 7 ? '时钟同步确认' : cause === 5 ? '时钟读取' : `COT=${cot}`;
        return { type: 'clock_sync', cot, addr, time, desc };
    }

    // [FIX-11][FIX-12] TI=206/207 累计量
    static parseEnergy(ti, asdu, offset, cot, addr, sq, num) {
        const results = [];
        const hasTime = (ti === 207);
        const itemSize = 4 + 1 + (hasTime ? 7 : 0); // float(4) + QDS(1) [+ time(7)]

        if (sq === 0) {
            for (let i = 0; i < num; i++) {
                if (asdu.length - offset < 3 + itemSize) throw new Error('Energy item too short');
                const objAddr = asdu.readUInt16LE(offset) | (asdu.readUInt8(offset + 2) << 16); offset += 3;
                const value   = asdu.readFloatLE(offset); offset += 4;
                const qds     = asdu.readUInt8(offset); offset += 1;
                let   time    = null;
                if (hasTime && asdu.length - offset >= 7) {
                    time = Parser104.parseCP56Time2a(asdu, offset); offset += 7;
                }
                results.push({ slot: i + 1, addr: objAddr, value, qds, time });
            }
        } else {
            if (asdu.length - offset < 3) throw new Error('Energy base addr missing');
            const baseAddr = asdu.readUInt16LE(offset) | (asdu.readUInt8(offset + 2) << 16); offset += 3;
            for (let j = 0; j < num; j++) {
                if (asdu.length - offset < itemSize) break;
                const value = asdu.readFloatLE(offset); offset += 4;
                const qds   = asdu.readUInt8(offset); offset += 1;
                let   time  = null;
                if (hasTime && asdu.length - offset >= 7) {
                    time = Parser104.parseCP56Time2a(asdu, offset); offset += 7;
                }
                results.push({ slot: j + 1, addr: baseAddr + j, value, qds, time });
            }
        }
        return { type: 'energy', hasTime, data: results };
    }

    // [FIX-13] 参数读写 — 统一结构修正
    static parseParamCommand(ti, asdu, offset, cot, addr, sq, num) {
        const results = [];
        const cause   = cot & 0x3F;

        // TI=200 切换定值区
        if (ti === 200) {
            if (asdu.length - offset < 5) throw new Error('Missing object address or SN (TI=200)');
            offset += 3; // skip IOA
            const sn = asdu.readUInt16LE(offset);
            const opMap = { 6: '切换请求', 7: '切换确认', 8: '切换撤销', 9: '切换撤销确认' };
            results.push({ type: 'Para_switch', operation: opMap[cause] ?? `COT=${cot}`, sn });
        }

        // TI=201 读定值区号
        else if (ti === 201) {
            if (asdu.length - offset < 3) throw new Error('Missing IOA (TI=201)');
            const objAddr = asdu.readUInt16LE(offset) | (asdu.readUInt8(offset + 2) << 16); offset += 3;
            if (cause === 7 && asdu.length - offset >= 6) {
                // 读区号响应：current(2) + min(2) + max(2)
                const current = asdu.readUInt16LE(offset); offset += 2;
                const min     = asdu.readUInt16LE(offset); offset += 2;
                const max     = asdu.readUInt16LE(offset); offset += 2;
                results.push({ type: 'SNNum', operation: '读区号响应', current, min, max });
            } else {
                const opMap = { 6: '读区号请求', 8: '读区号撤销', 9: '读区号撤销确认' };
                results.push({ type: 'SNNum', operation: opMap[cause] ?? `COT=${cot}`,
                    addr: `0x${objAddr.toString(16).padStart(6,'0')}` });
            }
        }

        // TI=202 读参数和定值
        else if (ti === 202) {
            if (asdu.length - offset < 2) throw new Error('Missing SN (TI=202)');
            const sn = asdu.readUInt16LE(offset); offset += 2;

            if (cause === 6) {
                // 读请求：SN(2) + N个地址(3)
                const addrs = [];
                for (let i = 0; i < num; i++) {
                    if (asdu.length - offset < 3) break;
                    const a = asdu.readUInt16LE(offset) | (asdu.readUInt8(offset + 2) << 16); offset += 3;
                    addrs.push(`0x${a.toString(16).padStart(6,'0')}`);
                }
                results.push({ type: 'Para_read', operation: '读请求', sn, addrs });
            }
            else if (cause === 7) {
                // [FIX-13] 读响应：SN(2) + PI(1) + [地址(3)+Tag(1)+Len(1)+Value] x N
                // PI 只有一个，在所有数据之前统一读取
                if (asdu.length - offset < 1) break_out: {
                    results.push({ type: 'Para_read', operation: '读响应(数据不足)', sn }); break break_out;
                }
                const pi      = asdu.readUInt8(offset); offset += 1;
                const piFlags = Parser104.parsePI(pi);
                let isFirst   = true;
                while (offset + 5 <= asdu.length) {
                    const a = asdu.readUInt16LE(offset) | (asdu.readUInt8(offset + 2) << 16); offset += 3;
                    const tag = asdu.readUInt8(offset); offset += 1;
                    const len = asdu.readUInt8(offset); offset += 1;
                    if (asdu.length - offset < len) break;
                    const vBuf  = asdu.slice(offset, offset + len); offset += len;
                    const parsed = Parser104.parseTLVValue(tag, vBuf);
                    results.push({
                        type: 'Para_read', operation: '读响应', sn,
                        addr: `0x${a.toString(16).padStart(6,'0')}`,
                        tag: parsed.tag, value: parsed.value,
                        pi: isFirst ? pi : null,
                        piFlags: isFirst ? piFlags : null,
                    });
                    isFirst = false;
                }
                if (results.length === 0)
                    results.push({ type: 'Para_read', operation: '读响应(空)', sn, pi, piFlags });
            }
            else {
                const opMap = { 8: '读撤销', 9: '读撤销确认' };
                results.push({ type: 'Para_read', operation: opMap[cause] ?? `COT=${cot}`, sn });
            }
        }

        // TI=203 写参数和定值
        else if (ti === 203) {
            if (asdu.length - offset < 2) throw new Error('Missing SN (TI=203)');
            const sn = asdu.readUInt16LE(offset); offset += 2;

            if (cause === 6) {
                // 写预置：SN(2) + PI(1) + N×[地址(3)+Tag(1)+Len(1)+Value]
                if (asdu.length - offset < 1) { results.push({ type:'Para_write', operation:'写预置(PI缺失)', sn }); }
                else {
                    const pi      = asdu.readUInt8(offset); offset += 1;
                    const piFlags = Parser104.parsePI(pi);
                    for (let i = 0; i < num; i++) {
                        if (asdu.length - offset < 5) break;
                        const a = asdu.readUInt16LE(offset) | (asdu.readUInt8(offset + 2) << 16); offset += 3;
                        const tag = asdu.readUInt8(offset); offset += 1;
                        const len = asdu.readUInt8(offset); offset += 1;
                        const vBuf = asdu.length - offset >= len
                            ? asdu.slice(offset, offset + len)
                            : asdu.slice(offset);
                        offset += Math.min(len, asdu.length - offset);
                        const parsed = Parser104.parseTLVValue(tag, vBuf);
                        results.push({
                            type:'Para_write', operation:'写预置', sn, pi, piFlags,
                            addr: `0x${a.toString(16).padStart(6,'0')}`,
                            tag: parsed.tag, value: parsed.value,
                        });
                    }
                }
            }
            else if (cause === 7) {
                // 写确认（可带回显）
                let pi = null, piFlags = null;
                if (asdu.length - offset >= 1) { pi = asdu.readUInt8(offset); piFlags = Parser104.parsePI(pi); offset += 1; }
                const values = [];
                while (offset + 5 <= asdu.length) {
                    const a = asdu.readUInt16LE(offset) | (asdu.readUInt8(offset + 2) << 16); offset += 3;
                    const tag = asdu.readUInt8(offset); offset += 1;
                    const len = asdu.readUInt8(offset); offset += 1;
                    if (asdu.length - offset < len) break;
                    const vBuf  = asdu.slice(offset, offset + len); offset += len;
                    const parsed = Parser104.parseTLVValue(tag, vBuf);
                    values.push({ addr:`0x${a.toString(16).padStart(6,'0')}`, tag:parsed.tag, value:parsed.value });
                }
                results.push({ type:'Para_write', operation: values.length ? '写确认(带回显)' : '写确认', sn, pi, piFlags, values });
            }
            else {
                const opMap = { 8:'撤销', 9:'撤销确认', 10:'激活终止' };
                let pi=null, piFlags=null;
                if (asdu.length-offset >= 1) { pi=asdu.readUInt8(offset); piFlags=Parser104.parsePI(pi); offset+=1; }
                results.push({ type:'Para_write', operation: opMap[cause] ?? `COT=${cot}`, sn, pi, piFlags });
            }
        }

        return { type: 'param', data: results };
    }

    // ========== 故障事件 TI=42 ==========

    // [FIX-02] 移除错误的 offset+=1 保留字节跳过
    static parseFault(asdu, offset, cot, addr) {
        const result = { type:'fault', cot, addr, yx:[], yc:[] };
        try {
            // 1. 带时标遥信个数
            if (asdu.length - offset < 1) return result;
            const yxCount = asdu.readUInt8(offset); offset += 1;

            // 2. N条遥信：类型(1)+点号(2)+值(1)+时标(7) = 11字节/条
            for (let i = 0; i < yxCount; i++) {
                if (asdu.length - offset < 11) break;
                const yxType  = asdu.readUInt8(offset);                   offset += 1;
                const yxPoint = asdu.readUInt16LE(offset);                 offset += 2;
                const yxVal   = asdu.readUInt8(offset);                    offset += 1;
                const yxTime  = Parser104.parseCP56Time2a(asdu, offset);   offset += 7;

                let state;
                if (yxType === 1 || yxType === 0x1e) {
                    state = (yxVal & 0x01) ? '合(1)' : '分(0)';
                } else if (yxType === 3 || yxType === 0x1f) {
                    state = Parser104._dpState(yxVal);
                } else {
                    state = `0x${yxVal.toString(16)}`;
                }

                result.yx.push({
                    type    : yxType,
                    typeHex : `0x${yxType.toString(16).padStart(2,'0')}`,
                    point   : yxPoint,
                    pointHex: `0x${yxPoint.toString(16).padStart(4,'0')}`,
                    state, time: yxTime,
                    stateHex: `0x${yxVal.toString(16).padStart(2,'0')}`,
                });
            }

            // 3. 遥信结束后跳过1字节保留/扩展字段（实际帧中存在，如0x1A）
            if (asdu.length - offset < 3) return result;
            offset += 1;  // 保留字节
            const ycCount = asdu.readUInt8(offset); offset += 1;
            const ycType  = asdu.readUInt8(offset); offset += 1;
            result.ycCount   = ycCount;
            result.ycType    = ycType;
            result.ycTypeHex = `0x${ycType.toString(16).padStart(2,'0')}`;

            const valueSize = (ycType === 9 || ycType === 11) ? 2 : 4;
            const isNorm    = (ycType === 9);

            // 4. N条遥测：地址(3)+值(valueSize)
            for (let i = 0; i < ycCount; i++) {
                if (asdu.length - offset < 3 + valueSize) break;
                const lo = asdu.readUInt8(offset), mi = asdu.readUInt8(offset+1), hi = asdu.readUInt8(offset+2);
                offset += 3;
                const ycAddr = (hi << 16) | (mi << 8) | lo;

                let raw, eng;
                if (valueSize === 4) {
                    eng = asdu.readFloatLE(offset);
                } else {
                    raw = asdu.readInt16LE(offset);
                    eng = isNorm ? parseFloat((raw / 32767.0).toFixed(6)) : raw;
                }
                offset += valueSize;

                const valueTypeMap = { 0x0d:'float', 0x09:'NVA(归一化)', 0x0b:'SVA(标度化)' };
                result.yc.push({
                    addr     : ycAddr,
                    hexAddr  : `0x${ycAddr.toString(16).padStart(6,'0')}`,
                    value    : eng,
                    rawValue : raw,
                    valueType: valueTypeMap[ycType] ?? `type=0x${ycType.toString(16)}`,
                });
            }
            result.description = `故障事件: ${result.yx.length}个遥信, ${result.yc.length}个遥测`;
        } catch (e) {
            result.error = e.message;
        }
        return result;
    }


    // ========== 文件服务（TI=120~127）==========

    static _nofName(nof) {
        const map = { 1:'录波文件', 2:'故障事件记录', 3:'遥控操作记录', 4:'定值修改记录', 5:'运行日志' };
        return map[nof] ?? `文件#${nof}`;
    }
    static _nosName(nos) { return nos === 0 ? '整体(无节)' : `第${nos}节`; }
    static _readLOF(buf, off) { return buf[off] | (buf[off+1] << 8) | (buf[off+2] << 16); }
    static _readUInt32LE(buf, off) { return buf.readUInt32LE(off); }
    static _sum8(buf) { let sum = 0; for (const b of buf) sum = (sum + b) & 0xFF; return sum; }
    static _resultDesc(code, map) { return map[code] ?? `未知(${code})`; }
    static _readAscii(buf, offset, len) {
        return buf.slice(offset, offset + len).toString('ascii');
    }

    // TI=120 文件可用 F_AF_NA: IOA(3)+NOF(2)+LOF(3)+SRQ(1)
    static parseFileAvailable(asdu, offset, cot, addr) {
        if (asdu.length - offset < 9) throw new Error('F_AF_NA too short');
        offset += 3;
        const nof = asdu.readUInt16LE(offset); offset += 2;
        const lof = Parser104._readLOF(asdu, offset); offset += 3;
        const srq = asdu.readUInt8(offset);
        return {
            type:'file_service', service:'F_AF_NA', desc:'文件可用通知',
            nof, nofName:Parser104._nofName(nof), lof, size:`${lof}字节`,
            status:(srq & 0x01) ? '可用' : '目录项', srq, cot, addr,
        };
    }

    // TI=121 文件召唤/目录请求 F_SC_NA: IOA(3)+NOF(2)+NOS(1)+SCQ(1)
    static parseFileCall(asdu, offset, cot, addr) {
        if (asdu.length - offset < 7) throw new Error('F_SC_NA too short');
        offset += 3;
        const nof = asdu.readUInt16LE(offset); offset += 2;
        const nos = asdu.readUInt8(offset); offset += 1;
        const scq = asdu.readUInt8(offset);
        const scqMap = { 0x00:'无请求',0x01:'选择文件',0x02:'请求文件',0x03:'撤销选择',0x05:'请求目录' };
        return {
            type:'file_service', service:'F_SC_NA',
            desc: scq===0x05 ? '目录查询请求' : '文件召唤',
            nof, nofName:Parser104._nofName(nof),
            nos, nosName:Parser104._nosName(nos),
            scq, scqDesc:scqMap[scq] ?? `SCQ=0x${scq.toString(16)}`,
            cot, addr,
        };
    }

    // TI=122 目录 F_DR_TA: IOA(3)+[NOF(2)+LOF(3)+CP56(7)+SRQ(1)]×N
    static parseFileDirectory(asdu, offset, cot, addr, num) {
        offset += 3;
        const entries = [];
        const count = num > 0 ? num : 255;
        for (let i = 0; i < count; i++) {
            if (asdu.length - offset < 13) break;
            const nof = asdu.readUInt16LE(offset); offset += 2;
            const lof = Parser104._readLOF(asdu, offset); offset += 3;
            const timeStr = Parser104.parseCP56Time2a(asdu, offset); offset += 7;
            const srq = asdu.readUInt8(offset); offset += 1;
            entries.push({
                nof, nofName:Parser104._nofName(nof),
                lof, size:`${lof}字节`, lastModified:timeStr,
                status:(srq & 0x01) ? '可用' : '不可用', srq,
            });
        }
        return {
            type:'file_service', service:'F_DR_TA',
            desc:`目录响应(${entries.length}个文件)`,
            entries, cot, addr,
        };
    }

    // TI=123 文件传输准备就绪 F_FR_NA: IOA(3)+NOF(2)+LOF(3)+FRQ(1)
    static parseFileReady(asdu, offset, cot, addr) {
        if (asdu.length - offset < 9) throw new Error('F_FR_NA too short');
        offset += 3;
        const nof = asdu.readUInt16LE(offset); offset += 2;
        const lof = Parser104._readLOF(asdu, offset); offset += 3;
        const frq = asdu.readUInt8(offset);
        return {
            type:'file_service', service:'F_FR_NA', desc:'文件传输准备就绪',
            nof, nofName:Parser104._nofName(nof), lof, size:`${lof}字节`,
            result:(frq & 0x01)===0 ? '就绪(肯定)' : '拒绝(否定)',
            condition:(frq & 0x02)!==0 ? '有条件传输' : '无条件传输',
            frq, cot, addr,
        };
    }

    // TI=124 节传输准备就绪 F_SR_NA: IOA(3)+NOF(2)+NOS(1)+LOS(3)+SRQ(1)
    static parseSectionReady(asdu, offset, cot, addr) {
        if (asdu.length - offset < 10) throw new Error('F_SR_NA too short');
        offset += 3;
        const nof = asdu.readUInt16LE(offset); offset += 2;
        const nos = asdu.readUInt8(offset); offset += 1;
        const los = Parser104._readLOF(asdu, offset); offset += 3;
        const srq = asdu.readUInt8(offset);
        return {
            type:'file_service', service:'F_SR_NA', desc:'节传输准备就绪',
            nof, nofName:Parser104._nofName(nof),
            nos, nosName:Parser104._nosName(nos),
            los, size:`${los}字节`,
            result:(srq & 0x01)===0 ? '就绪(肯定)' : '拒绝(否定)',
            srq, cot, addr,
        };
    }

    // TI=125 段落 F_SG_NA: IOA(3)+NOF(2)+NOS(1)+LOS(1)+DATA(LOS)
    static parseSegment(asdu, offset, cot, addr) {
        if (asdu.length - offset < 7) throw new Error('F_SG_NA too short');
        offset += 3;
        const nof = asdu.readUInt16LE(offset); offset += 2;
        const nos = asdu.readUInt8(offset); offset += 1;
        const los = asdu.readUInt8(offset); offset += 1;
        const dataEnd = Math.min(offset + los, asdu.length);
        const data    = asdu.slice(offset, dataEnd);
        const dataHex = data.toString('hex').toUpperCase().replace(/(.{64})/g,'$1\n').trim();
        return {
            type:'file_service', service:'F_SG_NA',
            desc:`文件段落(${data.length}字节数据)`,
            nof, nofName:Parser104._nofName(nof),
            nos, nosName:Parser104._nosName(nos),
            los, dataLen:data.length, dataHex,
            cot, addr,
        };
    }

    // TI=126 最后报文段/节 F_LS_NA: IOA(3)+NOF(2)+NOS(1)+LSQ(1)+CHS(1)
    static parseLastSegment(asdu, offset, cot, addr) {
        if (asdu.length - offset < 8) throw new Error('F_LS_NA too short');
        offset += 3;
        const nof = asdu.readUInt16LE(offset); offset += 2;
        const nos = asdu.readUInt8(offset); offset += 1;
        const lsq = asdu.readUInt8(offset); offset += 1;
        const chs = asdu.readUInt8(offset);
        const lsqMap = { 0:'最后段(继续)', 1:'节结束', 2:'文件结束', 3:'中止传输' };
        return {
            type:'file_service', service:'F_LS_NA',
            desc:lsqMap[lsq] ?? `LSQ=${lsq}`,
            nof, nofName:Parser104._nofName(nof),
            nos, nosName:Parser104._nosName(nos),
            lsq, lsqDesc:lsqMap[lsq] ?? `LSQ=${lsq}`,
            chs, chsHex:`0x${chs.toString(16).padStart(2,'0')}`,
            cot, addr,
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
                const directoryId = Parser104._readUInt32LE(asdu, offset); offset += 4;
                const dirNameLen = asdu.readUInt8(offset); offset += 1;
                if (asdu.length - offset < dirNameLen + 1 + 7 + 7) throw new Error('目录召唤目录名/时间长度不足');
                const directoryName = Parser104._readAscii(asdu, offset, dirNameLen); offset += dirNameLen;
                const queryFlag = asdu.readUInt8(offset); offset += 1;
                const queryFlagName = queryFlag === 0 ? '目录下所有文件' : queryFlag === 1 ? '目录下满足搜索时间段的文件' : `未知(${queryFlag})`;
                const startTime = Parser104.parseCP56Time2a(asdu, offset); offset += 7;
                const endTime = Parser104.parseCP56Time2a(asdu, offset); offset += 7;
                Object.assign(result, { directoryId, directoryName, dirNameLen, queryFlag, queryFlagName, startTime, endTime });
                break;
            }
            case 2: {
                if (asdu.length - offset < 1 + 4 + 1 + 1) throw new Error('目录召唤确认长度不足');
                const resultCode = asdu.readUInt8(offset); offset += 1;
                const directoryId = Parser104._readUInt32LE(asdu, offset); offset += 4;
                const hasMore = asdu.readUInt8(offset); offset += 1;
                const fileCount = asdu.readUInt8(offset); offset += 1;
                const entries = [];
                for (let i = 0; i < fileCount; i++) {
                    if (asdu.length - offset < 1) throw new Error('目录文件名长度缺失');
                    const nameLen = asdu.readUInt8(offset); offset += 1;
                    if (asdu.length - offset < nameLen + 1 + 4 + 7) throw new Error('目录文件项长度不足');
                    const fileName = Parser104._readAscii(asdu, offset, nameLen); offset += nameLen;
                    const fileAttr = asdu.readUInt8(offset); offset += 1;
                    const fileSize = Parser104._readUInt32LE(asdu, offset); offset += 4;
                    const fileTime = Parser104.parseCP56Time2a(asdu, offset); offset += 7;
                    entries.push({ fileName, fileAttr, fileSize, fileTime });
                }
                Object.assign(result, {
                    resultCode,
                    resultDesc: Parser104._resultDesc(resultCode, dirResultMap),
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
                const fileName = Parser104._readAscii(asdu, offset, fileNameLen); offset += fileNameLen;
                Object.assign(result, { fileNameLen, fileName });
                break;
            }
            case 4: {
                if (asdu.length - offset < 1 + 1) throw new Error('读文件激活确认长度不足');
                const resultCode = asdu.readUInt8(offset); offset += 1;
                const fileNameLen = asdu.readUInt8(offset); offset += 1;
                if (asdu.length - offset < fileNameLen + 4 + 4) throw new Error('读文件激活确认内容长度不足');
                const fileName = Parser104._readAscii(asdu, offset, fileNameLen); offset += fileNameLen;
                const fileId = Parser104._readUInt32LE(asdu, offset); offset += 4;
                const fileSize = Parser104._readUInt32LE(asdu, offset); offset += 4;
                Object.assign(result, {
                    resultCode,
                    resultDesc: Parser104._resultDesc(resultCode, readActivateResultMap),
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
                const fileId = Parser104._readUInt32LE(asdu, offset); offset += 4;
                const segmentNo = Parser104._readUInt32LE(asdu, offset); offset += 4;
                const hasMore = asdu.readUInt8(offset); offset += 1;
                const dataLen = asdu.length - offset - 1;
                if (dataLen < 0) throw new Error('文件数据传输校验码缺失');
                const fileData = asdu.slice(offset, offset + dataLen); offset += dataLen;
                const checksum = asdu.readUInt8(offset); offset += 1;
                Object.assign(result, {
                    fileId,
                    segmentNo,
                    hasMore,
                    hasMoreDesc: hasMore ? '有后续' : '无后续',
                    dataLen,
                    dataHex: fileData.toString('hex').toUpperCase().replace(/(.{64})/g, '$1\n').trim(),
                    checksum,
                    checksumHex: `0x${checksum.toString(16).padStart(2, '0')}`,
                    checksumCalc: Parser104._sum8(fileData),
                    checksumCalcHex: `0x${Parser104._sum8(fileData).toString(16).padStart(2, '0')}`,
                    checksumValid: Parser104._sum8(fileData) === checksum,
                });
                break;
            }
            case 6:
            case 10: {
                if (asdu.length - offset < 4 + 4 + 1) throw new Error('文件数据传输确认长度不足');
                const fileId = Parser104._readUInt32LE(asdu, offset); offset += 4;
                const segmentNo = Parser104._readUInt32LE(asdu, offset); offset += 4;
                const resultCode = asdu.readUInt8(offset); offset += 1;
                const resultMap = op === 6
                    ? { 0:'无后续', 1:'有后续' }
                    : transferConfirmMap;
                Object.assign(result, {
                    fileId,
                    segmentNo,
                    resultCode,
                    resultDesc: Parser104._resultDesc(resultCode, resultMap),
                });
                break;
            }
            case 7: {
                if (asdu.length - offset < 1) throw new Error('写文件激活长度不足');
                const fileNameLen = asdu.readUInt8(offset); offset += 1;
                if (asdu.length - offset < fileNameLen + 4 + 4) throw new Error('写文件激活内容长度不足');
                const fileName = Parser104._readAscii(asdu, offset, fileNameLen); offset += fileNameLen;
                const fileId = Parser104._readUInt32LE(asdu, offset); offset += 4;
                const fileSize = Parser104._readUInt32LE(asdu, offset); offset += 4;
                Object.assign(result, { fileNameLen, fileName, fileId, fileSize });
                break;
            }
            case 8: {
                if (asdu.length - offset < 1 + 1) throw new Error('写文件激活确认长度不足');
                const resultCode = asdu.readUInt8(offset); offset += 1;
                const fileNameLen = asdu.readUInt8(offset); offset += 1;
                if (asdu.length - offset < fileNameLen + 4 + 4) throw new Error('写文件激活确认内容长度不足');
                const fileName = Parser104._readAscii(asdu, offset, fileNameLen); offset += fileNameLen;
                const fileId = Parser104._readUInt32LE(asdu, offset); offset += 4;
                const fileSize = Parser104._readUInt32LE(asdu, offset); offset += 4;
                Object.assign(result, {
                    resultCode,
                    resultDesc: Parser104._resultDesc(resultCode, writeActivateResultMap),
                    fileNameLen,
                    fileName,
                    fileId,
                    fileSize,
                });
                break;
            }
            default:
                Object.assign(result, {
                    rawHex: asdu.slice(offset).toString('hex').toUpperCase(),
                });
                break;
        }

        return result;
    }

    // ── TI=210(0xD2) 私有扩展文件目录服务（南网/南瑞等厂家扩展）────────
    // 信息体：IOA(3) + SubType(1) + FileCount(1) + Reserved(4)
    //          + FileCount×[ NameLen(1)+Name(N)+FileType(1)+StartCP56(7)+EndCP56(7) ]
    // COT=5(req): 主站→终端 召唤目录请求（指定文件类型+时间范围过滤）
    // COT=13(file): 终端→主站 目录响应（返回文件列表）
    static parsePrivateFileDir(asdu, offset, cot, addr) {
        // SubType：查询方式
        const subTypeMap = {
            0x01:'按条数查询', 0x02:'按时间范围查询', 0x03:'按序号查询',
        };
        // FileType：文件格式（bit级标识，0x01=有起止时间段）
        const fileTypeMap = {
            0x00:'无时间过滤', 0x01:'按时间段过滤',
        };
        // 文件名路径 → 可读类型（支持 HISTORY/XXX 和裸名两种格式）
        const fileNameTypeMap = {
            'HISTORY/COMTRADE':'录波文件', 'COMTRADE':'录波文件',
            'HISTORY/SOE'     :'SOE事件记录', 'SOE':'SOE事件记录',
            'HISTORY/CTRL'    :'遥控操作记录', 'CTRL':'遥控操作记录',
            'HISTORY/EXTREME' :'极值记录', 'EXTREME':'极值记录',
            'HISTORY/FIXED'   :'定点记录', 'FIXED':'定点记录',
            'HISTORY/LOG'     :'日志记录', 'LOG':'日志记录',
            'HISTORY/USERLOG' :'自定义日志', 'USERLOG':'自定义日志',
        };

        if (asdu.length - offset < 3 + 6) throw new Error('TI=0xD2 too short');
        offset += 3; // skip IOA

        const subType   = asdu.readUInt8(offset); offset += 1;
        const fileCount = asdu.readUInt8(offset); offset += 1;
        offset += 4; // skip reserved(4)

        const files = [];
        for (let i = 0; i < fileCount; i++) {
            if (asdu.length - offset < 1) break;
            const nLen = asdu.readUInt8(offset); offset += 1;
            if (asdu.length - offset < nLen + 1 + 14) break;
            const name     = asdu.slice(offset, offset + nLen).toString('ascii'); offset += nLen;
            const fileType = asdu.readUInt8(offset); offset += 1;
            const startTime= Parser104.parseCP56Time2a(asdu, offset); offset += 7;
            const endTime  = Parser104.parseCP56Time2a(asdu, offset); offset += 7;
            files.push({
                name, fileType,
                fileTypeName: fileTypeMap[fileType] ?? `类型0x${fileType.toString(16)}`,
                fileCategory: fileNameTypeMap[name.toUpperCase()] ?? name,
                startTime, endTime,
            });
        }

        const cause = cot & 0x3F;
        const isRequest = (cause === 5 || cause === 6);
        // 用文件名推断总体描述
        const allCategories = [...new Set(files.map(f => f.fileCategory))].join('、') || '文件';
        return {
            type      : 'file_service',
            service   : 'PRIV_DIR',
            desc      : isRequest
                ? `召唤文件目录请求(${allCategories})`
                : `文件目录响应(${files.length}个文件)`,
            subType,
            subTypeName: subTypeMap[subType] ?? `SubType=0x${subType.toString(16)}`,
            fileCount,
            files,
            cot, addr,
        };
    }

    // TI=127 确认文件传输 F_AF_NA: IOA(3)+NOF(2)+NOS(1)+AFQ(1)
    static parseFileAck(asdu, offset, cot, addr) {
        if (asdu.length - offset < 7) throw new Error('F_AF_NA(ack) too short');
        offset += 3;
        const nof = asdu.readUInt16LE(offset); offset += 2;
        const nos = asdu.readUInt8(offset); offset += 1;
        const afq = asdu.readUInt8(offset);
        const codeMap = { 0:'无', 1:'肯定确认文件', 2:'否定确认文件', 3:'肯定确认节' };
        const code = afq & 0x03;
        const reason = (afq >> 2) & 0x3F;
        return {
            type:'file_service', service:'F_AF_NA', desc:'文件传输确认',
            nof, nofName:Parser104._nofName(nof),
            nos, nosName:Parser104._nosName(nos),
            afq, ackType:codeMap[code] ?? `code=${code}`,
            reason: reason ? `错误原因=${reason}` : '无错误',
            cot, addr,
        };
    }

    // ========== APDU 主解析入口 ==========
    static parseAPDU(buf) {
        if (buf.length < 6)  return { type:'error', error:'APDU too short' };
        if (buf[0] !== 0x68) return { type:'error', error:'Invalid start byte' };

        const len = buf[1];
        if (buf.length < len + 2) return { type:'error', error:'Buffer too short for APDU' };

        const ctrl = buf.slice(2, 6);
        const asdu = buf.slice(6, 2 + len);

        // S/U 帧（非 I 帧）
        const isIFormat = (ctrl[0] & 0x01) === 0;
        if (!isIFormat || asdu.length === 0) {
            return { type:'other', ctrl: ctrl.toString('hex') };
        }

        // ASDU 头部：TI(1)+VSQ(1)+COT(2)+CommonAddr(2)
        if (asdu.length < 6) return { type:'error', error:'ASDU too short' };

        let offset = 0;
        const ti    = asdu[offset++];
        const vsq   = asdu[offset++];
        const cotRaw= asdu.readUInt16LE(offset); offset += 2;
        const addr  = asdu.readUInt16LE(offset); offset += 2;

        // [FIX-06] 解析 COT 各位
        const cot   = cotRaw & 0x3F;           // 低6位：传送原因
        const pn    = (cotRaw >> 6) & 0x01;    // P/N 位：0=肯定, 1=否定
        const test  = (cotRaw >> 7) & 0x01;    // T 位：0=正常, 1=测试
        const cotDesc = COT_NAME[cot] ?? `cot=${cot}`;

        const sq  = (vsq >> 7) & 0x01;
        const num = vsq & 0x7F;

        // [FIX-06] 移除无效的 TI=0 容错分支
        try {
            switch (ti) {
                case 1:
                case 3:
                    return { ...Parser104.parseYX(ti, asdu, offset, cotRaw, addr, sq, num), pn, test, cotDesc };
                case 9:
                case 11:
                case 13:
                    return { ...Parser104.parseYC(ti, asdu, offset, cotRaw, addr, sq, num), pn, test, cotDesc };
                case 30:
                case 31:
                    return { ...Parser104.parseSOE(ti, asdu, offset, cotRaw, addr, sq, num), pn, test, cotDesc };
                case 42:
                    return { ...Parser104.parseFault(asdu, offset, cotRaw, addr), pn, test, cotDesc };
                case 45:
                case 46:
                    return { ...Parser104.parseRemoteControl(ti, asdu, offset, cotRaw, addr, sq, num, pn), pn, test, cotDesc };
                case 70:                         // [FIX-08]
                    return { ...Parser104.parseInitEnd(asdu, offset, cotRaw, addr), pn, test, cotDesc };
                case 100:
                    return { ...Parser104.parseTotalCall(asdu, offset, ti, cotRaw, addr), pn, test, cotDesc };
                case 101:                        // [FIX-09]
                    return { ...Parser104.parseEnergyCall(asdu, offset, cotRaw, addr), pn, test, cotDesc };
                case 103:                        // [FIX-10]
                    return { ...Parser104.parseClockSync(asdu, offset, cotRaw, addr), pn, test, cotDesc };
                case 200:
                case 201:
                case 202:
                case 203:
                    return { ...Parser104.parseParamCommand(ti, asdu, offset, cotRaw, addr, sq, num), pn, test, cotDesc };
                case 206:
                case 207:
                    return { ...Parser104.parseEnergy(ti, asdu, offset, cotRaw, addr, sq, num), pn, test, cotDesc };
                // 文件服务 TI=120~127
                case 120:
                    return { ...Parser104.parseFileAvailable(asdu, offset, cotRaw, addr), pn, test, cotDesc };
                case 121:
                    return { ...Parser104.parseFileCall(asdu, offset, cotRaw, addr), pn, test, cotDesc };
                case 122:
                    return { ...Parser104.parseFileDirectory(asdu, offset, cotRaw, addr, num), pn, test, cotDesc };
                case 123:
                    return { ...Parser104.parseFileReady(asdu, offset, cotRaw, addr), pn, test, cotDesc };
                case 124:
                    return { ...Parser104.parseSectionReady(asdu, offset, cotRaw, addr), pn, test, cotDesc };
                case 125:
                    return { ...Parser104.parseSegment(asdu, offset, cotRaw, addr), pn, test, cotDesc };
                case 126:
                    return { ...Parser104.parseLastSegment(asdu, offset, cotRaw, addr), pn, test, cotDesc };
                case 127:
                    return { ...Parser104.parseFileAck(asdu, offset, cotRaw, addr), pn, test, cotDesc };
                case 210:
                    return { ...Parser104.parseFileService210(asdu, offset, cotRaw, addr), pn, test, cotDesc };
                default:
                    return { type:'unknown', ti, tiHex:`0x${ti.toString(16).padStart(2,'0')}`,
                             cot: cotRaw, cotDesc, addr, pn, test };
            }
        } catch (e) {
            return { type:'error', error: e.message, ti, cot: cotRaw };
        }
    }

    // ========== 对外接口 ==========
    parse(input) {
        const toBuffer = item => {
            if (Buffer.isBuffer(item)) return item;
            if (typeof item === 'string') return Parser104.hexStringToBuffer(item);
            throw new Error('Invalid input type');
        };
        const buffers = Array.isArray(input) ? input.map(toBuffer) : [toBuffer(input)];
        return buffers.map(buf => Parser104.parseAPDU(buf));
    }
}

module.exports = Parser104;
