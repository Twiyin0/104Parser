// server.js
// IEC 60870-5-104 / DL/T634.5101 双协议解析服务
// 104 解析逻辑完全不变，新增 101 协议支持

const express     = require('express');
const path        = require('path');
const Parser104   = require('./104ParserClass');
const Parser101   = require('./101ParserClass');
const { detectProtocol } = require('./protocolDetector');

const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, '../public')));

const parser104 = new Parser104();
const parser101 = new Parser101();

app.post('/parse', (req, res) => {
    const { lines } = req.body;
    if (!Array.isArray(lines)) {
        return res.status(400).json({ error: '需要提供lines数组' });
    }

    const results = [];
    for (const line of lines) {
        if (!line || !line.trim()) continue;
        try {
            const { protocol, hexData } = detectProtocol(line);
            if (protocol === '101') {
                const parsed = parser101.parse(hexData);
                results.push(...parsed);
            } else {
                const parsed = parser104.parse(hexData);
                // 补充 protocol 标记，保持与101结果格式一致
                parsed.forEach(p => { if (p && typeof p === 'object') p.protocol = '104'; });
                results.push(...parsed);
            }
        } catch (e) {
            console.error('Parse error:', e.message);
            results.push({ type: 'error', error: e.message, raw: line, protocol: 'unknown' });
        }
    }
    res.json(results);
});

// ── /parseLog ─────────────────────────────────────────────────────────────────
// 解析整段 log 文件，逐行保留原始调试前缀，识别 hex 帧并解析
// Body: { logText: string, protocol?: '101'|'104'|'auto' }
// Response: { lines: [ { raw, prefix, protocol, frames: [...] } ] }
// ──────────────────────────────────────────────────────────────────────────────
app.post('/parseLog', express.json({ limit: '100mb' }), (req, res) => {
    const { logText, forceProtocol } = req.body;
    if (typeof logText !== 'string') return res.status(400).json({ error: 'logText required' });

    // Regex to extract hex data from log lines like:
    //  [xxx][yyy]:timestamp: file:... Tx(N) --->  68 15 ...
    //  [xxx][yyy]:timestamp: file:... Rx(N) <---   68 77 ...
    //  [xxx][yyy]:timestamp:!!!ScanLen[N]
    const LOG_LINE_RE = /^(.+?(?:Tx\(\d+\)\s*-+>|Rx\(\d+\)\s*<-+))\s+((?:[0-9A-Fa-f]{2}\s*)+)$/;
    const lines = logText.split(/\r?\n/);
    const result = [];

    for (const rawLine of lines) {
        const trimmed = rawLine.trim();
        if (!trimmed) { result.push({ raw: rawLine, type: 'empty' }); continue; }

        const m = LOG_LINE_RE.exec(trimmed);
        if (!m) {
            // Non-hex line – pass through as debug info
            result.push({ raw: rawLine, type: 'debug' });
            continue;
        }

        const prefix = m[1];
        const hexStr = m[2].trim();

        // Determine direction (Tx/Rx already in prefix) 
        let detectedProto, hexData;
        if (forceProtocol && forceProtocol !== 'auto') {
            detectedProto = forceProtocol;
            hexData = hexStr;
        } else {
            const det = detectProtocol(hexStr);
            detectedProto = det.protocol;
            hexData = det.hexData;
        }

        let frames = [];
        try {
            if (detectedProto === '101') {
                frames = parser101.parse(hexData);
            } else {
                frames = parser104.parse(hexData);
                frames.forEach(p => { if (p && typeof p === 'object') p.protocol = '104'; });
            }
        } catch (e) {
            frames = [{ type: 'error', error: e.message, protocol: detectedProto }];
        }

        result.push({ raw: rawLine, type: 'hex', prefix, hexStr, protocol: detectedProto, frames });
    }

    res.json({ lines: result });
});

const PORT = process.env.PORT || 33104;

// 如果是直接运行此文件，则启动服务器
if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`104/101 双协议解析器运行在 http://localhost:${PORT}`);
    });
}

module.exports = app;
