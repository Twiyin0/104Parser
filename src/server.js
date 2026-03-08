// server.js
// IEC 60870-5-104 / DL/T634.5101 双协议解析服务
// 104 解析逻辑完全不变，新增 101 协议支持

const express     = require('express');
const path        = require('path');
const Parser104   = require('./104ParserClass');
const Parser101   = require('./101ParserClass');
const { detectProtocol } = require('./protocolDetector');

const app = express();
app.use(express.json());
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

const PORT = process.env.PORT || 33104;
app.listen(PORT, () => {
    console.log(`104/101 双协议解析器运行在 http://localhost:${PORT}`);
});
