const fs = require('fs');
const path = require('path');
const archiver = require('archiver');
const { Client } = require('ssh2');
require('dotenv').config();

// ─────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────
const config = {
  localDir: path.resolve(__dirname, '..'),
  archiveFileName: 'project.tar.gz',
  remoteDir: '/opt/node/104Parser',

  host:     process.env.SSH_HOST     || 'host',
  port:     parseInt(process.env.SSH_PORT || '22', 10),
  username: process.env.SSH_USER     || 'name',
  password: process.env.SSH_PASSWORD || 'password',

  excludes: [
    'node_modules/**',
    '.git/**',
    '*.tar.gz',
    '.env*',
    'upload/**',
    'dist/**',
    'yarn.lock',
    'yarn-error.log',
  ],
};

// ─────────────────────────────────────────────
// Step 1: 本地压缩
// ─────────────────────────────────────────────
function createArchive() {
  return new Promise((resolve, reject) => {
    const outputPath = path.resolve(__dirname, config.archiveFileName);
    console.log(`\n[1/3] 正在压缩目录: ${config.localDir}`);
    console.log(`      排除: ${config.excludes.join(', ')}`);

    const output = fs.createWriteStream(outputPath);
    const archive = archiver('tar', { gzip: true, gzipOptions: { level: 6 } });

    output.on('close', () => {
      console.log(`      压缩完成，大小: ${(archive.pointer() / 1024 / 1024).toFixed(2)} MB`);
      resolve(outputPath);
    });
    archive.on('error', reject);
    archive.pipe(output);
    archive.glob('**/*', { cwd: config.localDir, ignore: config.excludes, dot: true });
    archive.finalize();
  });
}

// ─────────────────────────────────────────────
// Step 2 & 3: SFTP 上传 + SSH exec 解压
// ─────────────────────────────────────────────
async function uploadAndExtract(archivePath) {
  const remoteArchivePath = `${config.remoteDir}/${config.archiveFileName}`;

  console.log(`\n[2/3] 正在连接 → ${config.username}@${config.host}:${config.port}`);

  const conn = new Client();
  await new Promise((resolve, reject) => {
    conn.on('ready', resolve);
    conn.on('error', reject);
    conn.connect({ host: config.host, port: config.port, username: config.username, password: config.password });
  });
  console.log('      连接成功');

  try {
    // Step A: SFTP 上传
    const sftp = await new Promise((resolve, reject) => {
      conn.sftp((err, sftp) => err ? reject(err) : resolve(sftp));
    });

    console.log(`      正在上传 → ${remoteArchivePath}`);
    const totalBytes = fs.statSync(archivePath).size;

    await new Promise((resolve, reject) => {
      sftp.fastPut(archivePath, remoteArchivePath, {
        step: (transferred, _chunk, total) => {
          const pct = ((transferred / total) * 100).toFixed(1);
          process.stdout.write(`\r      上传进度: ${pct}%  (${(transferred/1024/1024).toFixed(2)}/${(totalBytes/1024/1024).toFixed(2)} MB)`);
        }
      }, (err) => {
        process.stdout.write('\n');
        err ? reject(new Error(`上传失败: ${err.message}`)) : resolve();
      });
    });
    console.log('      上传完成');

    // Step B: exec 解压
    console.log(`\n[3/3] 正在解压到 ${config.remoteDir} ...`);
    await new Promise((resolve, reject) => {
      const cmd = `tar -xzf "${remoteArchivePath}" -C "${config.remoteDir}" && rm -f "${remoteArchivePath}"; echo __DONE__`;
      conn.exec(cmd, (err, stream) => {
        if (err) return reject(err);
        let out = '';
        stream.stdout.on('data', (d) => { out += d; if (out.includes('__DONE__')) resolve(); });
        stream.stderr.on('data', (d) => { out += d; });
        stream.on('close', (code) => {
          if (code === 0 || out.includes('__DONE__')) resolve();
          else reject(new Error(`解压失败 (code ${code}): ${out}`));
        });
      });
    });
    console.log('      解压完成，远端压缩包已清理');

  } finally {
    conn.end();
  }
}

// ─────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────
async function main() {
  let archivePath;
  try {
    console.log('====== 开始部署 ======');
    archivePath = await createArchive();
    await uploadAndExtract(archivePath);
    console.log('\n====== 部署成功 ✓ ======');
  } catch (err) {
    console.error('\n✗ 部署失败:', err.message);
    process.exit(1);
  } finally {
    if (archivePath && fs.existsSync(archivePath)) {
      fs.unlinkSync(archivePath);
      console.log('本地临时文件已清理');
    }
  }
}

main();