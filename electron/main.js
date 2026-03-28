const { app, BrowserWindow } = require('electron');
const path = require('path');
const server = require('../src/server');

let mainWindow;
const port = process.env.PORT || 33105;

function createWindow() {
  // 创建浏览器窗口
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      enableRemoteModule: false,
    },
    icon: path.join(__dirname, '../public/favicon.ico'),
    show: false, // 先不显示窗口，等内容加载完成
  });

  // 加载应用的index.html
  mainWindow.loadURL(`http://localhost:${port}`);

  // 当内容加载完成后显示窗口
  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
  });

  // 打开开发者工具（可选，生产环境注释掉）
  // mainWindow.webContents.openDevTools();

  // 当窗口被关闭，这个事件会被触发
  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// 启动服务器，然后创建窗口
app.whenReady().then(() => {
  server.listen(port, () => {
    console.log(`✓ Server running on http://localhost:${port}`);
    createWindow();
  });
});

// 当全部窗口关闭时退出
app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});