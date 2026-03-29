const { app, BrowserWindow, Menu } = require('electron');  // 添加 Menu
const path = require('path');
const server = require('../src/server');

let mainWindow;
const port = process.env.PORT || 33105;

// 完全移除菜单栏
Menu.setApplicationMenu(null);

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      enableRemoteModule: false,
    },
    icon: path.join(__dirname, '../public/favicon.ico'),
    show: false,
    // autoHideMenuBar: true,  // 方案二：隐藏但 Alt 键可唤出
  });

  mainWindow.loadURL(`http://localhost:${port}`);

  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(() => {
  server.listen(port, () => {
    console.log(`✓ Server running on http://localhost:${port}`);
    createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});