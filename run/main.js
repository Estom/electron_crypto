const { app, BrowserWindow } = require('electron')

function createWindow() {
  // 创建浏览器窗口
  const win = new BrowserWindow({
    width: 10000,
    height: 10000,
    webPreferences: {
      nodeIntegration: true
    }
  })
  win.maximize()
  // 并且为你的应用加载index.html
  win.loadFile('index.html')
  //electron. --inspect启动调试
  // win.webContents.openDevTools();
}

app.whenReady().then(createWindow)

// 当全部窗口关闭时退出。
app.on('window-all-closed', () => {
  // 在 macOS 上，除非用户用 Cmd + Q 确定地退出，
  // 否则绝大部分应用及其菜单栏会保持激活。
  if (process.platform !== 'darwin') {
    app.quit();
  }
});
