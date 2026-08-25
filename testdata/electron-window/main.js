const { BrowserWindow, app } = require("electron");

function openMain() {
  // POSITIVE. With node integration on, anything that becomes script in this window --
  // a remote resource, a rendered message, an injected string -- has the filesystem and
  // the process API, which turns every scripting bug in the page into code running on
  // the machine.
  return new BrowserWindow({
    width: 1200,
    webPreferences: { nodeIntegration: true, contextIsolation: false },
  });
}

function openSafely() {
  // NEGATIVE. The page gets a page and nothing else. Whatever the preload chooses to
  // expose is the whole of what is reachable.
  return new BrowserWindow({
    width: 1200,
    webPreferences: { nodeIntegration: false, contextIsolation: true, preload: "./preload.js" },
  });
}

app.whenReady().then(openMain);

module.exports = { openMain, openSafely };
