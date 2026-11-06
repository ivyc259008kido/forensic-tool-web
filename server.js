const express = require("express");
const multer = require("multer");
const fs = require("fs");
const { parseLine, aggregateByIp, judgeIp, EXCLUDED_IPS } = require("./bruteforce.js");
const { analyzeFile } = require("./scan.js");

const app = express();
const PORT = 3000;

app.use(express.static("public"));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads/"),
  filename: (req, file, cb) => {
    const unique = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, unique + "-" + file.originalname);
  },
});
const upload = multer({ storage });

app.post("/upload-log", upload.single("logfile"), (req, res) => {
  const logPath = req.file.path;
  const lines = fs.readFileSync(logPath, "utf-8").split("\n");

  const events = [];
  for (const line of lines) {
    if (!line.trim()) continue;
    const parsed = parseLine(line, new Date().getFullYear());
    if (!parsed) continue;
    if (EXCLUDED_IPS.includes(parsed.ip)) continue;
    events.push(parsed);
  }

  if (events.length === 0) {
    return res.send("<p>解析対象のログが見つかりませんでした。</p><a href='/'>戻る</a>");
  }

  const ipMap = aggregateByIp(events);
  const results = [...ipMap.values()].map((entry) => judgeIp(entry, 5, 3));

  const levelColor = { critical: "#c1443c", warning: "#e07a3f", normal: "#2f7d6e" };
  const levelLabel = { critical: "🔴 危険", warning: "⚠ 警告", normal: "正常" };

  let rows = "";
  for (const r of results) {
    rows += `
      <tr>
        <td>${r.ip}</td>
        <td>${r.failedCount}回</td>
        <td>${r.acceptedCount}回</td>
        <td style="color:${levelColor[r.level]};font-weight:700">${levelLabel[r.level]}</td>
      </tr>`;
  }

  const html = `
    <!DOCTYPE html>
    <html lang="ja">
    <head>
      <meta charset="UTF-8">
      <title>解析結果 - Forensics Tool Web</title>
      <link rel="stylesheet" href="/style.css">
    </head>
    <body>
      <div class="container">
        <h1>解析結果</h1>
        <p class="subtitle">SSHログの解析が完了しました</p>
        <table style="width:100%;border-collapse:collapse">
          <tr style="background:#0b3d91;color:#fff">
            <th style="padding:12px;text-align:left">IPアドレス</th>
            <th style="padding:12px;text-align:left">失敗回数</th>
            <th style="padding:12px;text-align:left">成功回数</th>
            <th style="padding:12px;text-align:left">判定</th>
          </tr>
          ${rows}
        </table>
        <br>
        <a href="/" style="color:#2f6fed">戻る</a>
      </div>
    </body>
    </html>
  `;

  res.send(html);
});

app.post("/upload-folder", upload.array("folderfiles"), (req, res) => {
  const files = req.files;

  if (!files || files.length === 0) {
    return res.send("<p>ファイルが見つかりませんでした。</p><a href='/'>戻る</a>");
  }

  const results = files.map((f) => {
    const fixedName = Buffer.from(f.originalname, "latin1").toString("utf8");
    const r = analyzeFile(f.path);
    r.name = fixedName;
    r.extension = fixedName.includes(".")
      ? fixedName.split(".").pop().toLowerCase()
      : "(なし)";
    return r;
  });
  
  const spoofColor = "#c1443c";
  const okColor = "#2f7d6e";
  const naColor = "#5b6b84";

  let rows = "";
  for (const r of results) {
    let color = naColor;
    let label = "対象外";
    if (r.isSuspicious) {
      color = spoofColor;
      label = "⚠ 拡張子偽装の疑い";
    } else if (r.expectedType) {
      color = okColor;
      label = "正常";
    }

    rows += `
      <tr>
        <td>${r.name}</td>
        <td>.${r.extension}</td>
        <td>${r.sizeBytes} B</td>
        <td style="color:${color};font-weight:700">${label}</td>
      </tr>`;
  }

  const html = `
    <!DOCTYPE html>
    <html lang="ja">
    <head>
      <meta charset="UTF-8">
      <title>ファイル解析結果 - Forensics Tool Web</title>
      <link rel="stylesheet" href="/style.css">
    </head>
    <body>
      <div class="container">
        <h1>ファイル解析結果</h1>
        <p class="subtitle">${results.length}件のファイルを解析しました</p>
        <table style="width:100%;border-collapse:collapse">
          <tr style="background:#0b3d91;color:#fff">
            <th style="padding:12px;text-align:left">ファイル名</th>
            <th style="padding:12px;text-align:left">拡張子</th>
            <th style="padding:12px;text-align:left">サイズ</th>
            <th style="padding:12px;text-align:left">判定</th>
          </tr>
          ${rows}
        </table>
        <br>
        <a href="/" style="color:#2f6fed">戻る</a>
      </div>
    </body>
    </html>
  `;

  res.send(html);
});

app.listen(PORT, () => {
  console.log("サーバーが起動しました: http://localhost:3000");
});