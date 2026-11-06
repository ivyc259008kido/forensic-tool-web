const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { toHexPrefix, findSignatureByExtension, detectTypeByHex } = require("./signatures");

/**
 * 指定フォルダ以下を再帰的に走査し、全ファイルのパス一覧を取得する
 * @param {string} dirPath 走査対象フォルダ
 * @param {number} maxDepth 再帰する深さの上限(重くなりすぎ防止)
 * @param {number} currentDepth
 * @returns {string[]} ファイルパスの配列
 */
function walkDirectory(dirPath, maxDepth = 5, currentDepth = 0) {
  let results = [];
  if (currentDepth > maxDepth) return results;

  const entries = fs.readdirSync(dirPath, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dirPath, entry.name);
    if (entry.isDirectory()) {
      results = results.concat(walkDirectory(fullPath, maxDepth, currentDepth + 1));
    } else if (entry.isFile()) {
      results.push(fullPath);
    }
  }
  return results;
}

/**
 * ファイルのハッシュ値(MD5, SHA256)を計算する
 * @param {string} filePath
 * @returns {{md5: string, sha256: string}}
 */
function calculateHashes(filePath) {
  const fileBuffer = fs.readFileSync(filePath);
  const md5 = crypto.createHash("md5").update(fileBuffer).digest("hex");
  const sha256 = crypto.createHash("sha256").update(fileBuffer).digest("hex");
  return { md5, sha256 };
}

/**
 * 拡張子偽装をチェックする
 * 拡張子から期待される形式と、実際の先頭バイトから判定した形式を比較する
 * @param {string} filePath
 * @param {string} ext 拡張子（ドットなし、小文字）
 * @returns {{expected: string|null, actual: string|null, isSuspicious: boolean}}
 */
function checkExtensionSpoofing(filePath, ext) {
  // 先頭16バイトだけ読めば判定には十分
  const fd = fs.openSync(filePath, "r");
  const buffer = Buffer.alloc(16);
  const bytesRead = fs.readSync(fd, buffer, 0, 16, 0);
  fs.closeSync(fd);

  const hexPrefix = toHexPrefix(buffer.subarray(0, bytesRead));
  const expectedSig = findSignatureByExtension(ext);
  const actualSig = detectTypeByHex(hexPrefix);

  // 判定表に載っていない拡張子(txtなど)は「対象外」として偽装判定しない
  if (!expectedSig) {
    return { expected: null, actual: actualSig ? actualSig.type : null, isSuspicious: false };
  }

  // 期待される形式のシグネチャが実際の先頭バイトと一致するか
  const isMatch = hexPrefix.startsWith(expectedSig.hexPrefix);

  return {
    expected: expectedSig.type,
    actual: actualSig ? actualSig.type : "不明な形式",
    isSuspicious: !isMatch,
  };
}

/**
 * 1ファイル分の全情報(メタデータ+ハッシュ+偽装判定)をまとめて取得する
 * @param {string} filePath
 * @returns {object}
 */
function analyzeFile(filePath) {
  const stat = fs.statSync(filePath);
  const ext = path.extname(filePath).toLowerCase().replace(".", "");
  const hashes = calculateHashes(filePath);
  const spoofCheck = checkExtensionSpoofing(filePath, ext);

  return {
    path: filePath,
    name: path.basename(filePath),
    extension: ext || "(なし)",
    sizeBytes: stat.size,
    createdAt: stat.birthtime,
    modifiedAt: stat.mtime,
    accessedAt: stat.atime,
    md5: hashes.md5,
    sha256: hashes.sha256,
    expectedType: spoofCheck.expected,
    actualType: spoofCheck.actual,
    isSuspicious: spoofCheck.isSuspicious,
  };
}

/**
 * 指定フォルダ全体をスキャンし、結果の配列を返す
 * @param {string} targetDir
 * @returns {object[]}
 */
function scanFolder(targetDir) {
  const filePaths = walkDirectory(targetDir);
  return filePaths.map((filePath) => analyzeFile(filePath));
}

module.exports = { walkDirectory, calculateHashes, checkExtensionSpoofing, analyzeFile, scanFolder };
