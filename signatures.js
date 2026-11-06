// マジックバイト（ファイルシグネチャ）判定表
// 各形式の「ファイル先頭の決まった目印（16進数）」を定義する。
// 参考: https://en.wikipedia.org/wiki/List_of_file_signatures

const SIGNATURES = [
  { type: "PNG画像",   extensions: ["png"],         hexPrefix: "89504e47" },
  { type: "JPEG画像",  extensions: ["jpg", "jpeg"],  hexPrefix: "ffd8ff" },
  { type: "GIF画像",   extensions: ["gif"],          hexPrefix: "474946" },
  { type: "PDF文書",   extensions: ["pdf"],          hexPrefix: "25504446" },
  // docx/xlsx/pptx/zipはすべて内部的にZIP形式(PK)なので同じシグネチャになる
  { type: "ZIP系(docx/xlsx/pptx/zip)", extensions: ["docx", "xlsx", "pptx", "zip"], hexPrefix: "504b0304" },
  { type: "Windows実行ファイル(EXE)",  extensions: ["exe", "dll"], hexPrefix: "4d5a" },
  { type: "RAR書庫",   extensions: ["rar"],          hexPrefix: "526172211a0700" },
];

/**
 * ファイル先頭バイトを16進数文字列に変換して返す
 * @param {Buffer} buffer ファイルの先頭数バイト
 * @returns {string} 例 "89504e47"
 */
function toHexPrefix(buffer) {
  return buffer.toString("hex");
}

/**
 * 与えられた拡張子から「本来期待されるシグネチャ」を探す
 * @param {string} ext 拡張子（ドットなし、小文字）例: "jpg"
 * @returns {object|null}
 */
function findSignatureByExtension(ext) {
  return SIGNATURES.find((sig) => sig.extensions.includes(ext)) || null;
}

/**
 * ファイル先頭バイトの16進数から、実際の形式を推定する
 * @param {string} hexPrefix
 * @returns {object|null}
 */
function detectTypeByHex(hexPrefix) {
  return (
    SIGNATURES.find((sig) => hexPrefix.startsWith(sig.hexPrefix)) || null
  );
}

module.exports = { SIGNATURES, toHexPrefix, findSignatureByExtension, detectTypeByHex };
