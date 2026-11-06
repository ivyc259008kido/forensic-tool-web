// bruteforce.js
// SSHのログファイル（auth.log形式）を解析し、総当たり攻撃（ブルートフォース攻撃）の
// 疑いがあるIPアドレスを検出する
//
// 使い方:
//   node bruteforce.js <ログファイルのパス> [失敗回数のしきい値] [ユーザー名種類数のしきい値] [年]
//
// 例:
//   node bruteforce.js test_auth.log
//   node bruteforce.js /var/log/auth.log 5
//   node bruteforce.js test_auth.log 5 3 2026   ← ログに年が含まれない形式のため、年を指定できる
//
// しきい値の考え方:
//   失敗回数のしきい値（デフォルト5回）  … 同一ユーザーへの総当たり攻撃を検出する基準
//                                         （fail2banなど一般的なセキュリティツールの目安に合わせた）
//   ユーザー名種類数のしきい値（デフォルト3回）… 辞書攻撃（複数ユーザー名を試す攻撃）を検出する基準
//                                         正当なアクセスで3種類以上のユーザー名を試すことは
//                                         通常考えにくいため、失敗回数より低めに設定している
//
// 対応しているログの形式:
//   旧形式（Ubuntu/Debian系の /var/log/auth.log の標準的な形式）:
//     Aug 29 21:29:40 myhost sshd[12345]: Failed password for invalid user admin from 203.0.113.5 port 51234 ssh2
//     Aug 29 21:29:50 myhost sshd[12349]: Accepted password for root from 203.0.113.5 port 51238 ssh2
//   新形式（systemd-journald経由で出力される場合のISO8601形式）:
//     2026-07-28T09:15:51.909871+00:00 target-ubuntu sshd-session[1614]: Failed password for testuser from 192.168.100.20 port 53676 ssh2

const fs = require("fs");

// 集計対象から除外するIPアドレス（自分の管理アクセス用）
// 例：Windows側からSCPでログを取得した際の自分自身のアクセスなど、
// 攻撃ではない正当なアクセスのIPをここに追加する
const EXCLUDED_IPS = ["192.168.56.1"];

function formatDate(date) {
    const d = new Date(date);
    const pad = (n) => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(
        d.getHours()
    )}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

// "Aug 29 21:29:40" のような年なしの日時文字列を、指定された年のDateオブジェクトに変換する
function parseSyslogDate(monthDayTime, year) {
    // 例: "Aug 29 21:29:40" → "Aug 29 2026 21:29:40"
    const parts = monthDayTime.trim().split(/\s+/); // [Aug, 29, 21:29:40]
    const dateStr = `${parts[0]} ${parts[1]} ${year} ${parts[2]}`;
    return new Date(dateStr);
}

// 1行のログを解析し、意味のある情報を取り出す
function parseLine(line, year) {
    let timestamp;

    // 新形式: 2026-07-28T09:15:51.909871+00:00
    const isoMatch = line.match(/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})/);
    // 旧形式: Aug 29 21:29:40
    const syslogMatch = line.match(/^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/);

    if (isoMatch) {
        timestamp = new Date(isoMatch[1]);
    } else if (syslogMatch) {
        timestamp = parseSyslogDate(syslogMatch[1], year);
    } else {
        return null;
    }

    // ログイン失敗（無効なユーザー名を含む場合と、既存ユーザーの場合の両方に対応）
    const failedMatch = line.match(
        /Failed password for (invalid user\s+)?(\S+) from ([\d.]+) port (\d+)/
    );
    if (failedMatch) {
        return {
            timestamp,
            type: "failed",
            user: failedMatch[2],
            isInvalidUser: !!failedMatch[1],
            ip: failedMatch[3],
        };
    }

    // ログイン成功
    const acceptedMatch = line.match(
        /Accepted password for (\S+) from ([\d.]+) port (\d+)/
    );
    if (acceptedMatch) {
        return {
            timestamp,
            type: "accepted",
            user: acceptedMatch[1],
            ip: acceptedMatch[2],
        };
    }

    return null; // 対象外の行（このツールが扱わないログ種別）
}

// IPごとに集計する
function aggregateByIp(events) {
    const ipMap = new Map();

    for (const ev of events) {
        if (!ipMap.has(ev.ip)) {
            ipMap.set(ev.ip, {
                ip: ev.ip,
                failedCount: 0,
                acceptedCount: 0,
                attemptedUsers: new Set(),
                events: [],
            });
        }
        const entry = ipMap.get(ev.ip);
        entry.events.push(ev);
        if (ev.type === "failed") {
            entry.failedCount += 1;
            entry.attemptedUsers.add(ev.user);
        } else if (ev.type === "accepted") {
            entry.acceptedCount += 1;
        }
    }

    return ipMap;
}

// 各IPについて、しきい値をもとに疑わしさを判定する
// failThreshold: 失敗回数のしきい値（総当たり攻撃の検出用）
// userThreshold: 試行されたユーザー名の種類数のしきい値（辞書攻撃の検出用）
function judgeIp(entry, failThreshold, userThreshold) {
    // イベントを時系列に並べる
    const sorted = [...entry.events].sort((a, b) => a.timestamp - b.timestamp);

    // 「失敗が続いた後に成功」しているかどうか（＝侵入成功の疑い、最も危険）
    // ここでの判定は「失敗回数のしきい値」を基準にする
    let breachedAfterFailures = false;
    let failuresBeforeBreach = 0;
    let runningFailures = 0;
    for (const ev of sorted) {
        if (ev.type === "failed") {
            runningFailures += 1;
        } else if (ev.type === "accepted" && runningFailures >= failThreshold) {
            breachedAfterFailures = true;
            failuresBeforeBreach = runningFailures;
            break;
        }
    }

    const isBruteForce = entry.failedCount >= failThreshold;
    const isDictionaryAttack = entry.attemptedUsers.size >= userThreshold;

    let level = "normal";
    if (breachedAfterFailures) {
        level = "critical"; // 総当たり成功の疑い
    } else if (isBruteForce || isDictionaryAttack) {
        level = "warning"; // 総当たりの疑いはあるが、成功はしていない
    }

    return {
        ...entry,
        attemptedUsers: [...entry.attemptedUsers],
        firstSeen: sorted[0].timestamp,
        lastSeen: sorted[sorted.length - 1].timestamp,
        isBruteForce,
        isDictionaryAttack,
        breachedAfterFailures,
        failuresBeforeBreach,
        level,
    };
}

function printReport(results, failThreshold, userThreshold) {
    const critical = results.filter((r) => r.level === "critical");
    const warning = results.filter((r) => r.level === "warning");

    console.log("=== SSHログ 総当たり攻撃検出結果 ===");
    console.log(`失敗回数のしきい値: ${failThreshold}回／ユーザー名種類数のしきい値: ${userThreshold}種類`);
    console.log(`解析したIPアドレス数: ${results.length}件`);
    console.log(`🔴 侵入成功の疑い: ${critical.length}件`);
    console.log(`⚠ 総当たり攻撃の疑い（成功はしていない）: ${warning.length}件`);
    console.log("");

    for (const r of results) {
        console.log("--------------------------------------------------");
        console.log(`IPアドレス: ${r.ip}`);
        console.log(`失敗回数: ${r.failedCount}回`);
        console.log(`成功回数: ${r.acceptedCount}回`);
        console.log(`試行されたユーザー名: ${r.attemptedUsers.join(", ") || "なし"}`);
        console.log(`最初のアクセス: ${formatDate(r.firstSeen)}`);
        console.log(`最後のアクセス: ${formatDate(r.lastSeen)}`);

        if (r.level === "critical") {
            console.log(
                `判定: 🔴 危険 - ${r.failuresBeforeBreach}回失敗した後にログイン成功。侵入された可能性が高い`
            );
        } else if (r.level === "warning") {
            const reasons = [];
            if (r.isBruteForce) reasons.push(`失敗回数が${failThreshold}回以上`);
            if (r.isDictionaryAttack) reasons.push(`${userThreshold}種類以上のユーザー名を試行`);
            console.log(`判定: ⚠ 総当たり攻撃の疑い（${reasons.join(" / ")}）`);
        } else {
            console.log(`判定: 正常範囲`);
        }
    }
    console.log("--------------------------------------------------");
}

function saveAsJSON(results, outputPath) {
    const serializable = results.map((r) => ({
        ...r,
        firstSeen: formatDate(r.firstSeen),
        lastSeen: formatDate(r.lastSeen),
        events: undefined, // 生イベントは出力を軽くするため除外
    }));
    fs.writeFileSync(outputPath, JSON.stringify(serializable, null, 2), "utf-8");
}

function saveAsCSV(results, outputPath) {
    const headers = [
        "ip",
        "level",
        "failedCount",
        "acceptedCount",
        "attemptedUsers",
        "firstSeen",
        "lastSeen",
        "breachedAfterFailures",
        "failuresBeforeBreach",
    ];
    const lines = [headers.join(",")];

    for (const r of results) {
        const row = [
            r.ip,
            r.level,
            r.failedCount,
            r.acceptedCount,
            r.attemptedUsers.join(";"),
            formatDate(r.firstSeen),
            formatDate(r.lastSeen),
            r.breachedAfterFailures,
            r.failuresBeforeBreach,
        ].map((v) => `"${String(v).replace(/"/g, '""')}"`);
        lines.push(row.join(","));
    }

    const BOM = "\uFEFF";
    fs.writeFileSync(outputPath, BOM + lines.join("\n"), "utf-8");
}

function main() {
    const logPath = process.argv[2];
    const failThreshold = parseInt(process.argv[3], 10) || 5;   // 失敗回数のしきい値（デフォルト5回）
    const userThreshold = parseInt(process.argv[4], 10) || 3;   // ユーザー名種類数のしきい値（デフォルト3種類）
    const year = parseInt(process.argv[5], 10) || new Date().getFullYear();

    if (!logPath) {
        console.error("使い方: node bruteforce.js <ログファイルのパス> [失敗回数のしきい値] [ユーザー名種類数のしきい値] [年]");
        console.error("例: node bruteforce.js test_auth.log 5 3 2026");
        process.exit(1);
    }

    if (!fs.existsSync(logPath)) {
        console.error(`エラー: ログファイルが見つかりません -> ${logPath}`);
        process.exit(1);
    }

    const lines = fs.readFileSync(logPath, "utf-8").split("\n");
    const events = [];
    let excludedCount = 0;

    for (const line of lines) {
        if (!line.trim()) continue;
        const parsed = parseLine(line, year);
        if (!parsed) continue;

        if (EXCLUDED_IPS.includes(parsed.ip)) {
            excludedCount += 1;
            continue; // 除外リストに含まれるIPはカウントしない
        }

        events.push(parsed);
    }

    if (excludedCount > 0) {
        console.log(`除外リストのIP（${EXCLUDED_IPS.join(", ")}）に該当するログを${excludedCount}件、集計対象から除外しました。\n`);
    }

    if (events.length === 0) {
        console.log("解析対象のログ（Failed password / Accepted password）が見つかりませんでした。");
        console.log("ログの形式が対応形式と異なる可能性があります。README.mdを確認してください。");
        return;
    }

    const ipMap = aggregateByIp(events);
    const results = [...ipMap.values()]
        .map((entry) => judgeIp(entry, failThreshold, userThreshold))
        // 危険なものが上に来るように並べ替え（critical → warning → normal）
        .sort((a, b) => {
            const order = { critical: 0, warning: 1, normal: 2 };
            return order[a.level] - order[b.level];
        });

    printReport(results, failThreshold, userThreshold);

    saveAsJSON(results, "bruteforce_result.json");
    saveAsCSV(results, "bruteforce_result.csv");

    console.log("\n結果を保存しました:");
    console.log(" - bruteforce_result.json");
    console.log(" - bruteforce_result.csv");
}

if(require.main === module){
main();
}

module.exports = { parseLine,aggregateByIp,judgeIp,EXCLUDED_IPS };