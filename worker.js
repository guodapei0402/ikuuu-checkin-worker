/**
 * ikuuu 自动签到 Cloudflare Worker - 重构版 v2.0
 * ================================================
 * 核心改进：
 * 1. 完全去掉外部桥接服务依赖，直接用 Cookie 签到
 * 2. 多域名自动探测 + 故障切换
 * 3. 更健壮的错误处理和重试机制
 * 4. 保留完整的 Telegram Bot 交互功能
 *
 * 环境变量配置：
 *   必选：
 *     TELEGRAM_BOT_TOKEN   - Telegram Bot Token
 *     TELEGRAM_CHAT_ID     - 你的 Telegram Chat ID
 *     ENCRYPTION_SECRET    - 加密密钥（用于加密保存账号数据）
 *     IKUUU_KV             - KV 命名空间绑定
 *   可选：
 *     ADMIN_ID             - 管理员 Telegram ID（默认同 CHAT_ID）
 *     RUN_TOKEN            - HTTP 触发签到的 Token
 *     TELEGRAM_WEBHOOK_SECRET - Webhook 安全 Token
 *     TIME_ZONE            - 时区（默认 Asia/Shanghai）
 *     BASE_URL             - 自定义 ikuuu 域名（默认自动探测）
 */

// ============================================================================
// 常量配置
// ============================================================================

/** ikuuu 已知域名列表（按优先级排序，会动态探测可用性） */
const IKUUU_DOMAINS = [
  "https://ikuuu.win",
  "https://ikuuu.fyi",
  "https://ikuuu.one",
  "https://ikuuu.art",
  "https://ikuuu.me",
  "https://ikuuu.pw",
  "https://ikuuu.top",
  "https://ikuuu.eu",
  "https://ikuuu.uk",
  "https://ikuuu.dev",
  "https://ikuuu.co",
  "https://ikuuu.boo",
  "https://ikuuu.de",
  "https://ikuuu.nl",
  "https://ikuuu.ch",
  "https://ikuuu.org",
  "https://ikuuu.live",
  "https://ikuuu.ltd",
];

const DEFAULT_TIME_ZONE = "Asia/Shanghai";
const DEFAULT_CHECKIN_TIME = "08:00";
const DEFAULT_TIMEOUT_MS = 30000;
const SESSION_TTL_SECONDS = 600;

// KV 存储键 - 保持与原版 v1 键名一致，确保数据兼容
const ACCOUNTS_KEY = "accounts:v1";
const STATUS_KEY = "status:v1";
const WATCH_KEY = "watch:v1";
const SCHEDULE_KEY = "schedule:v1";
const DOMAIN_CACHE_KEY = "domain:active:v1";

// ============================================================================
// 工具函数
// ============================================================================

function textResponse(body, status = 200) {
  return new Response(body, {
    status,
    headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" },
  });
}

function getString(env, key, fallback = "") {
  const v = env[key];
  return typeof v === "string" && v.trim() ? v.trim() : fallback;
}

function parsePositiveInt(v, fallback) {
  const n = Number.parseInt(v, 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

function maskEmail(email) {
  const s = String(email || "");
  const at = s.indexOf("@");
  if (at <= 1) return s ? `${s[0] || "*"}***` : "unknown";
  return `${s.slice(0, 2)}***${s.slice(at)}`;
}

function isValidTimeString(v) {
  return /^([01]\d|2[0-3]):([0-5]\d)$/.test(String(v || ""));
}

function formatDate(tz) {
  return new Date().toLocaleString("zh-CN", { timeZone: tz, hour12: false });
}

function formatTimestamp(ts, tz) {
  if (!ts) return "暂无";
  return new Date(ts).toLocaleString("zh-CN", { timeZone: tz, hour12: false });
}

function getLocalTimeParts(tz, date = new Date()) {
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone: tz,
    year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
    hour12: false,
  }).formatToParts(date).reduce((a, p) => { a[p.type] = p.value; return a; }, {});
  return {
    year: +parts.year, month: +parts.month, day: +parts.day,
    hour: +parts.hour, minute: +parts.minute, second: +parts.second,
    dateText: `${parts.year}-${parts.month}-${parts.day}`,
    timeText: `${parts.hour}:${parts.minute}`,
  };
}

function looksLikeCookie(text) {
  const v = String(text || "").trim();
  return v.includes("=") && v.includes(";") &&
    /(?:uid|email|key|ip|session|token|remember|auth)/i.test(v);
}

function emailFromCookie(cookie) {
  const m = /(?:^|;\s*)email=([^;]+)/i.exec(cookie);
  if (!m) return "";
  try { return decodeURIComponent(m[1]); } catch { return m[1]; }
}

function emailFromHtml(html) {
  return /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i.exec(html)?.[0] || "";
}

// ============================================================================
// 加密解密（AES-GCM）
// ============================================================================

function base64UrlEncode(bytes) {
  let b = ""; for (const x of bytes) b += String.fromCharCode(x);
  return btoa(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlDecode(v) {
  const p = v.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((v.length + 3) % 4);
  const b = atob(p);
  return Uint8Array.from(b, c => c.charCodeAt(0));
}

async function deriveKey(secret, saltVersion = "v1") {
  const saltText = `ikuuu-cf-worker:${saltVersion}`;
  const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: new TextEncoder().encode(saltText), iterations: 100000, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

function getEncryptionSecret(env) {
  const s = getString(env, "ENCRYPTION_SECRET");
  if (!s) throw new Error("缺少 ENCRYPTION_SECRET，请配置用于加密保存账号的 Secret");
  return s;
}

async function encryptJson(env, value) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  // 新数据始终使用 v1 salt 保持兼容（与原版一致）
  const key = await deriveKey(getEncryptionSecret(env), "v1");
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(JSON.stringify(value)));
  return JSON.stringify({ v: 1, iv: base64UrlEncode(iv), data: base64UrlEncode(new Uint8Array(ct)) });
}

async function decryptJson(env, payload) {
  const p = JSON.parse(payload);
  if (!p || !p.iv || !p.data) throw new Error("账号数据格式无效");
  const secret = getEncryptionSecret(env);
  const ivBytes = base64UrlDecode(p.iv);
  const dataBytes = base64UrlDecode(p.data);
  // 按优先级尝试不同 salt 版本解密（v1 是原版使用的）
  const salts = ["v1", "v2"];
  for (const salt of salts) {
    try {
      const key = await deriveKey(secret, salt);
      const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: ivBytes }, key, dataBytes);
      return JSON.parse(new TextDecoder().decode(pt));
    } catch {
      // 解密失败，尝试下一个 salt
      continue;
    }
  }
  throw new Error("账号数据解密失败：请检查 ENCRYPTION_SECRET 是否正确");
}

// ============================================================================
// 配置构建
// ============================================================================

function buildTelegramConfig(env) {
  return {
    telegramBotToken: getString(env, "TELEGRAM_BOT_TOKEN"),
    telegramChatId: getString(env, "TELEGRAM_CHAT_ID"),
    adminId: getString(env, "ADMIN_ID", getString(env, "TELEGRAM_CHAT_ID")),
    webhookSecret: getString(env, "TELEGRAM_WEBHOOK_SECRET"),
  };
}

function buildConfig(env) {
  return {
    ...buildTelegramConfig(env),
    baseUrl: getString(env, "BASE_URL"),  // 空则自动探测
    runToken: getString(env, "RUN_TOKEN"),
    timeZone: getString(env, "TIME_ZONE", DEFAULT_TIME_ZONE),
    timeoutMs: parsePositiveInt(env.BRIDGE_TIMEOUT_MS, DEFAULT_TIMEOUT_MS),
  };
}

function isTelegramConfigured(c) {
  return Boolean(c.telegramBotToken && c.telegramChatId);
}

// ============================================================================
// KV 存储操作
// ============================================================================

function assertKv(env) {
  if (!env.IKUUU_KV) throw new Error("缺少 IKUUU_KV 绑定，请检查 wrangler.toml");
}

function normalizeAccounts(accounts) {
  if (!Array.isArray(accounts)) return [];
  return accounts.map(item => {
    if (Array.isArray(item) && item.length >= 1) {
      return { email: String(item[0] || ""), password: String(item[1] || ""), cookie: String(item[2] || ""), clashUrl: String(item[3] || "") };
    }
    if (item && typeof item === "object" && (item.email || item.cookie)) {
      return {
        email: String(item.email || ""),
        password: String(item.password || ""),
        cookie: String(item.cookie || ""),
        clashUrl: String(item.clashUrl || item.clash || ""),
      };
    }
    return null;
  }).filter(Boolean);
}

async function readAccounts(env) {
  assertKv(env);
  const stored = await env.IKUUU_KV.get(ACCOUNTS_KEY);
  if (stored) return normalizeAccounts(await decryptJson(env, stored));
  // 兼容环境变量
  const raw = getString(env, "ACCOUNTS_JSON");
  if (!raw) return [];
  try { return normalizeAccounts(JSON.parse(raw)); }
  catch (e) { throw new Error(`ACCOUNTS_JSON 不是合法 JSON：${e.message}`); }
}

async function writeAccounts(env, accounts) {
  assertKv(env);
  await env.IKUUU_KV.put(ACCOUNTS_KEY, await encryptJson(env, normalizeAccounts(accounts)));
}

async function readStatus(env) {
  assertKv(env);
  const s = await env.IKUUU_KV.get(STATUS_KEY, "json");
  return (s && typeof s === "object") ? s : null;
}

async function writeStatus(env, status) {
  assertKv(env);
  await env.IKUUU_KV.put(STATUS_KEY, JSON.stringify(status));
}

async function readSchedule(env) {
  assertKv(env);
  const v = await env.IKUUU_KV.get(SCHEDULE_KEY, "json");
  if (v && typeof v === "object" && /^\d{2}:\d{2}$/.test(String(v.time || ""))) return v;
  return { time: DEFAULT_CHECKIN_TIME };
}

async function writeSchedule(env, time) {
  assertKv(env);
  await env.IKUUU_KV.put(SCHEDULE_KEY, JSON.stringify({ time }));
}

function scheduleRunKey(dateText) { return `schedule-run:v1:${dateText}`; }

async function hasScheduledRunToday(env, dateText) {
  assertKv(env);
  return Boolean(await env.IKUUU_KV.get(scheduleRunKey(dateText)));
}

async function markScheduledRunToday(env, dateText) {
  assertKv(env);
  await env.IKUUU_KV.put(scheduleRunKey(dateText), "1", { expirationTtl: 3 * 24 * 3600 });
}

async function readWatch(env) {
  assertKv(env);
  const w = await env.IKUUU_KV.get(WATCH_KEY, "json");
  return (w && typeof w === "object") ? w : null;
}

async function writeWatch(env, watch) {
  assertKv(env);
  await env.IKUUU_KV.put(WATCH_KEY, JSON.stringify(watch));
}

async function clearWatch(env) {
  assertKv(env);
  await env.IKUUU_KV.delete(WATCH_KEY);
}

function sessionKey(chatId) { return `session:${chatId}`; }

async function readSession(env, chatId) {
  assertKv(env);
  const r = await env.IKUUU_KV.get(sessionKey(chatId), "json");
  return (r && typeof r === "object") ? r : null;
}

async function writeSession(env, chatId, session) {
  assertKv(env);
  await env.IKUUU_KV.put(sessionKey(chatId), JSON.stringify(session), { expirationTtl: SESSION_TTL_SECONDS });
}

async function clearSession(env, chatId) {
  assertKv(env);
  await env.IKUUU_KV.delete(sessionKey(chatId));
}

// 缓存可用域名
async function getCachedDomain(env) {
  assertKv(env);
  const d = await env.IKUUU_KV.get(DOMAIN_CACHE_KEY, "json");
  if (d && typeof d === "object" && d.url && d.ts) {
    // 缓存 6 小时有效
    if (Date.now() - d.ts < 6 * 3600 * 1000) return d.url;
  }
  return null;
}

async function setCachedDomain(env, url) {
  assertKv(env);
  await env.IKUUU_KV.put(DOMAIN_CACHE_KEY, JSON.stringify({ url, ts: Date.now() }), { expirationTtl: 24 * 3600 });
}

// ============================================================================
// 账号管理
// ============================================================================

async function saveAccount(env, account) {
  const accounts = await readAccounts(env);
  const norm = normalizeAccounts([account])[0];
  if (!norm) throw new Error("账号数据无效");
  const idx = accounts.findIndex(a => a.email && norm.email && a.email === norm.email);
  if (idx >= 0) accounts[idx] = { ...accounts[idx], ...norm };
  else accounts.push(norm);
  await writeAccounts(env, accounts);
  return accounts.length;
}

async function saveCookieAccount(env, account) {
  const accounts = await readAccounts(env);
  const norm = normalizeAccounts([account])[0];
  if (!norm || !norm.cookie) throw new Error("Cookie 账号数据无效");
  const idx = accounts.findIndex(a => a.email && norm.email && a.email === norm.email);
  if (idx >= 0) accounts[idx] = { ...accounts[idx], ...norm };
  else accounts.push(norm);
  await writeAccounts(env, accounts);
  return accounts.length;
}

// ============================================================================
// HTTP 请求（带超时）
// ============================================================================

async function fetchWithTimeout(url, init, timeoutMs = DEFAULT_TIMEOUT_MS) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort("request timeout"), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}

// ============================================================================
// 核心：多域名探测 + Cookie 直接签到
// ============================================================================

/**
 * 探测可用的 ikuuu 域名
 * 策略：并发 HEAD 请求所有域名，返回第一个响应正常的
 */
async function probeActiveDomain(env, config) {
  // 1. 如果用户手动配置了 BASE_URL，直接用
  if (config.baseUrl) return config.baseUrl.replace(/\/+$/, "");

  // 2. 检查缓存
  const cached = await getCachedDomain(env);
  if (cached) return cached;

  // 3. 并发探测
  console.log("开始探测可用 ikuuu 域名...");
  const results = await Promise.allSettled(
    IKUUU_DOMAINS.map(async (domain) => {
      const resp = await fetchWithTimeout(`${domain}/auth/login`, {
        method: "GET",
        headers: { "User-Agent": "Mozilla/5.0 ikuuu-worker/2.0" },
        redirect: "follow",
      }, 8000);
      if (resp.ok || resp.status === 302 || resp.status === 301) {
        return domain;
      }
      throw new Error(`${domain} HTTP ${resp.status}`);
    })
  );

  for (const r of results) {
    if (r.status === "fulfilled") {
      console.log(`探测到可用域名：${r.value}`);
      await setCachedDomain(env, r.value);
      return r.value;
    }
  }

  // 4. 全部失败，使用默认
  const fallback = IKUUU_DOMAINS[0];
  console.log(`所有域名探测失败，使用默认：${fallback}`);
  return fallback;
}

/**
 * 使用 Cookie 直接签到（核心函数）
 * 不再依赖任何外部桥接服务
 */
async function checkinWithCookie(baseUrl, cookie, timeoutMs) {
  const headers = {
    "Cookie": cookie,
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "application/json, text/javascript, */*; q=0.01",
    "X-Requested-With": "XMLHttpRequest",
    "Referer": `${baseUrl}/user`,
    "Origin": baseUrl,
  };

  // 先验证 Cookie 是否有效（访问用户页面）
  const userResp = await fetchWithTimeout(`${baseUrl}/user`, {
    method: "GET",
    headers: { ...headers, Accept: "text/html,*/*" },
    redirect: "manual",
  }, timeoutMs);

  // 302 跳转到登录页 = Cookie 已失效
  if (userResp.status === 301 || userResp.status === 302) {
    const location = userResp.headers.get("Location") || "";
    if (/auth\/login|login/i.test(location)) {
      return { success: false, error: "Cookie 已过期，请重新导入", needRelogin: true };
    }
  }

  if (!userResp.ok && userResp.status !== 200) {
    const text = await userResp.text().catch(() => "");
    if (/auth\/login|登录|请登录/i.test(text)) {
      return { success: false, error: "Cookie 已过期，请重新导入", needRelogin: true };
    }
    // 可能是域名问题，不是 Cookie 问题
    return { success: false, error: `访问用户页面失败：HTTP ${userResp.status}`, domainError: true };
  }

  // 执行签到
  const checkinResp = await fetchWithTimeout(`${baseUrl}/user/checkin`, {
    method: "POST",
    headers,
  }, timeoutMs);

  const text = await checkinResp.text();

  let data;
  try {
    data = JSON.parse(text);
  } catch {
    // 非 JSON 响应
    if (/auth\/login|登录/i.test(text)) {
      return { success: false, error: "Cookie 已过期，请重新导入", needRelogin: true };
    }
    return { success: false, error: `签到接口返回非 JSON：HTTP ${checkinResp.status} ${text.slice(0, 200)}` };
  }

  // ikuuu 签到响应格式：
  // 成功：{ ret: 1, msg: "获得了 xxx MB 流量" }
  // 已签到：{ ret: 0, msg: "您似乎已经签到过了" }
  const alreadyCheckedIn = data.ret === 0 && data.msg &&
    /已.{0,3}签到|already|checked/i.test(data.msg);

  return {
    success: data.ret === 1 || alreadyCheckedIn,
    alreadyDone: alreadyCheckedIn,
    msg: data.msg || (data.ret === 1 ? "签到成功" : "未知结果"),
    ret: data.ret,
    data,
  };
}

/**
 * 从用户页面提取账号信息和订阅链接
 */
async function fetchUserInfo(baseUrl, cookie, timeoutMs) {
  const resp = await fetchWithTimeout(`${baseUrl}/user`, {
    method: "GET",
    headers: {
      "Cookie": cookie,
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ikuuu-worker/2.0",
      "Accept": "text/html,*/*",
    },
    redirect: "manual",
  }, timeoutMs);

  if (resp.status === 301 || resp.status === 302) {
    throw new Error("Cookie 已过期或无效");
  }

  const html = await resp.text();
  if (/auth\/login|登录|请登录/i.test(html) && !emailFromHtml(html)) {
    throw new Error("Cookie 未登录或已过期");
  }

  return { email: emailFromCookie(cookie) || emailFromHtml(html) || `cookie-${Date.now()}`, html };
}

// ============================================================================
// 签到执行引擎
// ============================================================================

async function runCheckin(env, options = {}) {
  const shouldNotify = options.notify !== false;
  const config = buildConfig(env);
  const schedule = await readSchedule(env);
  const scheduleTime = isValidTimeString(schedule.time) ? schedule.time : DEFAULT_CHECKIN_TIME;
  const accounts = await readAccounts(env);
  const startedAt = new Date().toISOString();

  if (!accounts.length) {
    throw new Error("还没有账号，请先通过 /cookie 或 /add 导入账号");
  }

  // 筛选有 Cookie 的账号
  const cookieAccounts = accounts.filter(a => a.cookie);
  if (!cookieAccounts.length) {
    throw new Error(
      "没有可用的 Cookie 账号。\n" +
      "由于 ikuuu 启用了验证码保护，无法用密码自动登录。\n" +
      "请在浏览器登录后，通过 /cookie 命令导入 Cookie。"
    );
  }

  try {
    // 探测可用域名
    const baseUrl = await probeActiveDomain(env, config);
    console.log(`使用域名：${baseUrl}`);

    const results = [];
    let domainFailed = false;

    for (const account of cookieAccounts) {
      try {
        let result = await checkinWithCookie(baseUrl, account.cookie, config.timeoutMs);

        // 域名失败时尝试备用域名
        if (result.domainError && !config.baseUrl) {
          console.log(`域名 ${baseUrl} 访问失败，尝试备用域名...`);
          for (const altDomain of IKUUU_DOMAINS) {
            if (altDomain === baseUrl) continue;
            try {
              result = await checkinWithCookie(altDomain, account.cookie, config.timeoutMs);
              if (!result.domainError) {
                await setCachedDomain(env, altDomain);
                console.log(`切换到备用域名：${altDomain}`);
                break;
              }
            } catch { continue; }
          }
        }

        results.push({
          email: account.email || emailFromCookie(account.cookie) || "unknown",
          ...result,
        });
      } catch (err) {
        results.push({
          email: account.email || emailFromCookie(account.cookie) || "unknown",
          success: false,
          error: err.message || String(err),
        });
      }
    }

    // 汇总
    const successCount = results.filter(r => r.success).length;
    const failedCount = results.filter(r => !r.success).length;
    const summary = formatCheckinResult(results, config.timeZone, baseUrl);

    await writeStatus(env, {
      ok: successCount > 0,
      accountCount: cookieAccounts.length,
      resultCount: results.length,
      successCount,
      failedCount,
      startedAt,
      finishedAt: new Date().toISOString(),
      nextRunAt: nextRunTime(config.timeZone, scheduleTime),
      lastMessage: summary.slice(0, 3000),
      error: failedCount > 0 ? `${failedCount} 个账号签到失败` : "",
      domain: baseUrl,
    });

    await updateWatchPanel(env);
    if (shouldNotify) await sendTelegramMessage(env, summary);
    return summary;

  } catch (error) {
    await writeStatus(env, {
      ok: false,
      accountCount: cookieAccounts.length,
      resultCount: 0,
      successCount: 0,
      failedCount: cookieAccounts.length,
      startedAt,
      finishedAt: new Date().toISOString(),
      nextRunAt: nextRunTime(config.timeZone, scheduleTime),
      lastMessage: "",
      error: error?.message || String(error),
    });
    await updateWatchPanel(env);
    throw error;
  }
}

function formatCheckinResult(results, tz, domain) {
  const now = formatDate(tz);
  const lines = ["📋 ikuuu 签到任务汇总", "==============================", `📡 使用域名: ${domain}`, ""];

  for (const r of results) {
    lines.push(`账号：${maskEmail(r.email)}`);
    if (r.success) {
      if (r.alreadyDone) {
        lines.push(`ℹ️ 今日已签到`);
      } else {
        lines.push(`🎉 签到成功`);
      }
      if (r.msg) lines.push(`信息：${r.msg}`);
    } else {
      lines.push(`❌ 签到失败`);
      if (r.msg) lines.push(`信息：${r.msg}`);
      if (r.error) lines.push(`原因：${r.error}`);
      if (r.needRelogin) lines.push(`⚠️ 请重新导入 Cookie：/cookie`);
    }
    lines.push("");
  }

  const successCount = results.filter(r => r.success).length;
  lines.push(`✅ 成功: ${successCount}/${results.length}`);
  lines.push(`⏰ 执行时间: ${now}`);
  return lines.join("\n");
}

function nextRunTime(tz, timeText) {
  const now = new Date();
  const parts = getLocalTimeParts(tz, now);
  const [th, tm] = String(timeText || DEFAULT_CHECKIN_TIME).split(":").map(Number);
  const localNowUtc = Date.UTC(parts.year, parts.month - 1, parts.day, parts.hour, parts.minute, parts.second);
  const localTargetUtc = Date.UTC(parts.year, parts.month - 1, parts.day, th, tm, 0);
  const nextUtc = localNowUtc < localTargetUtc ? localTargetUtc : localTargetUtc + 86400000;
  return new Date(now.getTime() + (nextUtc - localNowUtc)).toISOString();
}

// ============================================================================
// Telegram 消息发送
// ============================================================================

async function sendTelegram(env, chatId, message) {
  const c = buildTelegramConfig(env);
  if (!c.telegramBotToken || !chatId) return;
  const resp = await fetch(`https://api.telegram.org/bot${c.telegramBotToken}/sendMessage`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ chat_id: chatId, text: message.slice(0, 3900), disable_web_page_preview: true }),
  });
  if (!resp.ok) console.log(`Telegram 推送失败：${resp.status}`);
}

async function sendTelegramKeyboard(env, chatId, message, keyboard) {
  const c = buildTelegramConfig(env);
  if (!c.telegramBotToken || !chatId) return;
  await fetch(`https://api.telegram.org/bot${c.telegramBotToken}/sendMessage`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ chat_id: chatId, text: message.slice(0, 3900), disable_web_page_preview: true, reply_markup: { inline_keyboard: keyboard } }),
  });
}

async function answerCallback(env, callbackId, text = "") {
  const c = buildTelegramConfig(env);
  if (!c.telegramBotToken || !callbackId) return;
  await fetch(`https://api.telegram.org/bot${c.telegramBotToken}/answerCallbackQuery`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ callback_query_id: callbackId, text: text.slice(0, 180), show_alert: false }),
  });
}

async function sendTelegramWithResult(env, chatId, message) {
  const c = buildTelegramConfig(env);
  if (!c.telegramBotToken || !chatId) return null;
  const resp = await fetch(`https://api.telegram.org/bot${c.telegramBotToken}/sendMessage`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ chat_id: chatId, text: message.slice(0, 3900), disable_web_page_preview: true }),
  });
  const data = await resp.json().catch(() => null);
  if (!resp.ok) return null;
  return data?.result || null;
}

async function editTelegramMessage(env, chatId, messageId, message) {
  const c = buildTelegramConfig(env);
  if (!c.telegramBotToken || !chatId || !messageId) return false;
  const resp = await fetch(`https://api.telegram.org/bot${c.telegramBotToken}/editMessageText`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ chat_id: chatId, message_id: messageId, text: message.slice(0, 3900), disable_web_page_preview: true }),
  });
  if (!resp.ok) { console.log(`Telegram 面板更新失败：${resp.status}`); return false; }
  return true;
}

async function sendTelegramMessage(env, message) {
  const c = buildTelegramConfig(env);
  if (!isTelegramConfigured(c)) return;
  await sendTelegram(env, c.telegramChatId, message);
}

async function notifyFailure(env, error, chatId = "") {
  const msg = `❌ ikuuu 签到执行失败：${error?.message || String(error)}`;
  console.log(msg);
  if (chatId) await sendTelegram(env, chatId, msg);
  else await sendTelegramMessage(env, msg);
  return msg;
}

// ============================================================================
// 状态面板
// ============================================================================

async function formatStatus(env) {
  const config = buildConfig(env);
  const accounts = await readAccounts(env);
  const status = await readStatus(env);
  const schedule = await readSchedule(env);
  const scheduleTime = isValidTimeString(schedule.time) ? schedule.time : DEFAULT_CHECKIN_TIME;
  const cookieCount = accounts.filter(a => a.cookie).length;
  const passwordCount = accounts.filter(a => a.password && !a.cookie).length;

  const lines = [
    "📊 ikuuu 自动签到状态",
    "==============================",
    `账号总数：${accounts.length}（Cookie: ${cookieCount}, 仅密码: ${passwordCount}）`,
    `自动签到时间：${scheduleTime}`,
  ];

  if (passwordCount > 0) {
    lines.push(`⚠️ ${passwordCount} 个仅密码账号无法签到，请导入 Cookie`);
  }

  if (!status) {
    lines.push(`上次执行：暂无`);
    lines.push(`下次预计：${formatTimestamp(nextRunTime(config.timeZone, scheduleTime), config.timeZone)}`);
    lines.push("状态：尚未执行过签到");
  } else {
    lines.push(`上次执行：${formatTimestamp(status.finishedAt, config.timeZone)}`);
    lines.push(`下次预计：${formatTimestamp(status.nextRunAt || nextRunTime(config.timeZone, scheduleTime), config.timeZone)}`);
    lines.push(`状态：${status.ok ? "✅ 正常" : "❌ 异常"}`);
    lines.push(`成功：${status.successCount ?? 0}`);
    lines.push(`失败：${status.failedCount ?? 0}`);
    if (status.domain) lines.push(`域名：${status.domain}`);
    if (status.error) lines.push(`错误：${status.error}`);
    if (status.lastMessage) lines.push("", "最近结果：", status.lastMessage.slice(0, 1200));
  }

  return lines.join("\n");
}

async function updateWatchPanel(env) {
  const watch = await readWatch(env);
  if (!watch || !watch.chatId || !watch.messageId) return;
  const ok = await editTelegramMessage(env, watch.chatId, watch.messageId, await formatStatus(env));
  if (!ok) await clearWatch(env);
}

// ============================================================================
// 定时签到
// ============================================================================

async function runScheduledCheckinIfNeeded(env) {
  const config = buildConfig(env);
  const schedule = await readSchedule(env);
  const time = isValidTimeString(schedule.time) ? schedule.time : DEFAULT_CHECKIN_TIME;
  const local = getLocalTimeParts(config.timeZone);
  if (local.timeText !== time) return;
  if (await hasScheduledRunToday(env, local.dateText)) return;
  await markScheduledRunToday(env, local.dateText);
  await runCheckin(env);
}

// ============================================================================
// Telegram Bot 命令处理
// ============================================================================

function helpText() {
  return [
    "ikuuu 签到机器人命令（v2.0 纯 Cookie 版）：",
    "════════════════════════════",
    "📌 账号管理：",
    "/cookie - 导入已验证登录态 Cookie（推荐）",
    "/add - 添加账号（仅保存，需另外导入 Cookie）",
    "/list - 查看账号列表",
    "/del 序号 - 删除指定账号",
    "/clear - 清空全部账号",
    "",
    "🚀 签到操作：",
    "/run - 立即签到",
    "/status - 查看当前状态",
    "/time HH:mm - 设置自动签到时间",
    "",
    "📊 监控面板：",
    "/watch - 创建自动更新状态面板",
    "/unwatch - 关闭面板",
    "",
    "⚙️ 其他：",
    "/domain - 查看/切换当前使用的域名",
    "/cancel - 取消当前输入",
    "/help - 查看帮助",
    "",
    "💡 提示：ikuuu 启用了验证码，无法用密码自动登录。",
    "请在浏览器完成验证后，复制 Cookie 通过 /cookie 导入。",
  ].join("\n");
}

function mainMenuText() {
  return [
    "ikuuu 签到控制面板 v2.0",
    "==============================",
    "✨ 纯 Cookie 签到，无需桥接服务",
    "点击下面按钮即可操作。",
  ].join("\n");
}

function mainMenuKeyboard() {
  return [
    [
      { text: "📋 账号列表", callback_data: "list" },
      { text: "🔑 导入 Cookie", callback_data: "cookie_import" },
    ],
    [
      { text: "🚀 立即签到", callback_data: "run" },
      { text: "📊 当前状态", callback_data: "status" },
    ],
    [
      { text: "⏰ 设置时间", callback_data: "time_set" },
      { text: "🔄 自动面板", callback_data: "watch" },
    ],
    [
      { text: "🛑 关闭面板", callback_data: "unwatch" },
      { text: "🌐 查看域名", callback_data: "domain" },
    ],
    [
      { text: "🗑 删除账号", callback_data: "delete_menu" },
      { text: "⚠️ 清空账号", callback_data: "clear_confirm" },
    ],
  ];
}

async function sendMainMenu(env, chatId) {
  await sendTelegramKeyboard(env, chatId, mainMenuText(), mainMenuKeyboard());
}

function isAdminMessage(message, env) {
  const adminId = buildTelegramConfig(env).adminId;
  return Boolean(adminId && message?.from && String(message.from.id) === String(adminId));
}

async function sendAccountList(env, chatId) {
  const accounts = await readAccounts(env);
  if (!accounts.length) {
    await sendTelegramKeyboard(env, chatId, "当前没有账号。点击下面按钮添加。", [[{ text: "🔑 导入 Cookie", callback_data: "cookie_import" }]]);
    return;
  }
  const lines = accounts.map((a, i) => {
    const status = a.cookie ? "🟢" : "🔴";
    return `${i + 1}. ${status} ${maskEmail(a.email)} ${a.cookie ? "(有Cookie)" : "(需导入Cookie)"}`;
  });
  await sendTelegram(env, chatId, lines.join("\n"));
}

async function sendDeleteMenu(env, chatId) {
  const accounts = await readAccounts(env);
  if (!accounts.length) {
    await sendTelegramKeyboard(env, chatId, "当前没有账号可删除。", [[{ text: "返回主菜单", callback_data: "menu" }]]);
    return;
  }
  const rows = accounts.map((a, i) => [{ text: `删除 ${i + 1}. ${maskEmail(a.email)}`, callback_data: `del:${i + 1}` }]);
  rows.push([{ text: "返回主菜单", callback_data: "menu" }]);
  await sendTelegramKeyboard(env, chatId, "选择要删除的账号：", rows);
}

async function startCookieImportFlow(env, chatId) {
  await writeSession(env, chatId, { flow: "import_cookie", step: "wait_cookie_import" });
  await sendTelegram(env, chatId, [
    "请直接发送 ikuuu 已验证 Cookie。",
    "",
    "获取方式：",
    "1. 浏览器打开 ikuuu.win 或 ikuuu.fyi",
    "2. 完成验证码并登录",
    "3. F12 打开开发者工具 → Application → Cookies",
    "4. 复制所有 Cookie（或用扩展一键复制）",
    "",
    "发送格式示例：uid=xxx; email=xxx; key=xxx; ip=xxx",
    "输入 /cancel 可取消。",
  ].join("\n"));
}

async function startTimeSetFlow(env, chatId) {
  const schedule = await readSchedule(env);
  await writeSession(env, chatId, { flow: "set_time", step: "wait_time" });
  await sendTelegram(env, chatId, `当前自动签到时间：${schedule.time}\n请发送新的北京时间，格式例如 08:00\n输入 /cancel 可取消。`);
}

async function startAddFlow(env, chatId) {
  await writeSession(env, chatId, { flow: "add_account", step: "wait_email" });
  await sendTelegram(env, chatId, [
    "开始添加 ikuuu 账号。",
    "请发送账号/邮箱。",
    "",
    "⚠️ 注意：由于 ikuuu 启用了验证码保护，仅保存密码无法自动登录。",
    "添加后还需要通过 /cookie 导入浏览器 Cookie 才能签到。",
    "推荐直接使用 /cookie 导入。",
    "",
    "输入 /cancel 可取消。",
  ].join("\n"));
}

// 主消息处理
async function handleTelegramUpdate(update, env) {
  const callback = update.callback_query;
  if (callback) { await handleCallback(callback, env); return; }

  const message = update.message || update.edited_message;
  if (!message || !message.chat || typeof message.text !== "string") return;

  const chatId = String(message.chat.id);
  if (!isAdminMessage(message, env)) {
    await sendTelegram(env, chatId, "无权限。只有管理员可以使用这个机器人。");
    return;
  }

  const text = message.text.trim();
  const command = text.split(/\s+/, 1)[0].toLowerCase().replace(/@.+$/, "");

  try {
    if (command === "/cancel") {
      await clearSession(env, chatId);
      await sendTelegram(env, chatId, "已取消当前输入流程。");
      return;
    }

    // 处理会话状态
    const session = await readSession(env, chatId);
    if (session && !text.startsWith("/")) {
      if (session.step === "wait_email") {
        await writeSession(env, chatId, { flow: "add_account", step: "wait_password", email: text });
        await sendTelegram(env, chatId, `已收到账号：${maskEmail(text)}\n请继续发送密码。\n输入 /cancel 可取消。`);
        return;
      }
      if (session.step === "wait_password" && session.email) {
        const count = await saveAccount(env, { email: session.email, password: text, cookie: "" });
        await clearSession(env, chatId);
        await sendTelegram(env, chatId, `✅ 已保存账号：${maskEmail(session.email)}\n当前账号数：${count}\n\n⚠️ 此账号需要导入 Cookie 才能签到。请用 /cookie 导入。\n🔒 建议删除刚才包含密码的消息。`);
        return;
      }
      if (session.step === "wait_cookie_import") {
        const config = buildConfig(env);
        const baseUrl = await probeActiveDomain(env, config);
        const info = await fetchUserInfo(baseUrl, text, config.timeoutMs);
        const count = await saveCookieAccount(env, { email: info.email, password: "", cookie: text });
        await clearSession(env, chatId);
        await sendTelegram(env, chatId, `✅ 已导入 Cookie 账号：${maskEmail(info.email)}\n当前账号数：${count}\n\n🔒 建议删除刚才包含 Cookie 的消息。`);
        return;
      }
      if (session.step === "wait_time") {
        if (!isValidTimeString(text)) {
          await sendTelegram(env, chatId, "时间格式错误，请发送 HH:mm，例如 08:00。\n输入 /cancel 可取消。");
          return;
        }
        await writeSchedule(env, text);
        await clearSession(env, chatId);
        await sendTelegram(env, chatId, `✅ 已设置自动签到时间为北京时间 ${text}`);
        return;
      }
      await clearSession(env, chatId);
    }

    // 直接发送 Cookie
    if (looksLikeCookie(text)) {
      const config = buildConfig(env);
      const baseUrl = await probeActiveDomain(env, config);
      const info = await fetchUserInfo(baseUrl, text, config.timeoutMs);
      const count = await saveCookieAccount(env, { email: info.email, password: "", cookie: text });
      await sendTelegram(env, chatId, `✅ 已识别并导入 Cookie 账号：${maskEmail(info.email)}\n当前账号数：${count}\n\n🔒 建议删除刚才包含 Cookie 的消息。`);
      return;
    }

    // 命令路由
    switch (command) {
      case "/start":
      case "/help":
      case "/menu":
        await sendMainMenu(env, chatId);
        break;

      case "/add": {
        const parts = text.split(/\s+/);
        if (parts.length >= 3) {
          const count = await saveAccount(env, { email: parts[1], password: parts.slice(2).join(" "), cookie: "" });
          await sendTelegram(env, chatId, `✅ 已保存账号：${maskEmail(parts[1])}\n当前账号数：${count}\n⚠️ 需导入 Cookie 才能签到。`);
        } else {
          await startAddFlow(env, chatId);
        }
        break;
      }

      case "/list":
        await sendAccountList(env, chatId);
        break;

      case "/cookie":
        await startCookieImportFlow(env, chatId);
        break;

      case "/time": {
        const val = text.split(/\s+/)[1] || "";
        if (val) {
          if (!isValidTimeString(val)) {
            await sendTelegram(env, chatId, "时间格式错误，请发送 /time HH:mm，例如 /time 08:00");
          } else {
            await writeSchedule(env, val);
            await sendTelegram(env, chatId, `✅ 已设置自动签到时间为北京时间 ${val}`);
          }
        } else {
          await startTimeSetFlow(env, chatId);
        }
        break;
      }

      case "/status":
        await sendTelegram(env, chatId, await formatStatus(env));
        break;

      case "/watch": {
        const sent = await sendTelegramWithResult(env, chatId, await formatStatus(env));
        if (!sent?.message_id) {
          await sendTelegram(env, chatId, "状态面板创建失败，请稍后重试。");
        } else {
          await writeWatch(env, { chatId, messageId: sent.message_id, createdAt: new Date().toISOString() });
          await sendTelegram(env, chatId, "✅ 自动更新状态面板已开启。每次签到后上面的状态消息会自动刷新。");
        }
        break;
      }

      case "/unwatch":
        await clearWatch(env);
        await sendTelegram(env, chatId, "✅ 已关闭自动更新状态面板。");
        break;

      case "/del": {
        const idx = Number.parseInt(text.split(/\s+/)[1], 10);
        const accounts = await readAccounts(env);
        if (!Number.isInteger(idx) || idx < 1 || idx > accounts.length) {
          await sendTelegram(env, chatId, "序号无效。先发送 /list 查看序号。");
        } else {
          const [removed] = accounts.splice(idx - 1, 1);
          await writeAccounts(env, accounts);
          await sendTelegram(env, chatId, `✅ 已删除账号：${maskEmail(removed.email)}`);
        }
        break;
      }

      case "/clear":
        await writeAccounts(env, []);
        await sendTelegram(env, chatId, "✅ 已清空全部账号。");
        break;

      case "/run":
        await sendTelegram(env, chatId, "🔄 开始执行 ikuuu 签到...");
        try {
          const result = await runCheckin(env, { notify: false });
          await sendTelegram(env, chatId, result);
        } catch (err) {
          await notifyFailure(env, err, chatId);
        }
        break;

      case "/domain": {
        const config = buildConfig(env);
        const cached = await getCachedDomain(env);
        const lines = ["🌐 域名信息："];
        if (config.baseUrl) lines.push(`手动配置：${config.baseUrl}`);
        if (cached) lines.push(`当前缓存：${cached}`);
        lines.push("", "可用域名列表：");
        lines.push(...IKUUU_DOMAINS.map((d, i) => `${i + 1}. ${d}`));
        lines.push("", "域名会在签到时自动探测并切换。");
        await sendTelegram(env, chatId, lines.join("\n"));
        break;
      }

      default:
        await sendTelegram(env, chatId, helpText());
    }
  } catch (error) {
    await notifyFailure(env, error, chatId);
  }
}

// Callback 处理
async function handleCallback(callback, env) {
  const chatId = callback.message?.chat?.id ? String(callback.message.chat.id) : "";
  if (!chatId) return;
  if (!callback.from || String(callback.from.id) !== String(buildTelegramConfig(env).adminId)) {
    await answerCallback(env, callback.id, "无权限");
    return;
  }
  const data = String(callback.data || "");
  await answerCallback(env, callback.id, "处理中...");

  try {
    switch (data) {
      case "menu":
        await sendMainMenu(env, chatId);
        break;

      case "list":
        await sendAccountList(env, chatId);
        break;

      case "status":
        await sendTelegramKeyboard(env, chatId, await formatStatus(env), [[{ text: "返回主菜单", callback_data: "menu" }]]);
        break;

      case "cookie_import":
        await startCookieImportFlow(env, chatId);
        break;

      case "time_set":
        await startTimeSetFlow(env, chatId);
        break;

      case "add":
        await startAddFlow(env, chatId);
        break;

      case "watch": {
        const sent = await sendTelegramWithResult(env, chatId, await formatStatus(env));
        if (!sent?.message_id) {
          await sendTelegram(env, chatId, "状态面板创建失败。");
        } else {
          await writeWatch(env, { chatId, messageId: sent.message_id, createdAt: new Date().toISOString() });
          await sendTelegram(env, chatId, "✅ 自动更新状态面板已开启。");
        }
        break;
      }

      case "unwatch":
        await clearWatch(env);
        await sendTelegram(env, chatId, "✅ 已关闭自动更新状态面板。");
        break;

      case "delete_menu":
        await sendDeleteMenu(env, chatId);
        break;

      case "domain": {
        const config = buildConfig(env);
        const cached = await getCachedDomain(env);
        const lines = ["🌐 域名信息："];
        if (config.baseUrl) lines.push(`手动配置：${config.baseUrl}`);
        if (cached) lines.push(`当前缓存：${cached}`);
        lines.push("", "域名会在签到时自动探测并切换。");
        await sendTelegramKeyboard(env, chatId, lines.join("\n"), [[{ text: "返回主菜单", callback_data: "menu" }]]);
        break;
      }

      case "run":
        await sendTelegram(env, chatId, "🔄 开始执行 ikuuu 签到...");
        try {
          const result = await runCheckin(env, { notify: false });
          await sendTelegram(env, chatId, result);
        } catch (err) {
          await notifyFailure(env, err, chatId);
        }
        break;

      case "clear_confirm":
        await sendTelegramKeyboard(env, chatId, "确认清空全部账号？此操作不可撤销。", [
          [{ text: "确认清空", callback_data: "clear_do" }, { text: "取消", callback_data: "menu" }],
        ]);
        break;

      case "clear_do":
        await writeAccounts(env, []);
        await sendTelegram(env, chatId, "✅ 已清空全部账号。");
        break;

      default:
        if (data.startsWith("del:")) {
          const idx = Number.parseInt(data.slice(4), 10);
          const accounts = await readAccounts(env);
          if (!Number.isInteger(idx) || idx < 1 || idx > accounts.length) {
            await sendTelegram(env, chatId, "序号无效，请重新打开删除菜单。");
          } else {
            const [removed] = accounts.splice(idx - 1, 1);
            await writeAccounts(env, accounts);
            await sendTelegram(env, chatId, `✅ 已删除账号：${maskEmail(removed.email)}`);
          }
        } else {
          await sendMainMenu(env, chatId);
        }
    }
  } catch (error) {
    await notifyFailure(env, error, chatId);
  }
}

// ============================================================================
// HTTP 认证
// ============================================================================

function isAuthorized(request, env) {
  const runToken = getString(env, "RUN_TOKEN");
  if (!runToken) return false;
  const url = new URL(request.url);
  const qt = url.searchParams.get("token") || "";
  const auth = request.headers.get("Authorization") || "";
  const bt = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
  return qt === runToken || bt === runToken;
}

// ============================================================================
// Worker 入口
// ============================================================================

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === "/health") {
      return textResponse("ok v2.0 - cookie direct checkin");
    }

    if (url.pathname === "/telegram/webhook") {
      if (request.method !== "POST") return textResponse("Method Not Allowed", 405);
      const secret = buildTelegramConfig(env).webhookSecret;
      if (secret && request.headers.get("X-Telegram-Bot-Api-Secret-Token") !== secret) {
        return textResponse("Unauthorized", 401);
      }
      const update = await request.json().catch(() => null);
      if (update) ctx.waitUntil(handleTelegramUpdate(update, env));
      return textResponse("ok");
    }

    if (url.pathname === "/run") {
      if (!["GET", "POST"].includes(request.method)) return textResponse("Method Not Allowed", 405);
      if (!isAuthorized(request, env)) return textResponse("Unauthorized", 401);
      try {
        const result = await runCheckin(env);
        return textResponse(result);
      } catch (error) {
        const msg = await notifyFailure(env, error);
        return textResponse(msg, 500);
      }
    }

    return textResponse([
      "ikuuu 签到 Worker v2.0 已运行",
      "================================",
      "✨ 纯 Cookie 签到，无需桥接服务",
      "🌐 支持多域名自动探测和切换",
      "",
      "Telegram 里发送 /help 管理账号",
      "访问 /health 查看状态",
    ].join("\n"));
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil(
      runScheduledCheckinIfNeeded(env).catch(error => notifyFailure(env, error))
    );
  },
};
