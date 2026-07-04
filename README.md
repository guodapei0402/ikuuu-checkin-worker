# ikuuu 自动签到 Cloudflare Worker v2.0

一个部署在 **Cloudflare Workers** 上的 ikuuu VPN 自动签到机器人，通过 **Telegram Bot** 进行交互管理。完全免费、无需服务器、无需桥接服务。

## 核心特性

- **零依赖** - 纯 Cookie 直签，无需任何外部桥接服务器
- **多域名自动切换** - 内置 18 个 ikuuu 域名，自动探测可用域名并缓存，一个挂了自动换下一个
- **Telegram Bot 全功能管理** - 添加/删除账号、导入 Cookie、立即签到、定时签到、状态面板，全部通过机器人按钮操作
- **定时自动签到** - 利用 Cron Triggers 每日自动执行，可自定义时间
- **AES-GCM 加密存储** - 账号数据加密保存在 Cloudflare KV 中
- **实时状态面板** - 自动刷新的签到结果看板
- **完全免费** - Cloudflare Workers 免费额度完全够用

## 环境变量配置

| 变量名 | 必选 | 说明 |
|--------|------|------|
| `TELEGRAM_BOT_TOKEN` | 是 | Telegram Bot Token（通过 [@BotFather](https://t.me/BotFather) 获取） |
| `TELEGRAM_CHAT_ID` | 是 | 你的 Telegram 用户 ID（通过 [@userinfobot](https://t.me/userinfobot) 获取） |
| `ENCRYPTION_SECRET` | 是 | 任意强密码，用于加密账号数据 |
| `IKUUU_KV` | 是 | KV 命名空间绑定（在 Worker 设置中绑定） |
| `ADMIN_ID` | 否 | 管理员 Telegram ID（默认同 CHAT_ID） |
| `RUN_TOKEN` | 否 | HTTP 接口触发签到的 Token |
| `TELEGRAM_WEBHOOK_SECRET` | 否 | Webhook 安全验证 Token |
| `TIME_ZONE` | 否 | 时区（默认 `Asia/Shanghai`） |
| `BASE_URL` | 否 | 手动指定 ikuuu 域名（默认自动探测） |

## 部署步骤

### 1. 创建 Worker

- 登录 [Cloudflare Dashboard](https://dash.cloudflare.com)
- 进入 **Workers & Pages** → 创建 Worker
- 将 `worker.js` 的内容粘贴进去 → 保存部署

### 2. 创建 KV 命名空间

- **Workers & Pages** → **KV** → 创建命名空间（名称随意，如 `IKUUU_KV`）
- 回到 Worker → **Settings** → **Bindings** → 添加 KV 绑定
- 变量名填 `IKUUU_KV`，选择刚创建的命名空间

### 3. 配置环境变量

- Worker → **Settings** → **Variables** → 添加上述必选变量
- `ENCRYPTION_SECRET` 建议使用强随机密码

### 4. 设置 Cron 定时触发

- Worker → **Triggers** → **Cron Triggers**
- 添加 `* * * * *`（每分钟检测，到设定时间自动签到）

### 5. 设置 Telegram Webhook

浏览器访问以下 URL（替换对应内容）：

```
https://api.telegram.org/bot<你的BOT_TOKEN>/setWebhook?url=https://<你的Worker域名>/telegram/webhook
```

### 6. 导入 Cookie

1. 浏览器打开 `ikuuu.win` 或 `ikuuu.fyi`
2. 完成验证码并登录
3. 按 `F12` 打开开发者工具 → **Application** → **Cookies**
4. 复制所有 Cookie（或用浏览器扩展一键复制）
5. 在 Telegram 机器人里发送 `/cookie` → 粘贴 Cookie

## Bot 命令

| 命令 | 说明 |
|------|------|
| `/cookie` | 导入浏览器 Cookie（推荐） |
| `/add` | 交互式添加账号 |
| `/list` | 查看已添加的账号 |
| `/del 序号` | 删除指定账号 |
| `/clear` | 清空全部账号 |
| `/run` | 立即执行签到 |
| `/status` | 查看签到状态 |
| `/time HH:mm` | 设置每日自动签到时间 |
| `/watch` | 创建自动刷新状态面板 |
| `/unwatch` | 关闭状态面板 |
| `/domain` | 查看/切换当前使用的域名 |
| `/cancel` | 取消当前输入 |
| `/help` | 查看所有命令 |

## 签到效果示例

```
📋 ikuuu 签到任务汇总
==============================
📡 使用域名: https://ikuuu.win

账号：dp***@outlook.com
🎉 签到成功
信息：你获得了 687 MB流量

账号：da***@outlook.com
🎉 签到成功
信息：你获得了 852 MB流量

✅ 成功: 2/2
⏰ 执行时间: 2026/7/4 22:08:19
```

## 注意事项

1. **必须用 Cookie 签到** - ikuuu 已启用 Geetest V4 验证码，无法用密码自动登录。需要在浏览器手动完成验证后导入 Cookie
2. **Cookie 有效期** - Cookie 会过期（通常数天到数周），过期后机器人会提醒你重新导入
3. **域名变更** - ikuuu 经常换域名，本项目已内置多域名自动切换，无需手动更新
4. **多账号支持** - 支持同时管理多个 ikuuu 账号，逐个签到

## 项目结构

```
.
├── worker.js          # Cloudflare Worker 主代码（直接粘贴到 CF 编辑器）
├── wrangler.toml      # Wrangler CLI 配置文件（可选，用于命令行部署）
└── README.md          # 本说明文档
```

## License

MIT
