# 糖糖云盘 (Cloudflare Pages 版)

基于 **Cloudflare Pages (Functions) + Cloudflare D1 数据库 + Backblaze B2 存储** 构建的高性能、极速分片直传的现代化云盘与图床系统。

本项目已从单文件 Cloudflare Worker 成功解耦重构为标准 **Cloudflare Pages** 工程结构，前后端完全分离，便于后续维护开发与通过 Git 自动化部署。

---

## 📁 目录结构说明

```
ziyuanzhan/
├── public/                       # 静态资源根目录（由 Cloudflare 边缘 CDN 全球分发）
│   ├── index.html                # 主页面 SPA 界面
│   ├── login.html                # 管理员登录界面
│   ├── css/
│   │   └── style.css             # 前端样式表（结构化美化提取，可自由定制主题）
│   └── js/
│       └── app.js                # 前端业务核心逻辑（并发上传、分片计算、断点续传等）
├── functions/                    # Cloudflare Pages Functions 后端云函数
│   └── [[path]].js               # 全局路由处理器（处理 /api/*, /file/*, /share/*, /login 等）
├── schema.sql                    # Cloudflare D1 数据库建表与索引脚本
├── wrangler.toml                 # Wrangler 配置文件（定义 D1 binding 与构建目录）
├── package.json                  # npm 配置文件与便捷脚本
└── ziyuanzhan.js.bak             # 原 Worker 单文件备份
```

---

## 🚀 部署指南

### 方式一：连接 GitHub 自动化部署（强烈推荐）

1. **初始化并推送到 GitHub 仓库**：
   在本地目录初始化 Git 仓库并推送到您的 GitHub / GitLab 账户：
   ```bash
   git init
   git add .
   git commit -m "Init Cloudflare Pages project"
   git branch -M main
   git remote add origin <您的仓库地址>
   git push -u origin main
   ```

2. **在 Cloudflare 创建 Pages 项目**：
   - 进入 [Cloudflare 控制台](https://dash.cloudflare.com/) -> **Workers 和 Pages** -> **创建应用程序** -> 选择 **Pages** -> **连接到 Git**。
   - 选中刚创建的 GitHub 仓库并点击“开始设置”。
   - **构建设置**：
     - 框架预设（Framework preset）：**无（None）**
     - 构建命令（Build command）：留空（不需要构建）
     - 构建输出目录（Build output directory）：填写 `public`
   - 点击 **保存并部署**。

3. **配置 D1 数据库绑定（核心）**：
   - 部署完成后，进入该 Pages 项目页面 -> **设置（Settings）** -> **函数（Functions）**。
   - 向下滚动找到 **D1 数据库绑定（D1 Database Bindings）**，点击 **添加绑定（Add binding）**：
     - **变量名称（Variable name）**：`DB` （必须大写，与代码严格一致）
     - **D1 数据库**：选择您已有的云盘 D1 数据库（如果是新建数据库，请先执行 `schema.sql` 建表）。
   - 点击保存。

4. **配置环境变量与密钥（Environment Variables）**：
   - 进入 **设置（Settings）** -> **环境变量（Environment Variables）** -> **添加变量**：
     | 变量名 | 类型 | 说明 |
     | :--- | :--- | :--- |
     | `ADMIN_USER` | 文本 (Plain text) | 管理员登录账号（默认 `admin`） |
     | `ADMIN_PASS` | 密钥 (Secret/加密) | 管理员登录密码 |
     | `B2_KEY_ID` | 密钥 (Secret/加密) | Backblaze B2 Application Key ID |
     | `B2_APP_KEY` | 密钥 (Secret/加密) | Backblaze B2 Application Key 密钥 |
   - 点击保存。

5. **重新部署生效**：
   - 进入该 Pages 项目的 **部署（Deployments）** 选项卡。
   - 点击最新部署右侧的 `...` -> **重试部署（Retry deployment）**，使新配置的环境变量与 D1 绑定生效。

---

### 方式二：使用 Wrangler 命令行直接部署

如果本地已配置 Node.js 和 Wrangler：

1. **部署静态文件与 Functions**：
   ```bash
   npx wrangler pages deploy public
   ```
2. **设置敏感密钥**：
   ```bash
   npx wrangler pages secret put ADMIN_PASS --project-name ziyuanzhan
   npx wrangler pages secret put B2_KEY_ID --project-name ziyuanzhan
   npx wrangler pages secret put B2_APP_KEY --project-name ziyuanzhan
   ```

---

## 🗄️ 数据库说明 (`schema.sql`)

如果您需要新建 D1 数据库或迁移数据，可以在本地通过 Wrangler 执行：

```bash
# 创建数据库（如果尚未创建）
npx wrangler d1 create ziyuanzhan-db

# 执行建表语句
npx wrangler d1 execute ziyuanzhan-db --file=./schema.sql
```

数据表包含：
- `files`：文件元数据（文件名、B2 存储路径、类型、大小、所属文件夹、显隐状态、上传时间）。
- `folder_meta`：加密文件夹的独立密码信息。
- `upload_sessions`：大文件分片并发直传状态中继表。

---

## 🛠️ 后续维护与二次开发

1. **修改前端样式与布局**：
   直接编辑 `public/css/style.css` 或 `public/index.html`，享受完整的代码语法高亮与格式化，修改后 `git push` 即自动部署生效。
2. **调整上传逻辑或前端组件**：
   前端所有交互与并发调度代码集中在 `public/js/app.js` 中。
3. **扩展后端接口**：
   动态 API、下载流式中继与鉴权逻辑均在 `functions/[[path]].js` 中。
4. **自定义域名绑定**：
   在 Cloudflare Pages 项目的 **自定义域（Custom Domains）** 中，可一键绑定您的独立个性域名并自动享受免费的 SSL/TLS 证书。
