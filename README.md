# 🍬 TTecloud (糖糖云盘)

基于 **Cloudflare Pages (Functions) + Cloudflare D1 + S3 兼容对象存储 (Backblaze B2 / Cloudflare R2 / AWS S3 / MinIO 等)** 构建的现代化、极速、高颜值的开源私有网盘与图床系统。

前后端完全解耦，0 服务器成本，纯边缘计算全球加速部署。

---

## 🌟 核心功能特性

### 1. 🚀 大文件多线程分片直传 & 断点续传
- **突破限制**：前端自动对大文件进行 10MB 分片直传 S3 存储桶，彻底绕过 Cloudflare 100MB 免费请求体大小限制，完美支持 GB 级超大文件。
- **并发批量入库**：支持多文件、多层级文件夹直接拖拽识别与高并发并行上传。
- **断点续传**：基于 D1 数据库动态维护上传会话与分片哈希，意外中断或页面刷新后再次上传同一文件，自动秒级跳过已传分片并断点续传。

### 2. 📥 网页分片下载 & 浏览器流式直写
- **小文件极速拉取**：享受边缘 CDN 强力缓存与低延迟直链。
- **大文件 3 线程并发分片下载**：前端 **3 线程 Range 分片并行下载** 技术，平衡传输吞吐与浏览器系统开销，就地直观展示进度。
- **磁盘流式写入（FileSystem Access API）**：超大文件直接边下载边落盘直写，不堆积浏览器内存，避免移动端或低配设备出现 OOM（内存溢出）崩溃。

### 3. 🛠️ 全能管理员控制台 (Admin Control Suite)
- **极简悬浮动作按钮 (FAB)**：右下角自适应动效圆钮，一键唤出管理控制台。
- **临时预签名直传 (CLI Upload)**：
  - 一键为指定文件名生成 24 小时有效的预签名 S3 PUT 直传命令。
  - 在任何 Linux 服务器、macOS 或 Windows 终端无需安装任何客户端或配置秘钥，仅用系统自带的 `curl` 即可秒级直推文件入库。
- **存储桶与 D1 数据一致性维护**：
  - **同步 D1**：扫描存储桶已有物理文件，一键反向录入 D1 数据库。
  - **碎片管理**：可视化查看所有未完成或废弃的分片上传残留，支持一键清空孤立碎片，杜绝空间占用与计费损耗。
  - **清死链**：自动检测清理数据库存在但存储桶中已丢失的失效死链。
  - **删游离**：自动检测清理存储桶存在但数据库中未记录的游离孤立文件。
- **GitHub Release 自动追更与云端同步**：
  - 订阅任意开源 GitHub 仓库（如 Magisk、v2rayN、Clash 等）。
  - 支持正向包含词（如 `apk, zip`）与负向排除词（如 `debug, sha256`）精确过滤附件。
  - 边缘函数自动定时或一键抓取最新版本并秒级同步到指定网盘目录。
  - 自动清理旧版本物理文件与数据库记录，始终仅保留最新版本，防止存储空间膨胀。
  - 深度支持 `GITHUB_TOKEN` 环境变量绑定，防范 GitHub 403 API 限频。
- **文件与目录权限体系**：
  - 支持单文件夹独立密码加密锁定与鉴权解锁。
  - 文件重命名、跨目录穿梭移动、显隐状态一键切换、文件永久删除。
  - 独立的单文件分享主页，一键生成复制直链与 Markdown 嵌入链接。
- **个性化进阶系统配置**：
  - 自定义 PC 端横屏背景壁纸与手机端竖屏背景壁纸。
  - 终端 CLI 附加 `Expect: 100-continue` 握手协议开关（兼容特定防火墙）。
  - 前端 SHA256 强哈希防断流校验开关。

---

## 🛠️ 准备工作

在开始部署前，请确保准备好以下资源：

1. **域名与 Cloudflare 账号**：
   - 注册并登录 [Cloudflare](https://dash.cloudflare.com/) 账号。
   - 准备一个托管在 Cloudflare 上的域名（如没有，也可以直接免费使用 Cloudflare Pages 赠送的 `*.pages.dev` 二级域名）。
2. **支持 S3 协议的对象存储桶**：
   - 本项目完全兼容标准 S3 协议，推荐选择：
     - **Backblaze B2**（免费 10GB 存储，每天享有免费 3 倍流出流量，极力推荐）
     - **Cloudflare R2**（免费 10GB 存储，0 出网流量费）
     - **Amazon AWS S3**、**MinIO**（私有部署）、**Wasabi**、**阿里云 OSS / 腾讯云 COS**（开启 S3 兼容模式）
   - 在对象存储中创建两个存储桶（可使用默认名称，也可以在 `config.json` 中自定义）：
     - 资源桶（默认：`tangyani-ziyuan`）
     - 图床桶（默认：`tangyani-tuchuang`）
3. **获取存储桶 S3 API 凭证**：
   - **Key ID / Access Key ID**
   - **Application Key / Secret Access Key**
   - 获取存储桶的 **S3 Endpoint 接入点**（如 B2 为 `https://s3.us-east-005.backblazeb2.com`，R2 为 `https://<account_id>.r2.cloudflarestorage.com`）与 **Region 区域**（如 `us-east-005`，R2 填 `auto`）。

---

## 📖 详细使用与部署教程

### 第一步：Fork 本仓库
点击本页面右上角的 **Fork** 按钮，将项目完整克隆到您自己的 GitHub 账号下。

---

### 第二步：配置 `config.json`
在您 Fork 后的仓库根目录下，找到并编辑 `config.json` 文件：

```json
{
  "site": {
    "title": "糖糖云盘",
    "cookieName": "TangYani_Admin_Token"
  },
  "s3": {
    "endpoint": "https://s3.us-east-005.backblazeb2.com",
    "region": "us-east-005",
    "buckets": {
      "resource": "tangyani-ziyuan",
      "image": "tangyani-tuchuang"
    }
  },
  "storage": {
    "maxStorageBytes": 10737418240,
    "maxStorageFormatted": "10 GB"
  }
}
```

- `s3.endpoint`：填写你的 S3 对象存储接入点 URL（结尾无需斜杠）。
- `s3.region`：填写你的存储桶所属区域代码（如 `us-east-005`、`auto`、`us-east-1` 等）。
- `s3.buckets.resource`：你的主资源存储桶名称。
- `s3.buckets.image`：你的图床存储桶名称。
- `storage.maxStorageBytes`：管理员控制台展示的总容量上限（单位：字节，例如 10GB 为 `10737418240`，20GB 为 `21474836480`）。

修改完成后提交保存（Commit changes）。

---

### 第三步：在 Cloudflare 创建 Pages 项目

1. 登录 [Cloudflare 控制台](https://dash.cloudflare.com/)。
2. 在左侧菜单点击 **Workers 和 Pages (Workers & Pages)**。
3. 点击 **创建应用程序 (Create Application)** -> 向下滚动在底部找到并选择 **Pages**。
4. 点击 **连接到 Git (Connect to Git)**，选择并授权您刚刚 Fork 的 GitHub 仓库。
5. 配置构建预设：
   - **项目名称**：自定义（如 `my-cloud`）
   - **生产分支**：`main` 或 `master`
   - **框架预设 (Framework preset)**：选择 **None (无)**
   - **构建命令 (Build command)**：**留空不填**
   - **构建输出目录 (Build output directory)**：填写 `public`
6. 点击 **保存并部署 (Save and Deploy)**。

---

### 第四步：创建并绑定 Cloudflare D1 数据库

1. 在 Cloudflare 左侧导航栏中，点击 **Workers 和 Pages** -> **D1 SQL 数据库**。
2. 点击 **创建数据库**，输入数据库名称（如 `cloud-db`），点击创建。
3. 进入刚刚创建的数据库，点击 **控制台 (Console)** 选项卡。
4. 打开本项目仓库中的 [`schema.sql`](./schema.sql)，将全部 SQL 语句复制并粘贴进控制台中执行，完成核心数据表与索引的初始化：
   - `files`：文件元数据与分类
   - `folder_meta`：文件夹密码加密表
   - `upload_sessions`：断点续传与碎片会话表
5. **绑定至 Pages 项目**：
   - 回到 **Workers 和 Pages** -> 点击进入你刚创建的 **Pages 项目**。
   - 点击顶部 **设置 (Settings)** -> 左侧 **函数 (Functions)**。
   - 向下滚动找到 **D1 数据库绑定 (D1 Database Bindings)**，点击 **添加绑定 (Add binding)**：
     - **变量名称 (Variable name)**：`DB`（⚠️ 必须为大写的 `DB`，与后端代码完全一致）
     - **D1 数据库**：下拉选择刚刚创建的 `cloud-db`
   - 点击 **保存**。

---

### 第五步：设置环境变量与安全密钥

在 Pages 项目的 **设置 (Settings)** -> **环境变量 (Environment Variables)** 中，点击 **添加变量**，添加以下参数：

| 变量名 | 必填 | 类型 | 说明与示例 |
| :--- | :---: | :---: | :--- |
| `ADMIN_USER` | 否 | 文本 (Plain text) | 管理员登录账号（若不设置，默认值为 `admin`） |
| `ADMIN_PASS` | **是** | 密钥 (Secret/加密) | 管理员登录强密码（必填） |
| `B2_KEY_ID` 或 `S3_ACCESS_KEY_ID` | **是** | 密钥 (Secret/加密) | 存储桶的 Key ID / Access Key ID |
| `B2_APP_KEY` 或 `S3_SECRET_ACCESS_KEY` | **是** | 密钥 (Secret/加密) | 存储桶的 Application Key / Secret Access Key |
| `GITHUB_TOKEN` | 否 | 密钥 (Secret/加密) | GitHub Personal Access Token（用于自动追更时突破 API 速率限制至 5000次/小时） |

> 💡 **提示**：环境变量中同时兼容 `B2_KEY_ID` 与标准 S3 的 `S3_ACCESS_KEY_ID`，您可根据习惯任意选用。

---

### 第六步：重新部署生效

1. 进入 Pages 项目的 **部署 (Deployments)** 页面。
2. 在最新一条部署记录右侧点击 `...` -> **重试部署 (Retry deployment)**。
3. 等待约 10 秒部署完成，点击 Cloudflare 分配的 `https://<项目名>.pages.dev` 即可直接进入系统！
4. （可选）在 **自定义域 (Custom Domains)** 页面绑定您自己的个性独立域名，自动享受全球 Anycast CDN 与 SSL 证书加速。

---

## 📂 仓库目录结构一览

```
TTecloud/
├── config.json                   # 核心配置文件（S3 端点、存储桶、容量配额、站点信息）
├── schema.sql                    # Cloudflare D1 数据库初始化与索引脚本
├── package.json                  # 项目依赖与便捷脚本
├── functions/                    # Cloudflare Pages Functions 后端边缘云函数
│   └── [[path]].js               # 全局路由、AWS4 签名、S3 代理、D1 交互与追更引擎
└── public/                       # 静态资源根目录（全球 CDN 边缘直发）
    ├── index.html                # 主程序单页面 (SPA)
    ├── login.html                # 独立管理员认证页
    ├── css/
    │   └── style.css             # 现代化玻璃拟态响应式样式表
    ├── js/
    │   └── app.js                # 前端核心业务引擎（分片计算、多线程直写、FAB 控制等）
    └── openmoji/                 # 精简版 OpenMoji 矢量表情与图标库（仅保留项目所需）
```

---

## 🤖 AI 声明 (AI Disclosure)

本项目（**TTecloud**）由人类开发者进行产品需求规划与架构设计，**全部核心业务逻辑、前端交互界面、后端边缘云函数算法（包括原生 AWS S3 V4 签名、并发分片管理、流式下载、GitHub 追更引擎）均由 AI 辅助编写、调试与全面优化完成**。

---

## 常见问题 (FAQ)

<details>
<summary><b>Q1: 上传大文件时会遇到 413 (Payload Too Large) 吗？</b></summary>
不会。系统内置了自动分片直传逻辑，无论文件多大，均在浏览器本地切片为 10MB 分块直接向 S3 存储桶发起直传，绕过了任何反向代理网关的请求体限制。
</details>

<details>
<summary><b>Q2: 使用网页分片下载时提示浏览器不受支持？</b></summary>
「3 线程磁盘流式直写」基于 Chromium 原生的 FileSystem Access API（如 Chrome、Edge 等 PC 浏览器体验最佳）。在手机端 Safari 或不受支持的浏览器中，系统会自动智能降级为原生下载或官方直链，确保 100% 可正常下载。
</details>

<details>
<summary><b>Q3: GitHub 追更报 403 API rate limit exceeded？</b></summary>
GitHub 匿名 API 限制每个 IP 每小时仅能请求 60 次，Cloudflare 边缘节点 IP 极易被限频。只需在 GitHub 生成一个无需勾选任何敏感权限的 Personal Access Token，填入环境变量 `GITHUB_TOKEN`，额度即可立刻提升至 5000 次/小时。
</details>

---

## 📄 开源许可证

本项目基于 [MIT License](./LICENSE) 协议开源。
