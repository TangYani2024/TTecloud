@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion
title TTecloud Installer

echo ==================================================
echo         欢迎使用 TTecloud 一键部署脚本
echo ==================================================
echo.

:: 0. 环境前置检查
echo INFO: 正在检测 Node.js 环境...
where npm >nul 2>nul
if !errorlevel! neq 0 (
    echo ERROR: 致命错误，未检测到 Node.js 环境。
    echo 请先前往 https://nodejs.org 下载并安装，然后重新运行本脚本。
    pause
    exit /b
)

:INPUT_PROJECT
set /p PROJECT_NAME="1. 请输入项目英文简称，如 ttecloud，必填: "
if "!PROJECT_NAME!"=="" (echo ERROR: 不能为空！ & goto INPUT_PROJECT)

set /p SITE_NAME="2. 请输入网盘站点名称，如 TTecloud，可中文，按回车默认: "
if "!SITE_NAME!"=="" set SITE_NAME=TTecloud

set /p CUSTOM_DOMAIN="3. 请输入自定义域名，如 dl.xxx.com，注意一定要是已经挂载到cloudflare的域名（的子域名），留空使用 workers.dev: "

set /p MAX_STORAGE_GB="4. 请输入网盘最大显示容量-GB，默认 10（B2存储桶免费额度是10GB）: "
if "!MAX_STORAGE_GB!"=="" set MAX_STORAGE_GB=10

set /p ADMIN_USER="5. 请输入后台管理员账号，默认 admin: "
if "!ADMIN_USER!"=="" set ADMIN_USER=admin

:INPUT_PASS
set /p ADMIN_PASS="6. 请输入后台管理员密码，必填: "
if "!ADMIN_PASS!"=="" (echo ERROR: 不能为空！ & goto INPUT_PASS)

echo.
echo --- S3 / B2 对象存储配置 ---
:INPUT_B2_KEY
set /p B2_KEY_ID="7. 请输入 B2 的 KeyID，必填: "
if "!B2_KEY_ID!"=="" (echo ERROR: 不能为空！ & goto INPUT_B2_KEY)

:INPUT_B2_APP
set /p B2_APP_KEY="8. 请输入 B2 的 ApplicationKey，必填: "
if "!B2_APP_KEY!"=="" (echo ERROR: 不能为空！ & goto INPUT_B2_APP)

:INPUT_B2_REGION
set /p B2_REGION="9. 请输入 B2 的 区域代码，如 us-east-005: "
if "!B2_REGION!"=="" (echo ERROR: 不能为空！ & goto INPUT_B2_REGION)

:INPUT_B2_ENDPOINT
set /p B2_ENDPOINT="10. 请输入 B2 S3 Endpoint，如 https://s3.us-east-005.backblazeb2.com: "
if "!B2_ENDPOINT!"=="" (echo ERROR: 不能为空！ & goto INPUT_B2_ENDPOINT)

:INPUT_B2_RES
set /p BUCKET_RESOURCE="11. 请输入 资源站 数据桶名称，必填: "
if "!BUCKET_RESOURCE!"=="" (echo ERROR: 不能为空！ & goto INPUT_B2_RES)

:INPUT_B2_IMG
set /p BUCKET_IMAGE="12. 请输入 图床 数据桶名称，必填: "
if "!BUCKET_IMAGE!"=="" (echo ERROR: 不能为空！ & goto INPUT_B2_IMG)

echo.
echo ==================================================
echo INFO: 正在检查并安装 Cloudflare Wrangler 工具...
call npm install -g wrangler >nul 2>&1
if !errorlevel! neq 0 (echo ERROR: Wrangler 安装失败，请检查网络！ & pause & exit /b)

echo INFO: 正在检查 B2 CLI 工具...
where b2 >nul 2>nul
if !errorlevel! neq 0 (
    if not exist b2.exe (
        echo INFO: 未找到 b2 命令，正在自动下载官方免安装版...
        powershell -Command "try { Write-Host '正在尝试从官方源下载...'; $ProgressPreference = 'SilentlyContinue'; Invoke-WebRequest -Uri 'https://github.com/Backblaze/B2_Command_Line_Tool/releases/latest/download/b2-windows.exe' -OutFile 'b2.exe' -UseBasicParsing } catch { Write-Host '官方源下载超时，正在切换至国内加速节点...'; Invoke-WebRequest -Uri 'https://mirror.ghproxy.com/https://github.com/Backblaze/B2_Command_Line_Tool/releases/latest/download/b2-windows.exe' -OutFile 'b2.exe' -UseBasicParsing }"
        
        for %%I in (b2.exe) do if %%~zI LSS 1048576 del b2.exe >nul 2>&1
        if not exist b2.exe (
            echo ERROR: b2.exe 下载失败！请手动下载并将其与本脚本放在同目录下。
            pause
            exit /b
        )
    )
    set B2_CMD=b2.exe
) else (
    set B2_CMD=b2
)

echo.
echo ==================================================
echo INFO: 开始进行账号与云端资源安全校验...

echo INFO: 1/3 正在验证 Backblaze B2 授权...
!B2_CMD! account authorize "!B2_KEY_ID!" "!B2_APP_KEY!" >nul 2>&1
if !errorlevel! neq 0 (
    echo ERROR: 致命错误，B2 KeyID 或 AppKey 不正确，或者网络无法连接至 B2！
    pause
    exit /b
)
echo SUCCESS: B2 授权通过！

echo INFO: 2/3 正在验证 B2 数据桶是否存在...
!B2_CMD! get-bucket "!BUCKET_RESOURCE!" >nul 2>&1
if !errorlevel! neq 0 (
    echo ERROR: 致命错误，找不到名为 "!BUCKET_RESOURCE!" 的资源桶！
    pause
    exit /b
)
!B2_CMD! get-bucket "!BUCKET_IMAGE!" >nul 2>&1
if !errorlevel! neq 0 (
    echo ERROR: 致命错误，找不到名为 "!BUCKET_IMAGE!" 的图床桶！
    pause
    exit /b
)
echo SUCCESS: 数据桶校验通过！

echo INFO: 3/3 正在拉起 Cloudflare 授权，如果浏览器弹出请允许...
call npx wrangler login
if !errorlevel! neq 0 (echo ERROR: Cloudflare 登录失败！ & pause & exit /b)
echo SUCCESS: Cloudflare 授权完成。

echo.
echo ==================================================
echo INFO: 正在构建 Cloudflare 云端架构...

echo INFO: 正在创建或获取 D1 数据库...
set DB_ID=
call npx wrangler d1 info !PROJECT_NAME!-db > d1_info.txt 2>nul
if !errorlevel! equ 0 (
    echo SUCCESS: 检测到 D1 数据库已存在，直接复用...
    for /f "tokens=2 delims=:" %%a in ('findstr /C:"database_id" d1_info.txt') do (
        set raw_id=%%a
        set raw_id=!raw_id:"=!
        set DB_ID=!raw_id: =!
    )
) else (
    call npx wrangler d1 create !PROJECT_NAME!-db > d1_output.txt
    if !errorlevel! neq 0 (echo ERROR: D1 数据库创建失败！ & pause & exit /b)
    for /f "tokens=2 delims=:" %%a in ('findstr /C:"database_id" d1_output.txt') do (
        set raw_id=%%a
        set raw_id=!raw_id:"=!
        set DB_ID=!raw_id: =!
    )
)
if exist d1_info.txt del d1_info.txt
if exist d1_output.txt del d1_output.txt
echo SUCCESS: D1 数据库准备就绪！ID: !DB_ID!

echo INFO: 正在创建 Queue 队列...
call npx wrangler queues create !PROJECT_NAME!-queue >nul 2>&1
echo SUCCESS: Queue 队列准备就绪！

echo INFO: 正在初始化 D1 数据库表结构...
if not exist schema.sql (echo ERROR: 未找到 schema.sql！ & pause & exit /b)
call npx wrangler d1 execute !PROJECT_NAME!-db --file=./schema.sql --remote >nul 2>&1
echo SUCCESS: 数据库表结构同步完成！

echo INFO: 正在配置 B2 数据桶跨域 CORS 规则...
set CORS_JSON=[{\"corsRuleName\":\"allowAll\",\"allowedOrigins\":[\"*\"],\"allowedHeaders\":[\"*\"],\"allowedOperations\":[\"s3_get\",\"s3_put\",\"s3_post\",\"s3_delete\",\"s3_head\"],\"exposeHeaders\":[\"ETag\"],\"maxAgeSeconds\":86400}]
!B2_CMD! update-bucket --corsRules "!CORS_JSON!" "!BUCKET_RESOURCE!" allPublic >nul 2>&1
!B2_CMD! update-bucket --corsRules "!CORS_JSON!" "!BUCKET_IMAGE!" allPublic >nul 2>&1
echo SUCCESS: B2 CORS 规则配置完毕！

echo.
echo ==================================================
echo INFO: 正在生成配置并部署代码...

echo name = "!PROJECT_NAME!" > wrangler.toml
echo main = "worker.js" >> wrangler.toml
echo compatibility_date = "2024-03-20" >> wrangler.toml
echo. >> wrangler.toml
if not "!CUSTOM_DOMAIN!"=="" (
    echo routes = [ { pattern = "!CUSTOM_DOMAIN!", custom_domain = true } ] >> wrangler.toml
    echo. >> wrangler.toml
)
echo [vars] >> wrangler.toml
echo SITE_NAME = "!SITE_NAME!" >> wrangler.toml
echo MAX_STORAGE_GB = "!MAX_STORAGE_GB!" >> wrangler.toml
echo ADMIN_USER = "!ADMIN_USER!" >> wrangler.toml
echo S3_REGION = "!B2_REGION!" >> wrangler.toml
echo S3_ENDPOINT = "!B2_ENDPOINT!" >> wrangler.toml
echo BUCKET_RESOURCE = "!BUCKET_RESOURCE!" >> wrangler.toml
echo BUCKET_IMAGE = "!BUCKET_IMAGE!" >> wrangler.toml
echo. >> wrangler.toml
echo [[d1_databases]] >> wrangler.toml
echo binding = "DB" >> wrangler.toml
echo database_name = "!PROJECT_NAME!-db" >> wrangler.toml
echo database_id = "!DB_ID!" >> wrangler.toml
echo. >> wrangler.toml
echo [[queues.producers]] >> wrangler.toml
echo queue = "!PROJECT_NAME!-queue" >> wrangler.toml
echo binding = "DOWNLOAD_QUEUE" >> wrangler.toml
echo. >> wrangler.toml
echo [[queues.consumers]] >> wrangler.toml
echo queue = "!PROJECT_NAME!-queue" >> wrangler.toml
echo max_batch_size = 10 >> wrangler.toml
echo max_batch_timeout = 5 >> wrangler.toml
echo max_retries = 3 >> wrangler.toml

for %%I in (worker.js) do if %%~zI LSS 1024 (
    echo ERROR: 致命错误，检测到 worker.js 可能是空文件！
    pause
    exit /b
)

call npx wrangler deploy
if !errorlevel! neq 0 (echo ERROR: 代码部署失败！请检查log或将log提交给ai分析。 & pause & exit /b)

echo INFO: 正在安全注入后台密码和密钥（后续可在CF worker的变量和机密下进行调整）...
echo !ADMIN_PASS!| call npx wrangler secret put ADMIN_PASS >nul 2>&1
echo !B2_KEY_ID!| call npx wrangler secret put B2_KEY_ID >nul 2>&1
echo !B2_APP_KEY!| call npx wrangler secret put B2_APP_KEY >nul 2>&1

echo.
echo ==================================================
echo SUCCESS: 部署成功！！！
if not "!CUSTOM_DOMAIN!"=="" (
    echo 你的网盘地址: https://!CUSTOM_DOMAIN!
) else (
    echo 你的网盘已上线，请前往 Cloudflare 仪表盘查看 workers.dev 域名。
)
echo ==================================================
pause