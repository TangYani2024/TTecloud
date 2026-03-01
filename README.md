# TTecloud
 仅邮箱和域名就可以得到的个人云盘。基于 Cloudflare Workers + D1 + B2，支持多线程分片上传、异步离线下载、图片直链、文件夹加密。带一键脚本。

需要cloudflare账号绑定域名以及backblaze存储桶，node.js环境

需要从B2得到以下信息
ApiID，ApplicationKey，存储桶名称（两个，一个云盘一个图床）
然后执行install.bat即可
国内用户无法下载B2.exe的话请访问Backblaze官网下载 https://www.backblaze.com/docs/cloud-storage-command-line-tools
