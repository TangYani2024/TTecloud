-- Cloudflare D1 数据库初始化结构

-- 1. 文件元数据表
CREATE TABLE IF NOT EXISTS files (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  b2_path TEXT NOT NULL,
  type TEXT NOT NULL,
  size INTEGER NOT NULL DEFAULT 0,
  folder TEXT DEFAULT '',
  is_hidden INTEGER DEFAULT 0,
  upload_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_files_type ON files(type);
CREATE INDEX IF NOT EXISTS idx_files_folder ON files(folder);
CREATE INDEX IF NOT EXISTS idx_files_upload_at ON files(upload_at);

-- 2. 文件夹加密与权限表
CREATE TABLE IF NOT EXISTS folder_meta (
  name TEXT PRIMARY KEY,
  password TEXT NOT NULL
);

-- 3. 分片上传中继会话表（用于大文件断点续传与碎片管理）
CREATE TABLE IF NOT EXISTS upload_sessions (
  file_hash TEXT PRIMARY KEY,
  b2_file_id TEXT NOT NULL,
  b2_path TEXT NOT NULL,
  bucket TEXT NOT NULL,
  folder TEXT DEFAULT '',
  uploaded_parts TEXT DEFAULT '[]'
);
