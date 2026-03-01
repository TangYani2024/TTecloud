-- 1. 文件主表
CREATE TABLE IF NOT EXISTS files (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    b2_path TEXT NOT NULL,
    type TEXT NOT NULL,
    size INTEGER DEFAULT 0,
    folder TEXT,
    is_hidden INTEGER DEFAULT 0,
    upload_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 2. 文件夹加密元数据表
CREATE TABLE IF NOT EXISTS folder_meta (
    name TEXT PRIMARY KEY,
    password TEXT NOT NULL
);

-- 3. 分片上传进度表 (断点续传)
CREATE TABLE IF NOT EXISTS upload_sessions (
    file_hash TEXT PRIMARY KEY,
    b2_file_id TEXT NOT NULL,
    b2_path TEXT NOT NULL,
    bucket TEXT NOT NULL,
    folder TEXT,
    uploaded_parts TEXT DEFAULT '[]',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 4. 离线下载任务表
CREATE TABLE IF NOT EXISTS downloads (
    id TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    name TEXT NOT NULL,
    folder TEXT,
    bucket TEXT NOT NULL,
    b2_path TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    loaded INTEGER DEFAULT 0,
    total INTEGER DEFAULT 0,
    b2_file_id TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 5. 离线下载分片状态表 (多线程并发下载)
CREATE TABLE IF NOT EXISTS download_parts (
    task_id TEXT NOT NULL,
    part_number INTEGER NOT NULL,
    status TEXT DEFAULT 'pending',
    sha1 TEXT,
    PRIMARY KEY (task_id, part_number)
);