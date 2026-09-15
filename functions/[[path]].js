import appConfig from '../config.json';

const CONFIG = {
  SITE_TITLE: (appConfig && appConfig.site && appConfig.site.title) || '糖糖云盘',
  AUTH_COOKIE_NAME: (appConfig && appConfig.site && appConfig.site.cookieName) || (appConfig && appConfig.AUTH_COOKIE_NAME) || 'TangYani_Admin_Token',
  MAX_STORAGE_BYTES: (appConfig && appConfig.storage && appConfig.storage.maxStorageBytes) || (appConfig && appConfig.MAX_STORAGE_BYTES) || 10737418240,
  S3_REGION: (appConfig && appConfig.s3 && appConfig.s3.region) || (appConfig && appConfig.S3_REGION) || 'us-east-005',
  S3_ENDPOINT: ((appConfig && appConfig.s3 && appConfig.s3.endpoint) || (appConfig && appConfig.S3_ENDPOINT) || 'https://s3.us-east-005.backblazeb2.com').replace(/\/+$/, ''),
  BUCKETS: {
    RESOURCE: (appConfig && appConfig.s3 && appConfig.s3.buckets && appConfig.s3.buckets.resource) || (appConfig && appConfig.BUCKETS && appConfig.BUCKETS.RESOURCE) || 'tangyani-ziyuan',
    IMAGE: (appConfig && appConfig.s3 && appConfig.s3.buckets && typeof appConfig.s3.buckets.image === 'string') ? appConfig.s3.buckets.image : ((appConfig && appConfig.BUCKETS && typeof appConfig.BUCKETS.IMAGE === 'string') ? appConfig.BUCKETS.IMAGE : '')
  }
};
const HAS_IMAGE = !!CONFIG.BUCKETS.IMAGE;

let globalCachedTotalSize = 0, globalLastSizeCalcTime = 0;
let globalSiteConfig = null, globalConfigTime = 0;

async function getSiteConfig(e, force = false) {
  if (!force && Date.now() - globalConfigTime < 300000 && globalSiteConfig) return globalSiteConfig;
  try {
    const rs = await awsS3Fetch(CONFIG.S3_ENDPOINT + '/' + CONFIG.BUCKETS.RESOURCE + '/' + encodeURIComponent('.sys/__site_config__.json'), { method: 'GET' }, e);
    if (rs.status === 200) {
      globalSiteConfig = await rs.json();
      globalConfigTime = Date.now();
    } else {
      globalSiteConfig = {};
    }
  } catch (err) {
    if (!globalSiteConfig) globalSiteConfig = {};
  }
  return globalSiteConfig;
}

function getBgLayer(c) {
  const cfg = c || globalSiteConfig || {};
  const pc = (cfg.bgPc || cfg.bgMobile || '').trim();
  const mb = (cfg.bgMobile || cfg.bgPc || '').trim();
  return '<div class="bg-layer" id="bg-layer"></div>' +
    '<style>' +
    'html,body{background-color:transparent!important;}' +
    ':root{--bg-op:1;}' +
    '.bg-layer{position:fixed!important;top:-5%!important;left:-5%!important;width:110vw!important;height:110vh!important;pointer-events:none!important;z-index:-3!important;background-size:cover!important;background-position:center!important;filter:blur(20px) brightness(1.05) saturate(110%)!important;opacity:0;transition:opacity 0.4s ease!important;}' +
    (pc ? '.bg-layer{background-image:url("' + pc + '");opacity:1!important;}' : '') +
    (mb ? '@media(max-width:768px){.bg-layer{background-image:url("' + mb + '");opacity:1!important;}}' : '') +
    '</style>' +
    '<script>' +
    '(function(){' +
    'try{' +
    'var p=' + JSON.stringify(cfg.bgPc || '') + '||localStorage.getItem("cfg_bgPc")||"";' +
    'var m=' + JSON.stringify(cfg.bgMobile || '') + '||localStorage.getItem("cfg_bgMobile")||p;' +
    'function syncBg(){' +
    'var isM=window.innerWidth<=768;var u=isM?(m||p):(p||m);' +
    'if(u){' +
    'document.documentElement.style.setProperty("--user-bg-url","url(\\""+u+"\\")");' +
    'document.documentElement.style.setProperty("--bg-op","1");' +
    'var el=document.getElementById("bg-layer");' +
    'if(el){el.style.backgroundImage="url(\\""+u+"\\")";el.style.opacity="1";}' +
    '}' +
    '}' +
    'syncBg();' +
    'window.addEventListener("resize",syncBg);' +
    '}catch(e){}' +
    '})();' +
    '</script>';
}

function escapeHTML(s) {
  return String(s).replace(/[&<>'"]/g, t => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[t] || t));
}

function awsUriEncode(s) {
  return encodeURIComponent(s).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());
}

function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

async function hashSha256(s) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return Array.from(new Uint8Array(d)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function hmacSha256(k, s) {
  const c = await crypto.subtle.importKey('raw', typeof k === 'string' ? new TextEncoder().encode(k) : k, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', c, new TextEncoder().encode(s)));
}

async function createAdminToken(e) {
  if (!e.ADMIN_PASS) throw new Error('No ADMIN_PASS');
  const t = Date.now().toString(), d = (e.ADMIN_USER || 'admin') + '|' + t, s = Array.from(await hmacSha256(e.ADMIN_PASS, d)).map(b => b.toString(16).padStart(2, '0')).join('');
  return encodeURIComponent(d + '|' + s);
}

async function verifyAdminToken(t, e, c) {
  if (!t || !e.ADMIN_PASS) return false;
  try {
    const p = decodeURIComponent(t).split('|');
    if (p.length !== 3) return false;
    const u = p[0], tm = parseInt(p[1]), s = p[2];
    if (Date.now() - tm > 2592000000) return false;
    if (c && c.lastLogoutTime && tm < c.lastLogoutTime) return false;
    const ex = Array.from(await hmacSha256(e.ADMIN_PASS, u + '|' + p[1])).map(b => b.toString(16).padStart(2, '0')).join('');
    return timingSafeEqual(s, ex) && u === (e.ADMIN_USER || 'admin');
  } catch (err) {
    return false;
  }
}

async function initD1Schema(db) {
  if (!db) return;
  const stmts = [
    `CREATE TABLE IF NOT EXISTS files (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      b2_path TEXT NOT NULL,
      type TEXT NOT NULL,
      size INTEGER NOT NULL DEFAULT 0,
      folder TEXT DEFAULT '',
      is_hidden INTEGER DEFAULT 0,
      upload_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE INDEX IF NOT EXISTS idx_files_type ON files(type)`,
    `CREATE INDEX IF NOT EXISTS idx_files_folder ON files(folder)`,
    `CREATE INDEX IF NOT EXISTS idx_files_upload_at ON files(upload_at)`,
    `CREATE TABLE IF NOT EXISTS folder_meta (
      name TEXT PRIMARY KEY,
      password TEXT NOT NULL
    )`,
    `CREATE TABLE IF NOT EXISTS upload_sessions (
      file_hash TEXT PRIMARY KEY,
      b2_file_id TEXT NOT NULL,
      b2_path TEXT NOT NULL,
      bucket TEXT NOT NULL,
      folder TEXT DEFAULT '',
      uploaded_parts TEXT DEFAULT '[]'
    )`
  ];
  await db.batch(stmts.map(s => db.prepare(s)));
}

function formatS3Error(txt) {
  if (!txt) return '对象存储未知错误';
  const codeMatch = txt.match(/<Code>(.*?)<\/Code>/i);
  const msgMatch = txt.match(/<Message>(.*?)<\/Message>/i);
  if (codeMatch || msgMatch) {
    const code = codeMatch ? codeMatch[1] : '';
    const msg = msgMatch ? msgMatch[1] : '';
    if (code === 'NoSuchBucket') return '存储桶不存在 (NoSuchBucket): 请检查 config.json 中的桶名称是否与实际创建的桶一致';
    if (code === 'InvalidAccessKeyId') return '存储桶 Key ID 错误 (InvalidAccessKeyId): 请检查 Pages 环境变量中的 S3_ACCESS_KEY_ID 或 B2_KEY_ID';
    if (code === 'SignatureDoesNotMatch') return '存储桶签名失败 (SignatureDoesNotMatch): 请检查 Pages 环境变量中的 Secret Key 是否正确';
    if (code === 'AccessDenied') return '存储桶访问受限 (AccessDenied): 凭证无读写权限或存储桶权限策略限制';
    if (code === 'EntityTooLarge') return '文件超出对象存储单次直传大小限制';
    return `存储桶异常 [${code}]: ${msg || txt.slice(0, 120)}`;
  }
  return txt.length > 200 ? (txt.slice(0, 200) + '...') : txt;
}

async function awsS3Fetch(u, o, e) {
  const keyId = e.S3_ACCESS_KEY_ID || e.B2_KEY_ID || e.S3_KEY_ID || '';
  const appKey = e.S3_SECRET_ACCESS_KEY || e.B2_APP_KEY || e.S3_APP_KEY || '';
  if (!keyId || !appKey) {
    throw new Error('存储桶密钥未配置！请在 Pages 环境变量中设置 S3_ACCESS_KEY_ID 与 S3_SECRET_ACCESS_KEY (或 B2_KEY_ID 与 B2_APP_KEY)');
  }
  const U = new URL(u), M = o.method || 'GET', amz = new Date().toISOString().replace(/[:-]|\.\d{3}/g, ''), dt = amz.slice(0, 8), rh = new Headers(o.headers || {}), sh = new Headers();
  const region = e.S3_REGION || CONFIG.S3_REGION;
  sh.set('host', U.host);
  sh.set('x-amz-date', amz);
  sh.set('x-amz-content-sha256', 'UNSIGNED-PAYLOAD');
  const cu = decodeURIComponent(U.pathname).split('/').map(awsUriEncode).join('/').replace(/%2F/g, '/'), cq = Array.from(U.searchParams).sort(([a], [b]) => a < b ? -1 : 1).map(([k, v]) => awsUriEncode(k) + '=' + awsUriEncode(v)).join('&'), sk = Array.from(sh.keys()).sort(), ch = sk.map(k => k + ':' + sh.get(k) + '\n').join(''), ss = sk.join(';'), crh = await hashSha256(M + '\n' + cu + '\n' + cq + '\n' + ch + '\n' + ss + '\nUNSIGNED-PAYLOAD'), cs = dt + '/' + region + '/s3/aws4_request', ks = await hmacSha256(await hmacSha256(await hmacSha256(await hmacSha256('AWS4' + appKey, dt), region), 's3'), 'aws4_request'), sig = Array.from(await hmacSha256(ks, 'AWS4-HMAC-SHA256\n' + amz + '\n' + cs + '\n' + crh)).map(b => b.toString(16).padStart(2, '0')).join('');
  rh.set('host', U.host);
  rh.set('x-amz-date', amz);
  rh.set('x-amz-content-sha256', 'UNSIGNED-PAYLOAD');
  rh.set('Authorization', 'AWS4-HMAC-SHA256 Credential=' + keyId + '/' + cs + ', SignedHeaders=' + ss + ', Signature=' + sig);
  return fetch(U.toString(), { ...o, headers: rh });
}

async function awsS3Presign(u, e, M = 'PUT', ex = 3600) {
  const keyId = e.S3_ACCESS_KEY_ID || e.B2_KEY_ID || e.S3_KEY_ID || '';
  const appKey = e.S3_SECRET_ACCESS_KEY || e.B2_APP_KEY || e.S3_APP_KEY || '';
  if (!keyId || !appKey) {
    throw new Error('存储桶密钥未配置！请在 Pages 环境变量中设置 S3_ACCESS_KEY_ID 与 S3_SECRET_ACCESS_KEY (或 B2_KEY_ID 与 B2_APP_KEY)');
  }
  const U = new URL(u), amz = new Date().toISOString().replace(/[:-]|\.\d{3}/g, ''), dt = amz.slice(0, 8);
  const region = e.S3_REGION || CONFIG.S3_REGION;
  const cs = dt + '/' + region + '/s3/aws4_request';
  U.searchParams.set('X-Amz-Algorithm', 'AWS4-HMAC-SHA256');
  U.searchParams.set('X-Amz-Credential', keyId + '/' + cs);
  U.searchParams.set('X-Amz-Date', amz);
  U.searchParams.set('X-Amz-Expires', ex.toString());
  U.searchParams.set('X-Amz-SignedHeaders', 'content-type;host');
  const cu = decodeURIComponent(U.pathname).split('/').map(awsUriEncode).join('/').replace(/%2F/g, '/'), cq = Array.from(U.searchParams).sort(([a], [b]) => a < b ? -1 : 1).map(([k, v]) => awsUriEncode(k) + '=' + awsUriEncode(v)).join('&'), ch = 'content-type:application/octet-stream\nhost:' + U.host + '\n', crh = await hashSha256(M + '\n' + cu + '\n' + cq + '\n' + ch + '\ncontent-type;host\nUNSIGNED-PAYLOAD'), ks = await hmacSha256(await hmacSha256(await hmacSha256(await hmacSha256('AWS4' + appKey, dt), region), 's3'), 'aws4_request'), sig = Array.from(await hmacSha256(ks, 'AWS4-HMAC-SHA256\n' + amz + '\n' + cs + '\n' + crh)).map(b => b.toString(16).padStart(2, '0')).join('');
  U.searchParams.set('X-Amz-Signature', sig);
  return U.toString();
}

function getS3Client(e) {
  return { fetch: (u, o = {}) => awsS3Fetch(u, o, e) };
}

function rLP(cfg) {
  const siteTitle = escapeHTML(CONFIG.SITE_TITLE);
  return '<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>登录 - ' + siteTitle + '</title><link rel="stylesheet" href="/css/style.css"><style>:root{--bgc:#ffffff;--tx:#1e293b;--cb:rgba(255,255,255,0.65);--cd:rgba(0,0,0,0.08)}body{font-family:-apple-system,sans-serif;background-color:var(--bgc);color:var(--tx);margin:0;display:flex;justify-content:center;align-items:center;min-height:100vh}.c{background:var(--cb);padding:35px 25px;border-radius:16px;box-shadow:0 8px 32px rgba(0,0,0,0.06);width:90%;max-width:350px;border:1px solid var(--cd);text-align:center;backdrop-filter:blur(16px) saturate(150%);-webkit-backdrop-filter:blur(16px) saturate(150%)}input,button{width:100%;padding:14px;margin:10px 0;box-sizing:border-box;border-radius:12px;border:1px solid var(--cd);background:rgba(0,0,0,0.03);color:inherit;outline:none;font-size:15px;transition:0.3s}input:focus{border-color:#3b82f6;background:rgba(0,0,0,0.05)}button{background:#3b82f6;color:#fff;border:none;cursor:pointer;font-weight:bold;margin-top:15px}button:hover{background:#2563eb;transform:translateY(-2px)}</style></head><body>' + getBgLayer(cfg) + '<div class="c"><h2 style="margin-top:0;font-size:22px;display:flex;align-items:center;justify-content:center;gap:6px"><img class="om-emoji om-emoji-lg" src="/openmoji/1F510.svg" alt="🔐"> 管理员验证</h2><p style="color:gray;font-size:13px;margin-bottom:20px">需要鉴权以访问核心控制面板</p><form action="/login" method="post"><input name="username" placeholder="账号" required><input type="password" name="password" placeholder="密码" required><button type="submit">登 录</button></form><a href="/" style="display:inline-block;margin-top:15px;font-size:13px;color:gray;text-decoration:none;">&larr; 返回首页</a></div></body></html>';
}

function rR(m, u, cfg) {
  return '<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><meta http-equiv="refresh" content="1.5;url=' + u + '"><style>:root{--bgc:#ffffff;--tx:#1e293b;--cb:rgba(255,255,255,0.65);--cd:rgba(0,0,0,0.08)}body{font-family:-apple-system,sans-serif;background-color:var(--bgc);color:var(--tx);margin:0;display:flex;justify-content:center;align-items:center;min-height:100vh}.c{background:var(--cb);padding:30px 40px;border-radius:16px;box-shadow:0 8px 32px rgba(0,0,0,0.06);border:1px solid var(--cd);text-align:center;backdrop-filter:blur(16px) saturate(150%);-webkit-backdrop-filter:blur(16px) saturate(150%)}</style></head><body>' + getBgLayer(cfg) + '<div class="c"><h2 style="margin:0">' + m + '</h2><p style="color:gray;font-size:14px;margin:15px 0 0">页面即将自动跳转...</p></div></body></html>';
}

function getShareIconSvg(name) {
  const ext = (name.split('.').pop() || '').toLowerCase();
  if (['zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz', 'iso', 'apk', 'dmg'].includes(ext)) {
    return '<svg viewBox="0 0 24 24" width="70" height="70" fill="none"><path d="M4 20h16a1 1 0 0 0 1-1V7a1 1 0 0 0-1-1h-7l-2-3H5a1 1 0 0 0-1 1v15a1 1 0 0 0 1 1Z" fill="#4ECDC4" fill-opacity="0.15" stroke="#4ECDC4" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/><path d="M3 8h18v11a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V8Z" fill="#A8E6E0" fill-opacity="0.18" stroke="#A8E6E0" stroke-width="1.1" stroke-linecap="round" stroke-linejoin="round"/><path d="M12 6v12" stroke="#4ECDC4" stroke-width="1.4" stroke-dasharray="1.8 2.2" stroke-opacity="0.7" stroke-linecap="round"/><rect x="11" y="9" width="2" height="2" rx="0.5" fill="#4ECDC4" fill-opacity="0.5"/><rect x="11" y="13" width="2" height="2" rx="0.5" fill="#4ECDC4" fill-opacity="0.5"/></svg>';
  }
  if (['mp4', 'mkv', 'avi', 'mov', 'wmv', 'flv', 'webm', 'm4v'].includes(ext)) {
    return '<svg viewBox="0 0 24 24" width="70" height="70" fill="none"><rect x="2" y="6" width="20" height="12" rx="2.5" fill="#1E3A5F" fill-opacity="0.35" stroke="#4A9EFF" stroke-width="1.2" stroke-linecap="round"/><rect x="5" y="9" width="3" height="6" rx="0.8" fill="#4A9EFF" fill-opacity="0.2"/><rect x="16" y="9" width="3" height="6" rx="0.8" fill="#4A9EFF" fill-opacity="0.2"/><circle cx="12" cy="12" r="2.8" fill="#FF6B9D" fill-opacity="0.35" stroke="#FF6B9D" stroke-width="1" stroke-linecap="round"/><path d="M11 10.8v2.4l2-1.2-2-1.2Z" fill="#FFB3D1" fill-opacity="0.7"/></svg>';
  }
  if (['mp3', 'flac', 'wav', 'aac', 'ogg', 'm4a'].includes(ext)) {
    return '<svg viewBox="0 0 24 24" width="70" height="70" fill="none"><rect x="3" y="4" width="18" height="16" rx="3" fill="#FFEAA7" fill-opacity="0.25" stroke="#FDCB6E" stroke-width="1.2" stroke-linecap="round"/><circle cx="9" cy="14" r="2.5" fill="#E17055" fill-opacity="0.5"/><circle cx="15" cy="12" r="2.5" fill="#E17055" fill-opacity="0.5"/><path d="M11.5 14V8l6-2v6" stroke="#E17055" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/></svg>';
  }
  if (['js', 'ts', 'html', 'css', 'json', 'py', 'java', 'c', 'cpp', 'sh', 'sql'].includes(ext)) {
    return '<svg viewBox="0 0 24 24" width="70" height="70" fill="none"><path d="M6 3h8l5 5v13a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1Z" fill="#1E2A3A" fill-opacity="0.4" stroke="#61DAFB" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/><path d="M14 3v5h5" fill="none" stroke="#61DAFB" stroke-width="1.2" stroke-opacity="0.6" stroke-linecap="round" stroke-linejoin="round"/><path d="M10.5 13.5L8.5 16l2 2.5" stroke="#61DAFB" stroke-width="1.3" fill="none" stroke-linecap="round" stroke-linejoin="round" stroke-opacity="0.9"/><path d="M13.5 13.5l2 2.5-2 2.5" stroke="#61DAFB" stroke-width="1.3" fill="none" stroke-linecap="round" stroke-linejoin="round" stroke-opacity="0.9"/><circle cx="12" cy="9" r="1" fill="#F0DB4F" fill-opacity="0.6"/></svg>';
  }
  return '<svg viewBox="0 0 24 24" width="70" height="70" fill="none"><path d="M6 3h8l5 5v13a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1Z" fill="#6C5CE7" fill-opacity="0.12" stroke="#6C5CE7" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/><path d="M14 3v5h5" fill="#A29BFE" fill-opacity="0.25" stroke="#6C5CE7" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/><path d="M9 13h6M9 17h4" stroke="#6C5CE7" stroke-width="1.2" stroke-linecap="round"/></svg>';
}

function rSP(f, o, p, cfg) {
  const ext = f.name.split('.').pop().toLowerCase(), sp = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'svg', 'ico'].includes(ext), s = escapeHTML(f.name), w = p ? '&pwd=' + encodeURIComponent(p) : '';
  const dlUrl = o + '/file/' + f.id + '?dl=1' + w;
  const fSize = Number(f.size) || 0;
  const fSizeStr = (fSize / 1048576).toFixed(2) + ' MB';
  const isSmall = fSize < 20 * 1024 * 1024;
  const siteTitle = escapeHTML(CONFIG.SITE_TITLE);
  const fastDlBtn = isSmall
    ? '<a href="' + dlUrl + '" download="' + s + '" class="btn btn-outline" style="text-decoration:none"><img class="om-emoji" src="/openmoji/1F4E5.svg" alt="📥"> 网页下载</a>'
    : '<button type="button" class="btn btn-outline" onclick="smartDl()"><img class="om-emoji" src="/openmoji/1F4E5.svg" alt="📥"> 网页下载</button>';

  return '<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>' + s + ' - ' + siteTitle + '</title><link rel="stylesheet" href="/css/style.css"><style>:root{--bgc:#ffffff;--tx:#1e293b;--cb:rgba(255,255,255,0.65);--cd:rgba(0,0,0,0.08)}body{font-family:-apple-system,sans-serif;background-color:var(--bgc);color:var(--tx);margin:0;display:flex;justify-content:center;align-items:center;min-height:100vh}.c{background:var(--cb);padding:30px;border-radius:16px;box-shadow:0 8px 32px rgba(0,0,0,0.06);border:1px solid var(--cd);text-align:center;max-width:400px;width:90%;backdrop-filter:blur(16px) saturate(150%);-webkit-backdrop-filter:blur(16px) saturate(150%)}img{max-width:100%;border-radius:12px;box-shadow:0 4px 15px rgba(0,0,0,0.1)}.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:12px 24px;border-radius:10px;font-weight:bold;transition:0.3s;box-sizing:border-box}.btn:hover{transform:scale(1.02)}.modal-overlay{position:fixed;inset:0;background:rgba(255,255,255,0.25);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);display:flex;align-items:center;justify-content:center;z-index:2000}.modal-content{background:var(--cb);padding:24px;border-radius:16px;box-shadow:0 12px 40px rgba(0,0,0,0.15);border:1px solid var(--cd);max-width:380px;width:90%;backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px)}</style></head><body>' + getBgLayer(cfg) + '<div class="c"><div style="margin:10px auto 15px auto;display:flex;align-items:center;justify-content:center;">' + (sp ? '<img src="' + o + '/file/' + f.id + (w ? '?' + w.slice(1) : '') + '">' : getShareIconSvg(f.name)) + '</div><h3>' + s + '</h3><p style="color:gray;font-size:14px;margin-bottom:15px">' + fSizeStr + '</p><div id="share-action-container" style="display:flex;flex-direction:column;gap:10px">' + fastDlBtn + '<a href="' + dlUrl + '" class="btn btn-outline" style="text-decoration:none"><img class="om-emoji" src="/openmoji/1F4E5.svg" alt="📥"> 原生下载</a></div></div><script>' +
  'const FILE = { name: ' + JSON.stringify(f.name) + ', size: ' + fSize + ', url: ' + JSON.stringify(dlUrl) + ' };' +
  'function formatBytes(b) { if (!b) return "0 B"; const k = 1024, s = ["B", "KB", "MB", "GB", "TB"], i = Math.floor(Math.log(b) / Math.log(k)); return parseFloat((b / Math.pow(k, i)).toFixed(2)) + " " + s[i]; }' +
  'function copyTxt(t) { if (navigator.clipboard && window.isSecureContext) { navigator.clipboard.writeText(t).catch(() => prompt("复制:", t)); } else { const a = document.createElement("textarea"); a.value = t; document.body.appendChild(a); a.select(); try { document.execCommand("copy"); } catch(e){} a.remove(); } }' +
  'let currAbort = null;' +
  'function closeModal(id) { const m = document.getElementById(id); if (m) m.remove(); }' +
  'function restoreShareActions() {' +
  '  const c = document.getElementById("share-action-container"); if (!c) return;' +
  '  c.innerHTML = ' + JSON.stringify(fastDlBtn + '<a href="' + dlUrl + '" class="btn btn-outline" style="text-decoration:none"><img class="om-emoji" src="/openmoji/1F4E5.svg" alt="📥"> 原生下载</a>') + ';' +
  '}' +
  'function smartDl() {' +
  '  const S20 = 20971520, S500 = 524288000;' +
  '  const isMobile = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent) || (navigator.maxTouchPoints > 1 && /Macintosh/i.test(navigator.userAgent));' +
  '  if (FILE.size < S20) {' +
  '    const a = document.createElement("a"); a.href = FILE.url; a.download = FILE.name; document.body.appendChild(a); a.click(); a.remove(); return;' +
  '  }' +
  '  if (FILE.size >= S20 && FILE.size <= S500) return dlMemory();' +
  '  if (FILE.size > S500) {' +
  '    if (!isMobile && typeof window.showSaveFilePicker === "function") return dlStream();' +
  '    return showTpModal();' +
  '  }' +
  '}' +
  'function dlMemory() {' +
  '  const c = document.getElementById("share-action-container"); if (!c) return;' +
  '  c.innerHTML = \'<div style="width:100%;padding:14px;background:rgba(0,0,0,.03);border-radius:12px;border:1px inset var(--cd);text-align:left"><div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px"><span id="dl-status" style="color:var(--tx,#1e293b);font-weight:700;font-size:13px;display:flex;align-items:center;gap:6px"><img class="om-emoji" src="/openmoji/1F4E5.svg" alt="📥"> 3 线程分片准备中...</span><span class="dl-stat-badge">3 线程分片</span></div><div class="progress-container" style="height:12px;margin:0 0 6px"><div id="dl-bar" class="progress-bar" style="width:0%"></div></div><div style="display:flex;justify-content:space-between;font-size:11px;color:gray"><span id="dl-bytes">0 B / \' + formatBytes(FILE.size) + \'</span><span id="dl-speed" style="color:#10b981;font-weight:700">0.0 MB/s</span><span id="dl-pct" style="font-weight:700">0%</span></div><div id="dl-actions" style="display:flex;gap:10px;margin-top:12px"><button type="button" class="btn btn-sm btn-outline flex-1" onclick="if(currAbort)currAbort.abort();restoreShareActions()">取消下载</button></div></div>\';' +
  '  const tc = 3, cs = Math.ceil(FILE.size / tc), chunks = new Array(tc);' +
  '  let db = 0, st = Date.now(); currAbort = new AbortController();' +
  '  const upd = () => {' +
  '    const p = Math.min(Math.round((db / FILE.size) * 100), 100), el = (Date.now() - st) / 1000;' +
  '    const sp = el > 0 ? (db / 1048576 / el).toFixed(1) : "0.0";' +
  '    const b = document.getElementById("dl-bar"), s = document.getElementById("dl-status"), spd = document.getElementById("dl-speed"), by = document.getElementById("dl-bytes"), pc = document.getElementById("dl-pct");' +
  '    if (b) b.style.width = p + "%"; if (s) s.innerHTML = "<img class=\\\'om-emoji\\\' src=\\\'/openmoji/1F4E5.svg\\\' alt=\\\'📥\\\'> " + (p >= 100 ? "拼装 3 分片 Blob 中..." : "3 线程接收中..."); if (spd) spd.innerText = sp + " MB/s"; if (by) by.innerText = formatBytes(db) + " / " + formatBytes(FILE.size); if (pc) pc.innerText = p + "%";' +
  '  };' +
  '  const tasks = Array.from({ length: tc }, (_, i) => {' +
  '    const s = i * cs, e = Math.min(s + cs - 1, FILE.size - 1);' +
  '    if (s > e) { chunks[i] = new Blob([]); return Promise.resolve(); }' +
  '    return fetch(FILE.url, { headers: { Range: "bytes=" + s + "-" + e }, signal: currAbort.signal }).then(async r => {' +
  '      if (r.status !== 206 && r.status !== 200) throw new Error("分片失败: " + r.status);' +
  '      const rd = r.body.getReader(), pBufs = [];' +
  '      while (true) { const { done, value } = await rd.read(); if (done) break; pBufs.push(value); db += value.length; upd(); }' +
  '      chunks[i] = new Blob(pBufs);' +
  '    });' +
  '  });' +
  '  Promise.all(tasks).then(() => {' +
  '    const s = document.getElementById("dl-status"), act = document.getElementById("dl-actions");' +
  '    if (s) { s.innerHTML = "本地秒保存成功！"; s.style.color = "#10b981"; }' +
  '    if (act) act.innerHTML = "<button type=\\\'button\\\' class=\\\'btn btn-sm btn-success flex-1\\\' onclick=\\\'restoreShareActions()\\\'>下载完毕</button>";' +
  '    const b = new Blob(chunks, { type: "application/octet-stream" }); chunks.length = 0;' +
  '    const u = URL.createObjectURL(b), a = document.createElement("a"); a.href = u; a.download = FILE.name; document.body.appendChild(a); a.click(); a.remove();' +
  '    setTimeout(() => URL.revokeObjectURL(u), 30000);' +
  '  }).catch(e => {' +
  '    if (e.name !== "AbortError") { alert("分片失败，转原生下载: " + e.message); window.open(FILE.url, "_blank"); restoreShareActions(); }' +
  '  });' +
  '}' +
  'async function dlStream() {' +
  '  let h; try { h = await window.showSaveFilePicker({ suggestedName: FILE.name }); } catch(e){ if(e.name === "AbortError") return; return showTpModal(); }' +
  '  let w; try { w = await h.createWritable(); } catch(e){ return showTpModal(); }' +
  '  const c = document.getElementById("share-action-container"); if (!c) return;' +
  '  c.innerHTML = \'<div style="width:100%;padding:14px;background:rgba(0,0,0,.03);border-radius:12px;border:1px inset var(--cd);text-align:left"><div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px"><span id="dl-status" style="color:var(--tx,#1e293b);font-weight:700;font-size:13px;display:flex;align-items:center;gap:6px"><img class="om-emoji" src="/openmoji/1F4E5.svg" alt="📥"> 3 线程磁盘直写准备中...</span><span class="dl-stat-badge">3 线程直写</span></div><div class="progress-container" style="height:12px;margin:0 0 6px"><div id="dl-bar" class="progress-bar" style="width:0%"></div></div><div style="display:flex;justify-content:space-between;font-size:11px;color:gray"><span id="dl-bytes">0 B / \' + formatBytes(FILE.size) + \'</span><span id="dl-speed" style="color:#10b981;font-weight:700">0.0 MB/s</span><span id="dl-pct" style="font-weight:700">0%</span></div><div id="dl-actions" style="display:flex;gap:10px;margin-top:12px"><button type="button" class="btn btn-sm btn-outline flex-1" onclick="if(currAbort)currAbort.abort();restoreShareActions()">取消下载</button></div></div>\';' +
  '  const tc = 3, cs = Math.ceil(FILE.size / tc); let db = 0, st = Date.now(), wQ = Promise.resolve(); currAbort = new AbortController();' +
  '  const safeW = (pos, buf) => { wQ = wQ.then(() => w.write({ type: "write", position: pos, data: buf })); return wQ; };' +
  '  const upd = () => {' +
  '    const p = Math.min(Math.round((db / FILE.size) * 100), 100), el = (Date.now() - st) / 1000;' +
  '    const sp = el > 0 ? (db / 1048576 / el).toFixed(1) : "0.0";' +
  '    const b = document.getElementById("dl-bar"), s = document.getElementById("dl-status"), spd = document.getElementById("dl-speed"), by = document.getElementById("dl-bytes"), pc = document.getElementById("dl-pct");' +
  '    if (b) b.style.width = p + "%"; if (s) s.innerHTML = "<img class=\\\'om-emoji\\\' src=\\\'/openmoji/1F4E5.svg\\\' alt=\\\'📥\\\'> " + (p >= 100 ? "正在刷盘固化..." : "3 线程流式直写磁盘中..."); if (spd) spd.innerText = sp + " MB/s"; if (by) by.innerText = formatBytes(db) + " / " + formatBytes(FILE.size); if (pc) pc.innerText = p + "%";' +
  '  };' +
  '  const tasks = Array.from({ length: tc }, (_, i) => {' +
  '    const s = i * cs, e = Math.min(s + cs - 1, FILE.size - 1);' +
  '    if (s > e) return Promise.resolve();' +
  '    let cur = s;' +
  '    return fetch(FILE.url, { headers: { Range: "bytes=" + s + "-" + e }, signal: currAbort.signal }).then(async r => {' +
  '      if (r.status !== 206 && r.status !== 200) throw new Error("分片失败: " + r.status);' +
  '      const rd = r.body.getReader();' +
  '      while (true) { const { done, value } = await rd.read(); if (done) break; await safeW(cur, value); cur += value.length; db += value.length; upd(); }' +
  '    });' +
  '  });' +
  '  Promise.all(tasks).then(async () => {' +
  '    await wQ; await w.close();' +
  '    const s = document.getElementById("dl-status"), act = document.getElementById("dl-actions");' +
  '    if (s) { s.innerHTML = "<img class=\\\'om-emoji\\\' src=\\\'/openmoji/2705.svg\\\' alt=\\\'✅\\\'> 磁盘直写完成！"; s.style.color = "#10b981"; }' +
  '    if (act) act.innerHTML = "<button type=\\\'button\\\' class=\\\'btn btn-sm btn-success flex-1\\\' onclick=\\\'restoreShareActions()\\\'>完成</button>";' +
  '  }).catch(async e => {' +
  '    try{await w.abort();}catch(_){}' +
  '    if(e.name !== "AbortError") { alert("直写失败，转原生下载: " + e.message); window.open(FILE.url, "_blank"); restoreShareActions(); }' +
  '  });' +
  '}' +
  'function showTpModal() {' +
  '  try { copyTxt(FILE.url); } catch(e){}' +
  '  const old = document.getElementById("tpM"); if (old) old.remove();' +
  '  const m = document.createElement("div"); m.className = "modal-overlay"; m.id = "tpM"; m.style.zIndex = "2000";' +
  '  m.innerHTML = \'<div class="modal-content" style="max-width:380px;text-align:center"><div style="font-size:42px;margin:5px auto 0"><img class="om-emoji om-emoji-lg" src="/openmoji/1F680.svg" alt="🚀"></div><h3 style="margin:8px 0 4px;font-size:17px">超大文件加速下载指引</h3><p style="color:gray;font-size:12px;margin:0 0 12px;word-break:break-all">文件：<b>\' + FILE.name + \'</b><br>大小：<b style="color:#3b82f6">\' + formatBytes(FILE.size) + \'</b>（大于 500MB）</p><div style="background:rgba(16,185,129,0.12);border:1px solid rgba(16,185,129,0.3);padding:10px 12px;border-radius:12px;margin-bottom:12px;font-size:12px;color:#065f46;display:flex;align-items:center;justify-content:center;gap:6px"><img class="om-emoji" src="/openmoji/2705.svg" alt="✅"><span><b>已自动将高速直链复制到剪贴板！</b></span></div><div style="text-align:left;background:rgba(0,0,0,0.03);border:1px solid var(--cd);padding:10px 12px;border-radius:12px;margin-bottom:14px;font-size:12px;line-height:1.5"><p style="color:gray;margin:0 0 8px">当前设备/浏览器不支持磁盘流式直写，直接内存下载极易导致网页闪退崩溃。强烈建议粘贴直链至专业工具满速下载：</p><div style="display:flex;flex-direction:column;gap:5px"><div class="app-badge-item">💻 <b>电脑推荐</b>: IDM / Motrix / FDM / 迅雷</div><div class="app-badge-item">📱 <b>手机推荐</b>: IDM+ / 迅雷 / 闪电下载</div></div></div><div style="display:flex;flex-direction:column;gap:8px"><button type="button" class="btn btn-success" style="width:100%;padding:12px" onclick="copyTxt(FILE.url);alert(\\\'已重新复制直链！\\\')"><img class="om-emoji" src="/openmoji/1F4CB.svg" alt="📋"> 再次复制直链</button><a href="\' + FILE.url + \'" class="btn btn-outline" target="_blank" style="text-decoration:none;padding:10px" onclick="closeModal(\\\'tpM\\\')"><img class="om-emoji" src="/openmoji/1F4E5.svg" alt="📥"> 仍尝试浏览器原生下载</a><button type="button" class="btn btn-outline" style="padding:10px" onclick="closeModal(\\\'tpM\\\')">关闭</button></div></div>\';' +
  '  document.body.appendChild(m);' +
  '}' +
  '</script></body></html>';
}

export async function onRequest(context) {
  const { request: req, env: e, next } = context;
  const U = new URL(req.url), P = U.pathname, C = req.headers.get('Cookie') || '';
  const tM = C.match(new RegExp('(?:^|; )' + CONFIG.AUTH_COOKIE_NAME + '=([^;]*)'));
  const aH = req.headers.get('Authorization');
  const token = (aH && aH.startsWith('Bearer ')) ? aH.substring(7) : (tM ? tM[1] : null);
  const cfg = await getSiteConfig(e);
  const iA = await verifyAdminToken(token, e, cfg);

  // 1. 根页面 SSR 注入云端配置
  if (P === '/' || P === '/index.html') {
    const res = await next();
    if (res && res.status === 200) {
      let html = await res.text();
      const siteTitle = escapeHTML(CONFIG.SITE_TITLE);
      html = html.replace(/<title>.*?<\/title>/, `<title>${siteTitle}</title>`);
      html = html.replace(/(<h2 class="header-title">[\s\S]*?<span>).*?(<\/span>)/, `$1${siteTitle}$2`);
      const clientCfg = Object.assign({}, cfg, { hasImageBucket: HAS_IMAGE, siteTitle: CONFIG.SITE_TITLE });
      html = html.replace('</head>', `<script>window.__CFG__=${JSON.stringify(clientCfg)};</script></head>`);
      const h = new Headers(res.headers);
      h.set('Content-Type', 'text/html;charset=UTF-8');
      return new Response(html, { status: 200, headers: h });
    }
    return res;
  }

  // 1.1 静态配置接口（方便客户端直接获取站点标题与基础配置）
  if (P === '/config.json') {
    return Response.json(appConfig || {}, {
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=60' }
    });
  }

  // 2. 登录认证接口
  if (P === '/login') {
    if (req.method === 'GET') {
      return new Response(rLP(cfg), { headers: { 'Content-Type': 'text/html;charset=UTF-8', 'Cache-Control': 'no-store, no-cache, must-revalidate' } });
    }
    const isJsonReq = req.headers.get('Accept')?.includes('application/json');
    const cType = req.headers.get('Content-Type') || '';
    let u, p;
    if (cType.includes('application/json')) {
      const j = await req.json();
      u = j.username;
      p = j.password;
    } else {
      const fd = await req.formData();
      u = fd.get('username');
      p = fd.get('password');
    }
    const adminUser = e.ADMIN_USER || 'admin';
    if (u === adminUser && p === e.ADMIN_PASS) {
      const newToken = await createAdminToken(e);
      if (isJsonReq) return Response.json({ ok: true, token: newToken, user: adminUser }, { status: 200 });
      return new Response(rR('🎉 欢迎回来！', '/', cfg), {
        headers: {
          'Content-Type': 'text/html;charset=UTF-8',
          'Cache-Control': 'no-store, no-cache, must-revalidate',
          'Set-Cookie': CONFIG.AUTH_COOKIE_NAME + '=' + newToken + '; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=2592000'
        }
      });
    }
    if (isJsonReq) return Response.json({ ok: false, error: '身份校验失败' }, { status: 401 });
    return new Response(rR('密码错误！', '/login', cfg), { headers: { 'Content-Type': 'text/html;charset=UTF-8', 'Cache-Control': 'no-store, no-cache, must-revalidate' } });
  }

  // 3. 退出登录
  if (P === '/logout') {
    cfg.lastLogoutTime = Date.now();
    globalSiteConfig = cfg;
    globalConfigTime = Date.now();
    await awsS3Fetch(CONFIG.S3_ENDPOINT + '/' + CONFIG.BUCKETS.RESOURCE + '/' + encodeURIComponent('.sys/__site_config__.json'), {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(cfg)
    }, e);
    return new Response(rR('已安全退出，所有设备已下线', '/', cfg), {
      headers: {
        'Content-Type': 'text/html;charset=UTF-8',
        'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
        'Set-Cookie': CONFIG.AUTH_COOKIE_NAME + '=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT'
      }
    });
  }

  // 4. 分享链接页面
  if (P.startsWith('/share/')) {
    const { results: R } = await e.DB.prepare("SELECT * FROM files WHERE id=?").bind(P.split('/')[2]).all();
    if (!R.length || (R[0].is_hidden === 1 && !iA)) return new Response('Not Found', { status: 404 });
    return new Response(rSP(R[0], U.origin, U.searchParams.get('pwd') || '', cfg), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
  }

  // 5. 文件下载与流式传输
  if (P.startsWith('/file/')) {
    const { results: R } = await e.DB.prepare("SELECT * FROM files WHERE id=?").bind(P.split('/')[2]).all();
    if (!R.length) return new Response('404', { status: 404 });
    const f = R[0];
    if (f.is_hidden === 1 && !iA) return new Response('403', { status: 403 });
    if (!iA && f.folder) {
      const m = await e.DB.prepare("SELECT password FROM folder_meta WHERE name=?").bind(f.folder).first();
      if (m && m.password) {
        const uP = U.searchParams.get('pwd');
        const lM = C.match(new RegExp('(?:^|; )lock_' + await hashSha256(f.folder) + '=([^;]*)'));
        if ((!lM || decodeURIComponent(lM[1]) !== m.password) && uP !== m.password) return new Response('401', { status: 401 });
      }
    }
    const sh = { 'Accept-Encoding': 'identity' };
    if (req.headers.has('Range')) {
      let r = req.headers.get('Range');
      if (r.includes(',')) r = r.split(',')[0];
      sh['Range'] = r;
    }
    if (req.headers.has('If-None-Match')) sh['If-None-Match'] = req.headers.get('If-None-Match');
    if (req.headers.has('If-Modified-Since')) sh['If-Modified-Since'] = req.headers.get('If-Modified-Since');
    const rs = await awsS3Fetch(CONFIG.S3_ENDPOINT + '/' + f.type + '/' + encodeURIComponent(f.b2_path), { headers: sh }, e);
    if (rs.status === 304) return new Response(null, { status: 304, headers: { 'Cache-Control': 'public, max-age=2592000', 'ETag': rs.headers.get('ETag'), 'Access-Control-Allow-Origin': '*' } });
    const rh = new Headers(rs.headers);
    rh.set('Content-Disposition', (U.searchParams.get('dl') === '1' ? 'attachment' : 'inline') + "; filename*=UTF-8''" + encodeURIComponent(f.name));
    rh.set('Access-Control-Allow-Origin', '*');
    rh.set('Access-Control-Expose-Headers', 'Content-Range, Accept-Ranges, Content-Length, Content-Disposition');
    rh.set('Access-Control-Allow-Headers', 'Range, If-None-Match, If-Modified-Since, Content-Type');
    if (!rh.has('Accept-Ranges')) rh.set('Accept-Ranges', 'bytes');
    rh.delete('Content-Encoding');
    if ([200, 206].includes(rs.status)) rh.set('Cache-Control', 'public, max-age=2592000, no-transform');
    return new Response(rs.body, { status: rs.status, headers: rh });
  }

  // 6. 后端 API 处理
  if (P.startsWith('/api/')) {
    try {
      const isPublicApi = P === '/api/data' || P === '/api/unlock';
      if (!isPublicApi && !iA) return Response.json({ ok: false, error: '未授权' }, { status: 401, headers: { 'Cache-Control': 'no-store' } });

      if (P === '/api/admin/config') {
        const bp = '.sys/__site_config__.json';
        if (req.method === 'GET') {
          const rs = await awsS3Fetch(CONFIG.S3_ENDPOINT + '/' + CONFIG.BUCKETS.RESOURCE + '/' + encodeURIComponent(bp), { method: 'GET' }, e);
          if (rs.status === 200) return new Response(rs.body, { headers: { 'Content-Type': 'application/json' } });
          return Response.json({});
        }
        if (req.method === 'POST') {
          const txt = await req.text();
          try {
            globalSiteConfig = JSON.parse(txt);
            globalConfigTime = Date.now();
          } catch (err) {}
          const rs = await awsS3Fetch(CONFIG.S3_ENDPOINT + '/' + CONFIG.BUCKETS.RESOURCE + '/' + encodeURIComponent(bp), {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: txt
          }, e);
          return Response.json({ ok: rs.ok });
        }
      }

      if (P === '/api/admin/github/rules') {
        const bp = '.sys/__site_config__.json';
        const cfgData = await getSiteConfig(e, true);
        if (req.method === 'GET') {
          return Response.json({
            rules: cfgData.githubSyncRules || [],
            hasToken: !!(e.GITHUB_TOKEN || e.GH_TOKEN)
          }, {
            headers: { 'Cache-Control': 'no-store, no-cache, must-revalidate' }
          });
        }
        if (req.method === 'POST') {
          const { rules } = await req.json();
          cfgData.githubSyncRules = rules || [];
          globalSiteConfig = cfgData;
          globalConfigTime = Date.now();
          const rs = await awsS3Fetch(CONFIG.S3_ENDPOINT + '/' + CONFIG.BUCKETS.RESOURCE + '/' + encodeURIComponent(bp), {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(cfgData)
          }, e);
          return Response.json({ ok: rs.ok }, {
            headers: { 'Cache-Control': 'no-store' }
          });
        }
      }

      if (P === '/api/admin/github/sync' && req.method === 'POST') {
        const bp = '.sys/__site_config__.json';
        const { ruleId, force } = await req.json();
        const cfgData = await getSiteConfig(e, true);
        const rules = cfgData.githubSyncRules || [];
        const rule = rules.find(r => r.id === ruleId);
        if (!rule) return Response.json({ ok: false, error: '未找到该追更任务' }, { headers: { 'Cache-Control': 'no-store' } });

        const cleanRepo = rule.repo.trim().replace(/^https?:\/\/github\.com\//, '').replace(/\/$/, '');
        if (!cleanRepo || !cleanRepo.includes('/')) return Response.json({ ok: false, error: 'GitHub 仓库格式不正确 (例: owner/repo)' }, { headers: { 'Cache-Control': 'no-store' } });

        const ghHeaders = {
          'User-Agent': 'Cloudflare-Worker-TangYani-Drive',
          'Accept': 'application/vnd.github.v3+json'
        };
        const ghToken = (e.GITHUB_TOKEN || e.GH_TOKEN || '').trim();
        if (ghToken) {
          ghHeaders['Authorization'] = `Bearer ${ghToken}`;
        }

        const ghRes = await fetch(`https://api.github.com/repos/${cleanRepo}/releases/latest`, {
          headers: ghHeaders
        });
        if (!ghRes.ok) {
          const errTxt = await ghRes.text();
          if (ghRes.status === 403 && !ghToken) {
            return Response.json({ ok: false, error: 'GitHub 匿名 IP 限频，请在 Cloudflare 环境变量中添加 GITHUB_TOKEN' }, { headers: { 'Cache-Control': 'no-store' } });
          }
          if (ghRes.status === 401) {
            return Response.json({ ok: false, error: 'Cloudflare 环境变量 GITHUB_TOKEN 无效或过期' }, { headers: { 'Cache-Control': 'no-store' } });
          }
          return Response.json({ ok: false, error: `GitHub API 错误 (${ghRes.status}): ${errTxt.slice(0, 100)}` }, { headers: { 'Cache-Control': 'no-store' } });
        }

        const rel = await ghRes.json();
        const tagName = rel.tag_name || '';
        const assets = rel.assets || [];

        const incWords = (rule.include || '').split(/[,，\s]+/).map(s => s.trim().toLowerCase()).filter(Boolean);
        const excWords = (rule.exclude || '').split(/[,，\s]+/).map(s => s.trim().toLowerCase()).filter(Boolean);

        const matchedAssets = assets.filter(a => {
          const fn = (a.name || '').toLowerCase();
          if (incWords.length > 0 && !incWords.some(w => fn.includes(w))) return false;
          if (excWords.length > 0 && excWords.some(w => fn.includes(w))) return false;
          return true;
        });

        const now = new Date();
        const pad = n => String(n).padStart(2, '0');
        const timeStr = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())} ${pad(now.getHours())}:${pad(now.getMinutes())}`;

        if (matchedAssets.length === 0) {
          return Response.json({ ok: true, skipped: true, tag: tagName, time: rule.lastUpdatedAt || timeStr, msg: `未找到符合正负词过滤的文件 (最新 Release 版本: ${tagName})` }, { headers: { 'Cache-Control': 'no-store' } });
        }

        if (!force && rule.lastTag === tagName && rule.lastFiles && rule.lastFiles.length > 0) {
          if (!rule.lastUpdatedAt) {
            rule.lastUpdatedAt = timeStr;
            globalSiteConfig = cfgData;
            globalConfigTime = Date.now();
            await awsS3Fetch(CONFIG.S3_ENDPOINT + '/' + CONFIG.BUCKETS.RESOURCE + '/' + encodeURIComponent(bp), {
              method: 'PUT',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(cfgData)
            }, e);
          }
          return Response.json({ ok: true, skipped: true, tag: tagName, time: rule.lastUpdatedAt || timeStr, msg: `已是最新版本 (${tagName})，无需更新` }, { headers: { 'Cache-Control': 'no-store' } });
        }

        const targetFolder = (rule.folder || cleanRepo.split('/')[1] || cleanRepo).trim();
        let newFiles = [];

        for (const asset of matchedAssets) {
          const fileRes = await fetch(asset.browser_download_url, {
            headers: { 'User-Agent': 'Cloudflare-Worker-TangYani-Drive' },
            redirect: 'follow'
          });
          if (!fileRes.ok) throw new Error(`拉取资源 ${asset.name} 失败 (${fileRes.status})`);

          const cleanFileName = asset.name.replace(/^.*[\\\/]/, '').replace(/[:*?"<>|]/g, '_');
          const newBp = Date.now() + '_' + cleanFileName;
          const bk = CONFIG.BUCKETS.RESOURCE;
          const putHeaders = {
            'Content-Type': asset.content_type || 'application/octet-stream',
            'x-amz-content-sha256': 'UNSIGNED-PAYLOAD'
          };
          if (asset.size) putHeaders['Content-Length'] = String(asset.size);

          const putRs = await awsS3Fetch(CONFIG.S3_ENDPOINT + '/' + bk + '/' + encodeURIComponent(newBp), {
            method: 'PUT',
            headers: putHeaders,
            body: fileRes.body
          }, e);
          if (!putRs.ok) throw new Error(`写入 B2 存储桶失败: ${await putRs.text()}`);

          const fileId = crypto.randomUUID();
          await e.DB.prepare("INSERT INTO files (id,name,b2_path,type,size,folder) VALUES (?,?,?,?,?,?)")
            .bind(fileId, cleanFileName, newBp, bk, asset.size || 0, targetFolder)
            .run();
          newFiles.push({ id: fileId, name: cleanFileName, b2_path: newBp, bucket: bk });
        }

        // 追更成功后清理旧版本文件（同时清理 B2 存储与 D1 数据库记录）
        // 1. 纳入原规则中记录的历史文件
        // 2. 纳入 targetFolder 下所有同名旧文件（防止同名文件覆盖导致重复或残留）
        const newFileIds = new Set(newFiles.map(f => f.id));
        const filesToDelete = [];
        const seenIds = new Set(newFileIds);

        if (rule.lastFiles && Array.isArray(rule.lastFiles)) {
          for (const old of rule.lastFiles) {
            if (old && old.id && !seenIds.has(old.id)) {
              seenIds.add(old.id);
              filesToDelete.push(old);
            }
          }
        }

        for (const nf of newFiles) {
          try {
            const { results } = await e.DB.prepare("SELECT id, name, b2_path, type as bucket FROM files WHERE folder=? AND name=?").bind(targetFolder, nf.name).all();
            if (results && results.length > 0) {
              for (const r of results) {
                if (r && r.id && !seenIds.has(r.id)) {
                  seenIds.add(r.id);
                  filesToDelete.push(r);
                }
              }
            }
          } catch (err) {}
        }

        for (const old of filesToDelete) {
          try {
            if (old.b2_path) {
              await awsS3Fetch(CONFIG.S3_ENDPOINT + '/' + (old.bucket || CONFIG.BUCKETS.RESOURCE) + '/' + encodeURIComponent(old.b2_path), { method: 'DELETE' }, e);
            }
            if (old.id) {
              await e.DB.prepare("DELETE FROM files WHERE id=?").bind(old.id).run();
            }
          } catch (err) {}
        }

        rule.lastTag = tagName;
        rule.lastUpdatedAt = timeStr;
        rule.lastFiles = newFiles;

        globalSiteConfig = cfgData;
        globalConfigTime = Date.now();
        globalLastSizeCalcTime = 0;
        await awsS3Fetch(CONFIG.S3_ENDPOINT + '/' + CONFIG.BUCKETS.RESOURCE + '/' + encodeURIComponent(bp), {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(cfgData)
        }, e);

        return Response.json({
          ok: true,
          synced: true,
          tag: tagName,
          time: timeStr,
          files: newFiles.map(f => f.name),
          msg: `成功更新 ${cleanRepo} (${tagName})，共同步 ${newFiles.length} 个文件至 [${targetFolder}]，旧版本已清理`
        }, {
          headers: { 'Cache-Control': 'no-store, no-cache, must-revalidate' }
        });
      }

      if (P === '/api/data' && req.method === 'GET') {
        const viewM = U.searchParams.get('view') || 'resource';
        let bk = (viewM === 'image' && HAS_IMAGE) ? CONFIG.BUCKETS.IMAGE : CONFIG.BUCKETS.RESOURCE;
        const hasFolder = U.searchParams.has('folder');
        const tF = hasFolder ? U.searchParams.get('folder') : null;
        const q = U.searchParams.get('q') || '';
        if (!e.DB) {
          return Response.json({
            isAdmin: iA,
            hasImage: HAS_IMAGE,
            siteTitle: CONFIG.SITE_TITLE,
            totalSize: 0,
            maxSize: CONFIG.MAX_STORAGE_BYTES,
            mode: hasFolder ? 'files' : 'folders',
            data: [],
            error: '未连接到 D1 数据库！若已在 Pages 设置中绑定了 DB，请进入 Pages 项目的【部署 (Deployments)】页面，点击最新部署右侧的【重试部署 (Retry deployment)】以激活绑定。'
          }, { headers: { 'Cache-Control': 'no-store, no-cache, must-revalidate' } });
        }
        try {
          if (Date.now() - globalLastSizeCalcTime > 600000) {
            globalCachedTotalSize = (await e.DB.prepare("SELECT SUM(size) as t FROM files").first())?.t || 0;
            globalLastSizeCalcTime = Date.now();
          }
          if (!hasFolder && !q) {
            const { results: R } = await e.DB.prepare("SELECT f.folder, COUNT(f.id) as count, SUM(f.size) as size, m.password FROM files f LEFT JOIN folder_meta m ON f.folder = m.name WHERE f.type=? " + (iA ? '' : 'AND f.is_hidden=0') + " GROUP BY f.folder ORDER BY f.folder ASC").bind(bk).all();
            return Response.json({
              isAdmin: iA,
              hasImage: HAS_IMAGE,
              siteTitle: CONFIG.SITE_TITLE,
              totalSize: globalCachedTotalSize,
              maxSize: CONFIG.MAX_STORAGE_BYTES,
              mode: 'folders',
              data: (R || []).map(r => ({ name: r.folder ?? '', count: r.count, size: r.size, locked: !!r.password }))
            }, { headers: { 'Cache-Control': 'no-store, no-cache, must-revalidate' } });
          }
          let qry = "SELECT f.*, m.password FROM files f LEFT JOIN folder_meta m ON f.folder = m.name WHERE f.type=? " + (iA ? '' : 'AND f.is_hidden=0'), prm = [bk];
          if (hasFolder) {
            if (!tF || !tF.trim()) {
              qry += " AND (f.folder = ? OR f.folder IS NULL OR TRIM(COALESCE(f.folder, '')) = '')";
              prm.push(tF || '');
            } else {
              qry += " AND f.folder=?";
              prm.push(tF);
            }
          }
          if (q) { qry += " AND f.name LIKE ?"; prm.push('%' + q + '%'); }
          const { results: R } = await e.DB.prepare(qry + " ORDER BY f.upload_at DESC").bind(...prm).all();
          let fF = [];
          let folderUnlockedMap = {};
          for (const f of (R || [])) {
            if (!iA && f.password) {
              const fKey = f.folder || '';
              if (!(fKey in folderUnlockedMap)) {
                const hash = await hashSha256(fKey);
                const lM = C.match(new RegExp('(?:^|; )lock_' + hash + '=([^;]*)'));
                folderUnlockedMap[fKey] = !!(lM && decodeURIComponent(lM[1]) === f.password);
              }
              if (!folderUnlockedMap[fKey]) continue;
            }
            fF.push({ id: f.id, name: f.name, size: f.size, folder: f.folder || '', is_hidden: f.is_hidden, upload_at: f.upload_at });
          }
          return Response.json({
            isAdmin: iA,
            hasImage: HAS_IMAGE,
            siteTitle: CONFIG.SITE_TITLE,
            totalSize: globalCachedTotalSize,
            maxSize: CONFIG.MAX_STORAGE_BYTES,
            mode: 'files',
            data: fF,
            folderMeta: (R && R.length) ? !!R[0].password : false
          }, { headers: { 'Cache-Control': 'no-store, no-cache, must-revalidate' } });
        } catch (dbErr) {
          const isTableMissing = dbErr.message && dbErr.message.toLowerCase().includes('no such table');
          if (isTableMissing) {
            try {
              await initD1Schema(e.DB);
              return Response.json({
                isAdmin: iA,
                hasImage: HAS_IMAGE,
                siteTitle: CONFIG.SITE_TITLE,
                totalSize: 0,
                maxSize: CONFIG.MAX_STORAGE_BYTES,
                mode: hasFolder ? 'files' : 'folders',
                data: []
              }, { headers: { 'Cache-Control': 'no-store, no-cache, must-revalidate' } });
            } catch (initErr) {
              return Response.json({
                isAdmin: iA,
                hasImage: HAS_IMAGE,
                siteTitle: CONFIG.SITE_TITLE,
                totalSize: 0,
                maxSize: CONFIG.MAX_STORAGE_BYTES,
                mode: hasFolder ? 'files' : 'folders',
                data: [],
                error: '检测到缺少核心数据表，自动初始化建表失败: ' + initErr.message
              }, { headers: { 'Cache-Control': 'no-store, no-cache, must-revalidate' } });
            }
          }
          return Response.json({
            isAdmin: iA,
            hasImage: HAS_IMAGE,
            siteTitle: CONFIG.SITE_TITLE,
            totalSize: 0,
            maxSize: CONFIG.MAX_STORAGE_BYTES,
            mode: hasFolder ? 'files' : 'folders',
            data: [],
            error: '数据库异常: ' + dbErr.message
          }, { headers: { 'Cache-Control': 'no-store, no-cache, must-revalidate' } });
        }
      }

      if (P === '/api/unlock') {
        const { folder: f, password: p } = await req.json();
        const fName = (f === null || f === undefined) ? '' : String(f);
        const m = await e.DB.prepare("SELECT password FROM folder_meta WHERE name=?").bind(fName).first();
        if (m && m.password === p) {
          return Response.json({ ok: true }, { headers: { 'Set-Cookie': 'lock_' + await hashSha256(fName) + '=' + encodeURIComponent(p) + '; Path=/; Secure; SameSite=Strict' } });
        }
        return Response.json({ ok: false, error: '密码错误' }, { status: 401 });
      }

      if (P === '/api/admin/cli_presign' && req.method === 'POST') {
        const d = await req.json(), bk = (d.type === 'image' && HAS_IMAGE) ? CONFIG.BUCKETS.IMAGE : CONFIG.BUCKETS.RESOURCE;
        const bp = Date.now() + '_' + d.filename.replace(/^.*[\\\/]/, '').replace(/[:*?"<>|]/g, '_');
        const url = await awsS3Presign(CONFIG.S3_ENDPOINT + '/' + bk + '/' + encodeURIComponent(bp), e, 'PUT', 86400);
        return Response.json({ url, b2Path: bp });
      }

      if (P === '/api/admin/action') {
        const p = await req.json();
        if (['delete', 'sync_d1_ghosts', 'sync_b2_orphans', 'clean_garbled', 'sync_b2_to_d1'].includes(p.action)) globalLastSizeCalcTime = 0;
        if (p.action === 'rename') await e.DB.prepare("UPDATE files SET name=? WHERE id=?").bind(p.name, p.id).run();
        if (p.action === 'move') await e.DB.prepare("UPDATE files SET folder=? WHERE id=?").bind(p.folder ?? '', p.id).run();
        if (p.action === 'toggle_hide') await e.DB.prepare("UPDATE files SET is_hidden=CASE WHEN is_hidden=1 THEN 0 ELSE 1 END WHERE id=?").bind(p.id).run();
        if (p.action === 'lock_folder') {
          const fName = (p.folder === null || p.folder === undefined) ? '' : String(p.folder);
          if (!p.password) await e.DB.prepare("DELETE FROM folder_meta WHERE name=?").bind(fName).run();
          else await e.DB.prepare("INSERT OR REPLACE INTO folder_meta (name, password) VALUES (?, ?)").bind(fName, p.password).run();
        }
        if (p.action === 'delete') {
          const f = await e.DB.prepare("SELECT b2_path, type FROM files WHERE id=?").bind(p.id).first();
          if (f) {
            await awsS3Fetch(CONFIG.S3_ENDPOINT + '/' + f.type + '/' + encodeURIComponent(f.b2_path), { method: 'DELETE' }, e);
            await e.DB.prepare("DELETE FROM files WHERE id=?").bind(p.id).run();
          }
        }
        if (['sync_d1_ghosts', 'sync_b2_orphans', 'sync_b2_to_d1'].includes(p.action)) {
          const aw = getS3Client(e), vM = p.viewMode || 'resource', bk = (vM === 'image' && HAS_IMAGE) ? CONFIG.BUCKETS.IMAGE : CONFIG.BUCKETS.RESOURCE;
          let s3 = [], iT = true, cT = '';
          while (iT) {
            let lU = CONFIG.S3_ENDPOINT + '/' + bk + '?list-type=2';
            if (cT) lU += '&continuation-token=' + encodeURIComponent(cT);
            const xml = await (await aw.fetch(lU)).text(), c = [...xml.matchAll(/<Contents>(.*?)<\/Contents>/gs)];
            for (const x of c) {
              const kM = x[1].match(/<Key>(.*?)<\/Key>/), lmM = x[1].match(/<LastModified>(.*?)<\/LastModified>/), szM = x[1].match(/<Size>(.*?)<\/Size>/);
              if (kM) s3.push({
                key: kM[1].replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'"),
                lastModified: lmM ? new Date(lmM[1]).getTime() : Date.now(),
                size: szM ? parseInt(szM[1]) : 0
              });
            }
            const tM = xml.match(/<IsTruncated>(true|false)<\/IsTruncated>/);
            iT = tM && tM[1] === 'true';
            if (iT) {
              const nM = xml.match(/<NextContinuationToken>(.*?)<\/NextContinuationToken>/);
              if (nM) cT = nM[1];
            }
          }
          if (p.action === 'sync_d1_ghosts') {
            const sK = new Set(s3.map(o => o.key)), { results: R } = await e.DB.prepare("SELECT * FROM files WHERE type=?").bind(bk).all();
            let dc = 0;
            for (const f of R) {
              if (!sK.has(f.b2_path)) {
                await e.DB.prepare("DELETE FROM files WHERE id=?").bind(f.id).run();
                dc++;
              }
            }
            return Response.json({ ok: true, msg: '清理了 ' + dc + ' 个死链！' });
          }
          if (p.action === 'sync_b2_orphans') {
            const fR = await e.DB.prepare("SELECT b2_path FROM files WHERE type=?").bind(bk).all();
            const uR = await e.DB.prepare("SELECT b2_path FROM upload_sessions WHERE bucket=?").bind(bk).all();
            const dK = new Set([...fR.results.map(r => r.b2_path), ...uR.results.map(r => r.b2_path)]);
            let dc = 0, nw = Date.now();
            for (const o of s3) {
              if (!dK.has(o.key) && (nw - o.lastModified > 86400000)) {
                await aw.fetch(CONFIG.S3_ENDPOINT + '/' + bk + '/' + encodeURIComponent(o.key), { method: 'DELETE' });
                dc++;
              }
            }
            return Response.json({ ok: true, msg: '清理了 ' + dc + ' 个游离文件！' });
          }
          if (p.action === 'sync_b2_to_d1') {
            const fR = await e.DB.prepare("SELECT b2_path FROM files WHERE type=?").bind(bk).all();
            const dK = new Set([...fR.results.map(r => r.b2_path)]);
            let dc = 0, b = [];
            for (const o of s3) {
              if (!dK.has(o.key)) {
                const fn = o.key.split('_').slice(1).join('_') || o.key;
                b.push(e.DB.prepare("INSERT INTO files (id,name,b2_path,type,size,folder) VALUES (?,?,?,?,?,?)").bind(crypto.randomUUID(), fn, o.key, bk, o.size, 'B2直传同步'));
                dc++;
              }
            }
            if (b.length > 0) {
              for (let i = 0; i < b.length; i += 50) await e.DB.batch(b.slice(i, i + 50));
            }
            return Response.json({ ok: true, msg: '成功将 ' + dc + ' 个 B2 游离文件同步归档至 [B2直传同步] 文件夹！' });
          }
        }
        if (p.action === 'clean_garbled') {
          const aw = getS3Client(e), { results: R } = await e.DB.prepare("SELECT * FROM files").all();
          let dc = 0;
          for (const f of R) {
            if (f.b2_path && f.b2_path.includes('%')) {
              await aw.fetch(CONFIG.S3_ENDPOINT + '/' + f.type + '/' + encodeURIComponent(f.b2_path), { method: 'DELETE' });
              await e.DB.prepare("DELETE FROM files WHERE id=?").bind(f.id).run();
              dc++;
            }
          }
          return Response.json({ ok: true, msg: '清理了 ' + dc + ' 个乱码！' });
        }
        return Response.json({ ok: true });
      }

      if (P === '/api/upload/sessions') return Response.json((await e.DB.prepare("SELECT * FROM upload_sessions").all()).results);

      if (P === '/api/upload/abort') {
        const d = await req.json(), tp = d.type || 'resource', bk = (tp === 'image' && HAS_IMAGE) ? CONFIG.BUCKETS.IMAGE : CONFIG.BUCKETS.RESOURCE;
        if (d.uploadId && d.b2Path) await awsS3Fetch(CONFIG.S3_ENDPOINT + '/' + bk + '/' + encodeURIComponent(d.b2Path) + '?uploadId=' + d.uploadId, { method: 'DELETE' }, e);
        if (d.fileHash) await e.DB.prepare("DELETE FROM upload_sessions WHERE file_hash=?").bind(d.fileHash).run();
        return Response.json({ ok: true });
      }

      if (P === '/api/upload/check') {
        const s = await e.DB.prepare("SELECT * FROM upload_sessions WHERE file_hash=?").bind((await req.json()).fileHash).first();
        return Response.json(s ? { exists: true, session: s } : { exists: false });
      }

      if (P === '/api/upload/single') {
        const fn = decodeURIComponent(req.headers.get('x-filename')).replace(/^.*[\\\/]/, '').replace(/[:*?"<>|]/g, '_');
        const bp = Date.now() + '_' + fn, tp = req.headers.get('x-type') || 'resource', bk = (tp === 'image' && HAS_IMAGE) ? CONFIG.BUCKETS.IMAGE : CONFIG.BUCKETS.RESOURCE;
        if (!bk) throw new Error('未配置当前模式对应的存储桶名称');
        const rs = await awsS3Fetch(CONFIG.S3_ENDPOINT + '/' + bk + '/' + encodeURIComponent(bp), {
          method: 'PUT',
          headers: { 'Content-Type': req.headers.get('content-type') || 'application/octet-stream', 'x-amz-content-sha256': 'UNSIGNED-PAYLOAD' },
          body: req.body
        }, e);
        if (!rs.ok) throw new Error(formatS3Error(await rs.text()));
        await e.DB.prepare("INSERT INTO files (id,name,b2_path,type,size,folder) VALUES (?,?,?,?,?,?)").bind(crypto.randomUUID(), fn, bp, bk, req.headers.get('content-length') || 0, decodeURIComponent(req.headers.get('x-folder'))).run();
        globalLastSizeCalcTime = 0;
        return Response.json({ ok: true });
      }

      if (P === '/api/upload/start') {
        const d = await req.json();
        d.filename = d.filename.replace(/^.*[\\\/]/, '').replace(/[:*?"<>|]/g, '_');
        const bp = Date.now() + '_' + d.filename, tp = d.type || 'resource', bk = (tp === 'image' && HAS_IMAGE) ? CONFIG.BUCKETS.IMAGE : CONFIG.BUCKETS.RESOURCE;
        if (!bk) throw new Error('未配置当前模式对应的存储桶名称');
        const rs = await awsS3Fetch(CONFIG.S3_ENDPOINT + '/' + bk + '/' + encodeURIComponent(bp) + '?uploads', { method: 'POST', headers: { 'Content-Type': d.contentType } }, e);
        if (!rs.ok) throw new Error(formatS3Error(await rs.text()));
        const ui = (await rs.text()).match(/<UploadId>(.*?)<\/UploadId>/)[1];
        await e.DB.prepare("INSERT OR REPLACE INTO upload_sessions (file_hash,b2_file_id,b2_path,bucket,folder,uploaded_parts) VALUES (?,?,?,?,?,'[]')").bind(d.fileHash, ui, bp, bk, d.folder).run();
        return Response.json({ fileId: ui, b2Path: bp });
      }

      if (P === '/api/upload/presign_batch') {
        const d = await req.json(), tp = d.type || 'resource', bk = (tp === 'image' && HAS_IMAGE) ? CONFIG.BUCKETS.IMAGE : CONFIG.BUCKETS.RESOURCE;
        if (!bk) throw new Error('未配置当前模式对应的存储桶名称');
        let u = {};
        for (const p of d.parts) u[p] = await awsS3Presign(CONFIG.S3_ENDPOINT + '/' + bk + '/' + encodeURIComponent(d.b2Path) + '?partNumber=' + p + '&uploadId=' + d.uploadId, e, 'PUT', 86400);
        return Response.json(u);
      }

      if (P === '/api/upload/sync_part') {
        const d = await req.json();
        await e.DB.prepare("UPDATE upload_sessions SET uploaded_parts=(SELECT json_group_array(json_object('partNumber',CAST(partNumber AS INTEGER),'etag',etag)) FROM (SELECT json_extract(value,'$.partNumber') as partNumber,json_extract(value,'$.etag') as etag FROM json_each(uploaded_parts) WHERE partNumber!=? UNION ALL SELECT ? as partNumber,? as etag)) WHERE file_hash=?").bind(d.partNumber, d.partNumber, d.etag, d.fileHash).run();
        return Response.json({ ok: true });
      }

      if (P === '/api/upload/part') {
        const h = { 'x-amz-content-sha256': 'UNSIGNED-PAYLOAD' };
        if (req.headers.get('content-length')) h['Content-Length'] = req.headers.get('content-length');
        const tp = req.headers.get('x-type') || 'resource', bk = (tp === 'image' && HAS_IMAGE) ? CONFIG.BUCKETS.IMAGE : CONFIG.BUCKETS.RESOURCE;
        const rs = await awsS3Fetch(CONFIG.S3_ENDPOINT + '/' + bk + '/' + encodeURIComponent(decodeURIComponent(req.headers.get('x-b2-path'))) + '?partNumber=' + req.headers.get('x-part-number') + '&uploadId=' + req.headers.get('x-file-id'), { method: 'PUT', headers: h, body: req.body }, e);
        if (!rs.ok) throw new Error(formatS3Error(await rs.text()));
        const fh = req.headers.get('x-file-hash'), et = rs.headers.get('ETag').replace(/"/g, ''), pn = parseInt(req.headers.get('x-part-number'));
        if (fh) await e.DB.prepare("UPDATE upload_sessions SET uploaded_parts=(SELECT json_group_array(json_object('partNumber',CAST(partNumber AS INTEGER),'etag',etag)) FROM (SELECT json_extract(value,'$.partNumber') as partNumber,json_extract(value,'$.etag') as etag FROM json_each(uploaded_parts) WHERE partNumber!=? UNION ALL SELECT ? as partNumber,? as etag)) WHERE file_hash=?").bind(pn, pn, et, fh).run();
        return Response.json({ etag: et });
      }

      if (P === '/api/upload/finish') {
        const d = await req.json();
        const xml = '<CompleteMultipartUpload>' + d.etagArray.map((t, i) => '<Part><PartNumber>' + (i + 1) + '</PartNumber><ETag>' + t + '</ETag></Part>').join('') + '</CompleteMultipartUpload>';
        const tp = d.type || 'resource', bk = (tp === 'image' && HAS_IMAGE) ? CONFIG.BUCKETS.IMAGE : CONFIG.BUCKETS.RESOURCE;
        const rs = await awsS3Fetch(CONFIG.S3_ENDPOINT + '/' + bk + '/' + encodeURIComponent(d.b2_path) + '?uploadId=' + d.fileId, { method: 'POST', body: xml }, e);
        if (!rs.ok) throw new Error(formatS3Error(await rs.text()));
        await e.DB.prepare("INSERT INTO files (id,name,b2_path,type,size,folder) VALUES (?,?,?,?,?,?)").bind(crypto.randomUUID(), d.name, d.b2_path, bk, d.size, d.folder).run();
        if (d.fileHash) await e.DB.prepare("DELETE FROM upload_sessions WHERE file_hash=?").bind(d.fileHash).run();
        globalLastSizeCalcTime = 0;
        return Response.json({ ok: true });
      }

      return Response.json({ ok: false, error: '接口不存在' }, { status: 404 });
    } catch (err) {
      if (err.message && err.message.toLowerCase().includes('no such table') && e.DB) {
        try {
          await initD1Schema(e.DB);
          return Response.json({ ok: false, error: '检测到缺少数据库表，已为您自动初始化完成！请重试操作。' }, { status: 500 });
        } catch (_) {}
      }
      return Response.json({ ok: false, error: err.message }, { status: 500 });
    }
  }

  // 7. 其余静态请求（CSS/JS/图片等）直接交由 Pages CDN
  return next();
}
