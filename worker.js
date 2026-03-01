// ==========================================
// TTecloud
// ==========================================
function getConfig(env) {
  return {
    AUTH_COOKIE_NAME: 'TTecloud_Admin_Token',
    MAX_STORAGE_BYTES: parseInt(env.MAX_STORAGE_GB || 10) * 1024 * 1024 * 1024, 
    S3_REGION: env.S3_REGION, 
    S3_ENDPOINT: env.S3_ENDPOINT,
    BUCKETS: {
      RESOURCE: env.BUCKET_RESOURCE,
      IMAGE: env.BUCKET_IMAGE
    }
  };
}

let globalCachedTotalSize = 0;
let globalLastSizeCalcTime = 0;

function escapeHTML(str) { return String(str).replace(/[&<>'"]/g, tag => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[tag] || tag)); }
function awsUriEncode(str) { return encodeURIComponent(str).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase()); }
async function hashSha256(string) { const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(string)); return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join(''); }
async function hmacSha256(key, string) {
  const cryptoKey = await crypto.subtle.importKey('raw', typeof key === 'string' ? new TextEncoder().encode(key) : key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, new TextEncoder().encode(string)); return new Uint8Array(sig);
}

async function createAdminToken(env) {
  const time = Date.now().toString();
  const data = `${env.ADMIN_USER || 'admin'}|${time}`;
  const sigHex = Array.from(await hmacSha256(env.ADMIN_PASS || 'default', data)).map(b => b.toString(16).padStart(2, '0')).join('');
  return encodeURIComponent(`${data}|${sigHex}`);
}
async function verifyAdminToken(tokenStr, env) {
  if (!tokenStr) return false;
  try {
    const parts = decodeURIComponent(tokenStr).split('|');
    if (parts.length !== 3) return false;
    const[user, time, sigHex] = parts;
    if (Date.now() - parseInt(time) > 86400000 * 30) return false; 
    const expectedHex = Array.from(await hmacSha256(env.ADMIN_PASS || 'default', `${user}|${time}`)).map(b => b.toString(16).padStart(2, '0')).join('');
    return sigHex === expectedHex && user === (env.ADMIN_USER || 'admin');
  } catch(e) { return false; }
}

async function awsS3Fetch(url, options, env) {
  const config = getConfig(env);
  const urlObj = new URL(url); const method = options.method || 'GET';
  const amzDate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, ''); const dateStamp = amzDate.slice(0, 8);
  const headers = new Headers(options.headers || {});
  if (!headers.has('host')) headers.set('host', urlObj.host); headers.set('x-amz-date', amzDate); if (!headers.has('x-amz-content-sha256')) headers.set('x-amz-content-sha256', 'UNSIGNED-PAYLOAD');
  const canonicalUri = decodeURIComponent(urlObj.pathname).split('/').map(awsUriEncode).join('/').replace(/%2F/g, '/');
  const canonicalQuerystring = Array.from(urlObj.searchParams).sort(([k1],[k2]) => k1 < k2 ? -1 : 1).map(([k, v]) => `${awsUriEncode(k)}=${awsUriEncode(v)}`).join('&');
  const signedHeaders = Array.from(headers.keys()).map(k => k.toLowerCase()).sort();
  const canonicalHeaders = signedHeaders.map(k => `${k}:${headers.get(k).trim().replace(/ +/g, ' ')}\n`).join('');
  const signedHeadersStr = signedHeaders.join(';');
  const canonicalRequestHash = await hashSha256(`${method}\n${canonicalUri}\n${canonicalQuerystring}\n${canonicalHeaders}\n${signedHeadersStr}\n${headers.get('x-amz-content-sha256')}`);
  const credentialScope = `${dateStamp}/${config.S3_REGION}/s3/aws4_request`;
  const kSigning = await hmacSha256(await hmacSha256(await hmacSha256(await hmacSha256(`AWS4${env.B2_APP_KEY}`, dateStamp), config.S3_REGION), 's3'), 'aws4_request');
  const signature = Array.from(await hmacSha256(kSigning, `AWS4-HMAC-SHA256\n${amzDate}\n${credentialScope}\n${canonicalRequestHash}`)).map(b => b.toString(16).padStart(2, '0')).join('');
  headers.set('Authorization', `AWS4-HMAC-SHA256 Credential=${env.B2_KEY_ID}/${credentialScope}, SignedHeaders=${signedHeadersStr}, Signature=${signature}`);
  return fetch(urlObj.toString(), { ...options, headers });
}

async function awsS3Presign(url, env, method = 'PUT', expiresIn = 3600) {
  const config = getConfig(env);
  const urlObj = new URL(url);
  const amzDate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, '');
  const dateStamp = amzDate.slice(0, 8);
  const credentialScope = `${dateStamp}/${config.S3_REGION}/s3/aws4_request`;

  urlObj.searchParams.set('X-Amz-Algorithm', 'AWS4-HMAC-SHA256');
  urlObj.searchParams.set('X-Amz-Credential', `${env.B2_KEY_ID}/${credentialScope}`);
  urlObj.searchParams.set('X-Amz-Date', amzDate);
  urlObj.searchParams.set('X-Amz-Expires', expiresIn.toString());
  urlObj.searchParams.set('X-Amz-SignedHeaders', 'content-type;host');

  const canonicalUri = decodeURIComponent(urlObj.pathname).split('/').map(awsUriEncode).join('/').replace(/%2F/g, '/');
  const canonicalQuerystring = Array.from(urlObj.searchParams).sort(([k1], [k2]) => k1 < k2 ? -1 : 1).map(([k, v]) => `${awsUriEncode(k)}=${awsUriEncode(v)}`).join('&');
  const canonicalHeaders = `content-type:application/octet-stream\nhost:${urlObj.host}\n`;
  const signedHeadersStr = 'content-type;host';
  const payloadHash = 'UNSIGNED-PAYLOAD';

  const canonicalRequestHash = await hashSha256(`${method}\n${canonicalUri}\n${canonicalQuerystring}\n${canonicalHeaders}\n${signedHeadersStr}\n${payloadHash}`);
  const stringToSign = `AWS4-HMAC-SHA256\n${amzDate}\n${credentialScope}\n${canonicalRequestHash}`;

  const kSigning = await hmacSha256(await hmacSha256(await hmacSha256(await hmacSha256(`AWS4${env.B2_APP_KEY}`, dateStamp), config.S3_REGION), 's3'), 'aws4_request');
  const signature = Array.from(await hmacSha256(kSigning, stringToSign)).map(b => b.toString(16).padStart(2, '0')).join('');

  urlObj.searchParams.set('X-Amz-Signature', signature);
  return urlObj.toString();
}

function getS3Client(env) { return { fetch: (url, options = {}) => awsS3Fetch(url, options, env) }; }

export default {
  async fetch(request, env) {
    const url = new URL(request.url); const path = url.pathname;
    const cookieStr = request.headers.get('Cookie') || '';
    const config = getConfig(env);
    const tokenMatch = cookieStr.match(new RegExp(`(?:^|; )${config.AUTH_COOKIE_NAME}=([^;]*)`));
    const isAdmin = await verifyAdminToken(tokenMatch ? tokenMatch[1] : null, env);

    if (path === '/') return new Response(getSPA_HTML(env), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
    if (path === '/login') {
      if (request.method === 'GET') return new Response(renderLoginPage(env), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
      const fd = await request.formData();
      if (fd.get('username') === (env.ADMIN_USER || 'admin') && fd.get('password') === env.ADMIN_PASS) {
        return new Response(renderRedirect('🎉 欢迎回来！', '/'), { headers: { 'Content-Type': 'text/html;charset=UTF-8', 'Set-Cookie': `${config.AUTH_COOKIE_NAME}=${await createAdminToken(env)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=2592000` } });
      }
      return new Response(renderRedirect('密码错误！', '/login'), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
    }
    if (path === '/logout') return new Response(renderRedirect('已退出', '/'), { headers: { 'Content-Type': 'text/html;charset=UTF-8', 'Set-Cookie': `${config.AUTH_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Strict; Expires=Thu, 01 Jan 1970 00:00:00 GMT` } });

    if (path.startsWith('/share/')) {
      const { results } = await env.DB.prepare("SELECT * FROM files WHERE id = ?").bind(path.split('/')[2]).all();
      if (!results.length || (results[0].is_hidden === 1 && !isAdmin)) return new Response('Not Found', { status: 404 });
      return new Response(renderSharePage(results[0], url.origin, env), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
    }

    if (path.startsWith('/file/')) {
      const { results } = await env.DB.prepare("SELECT * FROM files WHERE id = ?").bind(path.split('/')[2]).all();
      if (!results.length) return new Response('404 Not Found', { status: 404 });
      const f = results[0]; if (f.is_hidden === 1 && !isAdmin) return new Response('Forbidden', { status: 403 });
      if (!isAdmin && f.folder) {
         const meta = await env.DB.prepare("SELECT password FROM folder_meta WHERE name = ?").bind(f.folder).first();
         if (meta && meta.password) { const lMatch = cookieStr.match(new RegExp(`(?:^|; )lock_${await hashSha256(f.folder)}=([^;]*)`)); if (!lMatch || decodeURIComponent(lMatch[1]) !== meta.password) return new Response('加密保护', { status: 401 }); }
      }
      
      const s3Headers = {};
      if (request.headers.has('Range')) s3Headers['Range'] = request.headers.get('Range');
      if (request.headers.has('If-None-Match')) s3Headers['If-None-Match'] = request.headers.get('If-None-Match');
      if (request.headers.has('If-Modified-Since')) s3Headers['If-Modified-Since'] = request.headers.get('If-Modified-Since');

      const res = await awsS3Fetch(`${config.S3_ENDPOINT}/${f.type}/${encodeURIComponent(f.b2_path)}`, { headers: s3Headers, cf: { cacheEverything: true, cacheTtlByStatus: { "200-299": 2592000, "404": 10, "500-599": 0 } } }, env);
      
      if (res.status === 304) return new Response(null, { status: 304, headers: { 'Cache-Control': 'public, max-age=2592000', 'ETag': res.headers.get('ETag'), 'Access-Control-Allow-Origin': '*' } });

      const rh = new Headers(res.headers);
      rh.set('Content-Disposition', `${url.searchParams.get('dl') === '1' ? 'attachment' : 'inline'}; filename*=UTF-8''${encodeURIComponent(f.name)}`);
      rh.set('Access-Control-Allow-Origin', '*'); if([200, 206].includes(res.status)) { rh.set('Cache-Control', 'public, max-age=2592000'); if(!rh.has('Accept-Ranges')) rh.set('Accept-Ranges', 'bytes'); }
      return new Response(res.body, { status: res.status, headers: rh });
    }

    if (path.startsWith('/api/')) {
      if (path === '/api/data' && request.method === 'GET') {
         const bucket = (url.searchParams.get('view') || 'resource') === 'resource' ? config.BUCKETS.RESOURCE : config.BUCKETS.IMAGE;
         const tFolder = url.searchParams.get('folder'); const q = url.searchParams.get('q') || '';
         
         if (Date.now() - globalLastSizeCalcTime > 10 * 60 * 1000) {
            globalCachedTotalSize = (await env.DB.prepare("SELECT SUM(size) as t FROM files").first())?.t || 0;
            globalLastSizeCalcTime = Date.now();
         }
         const totalSize = globalCachedTotalSize;

         if (!tFolder && !q) {
            const { results } = await env.DB.prepare(`SELECT f.folder, COUNT(f.id) as count, SUM(f.size) as size, m.password FROM files f LEFT JOIN folder_meta m ON f.folder = m.name WHERE f.type = ? ${isAdmin ? '' : 'AND f.is_hidden = 0'} GROUP BY f.folder ORDER BY f.folder ASC`).bind(bucket).all();
            return Response.json({ isAdmin, totalSize, maxSize: config.MAX_STORAGE_BYTES, mode: 'folders', data: results.map(r => ({ name: r.folder, count: r.count, size: r.size, locked: !!r.password })) });
         }
         let query = `SELECT f.*, m.password FROM files f LEFT JOIN folder_meta m ON f.folder = m.name WHERE f.type = ? ${isAdmin ? '' : 'AND f.is_hidden = 0'}`;
         const params = [bucket]; if (tFolder) { query += " AND f.folder = ?"; params.push(tFolder); } if (q) { query += " AND f.name LIKE ?"; params.push(`%${q}%`); }
         query += ` ORDER BY f.upload_at DESC`;
         const { results } = await env.DB.prepare(query).bind(...params).all();
         let finalFiles =[];
         for (const f of results) {
            if (!isAdmin && f.password) { const lMatch = cookieStr.match(new RegExp(`(?:^|; )lock_${await hashSha256(f.folder)}=([^;]*)`)); if (!lMatch || decodeURIComponent(lMatch[1]) !== f.password) continue; }
            finalFiles.push({ id: f.id, name: f.name, size: f.size, folder: f.folder, is_hidden: f.is_hidden, upload_at: f.upload_at });
         }
         return Response.json({ isAdmin, totalSize, maxSize: config.MAX_STORAGE_BYTES, mode: 'files', data: finalFiles, folderMeta: results.length ? !!results[0].password : false });
      }
      if (path === '/api/unlock') { const { folder, password } = await request.json(); const meta = await env.DB.prepare("SELECT password FROM folder_meta WHERE name = ?").bind(folder).first(); if (meta && meta.password === password) return Response.json({ ok: true }, { headers: { 'Set-Cookie': `lock_${await hashSha256(folder)}=${encodeURIComponent(password)}; Path=/; Secure; SameSite=Strict; Max-Age=86400` }}); return Response.json({ ok: false, error: '密码错误！' }, { status: 401 }); }
      
      if (path === '/api/admin/action' && isAdmin) {
         const p = await request.json();
         if (['delete', 'sync_d1_ghosts', 'sync_b2_orphans', 'clean_garbled'].includes(p.action)) globalLastSizeCalcTime = 0; 
         
         if (p.action === 'rename') await env.DB.prepare("UPDATE files SET name = ? WHERE id = ?").bind(p.name, p.id).run();
         if (p.action === 'move') await env.DB.prepare("UPDATE files SET folder = ? WHERE id = ?").bind(p.folder, p.id).run();
         if (p.action === 'toggle_hide') await env.DB.prepare("UPDATE files SET is_hidden = CASE WHEN is_hidden = 1 THEN 0 ELSE 1 END WHERE id = ?").bind(p.id).run();
         if (p.action === 'lock_folder') { if (!p.password) await env.DB.prepare("DELETE FROM folder_meta WHERE name = ?").bind(p.folder).run(); else await env.DB.prepare("INSERT OR REPLACE INTO folder_meta (name, password) VALUES (?, ?)").bind(p.folder, p.password).run(); }
         if (p.action === 'delete') { const f = await env.DB.prepare("SELECT b2_path, type FROM files WHERE id = ?").bind(p.id).first(); if(f) { await awsS3Fetch(`${config.S3_ENDPOINT}/${f.type}/${encodeURIComponent(f.b2_path)}`, { method: 'DELETE' }, env); await env.DB.prepare("DELETE FROM files WHERE id = ?").bind(p.id).run(); } }
         
         if (p.action === 'sync_d1_ghosts' || p.action === 'sync_b2_orphans' || p.action === 'clean_garbled') {
               const aws = getS3Client(env);
               if (p.action === 'sync_d1_ghosts' || p.action === 'sync_b2_orphans') {
                   const bucket = p.viewMode === 'resource' ? config.BUCKETS.RESOURCE : config.BUCKETS.IMAGE;
                   let s3Objects =[], isTruncated = true, continuationToken = '';
                   
                   while (isTruncated) {
                       let listUrl = `${config.S3_ENDPOINT}/${bucket}?list-type=2`;
                       if (continuationToken) listUrl += `&continuation-token=${encodeURIComponent(continuationToken)}`;
                       const xml = await (await aws.fetch(listUrl)).text();
                       const contents =[...xml.matchAll(/<Contents>(.*?)<\/Contents>/gs)];
                       for (const c of contents) {
                           const kMatch = c[1].match(/<Key>(.*?)<\/Key>/);
                           const lmMatch = c[1].match(/<LastModified>(.*?)<\/LastModified>/);
                           if (kMatch) {
                               s3Objects.push({
                                   key: kMatch[1].replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'"),
                                   lastModified: lmMatch ? new Date(lmMatch[1]).getTime() : Date.now()
                               });
                           }
                       }
                       const truncMatch = xml.match(/<IsTruncated>(true|false)<\/IsTruncated>/);
                       isTruncated = truncMatch && truncMatch[1] === 'true';
                       if (isTruncated) { const nextMatch = xml.match(/<NextContinuationToken>(.*?)<\/NextContinuationToken>/); if (nextMatch) continuationToken = nextMatch[1]; }
                   }

                   if (p.action === 'sync_d1_ghosts') {
                       const s3Keys = new Set(s3Objects.map(o => o.key));
                       const { results } = await env.DB.prepare("SELECT * FROM files WHERE type = ?").bind(bucket).all();
                       let deletedCount = 0;
                       for (const f of results) { 
                           if (!s3Keys.has(f.b2_path)) { 
                               await env.DB.prepare("DELETE FROM files WHERE id = ?").bind(f.id).run(); 
                               deletedCount++; 
                           } 
                       }
                       return Response.json({ ok: true, msg: `✨ D1死链清理完毕！共清除了 ${deletedCount} 个底层丢失的幽灵数据！` });
                   }

                   if (p.action === 'sync_b2_orphans') {
                       const fRes = await env.DB.prepare("SELECT b2_path FROM files WHERE type = ?").bind(bucket).all();
                       const uRes = await env.DB.prepare("SELECT b2_path FROM upload_sessions WHERE bucket = ?").bind(bucket).all();
                       const dRes = await env.DB.prepare("SELECT b2_path FROM downloads WHERE bucket = ?").bind(bucket).all();
                       
                       const d1Keys = new Set([ ...fRes.results.map(r=>r.b2_path), ...uRes.results.map(r=>r.b2_path), ...dRes.results.map(r=>r.b2_path) ]);
                       let deletedCount = 0;
                       const SAFE_PERIOD_MS = 24 * 60 * 60 * 1000;
                       const now = Date.now();
                       
                       for (const obj of s3Objects) {
                           if (!d1Keys.has(obj.key) && (now - obj.lastModified > SAFE_PERIOD_MS)) {
                               await aws.fetch(`${config.S3_ENDPOINT}/${bucket}/${encodeURIComponent(obj.key)}`, { method: 'DELETE' });
                               deletedCount++;
                           }
                       }
                       return Response.json({ ok: true, msg: `✨ B2游离文件清理完毕！共物理删除了 ${deletedCount} 个遗留残余文件！(已自动跳过24小时内的新建文件)` });
                   }
               } else {
                   const { results } = await env.DB.prepare("SELECT * FROM files").all();
                   let deletedCount = 0;
                   for (const f of results) { if (f.b2_path && f.b2_path.includes('%')) { await aws.fetch(`${config.S3_ENDPOINT}/${f.type}/${encodeURIComponent(f.b2_path)}`, { method: 'DELETE' }); await env.DB.prepare("DELETE FROM files WHERE id = ?").bind(f.id).run(); deletedCount++; } }
                   return Response.json({ ok: true, msg: `✨ 清理完毕！共清除了 ${deletedCount} 个异常残余的乱码文件！` });
               }
           }
         return Response.json({ ok: true });
      }

      if (path === '/api/upload/sessions') { if (!isAdmin) return Response.json({}, { status: 403 }); return Response.json((await env.DB.prepare("SELECT * FROM upload_sessions").all()).results); }
      if (path === '/api/upload/abort') { if (!isAdmin) return Response.json({}, { status: 403 }); const { fileHash, uploadId, b2Path, bucket } = await request.json(); if (uploadId && b2Path && bucket) await awsS3Fetch(`${config.S3_ENDPOINT}/${bucket}/${encodeURIComponent(b2Path)}?uploadId=${uploadId}`, { method: 'DELETE' }, env); if (fileHash) await env.DB.prepare("DELETE FROM upload_sessions WHERE file_hash = ?").bind(fileHash).run(); return new Response('OK'); }
      if (path === '/api/upload/check') { if (!isAdmin) return Response.json({}, { status: 403 }); const { fileHash } = await request.json(); const session = await env.DB.prepare("SELECT * FROM upload_sessions WHERE file_hash = ?").bind(fileHash).first(); return Response.json(session ? { exists: true, session } : { exists: false }); }
      if (path === '/api/upload/single') {
         if (!isAdmin) return Response.json({}, { status: 403 }); let fname = decodeURIComponent(request.headers.get('x-filename')).replace(/^.*[\\\/]/, '').replace(/[:*?"<>|]/g, '_'); const b2Path = `${Date.now()}_${fname}`; const bucket = request.headers.get('x-bucket');
         const res = await awsS3Fetch(`${config.S3_ENDPOINT}/${bucket}/${encodeURIComponent(b2Path)}`, { method: 'PUT', headers: { 'Content-Type': request.headers.get('content-type') || 'application/octet-stream', 'x-amz-content-sha256': 'UNSIGNED-PAYLOAD' }, body: request.body }, env);
         if (!res.ok) throw new Error(await res.text()); await env.DB.prepare("INSERT INTO files (id, name, b2_path, type, size, folder) VALUES (?, ?, ?, ?, ?, ?)").bind(crypto.randomUUID(), fname, b2Path, bucket, request.headers.get('content-length')||0, decodeURIComponent(request.headers.get('x-folder'))).run();
         globalLastSizeCalcTime = 0;
         return new Response('OK');
      }
      if (path === '/api/upload/start') {
         if (!isAdmin) return Response.json({}, { status: 403 }); let { bucket, filename, contentType, fileHash, folder } = await request.json(); filename = filename.replace(/^.*[\\\/]/, '').replace(/[:*?"<>|]/g, '_'); const b2Path = `${Date.now()}_${filename}`;
         const r = await awsS3Fetch(`${config.S3_ENDPOINT}/${bucket}/${encodeURIComponent(b2Path)}?uploads`, { method: 'POST', headers: { 'Content-Type': contentType } }, env);
         if(!r.ok) throw new Error(await r.text()); const upId = (await r.text()).match(/<UploadId>(.*?)<\/UploadId>/)[1]; await env.DB.prepare("INSERT OR REPLACE INTO upload_sessions (file_hash, b2_file_id, b2_path, bucket, folder, uploaded_parts) VALUES (?, ?, ?, ?, ?, '[]')").bind(fileHash, upId, b2Path, bucket, folder).run(); return Response.json({ fileId: upId, b2Path });
      }
      if (path === '/api/upload/presign') { if (!isAdmin) return Response.json({}, { status: 403 }); return Response.json({ presignedUrl: await awsS3Presign(`${config.S3_ENDPOINT}/${url.searchParams.get('bucket')}/${encodeURIComponent(url.searchParams.get('b2Path'))}?partNumber=${url.searchParams.get('partNumber')}&uploadId=${url.searchParams.get('uploadId')}`, env, 'PUT', 3600) }); }
      
      if (path === '/api/upload/sync_part') { 
         if (!isAdmin) return Response.json({}, { status: 403 }); const { fileHash, partNumber, etag } = await request.json(); 
         await env.DB.prepare(`UPDATE upload_sessions SET uploaded_parts = (SELECT json_group_array(json_object('partNumber', CAST(partNumber AS INTEGER), 'etag', etag)) FROM (SELECT json_extract(value, '$.partNumber') as partNumber, json_extract(value, '$.etag') as etag FROM json_each(uploaded_parts) WHERE partNumber != ? UNION ALL SELECT ? as partNumber, ? as etag)) WHERE file_hash = ?`).bind(partNumber, partNumber, etag, fileHash).run(); 
         return Response.json({ ok: true }); 
      }
      if (path === '/api/upload/part') {
         if (!isAdmin) return Response.json({}, { status: 403 }); const h = { 'x-amz-content-sha256': 'UNSIGNED-PAYLOAD' }; if(request.headers.get('content-length')) h['Content-Length'] = request.headers.get('content-length');
         const r = await awsS3Fetch(`${config.S3_ENDPOINT}/${request.headers.get('x-bucket')}/${encodeURIComponent(decodeURIComponent(request.headers.get('x-b2-path')))}?partNumber=${request.headers.get('x-part-number')}&uploadId=${request.headers.get('x-file-id')}`, { method: 'PUT', headers: h, body: request.body }, env);
         if(!r.ok) throw new Error(await r.text()); const fHash = request.headers.get('x-file-hash'); const etag = r.headers.get('ETag').replace(/"/g, ''); const pNum = parseInt(request.headers.get('x-part-number'));
         if (fHash) { 
            await env.DB.prepare(`UPDATE upload_sessions SET uploaded_parts = (SELECT json_group_array(json_object('partNumber', CAST(partNumber AS INTEGER), 'etag', etag)) FROM (SELECT json_extract(value, '$.partNumber') as partNumber, json_extract(value, '$.etag') as etag FROM json_each(uploaded_parts) WHERE partNumber != ? UNION ALL SELECT ? as partNumber, ? as etag)) WHERE file_hash = ?`).bind(pNum, pNum, etag, fHash).run(); 
         }
         return Response.json({ etag });
      }
      if (path === '/api/upload/finish') {
         if (!isAdmin) return Response.json({}, { status: 403 }); const d = await request.json(); let xml = '<CompleteMultipartUpload>' + d.etagArray.map((e,i)=>`<Part><PartNumber>${i+1}</PartNumber><ETag>${e}</ETag></Part>`).join('') + '</CompleteMultipartUpload>';
         const r = await awsS3Fetch(`${config.S3_ENDPOINT}/${d.type}/${encodeURIComponent(d.b2_path)}?uploadId=${d.fileId}`, { method: 'POST', body: xml }, env); if(!r.ok) throw new Error(await r.text());
         await env.DB.prepare("INSERT INTO files (id, name, b2_path, type, size, folder) VALUES (?, ?, ?, ?, ?, ?)").bind(crypto.randomUUID(), d.name, d.b2_path, d.type, d.size, d.folder).run();
         if(d.fileHash) await env.DB.prepare("DELETE FROM upload_sessions WHERE file_hash = ?").bind(d.fileHash).run(); 
         globalLastSizeCalcTime = 0; 
         return new Response('OK');
      }

      if (path === '/api/remote/meta') {
         if (!isAdmin) return Response.json({}, { status: 403 });
         const { targetUrl } = await request.json(); const r = await fetch(targetUrl, { headers: { 'Range': 'bytes=0-0' }, redirect: 'follow' });
         if (!r.ok && r.status !== 206) throw new Error('无法连接到目标源站');
         let size = 0, supportRange = r.status === 206;
         if (supportRange) size = Number((r.headers.get('content-range')||'').split('/')[1]||0); else size = Number(r.headers.get('content-length')||0);
         let filename = targetUrl.split('/').pop().split('?')[0]; const disp = r.headers.get('content-disposition'); if (disp && disp.includes('filename=')) { const m = disp.match(/filename="?([^"]+)"?/); if (m) filename = m[1]; }
         filename = decodeURIComponent(filename).replace(/^.*[\\\/]/, '').replace(/[:*?"<>|]/g, '_') || 'unknown_file.bin';
         return Response.json({ filename, size, estSeconds: Math.max(1, Math.round(size / (supportRange ? 25*1024*1024 : 10*1024*1024))), supportRange });
      }
      if (path === '/api/remote/start') {
         if (!isAdmin) return Response.json({}, { status: 403 });
         let d = await request.json(); d.filename = d.filename.replace(/^.*[\\\/]/, '').replace(/[:*?"<>|]/g, '_');
         const taskId = crypto.randomUUID(); const b2Path = `${Date.now()}_${d.filename}`;
         if (d.supportRange && d.size > 10 * 1024 * 1024) {
             const r = await awsS3Fetch(`${config.S3_ENDPOINT}/${d.bucket}/${encodeURIComponent(b2Path)}?uploads`, { method: 'POST' }, env);
             const upId = (await r.text()).match(/<UploadId>(.*?)<\/UploadId>/)[1];
             await env.DB.prepare("INSERT INTO downloads (id, url, name, folder, bucket, b2_path, status, loaded, total, b2_file_id) VALUES (?, ?, ?, ?, ?, ?, 'downloading', 0, ?, ?)").bind(taskId, d.targetUrl, d.filename, d.folder, d.bucket, b2Path, d.size, upId).run();
             const cSize = 10 * 1024 * 1024; const parts = Math.ceil(d.size / cSize); const b =[], q =[];
             for(let i=0; i<parts; i++) { b.push(env.DB.prepare("INSERT INTO download_parts (task_id, part_number, status) VALUES (?, ?, 'pending')").bind(taskId, i+1)); q.push({ body: { type:'range_part', taskId, targetUrl:d.targetUrl, b2FileId:upId, partNumber:i+1, start:i*cSize, end:Math.min((i+1)*cSize-1, d.size-1), name:d.filename, b2Path, bucket:d.bucket, folder:d.folder, size:d.size }}); }
             for(let i=0;i<b.length;i+=50) await env.DB.batch(b.slice(i, i+50)); for(let i=0;i<q.length;i+=100) await env.DOWNLOAD_QUEUE.sendBatch(q.slice(i, i+100));
         } else {
             await env.DB.prepare("INSERT INTO downloads (id, url, name, folder, bucket, b2_path, status, loaded, total) VALUES (?, ?, ?, ?, ?, ?, 'pending', 0, ?)").bind(taskId, d.targetUrl, d.filename, d.folder, d.bucket, b2Path, d.size).run();
             await env.DOWNLOAD_QUEUE.send({ type: 'fallback', id: taskId, url: d.targetUrl, name: d.filename, folder: d.folder, bucket: d.bucket, b2Path, size: d.size });
         }
         return Response.json({ taskId });
      }
      if (path === '/api/remote/status') return Response.json(isAdmin ? (await env.DB.prepare("SELECT * FROM downloads WHERE status IN ('pending', 'downloading')").all()).results :[]);
      if (path === '/api/remote/cancel') { await env.DB.prepare("UPDATE downloads SET status = 'cancelled' WHERE id = ?").bind((await request.json()).taskId).run(); return new Response('OK'); }
    }
    return new Response('404 Not Found', { status: 404 });
  },

  async queue(batch, env) {
    const config = getConfig(env);
    for (const msg of batch.messages) {
      const t = msg.body; const id = t.taskId || t.id;
      const ck = await env.DB.prepare("SELECT status FROM downloads WHERE id = ?").bind(id).first(); if (!ck || ck.status === 'cancelled') continue;
      try {
        if (t.type === 'range_part') {
            const sRes = await fetch(t.targetUrl, { headers: { 'Range': `bytes=${t.start}-${t.end}` }, redirect: 'follow' });
            if (!sRes.ok && sRes.status !== 206) { msg.retry(); continue; }
            
            const cl = sRes.headers.get('content-length') || (t.end - t.start + 1).toString();
            const pr = await awsS3Fetch(`${config.S3_ENDPOINT}/${t.bucket}/${encodeURIComponent(t.b2Path)}?partNumber=${t.partNumber}&uploadId=${t.b2FileId}`, { method: 'PUT', headers: { 'Content-Length': cl, 'x-amz-content-sha256': 'UNSIGNED-PAYLOAD' }, body: sRes.body, duplex: 'half' }, env);
            if(!pr.ok) { msg.retry(); continue; }
            
            await env.DB.prepare("UPDATE download_parts SET status = 'completed', sha1 = ? WHERE task_id = ? AND part_number = ?").bind(pr.headers.get('ETag').replace(/"/g, ''), id, t.partNumber).run();
            await env.DB.prepare("UPDATE downloads SET loaded = loaded + ? WHERE id = ?").bind(parseInt(cl), id).run();
            
            const pd = await env.DB.prepare("SELECT COUNT(*) as c FROM download_parts WHERE task_id = ? AND status = 'pending'").bind(id).first();
            if (pd.c === 0) {
               const lock = await env.DB.prepare("UPDATE downloads SET status = 'finishing' WHERE id = ? AND status = 'downloading' RETURNING id").bind(id).first();
               if (lock) {
                   try {
                       const pts = await env.DB.prepare("SELECT sha1 as etag FROM download_parts WHERE task_id = ? ORDER BY part_number ASC").bind(id).all();
                       let xml = '<CompleteMultipartUpload>' + pts.results.map((p,i)=>`<Part><PartNumber>${i+1}</PartNumber><ETag>${p.etag}</ETag></Part>`).join('') + '</CompleteMultipartUpload>';
                       const fr = await awsS3Fetch(`${config.S3_ENDPOINT}/${t.bucket}/${encodeURIComponent(t.b2Path)}?uploadId=${t.b2FileId}`, { method: 'POST', body: xml }, env);
                       if (!fr.ok) throw new Error('S3 Merge Error');
                       await env.DB.prepare("INSERT INTO files (id, name, b2_path, type, size, folder) VALUES (?, ?, ?, ?, ?, ?)").bind(crypto.randomUUID(), t.name, t.b2Path, t.bucket, t.size, t.folder).run();
                       await env.DB.prepare("UPDATE downloads SET status = 'completed', loaded = total WHERE id = ?").bind(id).run();
                       globalLastSizeCalcTime = 0; 
                   } catch (mergeErr) {
                       await env.DB.prepare("UPDATE downloads SET status = 'downloading' WHERE id = ?").bind(id).run();
                       throw mergeErr; 
                   }
               }
            }
        } else {
            await env.DB.prepare("UPDATE downloads SET status = 'downloading' WHERE id = ?").bind(id).run();
            const sRes = await fetch(t.url, { redirect: 'follow' });
            if (!sRes.ok) { msg.retry(); continue; }
            if (t.size <= 10 * 1024 * 1024) {
               const pr = await awsS3Fetch(`${config.S3_ENDPOINT}/${t.bucket}/${encodeURIComponent(t.b2Path)}`, { method: 'PUT', headers: { 'Content-Type': sRes.headers.get('content-type') || 'application/octet-stream', 'Content-Length': t.size.toString(), 'x-amz-content-sha256': 'UNSIGNED-PAYLOAD' }, body: sRes.body, duplex: 'half' }, env);
               if(!pr.ok) { msg.retry(); continue; }
               await env.DB.prepare("INSERT INTO files (id, name, b2_path, type, size, folder) VALUES (?, ?, ?, ?, ?, ?)").bind(crypto.randomUUID(), t.name, t.b2Path, t.bucket, t.size, t.folder).run();
               await env.DB.prepare("UPDATE downloads SET status = 'completed', loaded = total WHERE id = ?").bind(id).run();
               globalLastSizeCalcTime = 0;
            } else { await env.DB.prepare("UPDATE downloads SET status = 'error' WHERE id = ?").bind(id).run(); }
        }
      } catch(e) { msg.retry(); } 
    }
  }
};

function renderLoginPage(env) { 
  return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>${env.SITE_NAME || 'TTecloud'} - 后台登录</title><style>body{font-family:sans-serif;background:#f8fafc;display:flex;justify-content:center;margin-top:10vh;}.card{background:#fff;padding:20px;border-radius:12px;box-shadow:0 4px 10px rgba(0,0,0,0.1);width:100%;max-width:350px;}input,button{width:100%;padding:10px;margin:10px 0;box-sizing:border-box;border-radius:6px;border:1px solid #ccc;}button{background:#3b82f6;color:#fff;border:none;cursor:pointer;}</style></head><body><div class="card"><h2 style="text-align:center;">🔐 身份验证</h2><form action="/login" method="post"><input type="text" name="username" placeholder="账号" required><input type="password" name="password" placeholder="密码" required><button type="submit">登录</button></form></div></body></html>`; 
}

function renderRedirect(m, u) { 
  return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta http-equiv="refresh" content="1.5;url=${u}"><style>body{font-family:sans-serif;text-align:center;margin-top:20vh;}</style></head><body><h2>${m}</h2><p>跳转中...</p></body></html>`; 
}

function renderSharePage(f, o, env) { 
  const isImg = f.name.match(/\.(jpg|jpeg|png|gif|webp)$/i); 
  const safeName = escapeHTML(f.name); 
  return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>${safeName} - ${env.SITE_NAME || 'TTecloud'}分享</title><style>body{font-family:sans-serif;background:#f8fafc;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;}.card{background:#fff;padding:30px;border-radius:12px;box-shadow:0 4px 15px rgba(0,0,0,0.1);text-align:center;max-width:400px;width:90%;}img{max-width:100%;border-radius:8px;}.btn{display:inline-block;padding:10px 20px;background:#3b82f6;color:#fff;text-decoration:none;border-radius:6px;margin-top:20px;}</style></head><body><div class="card">${isImg?`<img src="${o}/file/${f.id}">`:'<h1 style="font-size:50px;margin:0;">📄</h1>'}<h3>${safeName}</h3><p style="color:#666;font-size:14px;">大小: ${(f.size/1024/1024).toFixed(2)} MB</p><a href="${o}/file/${f.id}?dl=1" class="btn" target="_blank">立即下载</a></div></body></html>`; 
}

function getSPA_HTML(env) {
  const maxStorageGB = env.MAX_STORAGE_GB || '10';
  
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>${env.SITE_NAME || 'TTecloud'}</title>
  <style>
    :root { --primary: #3b82f6; --primary-hover: #2563eb; --bg: #f1f5f9; --text: #334155; --card: #ffffff; --border: #e2e8f0; --tag-bg: #e0e7ff; --tag-text: #3b82f6; }[data-theme="dark"] { --primary: #60a5fa; --primary-hover: #93c5fd; --bg: #0f172a; --text: #f1f5f9; --card: #1e293b; --border: #334155; --tag-bg: #1e3a8a; --tag-text: #bfdbfe; }
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 10px; display: flex; flex-direction: column; align-items: center; transition: 0.3s; }
    * { box-sizing: border-box; }
    .container { max-width: 900px; width: 100%; }
    .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; border-bottom: 1px solid var(--border); padding-bottom: 8px; flex-wrap: wrap; gap:5px;}
    .card { background: var(--card); padding: 15px; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.02); margin-bottom: 12px; border: 1px solid var(--border); }
    .nav-tabs { display: flex; gap: 8px; background: var(--bg); padding: 4px; border-radius: 8px; border: 1px solid var(--border); overflow-x: auto; white-space: nowrap; }
    .nav-tab { padding: 6px 12px; border-radius: 6px; text-decoration: none; color: var(--text); font-weight: bold; cursor:pointer; background:transparent; border:none; transition: 0.2s; font-size:13px; }
    .nav-tab.active { background: var(--primary); color: white; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    .btn { display: inline-flex; align-items: center; justify-content: center; gap: 4px; background: var(--primary); color: white !important; padding: 8px 14px; border: none; border-radius: 6px; cursor: pointer; text-decoration: none; font-size: 13px; font-weight: 500;}
    .btn:active { transform: scale(0.98); }
    .btn-sm { padding: 5px 10px; font-size: 12px; } .btn-outline { background: transparent; color: var(--text) !important; border: 1px solid var(--border); }
    .btn-danger { background: #ef4444; } .btn-warn { background: #f59e0b; } .btn-success { background: #10b981; }
    input, select { padding: 10px; border: 1px solid var(--border); border-radius: 6px; background: var(--bg); color: var(--text); font-size: 14px; width: 100%; outline: none; margin-bottom: 5px; }
    input:focus { border-color: var(--primary); }
    .grid-view { display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 12px; }
    .folder-card { background: var(--card); border: 1px solid var(--border); padding: 15px; border-radius: 10px; text-align: center; cursor: pointer; transition: 0.2s; }
    .folder-card:hover { transform: translateY(-2px); border-color: var(--primary); }
    .file-item { display: flex; justify-content: space-between; align-items: center; padding: 12px 0; border-bottom: 1px solid var(--border); gap: 10px; flex-wrap: wrap; }
    .file-item:last-child { border-bottom: none; }
    .tag { font-size: 11px; padding: 2px 6px; border-radius: 4px; background: var(--tag-bg); color: var(--tag-text); }
    .progress-container { width: 100%; background: var(--bg); border-radius: 6px; height: 12px; margin-top: 8px; overflow: hidden; border: 1px solid var(--border); }
    .progress-bar { height: 100%; background: linear-gradient(90deg, var(--primary), #60a5fa); transition: width 0.3s ease; }
    .upload-box { border: 2px dashed var(--border); padding: 20px 10px; text-align: center; border-radius: 8px; background: var(--bg); cursor: pointer; position: relative; }
    .upload-box input[type="file"] { position: absolute; top: 0; left: 0; width: 100%; height: 100%; opacity: 0; cursor: pointer; }
    .modal-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.6); backdrop-filter: blur(3px); display: flex; align-items: center; justify-content: center; z-index: 1000; }
    .modal-content { background: var(--card); padding: 20px; border-radius: 12px; width: 92%; max-width: 450px; max-height: 80vh; overflow-y: auto; display:flex; flex-direction:column; gap:10px;}
    .flex-row { display: flex; gap: 8px; align-items: center; width: 100%; }
    .dl-task { padding: 10px; background: var(--bg); border: 1px dashed var(--border); border-radius: 8px; margin-top: 10px; }
    .github-badge { position: fixed; bottom: 15px; left: 15px; background: rgba(255,255,255,0.7); backdrop-filter: blur(5px); color: #333; padding: 8px 12px; border-radius: 8px; text-decoration: none; font-size: 13px; font-weight: bold; border: 1px solid var(--border); box-shadow: 0 4px 6px rgba(0,0,0,0.1); display: flex; align-items: center; gap: 6px; z-index: 1000; transition: all 0.3s ease; }
    [data-theme="dark"] .github-badge { background: rgba(30,41,59,0.7); color: #fff; border-color: #334155; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
    .github-badge:hover { transform: translateY(-3px) scale(1.02); box-shadow: 0 6px 12px rgba(0,0,0,0.15); color: var(--primary); }
  </style>
</head>
<body data-theme="light">

  <a href="https://github.com/TangYani2024/TTecloud" target="_blank" class="github-badge">
    <svg height="16" width="16" viewBox="0 0 16 16" fill="currentColor"><path d="M8 0c4.42 0 8 3.58 8 8a8.013 8.013 0 0 1-5.45 7.59c-.4.08-.55-.17-.55-.38 0-.27.01-1.13.01-2.2 0-.75-.25-1.23-.54-1.48 1.78-.2 3.65-.88 3.65-3.95 0-.88-.31-1.59-.82-2.15.08-.2.36-1.02-.08-2.12 0 0-.67-.22-2.2.82-.64-.18-1.32-.27-2-.27-.68 0-1.36.09-2 .27-1.53-1.03-2.2-.82-2.2-.82-.44 1.1-.16 1.92-.08 2.12-.51.56-.82 1.28-.82 2.15 0 3.06 1.86 3.75 3.64 3.95-.23.2-.44.55-.51 1.07-.46.21-1.61.55-2.33-.66-.15-.24-.6-.83-1.23-.82-.67.01-.27.38.01.53.34.19.73.9.82 1.13.16.45.68 1.31 2.69.94 0 .67.01 1.3.01 1.49 0 .21-.15.45-.55.38A7.995 7.995 0 0 1 0 8c0-4.42 3.58-8 8-8Z"></path></svg>
    Powered by TTecloud
  </a>

  <div class="container">
    <div class="header">
      <h2 style="margin:0; font-size: 18px;">🍬 ${env.SITE_NAME || 'TTecloud'}</h2>
      <div class="nav-tabs" id="main-nav" style="display:none;">
         <button class="nav-tab active" id="tab-resource" onclick="app.switchView('resource')">🗂️ 资源</button>
         <button class="nav-tab" id="tab-image" onclick="app.switchView('image')">🖼️ 图床</button>
      </div>
      <div>
        <button class="btn btn-outline btn-sm" onclick="app.toggleTheme()">🌓</button>
        <span id="auth-btn"></span>
      </div>
    </div>

    <div class="card" id="storage-card" style="display:none; padding: 12px 15px; border-left: 4px solid var(--primary);">
       <div style="display:flex; justify-content:space-between; font-size:13px; margin-bottom:8px;">
           <span style="font-weight:bold; color:var(--text);">💽 存储空间概览</span>
           <span id="storage-text" style="font-weight:bold; color:var(--primary);">0 MB / ${maxStorageGB} GB (0%)</span>
       </div>
       <div class="progress-container" style="height: 10px; background: var(--border);">
           <div id="storage-bar" class="progress-bar" style="width: 0%; transition: width 0.8s ease, background 0.3s ease;"></div>
       </div>
    </div>

    <div class="card" id="admin-panel" style="display:none; border-top: 3px solid var(--primary);">
       <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px; flex-wrap:wrap; gap:5px;">
          <h3 style="margin:0; font-size:15px;">🚀 高速入库核心</h3>
          <div class="nav-tabs" style="padding:2px; display:flex;">
             <button id="mode-local" class="nav-tab active" onclick="app.switchUploadMode('local')">直传</button>
             <button id="mode-cloud" class="nav-tab" onclick="app.switchUploadMode('cloud')">离线</button>
          </div>
       </div>
       
       <div id="form-local" style="display:flex; flex-direction:column; gap:10px;">
          <div class="flex-row">
             <input type="text" id="up-folder" placeholder="输入目录 (默认根目录)" style="flex:1;">
          </div>
          <div class="flex-row" style="margin-top:2px; flex-wrap:wrap;">
             <button class="btn btn-sm btn-outline" style="white-space:nowrap; flex:1;" onclick="app.showSessionsModal()">🧹 断点碎片清理</button>
             <button class="btn btn-sm btn-warn" style="white-space:nowrap; flex:1; border:none; color:white!important;" onclick="app.adminAct('sync_d1_ghosts', null, null)">🗑️ 清 D1 死链</button>
             <button class="btn btn-sm btn-danger" style="white-space:nowrap; flex:1;" onclick="app.adminAct('sync_b2_orphans', null, null)">💣 删 B2 游离</button>
          </div>
          <div class="upload-box">
             <input type="file" id="up-file" onchange="document.getElementById('file-name-display').innerText = this.files[0]?.name || '点击或拖拽选择文件'">
             <div id="file-name-display" style="color:var(--primary); font-weight:bold; font-size:14px;">➕ 点击选择需上传的文件</div>
          </div>
          <button id="uploadBtn" class="btn" onclick="app.uploadLocal()" style="width:100%; font-size:15px; padding:12px;">⚡ 发起多线程疾速上传</button>
       </div>

       <div id="form-cloud" style="display:none; flex-direction:column; gap:10px; background:var(--bg); padding:15px; border-radius:8px;">
          <div style="display:flex; gap:8px;">
             <input type="url" id="remoteUrl" placeholder="输入直链 URL..." style="flex:1; margin:0;">
             <button type="button" id="parseBtn" class="btn btn-outline" onclick="app.parseRemoteUrl()">解析</button>
          </div>
          <div id="remoteInfo" style="display:none; margin-top:5px;">
             <div class="flex-row">
               <input type="text" id="remoteFolder" placeholder="指定分类" style="flex:1;">
               <input type="text" id="remoteFilename" placeholder="保存文件名" style="flex:2;">
             </div>
             <div style="font-size:12px; margin:8px 0; color:gray;">📦 <b id="remoteSizeTxt"></b> | ⏱️ <b id="remoteTimeTxt"></b></div>
             <button type="button" id="startRemoteBtn" class="btn btn-success" onclick="app.startRemoteDownload()" style="width:100%;">✅ 投递离线任务</button>
          </div>
       </div>

       <div id="uploadProgress" style="display:none; width:100%; margin-top:15px; padding: 12px; background: var(--bg); border-radius: 8px; border: 1px solid var(--border);">
          <div style="display:flex; justify-content:space-between; font-size:12px; margin-bottom:5px;">
             <span id="uploadStatus" style="color:var(--primary); font-weight:bold;">分析中...</span>
             <span id="uploadPercent" style="font-weight:bold; color:var(--text);">0%</span>
          </div>
          <div class="progress-container"><div id="uploadProgressBar" class="progress-bar" style="width: 0%;"></div></div>
          <div style="display:flex; justify-content:space-between; margin-top:12px; align-items:center;">
             <div style="font-size:11px; color:gray; line-height: 1.4;" id="uploadSpeedTxt">初始化网络通道...</div>
             <div style="display:flex; gap:8px; align-items:center;">
                 <button type="button" id="pauseUploadBtn" class="btn btn-sm btn-warn" style="display:none;" onclick="app.togglePause()">⏸️ 暂停</button>
                 <button type="button" id="cancelUploadBtn" class="btn btn-sm btn-danger" onclick="app.cancelUpload()">🗑️ 取消</button>
             </div>
          </div>
       </div>

       <div id="remoteTaskContainer"></div>
    </div>

    <div class="card" style="display:flex; gap:10px; flex-wrap:wrap; align-items:center;">
       <button class="btn btn-sm btn-outline" onclick="app.goHome()" id="btn-back" style="display:none;">&larr; 返回</button>
       <span id="breadcrumb" style="font-weight:bold; font-size:15px; flex:1; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">📁 根目录</span>
       <input type="text" id="search-input" placeholder="🔍 搜索..." oninput="app.debounceSearch()" style="width:120px; padding:6px; margin:0;">
    </div>

    <div class="card" id="dynamic-area" style="padding:15px; transition:0.3s; min-height: 200px;"></div>
  </div>

  <script>
    const app = {
       state: { view: 'resource', folder: null, q: '', isAdmin: false },
       
       escapeHTML(str) { return String(str).replace(/[&<>'"]/g, tag => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[tag] || tag)); },

       async init() {
          this.toggleTheme(localStorage.getItem('site-theme'));
          window.addEventListener('hashchange', () => this.parseHash());
          this.parseHash();
          setInterval(() => this.pollRemoteTasks(), 2500);
          window.addEventListener('beforeunload', (e) => { if(this.isUploading && !this.isPaused) { e.preventDefault(); e.returnValue='上传中'; } });
       },
       parseHash() {
          const hash = window.location.hash.slice(1); const params = new URLSearchParams(hash);
          this.state.view = params.get('view') || 'resource'; this.state.folder = params.get('folder') || null; this.state.q = params.get('q') || '';
          document.getElementById('search-input').value = this.state.q;
          document.getElementById('tab-resource').classList.toggle('active', this.state.view === 'resource');
          document.getElementById('tab-image').classList.toggle('active', this.state.view === 'image');
          this.fetchData();
       },
       setHash() {
          let h = \`view=\${this.state.view}\`;
          if (this.state.folder) h += \`&folder=\${encodeURIComponent(this.state.folder)}\`;
          if (this.state.q) h += \`&q=\${encodeURIComponent(this.state.q)}\`;
          window.location.hash = h;
       },
       switchView(v) { this.state.view = v; this.state.folder = null; this.state.q = ''; this.setHash(); },
       goHome() { this.state.folder = null; this.setHash(); },
       goToFolder(fName, isLocked) {
          if(!this.state.isAdmin && isLocked) {
             const pwd = prompt('🔒 文件夹加密，请输入密码：'); if(!pwd) return;
             fetch('/api/unlock', { method:'POST', body:JSON.stringify({folder:fName, password:pwd}) }).then(r=>r.json()).then(res=>{ if(res.ok) { this.state.folder=fName; this.setHash(); } else alert(res.error); });
             return;
          }
          this.state.folder = fName; this.setHash(); 
       },
       debounceSearch() { clearTimeout(this.st); this.st = setTimeout(() => { this.state.q = document.getElementById('search-input').value.trim(); this.setHash(); }, 400); },

       async fetchData() {
          const area = document.getElementById('dynamic-area'); area.style.opacity = '0.5';
          try {
             let u = \`/api/data?view=\${this.state.view}\`; if(this.state.folder) u += \`&folder=\${encodeURIComponent(this.state.folder)}\`; if(this.state.q) u += \`&q=\${encodeURIComponent(this.state.q)}\`;
             const r = await fetch(u); if(r.status === 401) { alert('密码过期'); this.goHome(); return; }
             const res = await r.json(); this.state.isAdmin = res.isAdmin;
             
             document.getElementById('auth-btn').innerHTML = res.isAdmin ? '<a href="/logout" class="btn btn-sm btn-outline">退出</a>' : '<a href="/login" class="btn btn-sm btn-outline">管理登录</a>';
             document.getElementById('main-nav').style.display = res.isAdmin ? 'flex' : 'none';
             document.getElementById('admin-panel').style.display = res.isAdmin ? 'block' : 'none';
             document.getElementById('btn-back').style.display = this.state.folder ? 'inline-flex' : 'none';
             document.getElementById('breadcrumb').innerText = this.state.folder ? \`📂 \${this.escapeHTML(this.state.folder)}\` : '📁 根目录';
             
             if (res.isAdmin) {
                document.getElementById('storage-card').style.display = 'block';
                const pct = res.maxSize > 0 ? Math.min((res.totalSize / res.maxSize) * 100, 100).toFixed(1) : 0;
                document.getElementById('storage-text').innerText = \`\${this.formatBytes(res.totalSize)} / \${this.formatBytes(res.maxSize)} (\${pct}%)\`;
                const sBar = document.getElementById('storage-bar');
                sBar.style.width = pct + '%';
                if (pct > 90) sBar.style.background = '#ef4444'; 
                else if (pct > 75) sBar.style.background = '#f59e0b'; 
                else sBar.style.background = 'linear-gradient(90deg, var(--primary), #60a5fa)'; 
             } else {
                document.getElementById('storage-card').style.display = 'none';
             }

             if (res.mode === 'folders') this.renderFolders(res.data); else this.renderFiles(res.data);
          } catch(e) {} finally { area.style.opacity = '1'; }
       },

       renderFolders(arr) {
          const area = document.getElementById('dynamic-area'); if(!arr.length) return area.innerHTML = '<p style="text-align:center; color:gray;">空空如也~</p>';
          let html = '<div class="grid-view">';
          arr.forEach(f => {
             const safeName = this.escapeHTML(f.name);
             const jsName = f.name.replace(/\\\\/g, '\\\\\\\\').replace(/'/g, "\\\\'").replace(/"/g, '\\\\\\"');
             const adminBtns = this.state.isAdmin ? \`<div style="margin-top:8px;"><button class="btn btn-sm btn-outline" onclick="event.stopPropagation(); app.adminFolder('\${jsName}')">🔐</button></div>\` : '';
             html += \`<div class="folder-card" onclick="app.goToFolder('\${jsName}', \${f.locked})"><div style="font-size:35px; margin-bottom:5px;">\${f.locked ? '🗃️' : '📁'}</div><div style="font-weight:bold; font-size:14px; word-break:break-all;">\${safeName}</div><div style="color:gray; font-size:11px; margin-top:5px;">\${f.count} 项 | \${this.formatBytes(f.size)}</div>\${adminBtns}</div>\`;
          }); area.innerHTML = html + '</div>';
       },

       // 📌 全局轻量级 Toast 提示组件
       toast(msg) {
          const t = document.createElement('div'); t.innerText = msg;
          t.style.cssText = 'position:fixed; top:20px; left:50%; transform:translateX(-50%); background:var(--primary); color:#fff; padding:8px 16px; border-radius:20px; font-size:14px; z-index:9999; box-shadow:0 4px 10px rgba(0,0,0,0.2); transition:0.3s; opacity:0; pointer-events:none;';
          document.body.appendChild(t); t.offsetHeight; t.style.opacity = '1';
          setTimeout(() => { t.style.opacity = '0'; setTimeout(()=>t.remove(), 300); }, 2000);
       },

       // 📌 通用复制功能内核
       copyText(txt) {
          if(navigator.clipboard && window.isSecureContext) {
             navigator.clipboard.writeText(txt).then(()=>this.toast('✅ 复制成功！')).catch(()=>prompt('手动复制:', txt));
          } else {
             const ta = document.createElement('textarea'); ta.value = txt; ta.style.position='fixed'; ta.style.opacity='0'; document.body.appendChild(ta); ta.select();
             try { document.execCommand('copy'); this.toast('✅ 复制成功！'); } catch(e) { prompt('手动复制:', txt); }
             document.body.removeChild(ta);
          }
       },

       // 📌 生成图床专属链接
       copyImgLink(id) { this.copyText(\`\${window.location.origin}/file/\${id}\`); },
       copyImgMd(id, name) { this.copyText(\`![\${name}](\${window.location.origin}/file/\${id})\`); },

       renderFiles(arr) {
          const area = document.getElementById('dynamic-area'); if(!arr.length) return area.innerHTML = '<p style="text-align:center; color:gray;">暂无文件~</p>';
          let html = '<div>';
          arr.forEach(f => {
             const safeName = this.escapeHTML(f.name);
             const jsName = f.name.replace(/\\\\/g, '\\\\\\\\').replace(/'/g, "\\\\'").replace(/"/g, '\\\\\\"');
             
             // 🖼️ 图床与缩略图逻辑判断
             const isImgView = this.state.view === 'image';
             const isImgExt = /\\.(jpg|jpeg|png|gif|webp|bmp|svg|ico)$/i.test(f.name);
             const showPreview = isImgView || isImgExt;

             // 📐 生成带缩略图的左侧区域
             let previewHTML = '';
             if (showPreview) {
                 previewHTML = \`<a href="/file/\${f.id}" target="_blank" style="width: 50px; height: 50px; flex-shrink: 0; background: var(--bg); border: 1px solid var(--border); border-radius: 6px; overflow: hidden; display: flex; align-items: center; justify-content: center;"><img src="/file/\${f.id}" loading="lazy" style="width:100%; height:100%; object-fit:cover;" alt="preview"></a>\`;
             } else {
                 previewHTML = \`<div style="width: 50px; height: 50px; flex-shrink: 0; background: var(--tag-bg); color: var(--primary); border-radius: 6px; display:flex; align-items:center; justify-content:center; font-size:24px;">📄</div>\`;
             }

             // 🎯 根据板块动态渲染交互按钮
             let actionBtns = '';
             if (isImgView) {
                 // 图床模式：隐藏分享，提供快捷复制功能
                 actionBtns += \`<button class="btn btn-sm btn-outline" onclick="app.copyImgLink('\${f.id}')">复制链接</button>\`;
                 actionBtns += \`<button class="btn btn-sm btn-outline" onclick="app.copyImgMd('\${f.id}', '\${jsName}')">Markdown</button>\`;
             } else {
                 // 资源网盘模式：保留原有的下载和分享页
                 actionBtns += \`<a href="/file/\${f.id}?dl=1" class="btn btn-sm btn-outline" target="_blank">下载</a>\`;
                 actionBtns += \`<a href="/share/\${f.id}" class="btn btn-sm btn-outline" target="_blank">分享</a>\`;
             }
             actionBtns += this.renderAdminBtns(f);

             // 🧩 拼接文件条目（改用 Flex 内嵌布局确保缩略图不换行）
             html += \`<div class="file-item" \${f.is_hidden ? 'style="opacity: 0.5;"' : ''}>
                <div style="display:flex; flex:1; align-items:center; gap:12px; min-width:200px; overflow:hidden;">
                    \${previewHTML}
                    <div style="flex:1; overflow:hidden;">
                       <div style="font-weight:bold; font-size:14px; margin-bottom:4px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;" title="\${safeName}">\${safeName}</div>
                       <span class="tag">\${this.formatBytes(f.size)}</span>
                    </div>
                </div>
                <div style="display:flex; gap:5px; flex-wrap:wrap; align-items:center; justify-content:flex-end;">\${actionBtns}</div>
             </div>\`;
          });
          area.innerHTML = html + '</div>';
       },

       renderAdminBtns(f) {
          if(!this.state.isAdmin) return '';
          const jsName = f.name.replace(/\\\\/g, '\\\\\\\\').replace(/'/g, "\\\\'").replace(/"/g, '\\\\\\"');
          const jsFolder = f.folder ? f.folder.replace(/\\\\/g, '\\\\\\\\').replace(/'/g, "\\\\'").replace(/"/g, '\\\\\\"') : '';
          return \`<button class="btn btn-sm btn-outline" onclick="app.adminAct('rename', '\${f.id}', '\${jsName}')">✏️</button><button class="btn btn-sm btn-outline" onclick="app.adminAct('move', '\${f.id}', '\${jsFolder}')">✂️</button><button class="btn btn-sm \${f.is_hidden?'btn-warn':'btn-outline'}" onclick="app.adminAct('toggle_hide', '\${f.id}')">👁️</button><button class="btn btn-sm btn-danger" onclick="app.adminAct('delete', '\${f.id}')">🗑️</button>\`;
       },
       async adminAct(action, id, param) {
          let req = { action, id, viewMode: this.state.view };
          if (action === 'delete' && !confirm('警告：永久删除？')) return;
          if (action === 'rename') { const n = prompt('新名称：', param); if(!n || n===param) return; req.name = n; }
          if (action === 'move') { const n = prompt('目标目录：', param); if(!n || n===param) return; req.folder = n; }
          
          if (action === 'sync_d1_ghosts' && !confirm('扫描 D1 数据库，删除 B2 桶中不存在的【死链记录】。\\n\\n极度安全，不会影响任何真实文件，确认执行？')) return;
          if (action === 'sync_b2_orphans' && !confirm('🚨 警告：极度危险操作！🚨\\n\\n将扫描 B2 桶，物理删除所有【不在 D1 记录中】且【距今超过24小时】的游离文件！\\n\\n如果你通过其他途径（如图床插件）也向这个桶传了文件，它们将被瞬间清空！\\n请确认该桶仅供本网盘独占使用！确认执行？')) return;

          try { 
              const r = await fetch('/api/admin/action', { method: 'POST', body: JSON.stringify(req) }); 
              const res = await r.json();
              if (res.msg) alert(res.msg);
              this.fetchData(); 
          } catch(e) { alert('操作失败'); }
       },
       async adminFolder(fName) { const pwd = prompt(\`设置目录[\${fName}] 密码(留空清除)：\`); if(pwd === null) return; await fetch('/api/admin/action', { method: 'POST', body: JSON.stringify({ action:'lock_folder', folder:fName, password:pwd }) }); this.fetchData(); },

       switchUploadMode(m) {
          document.getElementById('mode-local').classList.toggle('active', m==='local'); 
          document.getElementById('mode-cloud').classList.toggle('active', m==='cloud');
          document.getElementById('form-local').style.display = m==='local' ? 'flex' : 'none'; 
          document.getElementById('form-cloud').style.display = m==='cloud' ? 'flex' : 'none';
          document.getElementById('uploadProgress').style.display = 'none';
       },

       isUploading: false, isPaused: false, cancelFlag: false, ctrl: null, glUpId: null, glPath: null, glHash: null,
       uBytes: 0, sessionBytes: 0, accumulatedTime: 0, lastResumeTime: 0, activeTasks: {},

       togglePause() {
           this.isPaused = !this.isPaused;
           const pBtn = document.getElementById('pauseUploadBtn');
           if (this.isPaused) {
               this.accumulatedTime += (Date.now() - this.lastResumeTime);
               pBtn.innerHTML = '▶️ 继续'; pBtn.className = 'btn btn-sm btn-success';
               document.getElementById('uploadSpeedTxt').innerText = '任务已冻结休眠...';
               document.getElementById('uploadStatus').innerText = '⏸️ 暂停中';
               if(this.ctrl) this.ctrl.abort(); 
           } else {
               pBtn.innerHTML = '⏸️ 暂停'; pBtn.className = 'btn btn-sm btn-warn';
               document.getElementById('uploadStatus').innerText = '🚀 满血复苏中...';
               this.ctrl = new AbortController();
               this.lastResumeTime = Date.now();
           }
       },

       cancelUpload() { 
           if(!confirm('确定彻底取消并销毁已传碎片？')) return; 
           this.cancelFlag = true; this.isPaused = false; 
           if(this.ctrl) this.ctrl.abort(); 
       },

       async getFastHash(t) { const buf = new TextEncoder().encode(t); const hash = await crypto.subtle.digest('SHA-1', buf); return Array.from(new Uint8Array(hash)).map(b=>b.toString(16).padStart(2,'0')).join(''); },
       
       async fetchWithTimeout(url, options, timeoutMs = 60000) {
          const controller = new AbortController(); const id = setTimeout(() => controller.abort(), timeoutMs);
          if (options.signal) { options.signal.addEventListener('abort', () => controller.abort()); if(options.signal.aborted) controller.abort(); }
          try { return await fetch(url, { ...options, signal: controller.signal }); } 
          catch(err) { if (err.name === 'AbortError' && !options.signal?.aborted) throw new Error('网络请求硬超时'); throw err; } 
          finally { clearTimeout(id); }
       },

       async uploadLocal() {
          const file = document.getElementById('up-file').files[0]; const folder = document.getElementById('up-folder').value || '默认分类';
          if(!file) return alert('请先选择文件');
          const bucket = this.state.view === 'resource' ? '${env.BUCKET_RESOURCE}' : '${env.BUCKET_IMAGE}';
          const pDiv = document.getElementById('uploadProgress'), pBar = document.getElementById('uploadProgressBar'), pTxt = document.getElementById('uploadPercent'), sTxt = document.getElementById('uploadStatus'), btn = document.getElementById('uploadBtn'), cBtn = document.getElementById('cancelUploadBtn'), pBtn = document.getElementById('pauseUploadBtn');
          
          this.isUploading = true; this.isPaused = false; this.cancelFlag = false; this.ctrl = new AbortController();
          this.uBytes = 0; this.sessionBytes = 0; this.accumulatedTime = 0; this.lastResumeTime = Date.now(); this.activeTasks = {};
          
          pDiv.style.display = 'block'; btn.style.display = 'none'; cBtn.style.display = 'inline-flex'; pBar.style.width = '0%'; pTxt.innerText = '0%'; pBtn.innerHTML = '⏸️ 暂停'; pBtn.className = 'btn btn-sm btn-warn'; document.getElementById('uploadSpeedTxt').innerText = '引擎预热中...';

          try {
             let CHUNK_SIZE = 10 * 1024 * 1024;
             if (file.size <= 10 * 1024 * 1024) CHUNK_SIZE = file.size; 
             else if (file.size <= 50 * 1024 * 1024) CHUNK_SIZE = 5 * 1024 * 1024; 
             else if (file.size <= 500 * 1024 * 1024) CHUNK_SIZE = 10 * 1024 * 1024; 
             else CHUNK_SIZE = 20 * 1024 * 1024; 

             this.glHash = await this.getFastHash(file.name + file.size + file.lastModified + CHUNK_SIZE);
             
             if (file.size <= 10 * 1024 * 1024) {
                 pBtn.style.display = 'none'; sTxt.innerText = '执行单发秒传...';
                 const r = await this.fetchWithTimeout('/api/upload/single', { method:'POST', headers:{'x-filename':encodeURIComponent(file.name),'x-bucket':bucket,'x-folder':encodeURIComponent(folder),'content-type':file.type||'application/octet-stream'}, body:file, signal:this.ctrl.signal }, 120000);
                 if(!r.ok) throw new Error(await r.text()); pBar.style.width='100%'; pTxt.innerText='100%';
                 
                 let elapsedSec = (Date.now() - this.lastResumeTime) / 1000;
                 let avgSpeed = elapsedSec > 0 ? (file.size / elapsedSec) : 0;
                 document.getElementById('uploadSpeedTxt').innerText = \`⚡ 平均速度: \${this.formatBytes(avgSpeed)}/s\\n⏳ 剩余时间: 0秒\`;
             } else {
                 pBtn.style.display = 'inline-flex';
                 sTxt.innerText = '探测历史记录...';
                 const ck = await (await this.fetchWithTimeout('/api/upload/check', { method:'POST', body:JSON.stringify({fileHash:this.glHash}), signal:this.ctrl.signal }, 15000)).json();
                 let fId, bPath, uParts =[];
                 if(ck.exists) { fId=ck.session.b2_file_id; bPath=ck.session.b2_path; uParts=JSON.parse(ck.session.uploaded_parts||'[]'); sTxt.innerText = '触发断点续传！'; }
                 else { sTxt.innerText = '建立 S3 矩阵...'; const st = await (await this.fetchWithTimeout('/api/upload/start', { method:'POST', body:JSON.stringify({bucket,filename:file.name,contentType:file.type||'application/octet-stream',fileHash:this.glHash,folder}), signal:this.ctrl.signal }, 15000)).json(); fId=st.fileId; bPath=st.b2Path; }
                 this.glUpId = fId; this.glPath = bPath;
                 const tChunks = Math.ceil(file.size/CHUNK_SIZE); let eDict = {}; uParts.forEach(p=>eDict[p.partNumber]=p.etag);
                 this.uBytes = uParts.length * CHUNK_SIZE; if(this.uBytes > file.size) this.uBytes = file.size;
                 
                 let taskPool =[]; for(let i=1; i<=tChunks; i++) { if(!eDict[i]) taskPool.push(i); }
                 let uErr = null; let partAttempts = {};

                 const createWorker = async (workerId, initChannelType) => {
                     let channelType = initChannelType;
                     while(taskPool.length > 0 && !uErr && !this.cancelFlag) {
                         while (this.isPaused && !this.cancelFlag) { await new Promise(r => setTimeout(r, 500)); }
                         if (this.cancelFlag || uErr) break;

                         const pNum = taskPool.shift(); if(!pNum) break;
                         const chunk = file.slice((pNum-1)*CHUNK_SIZE, pNum*CHUNK_SIZE);
                         let success = false; partAttempts[pNum] = partAttempts[pNum] || 0;

                         while(!success && !uErr && !this.cancelFlag) {
                             while (this.isPaused && !this.cancelFlag) { await new Promise(r => setTimeout(r, 500)); }
                             if (this.cancelFlag || uErr) break;

                             try {
                                 this.activeTasks[workerId] = \`W\${workerId}\`; 
                                 sTxt.innerText = \`数据灌入中...[切片: \${CHUNK_SIZE/1024/1024}MB]\`;
                                 
                                 let etag;
                                 if (channelType === 'CF_PROXY') {
                                     const r = await this.fetchWithTimeout('/api/upload/part', { method:'POST', headers:{'x-file-id':fId,'x-file-hash':this.glHash,'x-part-number':pNum,'x-b2-path':encodeURIComponent(bPath),'x-bucket':bucket}, body:chunk, signal:this.ctrl.signal }, 60000);
                                     if(!r.ok) throw new Error(await r.text()); etag = (await r.json()).etag;
                                 } else {
                                     const pRes = await this.fetchWithTimeout(\`/api/upload/presign?uploadId=\${fId}&partNumber=\${pNum}&b2Path=\${encodeURIComponent(bPath)}&bucket=\${bucket}\`, { signal: this.ctrl.signal }, 15000);
                                     if(!pRes.ok) throw new Error('预签名获取失败');
                                     const r = await this.fetchWithTimeout((await pRes.json()).presignedUrl, { method: 'PUT', headers: { 'Content-Type': 'application/octet-stream' }, body: chunk, signal: this.ctrl.signal }, 60000);
                                     if(!r.ok) throw new Error('B2 直传失败'); etag = r.headers.get('ETag').replace(/"/g, '');
                                     fetch('/api/upload/sync_part', { method: 'POST', headers: {'content-type':'application/json'}, body: JSON.stringify({ fileHash: this.glHash, partNumber: pNum, etag }) }).catch(()=>{});
                                 }

                                 eDict[pNum] = etag; this.uBytes += chunk.size; this.sessionBytes += chunk.size;
                                 const cPct = Math.min(Math.round((this.uBytes/file.size)*100), 99); pBar.style.width=cPct+'%'; pTxt.innerText=cPct+'%';
                                 success = true; this.activeTasks[workerId] = null;
                                 
                                 let currentActiveTime = this.accumulatedTime + (Date.now() - this.lastResumeTime);
                                 let elapsedSec = currentActiveTime / 1000;
                                 let avgSpeed = elapsedSec > 0 ? (this.sessionBytes / elapsedSec) : 0;
                                 let activeCount = Object.values(this.activeTasks).filter(Boolean).length;
                                 let remainingBytes = file.size - this.uBytes;
                                 let remainingSec = avgSpeed > 0 ? Math.round(remainingBytes / avgSpeed) : 0;
                                 let timeStr = remainingSec > 60 ? \`\${Math.floor(remainingSec/60)}分\${remainingSec%60}秒\` : \`\${remainingSec}秒\`;
                                 document.getElementById('uploadSpeedTxt').innerText = \`活跃通道: \${activeCount} ⚡ 平均速度: \${this.formatBytes(avgSpeed)}/s\\n⏳ 剩余时间: \${timeStr}\`;
                                 
                             } catch(e) {
                                 if (this.cancelFlag) break;
                                 if (this.isPaused) {
                                     if(!taskPool.includes(pNum)) taskPool.unshift(pNum);
                                     this.activeTasks[workerId] = null;
                                     break; 
                                 }
                                 partAttempts[pNum]++;
                                 if (partAttempts[pNum] >= 6) { uErr = new Error(\`分片 \${pNum} 极度不稳定，网络阻断\`); break; }
                                 channelType = channelType === 'CF_PROXY' ? 'B2_DIRECT' : 'CF_PROXY';
                                 if (partAttempts[pNum] % 2 === 0) { taskPool.push(pNum); this.activeTasks[workerId] = null; break; }
                                 await new Promise(r => setTimeout(r, 2000));
                             }
                         }
                     }
                 };

                 const workers =[
                     createWorker(1, 'B2_DIRECT'), createWorker(2, 'B2_DIRECT'), createWorker(3, 'B2_DIRECT'), createWorker(4, 'B2_DIRECT'), createWorker(5, 'B2_DIRECT'),
                     createWorker(6, 'CF_PROXY'), createWorker(7, 'CF_PROXY'), createWorker(8, 'CF_PROXY'), createWorker(9, 'CF_PROXY'), createWorker(10, 'CF_PROXY')
                 ];
                 await Promise.all(workers); if(uErr) throw uErr; if(this.cancelFlag) throw new DOMException("Abort","AbortError");

                 document.getElementById('uploadSpeedTxt').innerText = '传输完毕，正在组装...'; sTxt.innerText = '闪电合并中...'; 
                 let eArr=[]; for(let i=1;i<=tChunks;i++) eArr.push(eDict[i]);
                 const fR = await this.fetchWithTimeout('/api/upload/finish', { method:'POST', body:JSON.stringify({fileId:fId,etagArray:eArr,name:file.name,b2_path:bPath,type:bucket,size:file.size,folder,fileHash:this.glHash}), signal:this.ctrl.signal }, 30000);
                 if(!fR.ok) throw new Error('合并失败'); pBar.style.width='100%'; pTxt.innerText='100%';
             }
             sTxt.innerText = '🚀 上传成功！'; this.isUploading = false; cBtn.style.display = 'none'; pBtn.style.display = 'none'; document.getElementById('uploadSpeedTxt').innerText = '已完美入库';
             setTimeout(() => { btn.style.display='flex'; pDiv.style.display='none'; document.getElementById('up-file').value=''; document.getElementById('file-name-display').innerText='➕ 点击选择需上传的文件'; this.fetchData(); }, 1500);
          } catch(err) {
             this.isUploading = false; cBtn.style.display = 'none'; pBtn.style.display = 'none'; document.getElementById('uploadSpeedTxt').innerText = '';
             if(err.name === 'AbortError' || this.cancelFlag) { sTxt.innerText='彻底销毁中...'; sTxt.style.color='red'; if(this.glUpId) await fetch('/api/upload/abort',{method:'POST',body:JSON.stringify({fileHash:this.glHash,uploadId:this.glUpId,b2Path:this.glPath,bucket})}); alert('已安全取消！历史碎片已抹除。'); }
             else { alert('致命错误: '+err.message); }
             btn.style.display = 'flex'; pDiv.style.display = 'none';
          }
       },

       async showSessionsModal() {
          const m = document.createElement('div'); m.className = 'modal-overlay'; m.id = 'sessionsModal';
          m.innerHTML = \`<div class="modal-content">
              <h3 style="margin-top:0; margin-bottom:5px;">🧹 断点碎片管理</h3>
              <p style="font-size:12px; color:#64748b; line-height:1.4; margin-bottom:10px;">💡 若要继续上传，直接在主界面重新选择同一个文件即可自动续传。点击强制抹除可彻底释放空间。</p>
              <div id="sessionsList" style="max-height:45vh; overflow-y:auto; margin-bottom:15px; padding-right:5px;">加载中...</div>
              <button class="btn btn-outline" style="width:100%; margin-top:auto;" onclick="document.body.removeChild(this.parentElement.parentElement)">关闭面板</button>
          </div>\`;
          document.body.appendChild(m);
          try {
             const d = await (await fetch('/api/upload/sessions')).json(); let h = d.length ? '' : '<p style="text-align:center; color:gray; margin-top:20px;">无残留任务，极其干净</p>';
             d.forEach(s => { const p = JSON.parse(s.uploaded_parts||'[]'); h += \`<div style="padding:10px; border:1px solid var(--border); margin-bottom:8px; border-radius:8px; background:var(--bg);"><div style="font-weight:bold; word-break:break-all; font-size:13px; color:var(--text);">\${this.escapeHTML(s.b2_path.split('_').slice(1).join('_'))}</div><div style="font-size:12px; color:gray; margin:5px 0;">进度: 已缓冲 \${p.length} 块</div><button class="btn btn-sm btn-danger" style="width:100%;" onclick="app.abortSession('\${s.file_hash}', '\${s.b2_file_id}', '\${s.b2_path}', '\${s.bucket}')">🗑️ 强制抹除</button></div>\`; });
             document.getElementById('sessionsList').innerHTML = h;
          } catch(e) {}
       },
       async abortSession(fH, uI, bP, bk) { if(!confirm('此操作不可逆，确定抹除云端碎片？')) return; await fetch('/api/upload/abort', {method:'POST',body:JSON.stringify({fileHash:fH,uploadId:uI,b2Path:bP,bucket:bk})}); document.body.removeChild(document.getElementById('sessionsModal')); this.showSessionsModal(); },

       remoteInfo: {}, rPrevLoaded: {}, rPrevTime: {},
       async parseRemoteUrl() {
          const u = document.getElementById('remoteUrl').value; const b = document.getElementById('parseBtn'); if(!u) return;
          b.innerText='解析中'; b.disabled=true;
          try { const d=await (await fetch('/api/remote/meta', {method:'POST',body:JSON.stringify({targetUrl:u})})).json(); this.remoteInfo=d; document.getElementById('remoteInfo').style.display='block'; document.getElementById('remoteFilename').value=d.filename; document.getElementById('remoteSizeTxt').innerHTML=this.formatBytes(d.size) + (d.supportRange?' <span style="color:green;">⚡并发支持</span>':' <span style="color:red;">🐢单线支持</span>'); document.getElementById('remoteTimeTxt').innerText=\`\${Math.floor(d.estSeconds/60)}分\${d.estSeconds%60}秒\`; } catch(e) { alert('解析失败'); } finally { b.innerText='解析'; b.disabled=false; }
       },
       async startRemoteDownload() {
          const b = document.getElementById('startRemoteBtn'); b.disabled=true; b.innerText='投递中...';
          await fetch('/api/remote/start', {method:'POST', body:JSON.stringify({targetUrl:document.getElementById('remoteUrl').value, filename:document.getElementById('remoteFilename').value, size:this.remoteInfo.size, folder:document.getElementById('remoteFolder').value||'默认分类', bucket:this.state.view==='resource'?'${env.BUCKET_RESOURCE}':'${env.BUCKET_IMAGE}', supportRange:this.remoteInfo.supportRange})});
          document.getElementById('remoteUrl').value=''; document.getElementById('remoteInfo').style.display='none'; b.disabled=false; b.innerText='✅ 投递离线任务'; this.pollRemoteTasks();
       },
       async pollRemoteTasks() {
          if(!this.state.isAdmin) return;
          try {
             const ts = await (await fetch('/api/remote/status')).json(); const c = document.getElementById('remoteTaskContainer'); if(!c) return;
             if(!ts.length && c.innerHTML!=='') { c.innerHTML=''; this.fetchData(); return; }
             let h=''; const now=Date.now();
             ts.forEach(t => {
                const p = t.total ? Math.min(Math.round((t.loaded/t.total)*100), 100) : 0; let sTxt = '计算中...';
                if(this.rPrevLoaded[t.id] && this.rPrevTime[t.id]) { const bDiff = t.loaded - this.rPrevLoaded[t.id]; const tDiff = (now - this.rPrevTime[t.id])/1000; if(tDiff>0 && bDiff>=0) sTxt = this.formatBytes(bDiff/tDiff)+'/s'; }
                this.rPrevLoaded[t.id] = t.loaded; this.rPrevTime[t.id] = now;
                const st = t.status==='pending'?'排队中...':t.status==='finishing'?'🔄 缝合碎片':t.status==='error'?'❌ 异常重试中':\`\${this.formatBytes(t.loaded)}/\${this.formatBytes(t.total)} ⚡ \${sTxt}\`;
                h += \`<div class="dl-task"><div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:5px;"><strong style="word-break:break-all;">\${this.escapeHTML(t.name)}</strong><span style="color:\${t.status==='error'?'red':'var(--primary)'}">\${st}</span></div><div class="progress-container"><div class="progress-bar" style="width:\${p}%; \${t.status==='error'?'background:red;':''}"></div></div><div style="text-align:right; margin-top:5px;"><button onclick="fetch('/api/remote/cancel',{method:'POST',body:JSON.stringify({taskId:'\${t.id}'})}); app.pollRemoteTasks();" class="btn btn-sm btn-danger">中断取消</button></div></div>\`;
             }); c.innerHTML = h;
          } catch(e){}
       },

       formatBytes(b) { if(!b) return '0 B'; const k=1024, s=['B','KB','MB','GB','TB'], i=Math.floor(Math.log(b)/Math.log(k)); return parseFloat((b/Math.pow(k,i)).toFixed(2))+' '+s[i]; },
       toggleTheme(force) { const h = document.documentElement; const n = force || (h.getAttribute('data-theme') === 'dark' ? 'light' : 'dark'); h.setAttribute('data-theme', n); localStorage.setItem('site-theme', n); }
    };
    app.init();
  </script>
</body>
</html>`;
}