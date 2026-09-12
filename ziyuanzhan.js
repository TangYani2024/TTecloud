const CONFIG = {
  AUTH_COOKIE_NAME: 'TangYani_Admin_Token',
  MAX_STORAGE_BYTES: 10737418240,
  S3_REGION: 'us-east-005',
  S3_ENDPOINT: 'https://s3.us-east-005.backblazeb2.com',
  BUCKETS: { RESOURCE: 'tangyani-ziyuan', IMAGE: 'tangyani-tuchuang' }
};

let globalCachedTotalSize = 0, globalLastSizeCalcTime = 0;
let globalSiteConfig = null, globalConfigTime = 0;

async function getSiteConfig(e) {
  if (Date.now() - globalConfigTime < 300000 && globalSiteConfig) return globalSiteConfig;
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
    (mb ? '@media(max-width:768px){.bg-layer{background-image:url("' + mb + '");}}' : '') +
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

async function awsS3Fetch(u, o, e) {
  const U = new URL(u), M = o.method || 'GET', amz = new Date().toISOString().replace(/[:-]|\.\d{3}/g, ''), dt = amz.slice(0, 8), rh = new Headers(o.headers || {}), sh = new Headers();
  sh.set('host', U.host);
  sh.set('x-amz-date', amz);
  sh.set('x-amz-content-sha256', 'UNSIGNED-PAYLOAD');
  const cu = decodeURIComponent(U.pathname).split('/').map(awsUriEncode).join('/').replace(/%2F/g, '/'), cq = Array.from(U.searchParams).sort(([a], [b]) => a < b ? -1 : 1).map(([k, v]) => awsUriEncode(k) + '=' + awsUriEncode(v)).join('&'), sk = Array.from(sh.keys()).sort(), ch = sk.map(k => k + ':' + sh.get(k) + '\n').join(''), ss = sk.join(';'), crh = await hashSha256(M + '\n' + cu + '\n' + cq + '\n' + ch + '\n' + ss + '\nUNSIGNED-PAYLOAD'), cs = dt + '/' + CONFIG.S3_REGION + '/s3/aws4_request', ks = await hmacSha256(await hmacSha256(await hmacSha256(await hmacSha256('AWS4' + e.B2_APP_KEY, dt), CONFIG.S3_REGION), 's3'), 'aws4_request'), sig = Array.from(await hmacSha256(ks, 'AWS4-HMAC-SHA256\n' + amz + '\n' + cs + '\n' + crh)).map(b => b.toString(16).padStart(2, '0')).join('');
  rh.set('host', U.host);
  rh.set('x-amz-date', amz);
  rh.set('x-amz-content-sha256', 'UNSIGNED-PAYLOAD');
  rh.set('Authorization', 'AWS4-HMAC-SHA256 Credential=' + e.B2_KEY_ID + '/' + cs + ', SignedHeaders=' + ss + ', Signature=' + sig);
  return fetch(U.toString(), { ...o, headers: rh });
}

async function awsS3Presign(u, e, M = 'PUT', ex = 3600) {
  const U = new URL(u), amz = new Date().toISOString().replace(/[:-]|\.\d{3}/g, ''), dt = amz.slice(0, 8), cs = dt + '/' + CONFIG.S3_REGION + '/s3/aws4_request';
  U.searchParams.set('X-Amz-Algorithm', 'AWS4-HMAC-SHA256');
  U.searchParams.set('X-Amz-Credential', e.B2_KEY_ID + '/' + cs);
  U.searchParams.set('X-Amz-Date', amz);
  U.searchParams.set('X-Amz-Expires', ex.toString());
  U.searchParams.set('X-Amz-SignedHeaders', 'content-type;host');
  const cu = decodeURIComponent(U.pathname).split('/').map(awsUriEncode).join('/').replace(/%2F/g, '/'), cq = Array.from(U.searchParams).sort(([a], [b]) => a < b ? -1 : 1).map(([k, v]) => awsUriEncode(k) + '=' + awsUriEncode(v)).join('&'), ch = 'content-type:application/octet-stream\nhost:' + U.host + '\n', crh = await hashSha256(M + '\n' + cu + '\n' + cq + '\n' + ch + '\ncontent-type;host\nUNSIGNED-PAYLOAD'), ks = await hmacSha256(await hmacSha256(await hmacSha256(await hmacSha256('AWS4' + e.B2_APP_KEY, dt), CONFIG.S3_REGION), 's3'), 'aws4_request'), sig = Array.from(await hmacSha256(ks, 'AWS4-HMAC-SHA256\n' + amz + '\n' + cs + '\n' + crh)).map(b => b.toString(16).padStart(2, '0')).join('');
  U.searchParams.set('X-Amz-Signature', sig);
  return U.toString();
}

function getS3Client(e) {
  return { fetch: (u, o = {}) => awsS3Fetch(u, o, e) };
}

export default {
  async fetch(req, e) {
    const U = new URL(req.url), P = U.pathname, C = req.headers.get('Cookie') || '';
    const tM = C.match(new RegExp('(?:^|; )' + CONFIG.AUTH_COOKIE_NAME + '=([^;]*)'));
    const aH = req.headers.get('Authorization');
    const token = (aH && aH.startsWith('Bearer ')) ? aH.substring(7) : (tM ? tM[1] : null);
    const cfg = await getSiteConfig(e);
    const iA = await verifyAdminToken(token, e, cfg);

    if (P === '/') {
      const html = SPA_HTML.replace('</head>', `<script>window.__CFG__=${JSON.stringify(cfg)};</script></head>`);
      return new Response(html, { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
    }

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

    if (P.startsWith('/share/')) {
      const { results: R } = await e.DB.prepare("SELECT * FROM files WHERE id=?").bind(P.split('/')[2]).all();
      if (!R.length || (R[0].is_hidden === 1 && !iA)) return new Response('Not Found', { status: 404 });
      return new Response(rSP(R[0], U.origin, U.searchParams.get('pwd') || '', cfg), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
    }

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
      if (!rh.has('Accept-Ranges')) rh.set('Accept-Ranges', 'bytes');
      rh.delete('Content-Encoding');
      if ([200, 206].includes(rs.status)) rh.set('Cache-Control', 'public, max-age=2592000, no-transform');
      return new Response(rs.body, { status: rs.status, headers: rh });
    }

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

        if (P === '/api/data' && req.method === 'GET') {
          const viewM = U.searchParams.get('view') || 'resource';
          let bk = viewM === 'image' ? CONFIG.BUCKETS.IMAGE : CONFIG.BUCKETS.RESOURCE;
          const hasFolder = U.searchParams.has('folder');
          const tF = hasFolder ? U.searchParams.get('folder') : null;
          const q = U.searchParams.get('q') || '';
          if (Date.now() - globalLastSizeCalcTime > 600000) {
            globalCachedTotalSize = (await e.DB.prepare("SELECT SUM(size) as t FROM files").first())?.t || 0;
            globalLastSizeCalcTime = Date.now();
          }
          if (!hasFolder && !q) {
            const { results: R } = await e.DB.prepare("SELECT f.folder, COUNT(f.id) as count, SUM(f.size) as size, m.password FROM files f LEFT JOIN folder_meta m ON f.folder = m.name WHERE f.type=? " + (iA ? '' : 'AND f.is_hidden=0') + " GROUP BY f.folder ORDER BY f.folder ASC").bind(bk).all();
            return Response.json({
              isAdmin: iA,
              totalSize: globalCachedTotalSize,
              maxSize: CONFIG.MAX_STORAGE_BYTES,
              mode: 'folders',
              data: R.map(r => ({ name: r.folder ?? '', count: r.count, size: r.size, locked: !!r.password }))
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
          for (const f of R) {
            if (!iA && f.password) {
              const lM = C.match(new RegExp('(?:^|; )lock_' + await hashSha256(f.folder || '') + '=([^;]*)'));
              if (!lM || decodeURIComponent(lM[1]) !== f.password) continue;
            }
            fF.push({ id: f.id, name: f.name, size: f.size, folder: f.folder || '', is_hidden: f.is_hidden, upload_at: f.upload_at });
          }
          return Response.json({
            isAdmin: iA,
            totalSize: globalCachedTotalSize,
            maxSize: CONFIG.MAX_STORAGE_BYTES,
            mode: 'files',
            data: fF,
            folderMeta: R.length ? !!R[0].password : false
          }, { headers: { 'Cache-Control': 'no-store, no-cache, must-revalidate' } });
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
          const d = await req.json(), bk = d.type === 'image' ? CONFIG.BUCKETS.IMAGE : CONFIG.BUCKETS.RESOURCE;
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
            const aw = getS3Client(e), vM = p.viewMode || 'resource', bk = vM === 'image' ? CONFIG.BUCKETS.IMAGE : CONFIG.BUCKETS.RESOURCE;
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
          const d = await req.json(), tp = d.type || 'resource', bk = tp === 'image' ? CONFIG.BUCKETS.IMAGE : CONFIG.BUCKETS.RESOURCE;
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
          const bp = Date.now() + '_' + fn, tp = req.headers.get('x-type') || 'resource', bk = tp === 'image' ? CONFIG.BUCKETS.IMAGE : CONFIG.BUCKETS.RESOURCE;
          const rs = await awsS3Fetch(CONFIG.S3_ENDPOINT + '/' + bk + '/' + encodeURIComponent(bp), {
            method: 'PUT',
            headers: { 'Content-Type': req.headers.get('content-type') || 'application/octet-stream', 'x-amz-content-sha256': 'UNSIGNED-PAYLOAD' },
            body: req.body
          }, e);
          if (!rs.ok) throw new Error(await rs.text());
          await e.DB.prepare("INSERT INTO files (id,name,b2_path,type,size,folder) VALUES (?,?,?,?,?,?)").bind(crypto.randomUUID(), fn, bp, bk, req.headers.get('content-length') || 0, decodeURIComponent(req.headers.get('x-folder'))).run();
          globalLastSizeCalcTime = 0;
          return Response.json({ ok: true });
        }

        if (P === '/api/upload/start') {
          const d = await req.json();
          d.filename = d.filename.replace(/^.*[\\\/]/, '').replace(/[:*?"<>|]/g, '_');
          const bp = Date.now() + '_' + d.filename, tp = d.type || 'resource', bk = tp === 'image' ? CONFIG.BUCKETS.IMAGE : CONFIG.BUCKETS.RESOURCE;
          const rs = await awsS3Fetch(CONFIG.S3_ENDPOINT + '/' + bk + '/' + encodeURIComponent(bp) + '?uploads', { method: 'POST', headers: { 'Content-Type': d.contentType } }, e);
          if (!rs.ok) throw new Error(await rs.text());
          const ui = (await rs.text()).match(/<UploadId>(.*?)<\/UploadId>/)[1];
          await e.DB.prepare("INSERT OR REPLACE INTO upload_sessions (file_hash,b2_file_id,b2_path,bucket,folder,uploaded_parts) VALUES (?,?,?,?,?,'[]')").bind(d.fileHash, ui, bp, bk, d.folder).run();
          return Response.json({ fileId: ui, b2Path: bp });
        }

        if (P === '/api/upload/presign_batch') {
          const d = await req.json(), tp = d.type || 'resource', bk = tp === 'image' ? CONFIG.BUCKETS.IMAGE : CONFIG.BUCKETS.RESOURCE;
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
          const tp = req.headers.get('x-type') || 'resource', bk = tp === 'image' ? CONFIG.BUCKETS.IMAGE : CONFIG.BUCKETS.RESOURCE;
          const rs = await awsS3Fetch(CONFIG.S3_ENDPOINT + '/' + bk + '/' + encodeURIComponent(decodeURIComponent(req.headers.get('x-b2-path'))) + '?partNumber=' + req.headers.get('x-part-number') + '&uploadId=' + req.headers.get('x-file-id'), { method: 'PUT', headers: h, body: req.body }, e);
          if (!rs.ok) throw new Error(await rs.text());
          const fh = req.headers.get('x-file-hash'), et = rs.headers.get('ETag').replace(/"/g, ''), pn = parseInt(req.headers.get('x-part-number'));
          if (fh) await e.DB.prepare("UPDATE upload_sessions SET uploaded_parts=(SELECT json_group_array(json_object('partNumber',CAST(partNumber AS INTEGER),'etag',etag)) FROM (SELECT json_extract(value,'$.partNumber') as partNumber,json_extract(value,'$.etag') as etag FROM json_each(uploaded_parts) WHERE partNumber!=? UNION ALL SELECT ? as partNumber,? as etag)) WHERE file_hash=?").bind(pn, pn, et, fh).run();
          return Response.json({ etag: et });
        }

        if (P === '/api/upload/finish') {
          const d = await req.json();
          const xml = '<CompleteMultipartUpload>' + d.etagArray.map((t, i) => '<Part><PartNumber>' + (i + 1) + '</PartNumber><ETag>' + t + '</ETag></Part>').join('') + '</CompleteMultipartUpload>';
          const tp = d.type || 'resource', bk = tp === 'image' ? CONFIG.BUCKETS.IMAGE : CONFIG.BUCKETS.RESOURCE;
          const rs = await awsS3Fetch(CONFIG.S3_ENDPOINT + '/' + bk + '/' + encodeURIComponent(d.b2_path) + '?uploadId=' + d.fileId, { method: 'POST', body: xml }, e);
          if (!rs.ok) throw new Error(await rs.text());
          await e.DB.prepare("INSERT INTO files (id,name,b2_path,type,size,folder) VALUES (?,?,?,?,?,?)").bind(crypto.randomUUID(), d.name, d.b2_path, bk, d.size, d.folder).run();
          if (d.fileHash) await e.DB.prepare("DELETE FROM upload_sessions WHERE file_hash=?").bind(d.fileHash).run();
          globalLastSizeCalcTime = 0;
          return Response.json({ ok: true });
        }

        return Response.json({ ok: false, error: '接口不存在' }, { status: 404 });
      } catch (err) {
        return Response.json({ ok: false, error: err.message }, { status: 500 });
      }
    }

    return new Response('404', { status: 404 });
  }
};

function rLP(cfg) {
  return '<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>登录</title><style>:root{--bgc:#ffffff;--tx:#1e293b;--cb:rgba(255,255,255,0.65);--cd:rgba(0,0,0,0.08)}body{font-family:-apple-system,sans-serif;background-color:var(--bgc);color:var(--tx);margin:0;display:flex;justify-content:center;align-items:center;min-height:100vh}.c{background:var(--cb);padding:35px 25px;border-radius:16px;box-shadow:0 8px 32px rgba(0,0,0,0.06);width:90%;max-width:350px;border:1px solid var(--cd);text-align:center;backdrop-filter:blur(16px) saturate(150%);-webkit-backdrop-filter:blur(16px) saturate(150%)}input,button{width:100%;padding:14px;margin:10px 0;box-sizing:border-box;border-radius:12px;border:1px solid var(--cd);background:rgba(0,0,0,0.03);color:inherit;outline:none;font-size:15px;transition:0.3s}input:focus{border-color:#3b82f6;background:rgba(0,0,0,0.05)}button{background:#3b82f6;color:#fff;border:none;cursor:pointer;font-weight:bold;margin-top:15px}button:hover{background:#2563eb;transform:translateY(-2px)}</style></head><body>' + getBgLayer(cfg) + '<div class="c"><h2 style="margin-top:0;font-size:22px">🔐 管理员验证</h2><p style="color:gray;font-size:13px;margin-bottom:20px">需要鉴权以访问核心控制面板</p><form action="/login" method="post"><input name="username" placeholder="账号" required><input type="password" name="password" placeholder="密码" required><button type="submit">登 录</button></form></div></body></html>';
}

function rR(m, u, cfg) {
  return '<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><meta http-equiv="refresh" content="1.5;url=' + u + '"><style>:root{--bgc:#ffffff;--tx:#1e293b;--cb:rgba(255,255,255,0.65);--cd:rgba(0,0,0,0.08)}body{font-family:-apple-system,sans-serif;background-color:var(--bgc);color:var(--tx);margin:0;display:flex;justify-content:center;align-items:center;min-height:100vh}.c{background:var(--cb);padding:30px 40px;border-radius:16px;box-shadow:0 8px 32px rgba(0,0,0,0.06);border:1px solid var(--cd);text-align:center;backdrop-filter:blur(16px) saturate(150%);-webkit-backdrop-filter:blur(16px) saturate(150%)}</style></head><body>' + getBgLayer(cfg) + '<div class="c"><h2 style="margin:0">' + m + '</h2><p style="color:gray;font-size:14px;margin:15px 0 0">页面即将自动跳转...</p></div></body></html>';
}

function rSP(f, o, p, cfg) {
  const ext = f.name.split('.').pop().toLowerCase(), sp = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'svg', 'ico'].includes(ext), s = escapeHTML(f.name), w = p ? '&pwd=' + encodeURIComponent(p) : '';
  return '<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>' + s + '</title><style>:root{--bgc:#ffffff;--tx:#1e293b;--cb:rgba(255,255,255,0.65);--cd:rgba(0,0,0,0.08)}body{font-family:-apple-system,sans-serif;background-color:var(--bgc);color:var(--tx);margin:0;display:flex;justify-content:center;align-items:center;min-height:100vh}.c{background:var(--cb);padding:30px;border-radius:16px;box-shadow:0 8px 32px rgba(0,0,0,0.06);border:1px solid var(--cd);text-align:center;max-width:400px;width:90%;backdrop-filter:blur(16px) saturate(150%);-webkit-backdrop-filter:blur(16px) saturate(150%)}img{max-width:100%;border-radius:12px;box-shadow:0 4px 15px rgba(0,0,0,0.1)}.btn{display:inline-block;padding:12px 24px;background:#3b82f6;color:#fff;text-decoration:none;border-radius:10px;margin-top:20px;font-weight:bold;transition:0.3s}.btn:hover{transform:scale(1.05);background:#2563eb;box-shadow:0 8px 20px rgba(59,130,246,0.3)}</style></head><body>' + getBgLayer(cfg) + '<div class="c">' + (sp ? '<img src="' + o + '/file/' + f.id + (w ? '?' + w.slice(1) : '') + '">' : '<h1 style="font-size:60px;margin:0;">📄</h1>') + '<h3>' + s + '</h3><p style="color:gray;font-size:14px;">' + (f.size / 1048576).toFixed(2) + ' MB</p><a href="' + o + '/file/' + f.id + '?dl=1' + w + '" class="btn">📥 立即下载</a></div></body></html>';
}

const SPA_HTML = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=1.0,user-scalable=no"><title>糖糖云盘</title><style>html{scrollbar-gutter:stable;overflow-y:scroll}:root{--primary:#3b82f6;--ph:#2563eb;--bgc:#ffffff;--tx:#1e293b;--cb:rgba(255,255,255,0.65);--cd:rgba(0,0,0,0.08);--tb:rgba(59,130,246,0.15);--sp:cubic-bezier(0.2,0.8,0.2,1)}*{-webkit-tap-highlight-color:transparent;box-sizing:border-box}body{font-family:-apple-system,sans-serif;background-color:var(--bgc);color:var(--tx);margin:0;padding:15px 10px;display:flex;flex-direction:column;min-height:100vh;overflow-x:hidden}.bg-layer{content:"";position:fixed;top:-5%;left:-5%;width:110vw;height:calc(var(--app-height, 100vh) * 1.1);pointer-events:none;z-index:-3;background-image:var(--user-bg-url);background-size:cover;background-position:center;filter:blur(20px) brightness(1.05) saturate(110%);opacity:var(--bg-op, 0);transition:opacity 0.4s ease}button,input,.card,.folder-card,.file-card,.modal-content,.nav-tab,.upload-box{transition:all .3s var(--sp);will-change:transform}.container{max-width:900px;width:100%;margin:0 auto;position:relative;z-index:1}body.modal-open .container{pointer-events:none}.card,.folder-card,.file-card,.modal-content{background:var(--cb);padding:16px;border-radius:16px;box-shadow:0 4px 16px rgba(0,0,0,.04),inset 0 1px 1px rgba(255,255,255,.2);border:1px solid var(--cd);margin-bottom:14px;backdrop-filter:blur(16px) saturate(150%);-webkit-backdrop-filter:blur(16px) saturate(150%)}.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;border-bottom:1px solid var(--cd);padding-bottom:10px;flex-wrap:wrap;gap:5px}.nav-tabs{display:flex;position:relative;background:rgba(0,0,0,.04);padding:4px;border-radius:12px;overflow-x:auto;white-space:nowrap;z-index:1;backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px)}.nav-indicator{position:absolute;top:4px;bottom:4px;left:0;background:var(--primary);border-radius:10px;transition:transform .4s var(--sp),width .4s var(--sp);z-index:-1;box-shadow:0 4px 15px rgba(59,130,246,.35)}.nav-tab{padding:8px 16px;border-radius:10px;color:var(--tx);font-weight:700;cursor:pointer;background:0 0;border:none;font-size:13px}.nav-tab.active{color:#fff}.btn{display:inline-flex;align-items:center;justify-content:center;gap:4px;background:var(--primary);color:#fff!important;padding:10px 16px;border:none;border-radius:10px;cursor:pointer;font-size:13px;font-weight:700}.btn:hover{background:var(--ph);transform:translateY(-2px) scale(1.02);box-shadow:0 6px 20px rgba(59,130,246,.3)}.btn:active{transform:scale(.96)}.btn-sm{padding:6px 12px;font-size:12px}.btn-outline{background:0 0;color:var(--tx)!important;border:1px solid var(--cd);box-shadow:0 2px 8px rgba(0,0,0,.02)}.btn-outline:hover{background:rgba(0,0,0,.05)}.btn-danger{background:#ef4444}.btn-danger:hover{background:#dc2626}.btn-warn{background:#f59e0b}.btn-warn:hover{background:#d97706}.btn-success{background:#10b981}.btn-success:hover{background:#059669}input,select{padding:12px;border:1px solid var(--cd);border-radius:10px;background:rgba(0,0,0,.03);color:var(--tx);font-size:14px;width:100%;outline:0;margin-bottom:5px;}input:focus{border-color:var(--primary);box-shadow:0 0 0 3px rgba(59,130,246,.2)}.grid-view{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:14px}.folder-card,.file-card{cursor:pointer;margin-bottom:0;display:flex;flex-direction:column;justify-content:space-between}.folder-card:hover,.file-card:hover{transform:translateY(-4px) scale(1.03);border-color:var(--primary);box-shadow:0 12px 30px rgba(59,130,246,.15)}.file-preview{height:90px;display:flex;align-items:center;justify-content:center;font-size:45px;margin-bottom:12px;border-radius:10px;background:rgba(0,0,0,.03);overflow:hidden}.file-preview img{width:100%;height:100%;object-fit:cover}.file-name{font-weight:700;font-size:13px;margin-bottom:6px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.file-meta{color:gray;font-size:11px}.progress-container{width:100%;background:rgba(0,0,0,.05);border-radius:10px;height:12px;margin-top:8px;overflow:hidden;border:1px inset var(--cd)}.progress-bar{height:100%;background:linear-gradient(90deg,var(--primary),#60a5fa);border-radius:10px;transition:width .2s}.upload-box{border:2px dashed var(--cd);padding:30px 10px;text-align:center;border-radius:14px;background:rgba(0,0,0,.02);cursor:pointer;position:relative;backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px)}.upload-box:hover{border-color:var(--primary);background:var(--tb);transform:scale(1.01)}.upload-box input[type="file"]{position:absolute;top:0;left:0;width:100%;height:100%;opacity:0;cursor:pointer}.modal-overlay{position:fixed;inset:0;background:rgba(255,255,255,.2);backdrop-filter:blur(16px) brightness(1.15) saturate(120%);-webkit-backdrop-filter:blur(16px) brightness(1.15) saturate(120%);display:flex;align-items:center;justify-content:center;z-index:1000}.modal-content{position:relative;width:90%;max-width:400px;max-height:85vh;overflow-y:auto;display:flex;flex-direction:column;gap:12px;box-shadow:0 20px 50px rgba(0,0,0,.15);margin:0;scrollbar-gutter:stable}.flex-row{display:flex;gap:10px;align-items:center;width:100%}.flex-1{flex:1;text-align:center;justify-content:center}@keyframes spin{100%{transform:rotate(360deg)}}@keyframes dash{0%{stroke-dasharray:1,150;stroke-dashoffset:0}50%{stroke-dasharray:90,150;stroke-dashoffset:-35}100%{stroke-dasharray:90,150;stroke-dashoffset:-124}}@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.5}}::-webkit-scrollbar{width:6px;height:6px}::-webkit-scrollbar-thumb{background:var(--cd);border-radius:10px}::-webkit-scrollbar-track{background:0 0}</style></head><body><div class="bg-layer"></div><div class="container"><div class="header"><h2 style="margin:0;font-size:19px;display:flex;align-items:center;gap:5px">🍬 <span>糖糖云盘</span></h2><div class="nav-tabs" id="main-nav" style="display:none"><div class="nav-indicator" id="ind-main"></div><button class="nav-tab active" id="tab-resource" onclick="app.switchView('resource')">🗂️ 资源</button><button class="nav-tab" id="tab-image" onclick="app.switchView('image')">🖼️ 图床</button></div><div><span id="auth-btn"></span></div></div><div class="card" id="storage-card" style="display:none;padding:16px 20px;border-left:5px solid var(--primary)"><div style="display:flex;justify-content:space-between;font-size:13px;margin-bottom:8px"><span style="font-weight:700">💽 存储空间概览</span><span id="storage-text" style="font-weight:700;color:var(--primary)">0 MB / 10 GB (0%)</span></div><div class="progress-container" style="height:12px"><div id="storage-bar" class="progress-bar" style="width:0%"></div></div></div><div class="card" id="admin-panel" style="display:none;border-top:4px solid var(--primary)"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:15px;flex-wrap:wrap;gap:5px"><h3 style="margin:0;font-size:15px">🚀 高速入库核心</h3><div class="nav-tabs" id="up-nav"><div class="nav-indicator" id="ind-up"></div><button id="mode-local" class="nav-tab active" onclick="app.switchUploadMode('local')">直传</button><button id="mode-cli" class="nav-tab" onclick="app.switchUploadMode('cli')">终端CLI</button><button id="mode-settings" class="nav-tab" onclick="app.switchUploadMode('settings')">⚙️ 设置</button></div></div><div id="form-local" style="display:flex;flex-direction:column;gap:12px"><div class="flex-row"><input type="text" id="up-folder" placeholder="输入目录 (默认根目录)" style="flex:1"></div><div class="flex-row" style="flex-wrap:wrap"><button class="btn btn-sm btn-success flex-1" style="white-space:nowrap;border:none" onclick="app.adminAct('sync_b2_to_d1',null,null)">🔄 同步D1</button><button class="btn btn-sm btn-outline flex-1" style="white-space:nowrap" onclick="app.showSessionsModal()">🧹 碎片</button><button class="btn btn-sm btn-warn flex-1" style="white-space:nowrap;border:none" onclick="app.adminAct('sync_d1_ghosts',null,null)">🗑️ 清死链</button><button class="btn btn-sm btn-danger flex-1" style="white-space:nowrap;border:none" onclick="app.adminAct('sync_b2_orphans',null,null)">💣 删游离</button></div><div class="upload-box" id="drop-zone" ondragover="event.preventDefault();this.style.borderColor='var(--primary)'" ondragleave="event.preventDefault();this.style.borderColor=''" ondrop="event.preventDefault();this.style.borderColor='';app.enqueueFiles(event.dataTransfer.items,true)"><input type="file" id="up-file" multiple onchange="app.enqueueFiles(this.files,false)"><div id="file-name-display" style="color:var(--primary);font-weight:700;font-size:15px">➕ 点击选择多文件，或直接拖拽文件夹到此处</div></div><div id="queue-info" style="font-size:12px;color:gray;text-align:center">完美支持多文件、多级文件夹拖拽识别并发</div><button id="uploadBtn" class="btn" onclick="app.startUploadQueue()" style="width:100%;font-size:16px;padding:14px">⚡ 发起多线程疾速并发上传</button><div id="uploadProgress" style="display:none;width:100%;padding:16px;background:rgba(0,0,0,.03);border-radius:12px;border:1px inset var(--cd)"><div style="display:flex;justify-content:space-between;font-size:13px;margin-bottom:8px"><span id="uploadStatus" style="color:var(--primary);font-weight:700">上传队列处理中...</span><span id="uploadPercent" style="font-weight:700">0/0</span></div><div class="progress-container" style="height:14px"><div id="uploadProgressBar" class="progress-bar" style="width:0%"></div></div><div style="display:flex;justify-content:flex-end;margin-top:14px;align-items:center"><button type="button" id="cancelUploadBtn" class="btn btn-sm btn-danger" onclick="app.cancelQueue()">🗑️ 取消全部队列</button></div><div id="queueList" style="margin-top:15px;max-height:220px;overflow-y:auto;display:flex;flex-direction:column;gap:8px;padding-right:5px"></div></div></div><div id="form-cli" style="display:none;flex-direction:column;gap:12px;background:rgba(0,0,0,.03);padding:16px;border-radius:12px"><h3 style="margin:0 0 5px;font-size:15px">💻 终端 CLI 交互</h3><p style="font-size:12px;color:gray;margin:0;line-height:1.5">将文件直接推送到 B2 存储桶，速度极快且无超时限制。上传完成后，请回到 <b style="color:var(--primary)">直传</b> 面板点击【同步D1】将其归档入库。</p><div style="background:#1e293b;color:#a5b4fc;padding:12px;border-radius:10px;font-family:monospace;font-size:12px;overflow-x:auto;line-height:1.6;white-space:nowrap"><div style="color:#60a5fa"># AWS CLI 方式 (需先配置对应桶权限)</div><span class="d-b64" data-b="YXdzIHMzIGNw"></span> ./your_file s3://<span id="cli-bk1">tangyani-ziyuan</span>/ --endpoint-url https://s3.us-east-005.backblazeb2.com<br><br><div style="color:#60a5fa"># Rclone 方式</div><span class="d-b64" data-b="cmNsb25lIGNvcHk="></span> ./your_file b2_remote:<span id="cli-bk2">tangyani-ziyuan</span>/</div><div style="margin-top:5px;display:flex;gap:10px;align-items:center"><input type="text" id="cli-temp-name" placeholder="或输入文件名生成一键临时预签名命令..." style="flex:1;margin:0;font-size:12px"><button class="btn btn-success btn-sm" onclick="app.generateCliUpload()" style="white-space:nowrap">获取 <span class="d-b64" data-b="Q3VybA=="></span> 上传</button></div></div><div id="form-settings" style="display:none;flex-direction:column;gap:12px;background:rgba(0,0,0,.03);padding:16px;border-radius:12px"><h3 style="margin:0 0 5px;font-size:15px">⚙️ 进阶配置</h3><label style="font-size:13px;display:flex;align-items:center;gap:8px;font-weight:bold;">💻 PC 横屏壁纸</label><input type="url" id="cfg-bgPc" placeholder="输入图片直链 (留空恢复默认)" style="margin:0;margin-bottom:8px;"><label style="font-size:13px;display:flex;align-items:center;gap:8px;font-weight:bold;">📱 手机竖屏壁纸</label><input type="url" id="cfg-bgMobile" placeholder="输入图片直链 (留空恢复默认)" style="margin:0;margin-bottom:12px;"><label style="font-size:13px;display:flex;align-items:center;gap:8px;cursor:pointer"><input type="checkbox" id="cfg-expect" style="width:auto;margin:0"> 终端 CLI 附加 Expect: 100-continue 头</label><p style="font-size:11px;color:gray;margin:0 0 10px 24px">某些防火墙或网关遇到此头会报 417 错误，取消勾选即可跳过此协议握手。</p><label style="font-size:13px;display:flex;align-items:center;gap:8px;cursor:pointer"><input type="checkbox" id="cfg-sha256" style="width:auto;margin:0"> 启用强哈希运算防断流 (前端)</label><p style="font-size:11px;color:gray;margin:0 0 10px 24px">在前端计算 SHA256 确保完整性。注意：此功能极度耗费手机/低端机 CPU 甚至可能导致崩溃，请谨慎开启。</p><button id="save-cfg-btn" class="btn btn-success" style="width:100%;font-size:15px;padding:12px;" onclick="app.saveSettingsFromUI()">💾 保存并同步云端配置</button></div></div><div class="card" style="display:flex;gap:12px;flex-wrap:wrap;align-items:center"><button class="btn btn-sm btn-outline" onclick="app.goHome()" id="btn-back" style="display:none">&larr; 返回</button><span id="breadcrumb" style="font-weight:700;font-size:16px;flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">📁 根目录</span><input type="text" id="search-input" placeholder="🔍 搜索..." oninput="app.debounceSearch()" style="width:140px;padding:10px 12px;margin:0;border-radius:10px"></div><div id="dynamic-area" style="min-height:200px"></div></div><script>
const app={state:{view:'resource',folder:null,q:'',isAdmin:false,currentPwd:'',fileList:[]},configLoaded:false,
settings:{expect:localStorage.getItem('cfg_expect')==='true',sha256:localStorage.getItem('cfg_sha256')==='true',bgPc:(window.__CFG__&&window.__CFG__.bgPc)||localStorage.getItem('cfg_bgPc')||'',bgMobile:(window.__CFG__&&window.__CFG__.bgMobile)||localStorage.getItem('cfg_bgMobile')||''},
lastWidth:window.innerWidth,
updateAppHeight(){document.documentElement.style.setProperty('--app-height',window.innerHeight+'px');},
escapeHTML(s){return String(s).replace(/[&<>'"]/g,t=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[t]||t));},
updInd(i,el){const d=document.getElementById(i);if(d&&el){d.style.width=el.offsetWidth+'px';d.style.transform='translateX('+el.offsetLeft+'px)';}},
async init(){document.querySelectorAll('.d-b64').forEach(e=>e.innerText=atob(e.dataset.b));this.refreshSettingsUI();this.updateAppHeight();this.applyBg();window.addEventListener('hashchange',()=>this.parseHash());this.parseHash();window.addEventListener('beforeunload',e=>{if(this.isUploading){e.preventDefault();e.returnValue='上传中';}});window.addEventListener('popstate',e=>{document.querySelectorAll('.modal-overlay').forEach(m=>app.closeModal(m.id,1));});window.addEventListener('resize',()=>{const cw=window.innerWidth;if(cw<=768&&cw===this.lastWidth)return;this.lastWidth=cw;this.updateAppHeight();this.updInd('ind-main',document.querySelector('#main-nav .active'));this.updInd('ind-up',document.querySelector('#up-nav .active'));this.applyBg();});},
refreshSettingsUI(){if(document.getElementById('cfg-expect')){document.getElementById('cfg-expect').checked=this.settings.expect;document.getElementById('cfg-sha256').checked=this.settings.sha256;document.getElementById('cfg-bgPc').value=this.settings.bgPc;document.getElementById('cfg-bgMobile').value=this.settings.bgMobile;}},
applyBg(){const isM=window.innerWidth<=768;const u=isM?this.settings.bgMobile:this.settings.bgPc;if(u){document.documentElement.style.setProperty('--user-bg-url','url('+u+')');document.documentElement.style.setProperty('--bg-op','1');}else{document.documentElement.style.removeProperty('--user-bg-url');document.documentElement.style.setProperty('--bg-op','0');}},
async loadCloudConfig(){try{const r=await fetch('/api/admin/config');const d=await r.json();if(d&&Object.keys(d).length>0){this.settings={...this.settings,...d};localStorage.setItem('cfg_expect',this.settings.expect);localStorage.setItem('cfg_sha256',this.settings.sha256);localStorage.setItem('cfg_bgPc',this.settings.bgPc||'');localStorage.setItem('cfg_bgMobile',this.settings.bgMobile||'');this.applyBg();this.refreshSettingsUI();}}catch(e){}},
async saveConfigToCloud(){localStorage.setItem('cfg_expect',this.settings.expect);localStorage.setItem('cfg_sha256',this.settings.sha256);localStorage.setItem('cfg_bgPc',this.settings.bgPc);localStorage.setItem('cfg_bgMobile',this.settings.bgMobile);this.applyBg();this.refreshSettingsUI();try{const b=document.getElementById('save-cfg-btn');if(b)b.innerText='正在同步至云端...';await fetch('/api/admin/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(this.settings)});if(b)b.innerText='💾 保存并同步云端配置';this.toast('☁️ 云端同步成功');}catch(e){this.toast('❌ 云端同步失败');}},
saveSettingsFromUI(){this.settings.expect=document.getElementById('cfg-expect').checked;this.settings.sha256=document.getElementById('cfg-sha256').checked;this.settings.bgPc=document.getElementById('cfg-bgPc').value.trim();this.settings.bgMobile=document.getElementById('cfg-bgMobile').value.trim();this.saveConfigToCloud();},
setWallpaper(id,type){const url=window.location.origin+'/file/'+id;if(type==='pc')this.settings.bgPc=url;else this.settings.bgMobile=url;this.saveConfigToCloud();this.closeModal('fM');this.toast(type==='pc'?'✅ 已设为 PC 横屏壁纸':'✅ 已设为手机竖屏壁纸');},
parseHash(){const h=window.location.hash.slice(1),p=new URLSearchParams(h);this.state.view=p.get('view')||'resource';this.state.folder=p.get('folder')||null;this.state.q=p.get('q')||'';document.getElementById('search-input').value=this.state.q;document.querySelectorAll('#main-nav .nav-tab').forEach(b=>b.classList.toggle('active',b.id==='tab-'+this.state.view));this.updInd('ind-main',document.getElementById('tab-'+this.state.view));this.fetchData();},
setHash(){let h='view='+this.state.view;if(this.state.folder)h+='&folder='+encodeURIComponent(this.state.folder);if(this.state.q)h+='&q='+encodeURIComponent(this.state.q);window.location.hash=h;},
switchView(v){this.state.view=v;this.state.folder=null;this.state.q='';this.state.currentPwd='';document.querySelectorAll('#main-nav .nav-tab').forEach(b=>b.classList.toggle('active',b.id==='tab-'+v));this.updInd('ind-main',document.getElementById('tab-'+v));if(document.getElementById('mode-cli').classList.contains('active'))this.switchUploadMode('cli');this.setHash();},
goHome(){this.state.folder=null;this.state.currentPwd='';this.setHash();},
goToFolder(f,l){if(!this.state.isAdmin&&l){const p=prompt('🔒 加密目录密码：');if(!p)return;fetch('/api/unlock',{method:'POST',body:JSON.stringify({folder:f,password:p})}).then(r=>r.json()).then(rs=>{if(rs.ok){this.state.folder=f;this.state.currentPwd=p;this.setHash();}else alert(rs.error);});return;}this.state.folder=f;this.state.currentPwd='';this.setHash();},
debounceSearch(){clearTimeout(this.st);this.st=setTimeout(()=>{this.state.q=document.getElementById('search-input').value.trim();this.setHash();},400);},
async fetchData(){const a=document.getElementById('dynamic-area');a.innerHTML='<div style="display:flex;flex-direction:column;align-items:center;padding:60px 0;color:var(--primary);"><svg width="48" height="48" viewBox="0 0 50 50" style="animation:spin 2s linear infinite;"><circle cx="25" cy="25" r="20" fill="none" stroke="var(--cd)" stroke-width="4"></circle><circle cx="25" cy="25" r="20" fill="none" stroke="var(--primary)" stroke-width="4" stroke-linecap="round" stroke-dasharray="90 150" style="animation:dash 1.5s ease-in-out infinite;"></circle></svg><div style="margin-top:15px;font-size:13px;font-weight:bold;letter-spacing:1px;animation:pulse 1.5s ease-in-out infinite;">核心引擎跃迁中...</div></div>';try{let u='/api/data?view='+this.state.view;if(this.state.folder)u+='&folder='+encodeURIComponent(this.state.folder);if(this.state.q)u+='&q='+encodeURIComponent(this.state.q);const r=await fetch(u);if(r.status===401){alert('权限验证失败，或管理员状态已失效');this.goHome();return;}const rs=await r.json();this.state.isAdmin=rs.isAdmin;document.getElementById('auth-btn').innerHTML=rs.isAdmin?'<a href="/logout" class="btn btn-sm btn-outline">退出</a>':'<a href="/login" class="btn btn-sm btn-outline">管理登录</a>';document.getElementById('main-nav').style.display=rs.isAdmin?'flex':'none';document.getElementById('admin-panel').style.display=rs.isAdmin?'block':'none';document.getElementById('btn-back').style.display=this.state.folder?'inline-flex':'none';document.getElementById('breadcrumb').innerText=this.state.folder?'📂 '+this.escapeHTML(this.state.folder):'📁 根目录';if(rs.isAdmin){document.getElementById('storage-card').style.display='block';const p=rs.maxSize>0?Math.min((rs.totalSize/rs.maxSize)*100,100).toFixed(1):0;document.getElementById('storage-text').innerText=this.formatBytes(rs.totalSize)+' / '+this.formatBytes(rs.maxSize)+' ('+p+'%)';const sb=document.getElementById('storage-bar');sb.style.width=p+'%';sb.style.background=p>90?'#ef4444':p>75?'#f59e0b':'';setTimeout(()=>{this.updInd('ind-main',document.querySelector('#main-nav .active'));this.updInd('ind-up',document.querySelector('#up-nav .active'));},50);if(!this.configLoaded){this.configLoaded=true;this.loadCloudConfig();}}else document.getElementById('storage-card').style.display='none';this.state.fileList=rs.data||[];const renderDom=()=>{if(rs.mode==='folders')this.renderFolders(rs.data);else this.renderFiles(rs.data);};if(document.startViewTransition)document.startViewTransition(()=>renderDom());else renderDom();}catch(e){}},
renderFolders(arr){const a=document.getElementById('dynamic-area');if(!arr.length)return a.innerHTML='<p style="text-align:center;color:gray;margin-top:40px">空空如也~</p>';let h='<div class="grid-view">';arr.forEach(f=>{const sn=this.escapeHTML(f.name);h+='<div class="folder-card" data-f="'+sn+'" data-l="'+f.locked+'" onclick="app.goToFolder(this.dataset.f,this.dataset.l===\\'true\\'||this.dataset.l===\\'1\\')"><div><div style="font-size:45px;margin-bottom:10px">'+(f.locked?'🗃️':'📁')+'</div><div style="font-weight:bold;font-size:14px;word-break:break-all;line-height:1.3">'+sn+'</div></div><div><div style="color:gray;font-size:11px;margin-top:8px">'+f.count+' 项 | '+this.formatBytes(f.size)+'</div>';if(this.state.isAdmin)h+='<div style="margin-top:12px"><button class="btn btn-sm btn-outline" style="width:100%" data-f="'+sn+'" onclick="event.stopPropagation();app.adminFolder(this.dataset.f)">🔐 权限</button></div>';h+='</div></div>';});a.innerHTML=h+'</div>';},
toast(m){const t=document.createElement('div');t.innerText=m;t.style.cssText='position:fixed;top:30px;left:50%;transform:translate(-50%,-20px);background:rgba(30,41,59,0.85);color:#fff;padding:12px 24px;border-radius:30px;font-size:14px;z-index:10000;box-shadow:0 10px 30px rgba(0,0,0,0.2);transition:all 0.4s;opacity:0;pointer-events:none;border:1px solid rgba(255,255,255,0.1);font-weight:bold';document.body.appendChild(t);t.offsetHeight;t.style.opacity='1';t.style.transform='translate(-50%,0)';setTimeout(()=>{t.style.opacity='0';t.style.transform='translate(-50%,-20px)';setTimeout(()=>t.remove(),400);},2500);},
copyText(txt){if(navigator.clipboard&&window.isSecureContext)navigator.clipboard.writeText(txt).then(()=>this.toast('✅ 复制成功！')).catch(()=>prompt('手动复制:',txt));else{const ta=document.createElement('textarea');ta.value=txt;ta.style.position='fixed';ta.style.opacity='0';document.body.appendChild(ta);ta.select();try{document.execCommand('copy');this.toast('✅ 复制成功！');}catch(e){prompt('手动复制:',txt);}document.body.removeChild(ta);}},
copyImgLink(id){this.copyText(window.location.origin+'/file/'+id);},copyImgMd(id,n){this.copyText('!['+n+']('+window.location.origin+'/file/'+id+')');},
renderFiles(arr){const a=document.getElementById('dynamic-area');if(!arr.length)return a.innerHTML='<p style="text-align:center;color:gray;margin-top:40px">暂无文件~</p>';let h='<div class="grid-view">';arr.forEach(f=>{const sn=this.escapeHTML(f.name),ext=f.name.split('.').pop().toLowerCase(),sp=(this.state.view==='image'||['jpg','jpeg','png','gif','webp','bmp','svg','ico'].includes(ext)),ph=sp?'<img src="/file/'+f.id+'" loading="lazy">':'📄',hb=f.is_hidden?'<div style="position:absolute;top:6px;right:6px;font-size:10px;background:rgba(239,68,68,0.8);color:#fff;padding:2px 6px;border-radius:6px;font-weight:bold;box-shadow:0 2px 5px rgba(0,0,0,0.2)">隐藏</div>':'';h+='<div class="file-card" data-id="'+f.id+'" onclick="app.showFileAction(this.dataset.id)" '+(f.is_hidden?'style="opacity:0.6"':'')+'>'+hb+'<div><div class="file-preview">'+ph+'</div><div class="file-name" title="'+sn+'">'+sn+'</div></div><div class="file-meta">'+this.formatBytes(f.size)+'</div></div>';});h+='</div>';a.innerHTML=h;},
showFileAction(id){const f=this.state.fileList.find(x=>x.id===id);if(!f)return;history.pushState({mdl:id},'');const sn=this.escapeHTML(f.name),ext=f.name.split('.').pop().toLowerCase(),iv=this.state.view==='image',sp=(iv||['jpg','jpeg','png','gif','webp','bmp','svg','ico'].includes(ext)),pr=sp?'<img src="/file/'+f.id+'" style="width:120px;height:120px;object-fit:cover;border-radius:14px;margin:0 auto;display:block;box-shadow:0 8px 20px rgba(0,0,0,0.15);border:1px solid var(--cd)">':'<div style="font-size:70px;text-align:center;margin:10px 0;text-shadow:0 4px 10px rgba(0,0,0,0.1)">📄</div>',pq=this.state.currentPwd?'&pwd='+encodeURIComponent(this.state.currentPwd):'',ps=this.state.currentPwd?'?pwd='+encodeURIComponent(this.state.currentPwd):'';let b='';if(iv){b+='<div id="primary-actions" class="flex-row" style="flex-wrap:wrap;width:100%"><button class="btn btn-outline flex-1" style="padding:12px" data-id="'+f.id+'" onclick="app.copyImgLink(this.dataset.id);app.closeModal(\\'fM\\')">🔗 复制直链</button><button class="btn btn-outline flex-1" style="padding:12px" data-id="'+f.id+'" data-n="'+sn+'" onclick="app.copyImgMd(this.dataset.id,this.dataset.n);app.closeModal(\\'fM\\')">📝 Markdown</button><a href="/file/'+f.id+'?dl=1'+pq+'" class="btn flex-1" target="_blank" style="text-decoration:none;padding:12px;font-size:14px;box-shadow:0 8px 20px rgba(59,130,246,0.3)" onclick="app.closeModal(\\'fM\\')">📥 下载</a><button class="btn flex-1" style="padding:12px;background:#10b981" onclick="document.getElementById(\\'primary-actions\\').style.display=\\'none\\';document.getElementById(\\'bg-options\\').style.display=\\'flex\\'">🖼️ 设为壁纸</button></div><div id="bg-options" class="flex-row" style="display:none;flex-wrap:wrap;width:100%"><button class="btn btn-success flex-1" style="padding:12px" data-id="'+f.id+'" onclick="app.setWallpaper(this.dataset.id,\\'pc\\')">💻 设为 PC 横屏</button><button class="btn btn-success flex-1" style="padding:12px" data-id="'+f.id+'" onclick="app.setWallpaper(this.dataset.id,\\'mobile\\')">📱 设为手机竖屏</button><button class="btn btn-outline flex-1" style="padding:12px" onclick="document.getElementById(\\'bg-options\\').style.display=\\'none\\';document.getElementById(\\'primary-actions\\').style.display=\\'flex\\'">取消</button></div>';}else{b+='<a href="/file/'+f.id+'?dl=1'+pq+'" class="btn flex-1" target="_blank" style="text-decoration:none;padding:12px;font-size:14px;box-shadow:0 8px 20px rgba(59,130,246,0.3)" onclick="app.closeModal(\\'fM\\')">📥 下载</a><a href="/share/'+f.id+ps+'" class="btn btn-outline flex-1" target="_blank" style="text-decoration:none;padding:12px;font-size:14px" onclick="app.closeModal(\\'fM\\')">📤 分享</a>';}let wgCmd='',cuCmd='';if(this.state.isAdmin){const dlUrl=window.location.origin+'/file/'+f.id+'?dl=1'+pq;wgCmd=atob('d2dldCAtTyAi')+f.name+atob('IiAi')+dlUrl+atob('Ig==');cuCmd=atob('Y3VybCAtTCAtbyAi')+f.name+atob('IiAi')+dlUrl+atob('Ig==');b+='<div style="width:100%;height:1px;background:var(--cd);margin:10px 0;opacity:0.5"></div><div class="flex-row" style="flex-wrap:wrap;justify-content:center"><button id="cmd_wg_btn" class="btn btn-outline btn-sm flex-1">📋 复制 '+atob('V2dldA==')+' 下载</button><button id="cmd_cu_btn" class="btn btn-outline btn-sm flex-1">📋 复制 '+atob('Q3VybA==')+' 下载</button></div><div style="width:100%;height:1px;background:var(--cd);margin:10px 0;opacity:0.5"></div><div class="flex-row" style="flex-wrap:wrap;justify-content:center"><button class="btn btn-outline btn-sm flex-1" data-id="'+f.id+'" data-n="'+sn+'" onclick="app.adminAct(\\'rename\\',this.dataset.id,this.dataset.n);app.closeModal(\\'fM\\')">✏️ 重命名</button><button class="btn btn-outline btn-sm flex-1" data-id="'+f.id+'" data-fd="'+this.escapeHTML(f.folder||'')+'" onclick="app.adminAct(\\'move\\',this.dataset.id,this.dataset.fd);app.closeModal(\\'fM\\')">✂️ 移动</button><button class="btn '+(f.is_hidden?'btn-warn':'btn-outline')+' btn-sm flex-1" data-id="'+f.id+'" onclick="app.adminAct(\\'toggle_hide\\',this.dataset.id);app.closeModal(\\'fM\\')">👁️ 显隐</button><button class="btn btn-danger btn-sm flex-1" data-id="'+f.id+'" onclick="app.adminAct(\\'delete\\',this.dataset.id);app.closeModal(\\'fM\\')">🗑️ 删除</button></div>';}b+='<button class="btn btn-outline" style="width:100%;margin-top:10px;padding:12px;border-radius:12px" onclick="app.closeModal(\\'fM\\')">❌ 关闭面板</button>';const m=document.createElement('div');m.className='modal-overlay';m.id='fM';m.style.opacity='0';m.innerHTML='<div class="modal-content" style="opacity:0;transform:scale(0.95) translateY(15px)">'+pr+'<h3 style="text-align:center;margin:15px 0 5px;word-break:break-all;font-size:16px;line-height:1.4">'+sn+'</h3><p style="text-align:center;color:gray;font-size:12px;margin:0 0 15px">'+this.formatBytes(f.size)+'</p><div style="display:flex;gap:12px;flex-wrap:wrap;justify-content:center">'+b+'</div></div>';document.body.appendChild(m);document.body.classList.add('modal-open');if(this.state.isAdmin){document.getElementById('cmd_wg_btn').onclick=()=>{app.copyText(wgCmd);app.closeModal('fM');};document.getElementById('cmd_cu_btn').onclick=()=>{app.copyText(cuCmd);app.closeModal('fM');};}const mc=m.querySelector('.modal-content');mc.style.willChange='transform, opacity';m.animate([{opacity:0},{opacity:1}],{duration:200,fill:'forwards'});mc.animate([{transform:'scale(0.95) translateY(15px)',opacity:0},{transform:'scale(1) translateY(0)',opacity:1}],{duration:350,easing:'cubic-bezier(0.175,0.885,0.32,1.275)',fill:'forwards'});},
closeModal(id,p){const m=document.getElementById(id);if(m){document.body.classList.remove('modal-open');const mc=m.querySelector('.modal-content');mc.animate([{transform:'scale(1) translateY(0)',opacity:1},{transform:'scale(0.95) translateY(15px)',opacity:0}],{duration:200,easing:'ease-in',fill:'forwards'});const a=m.animate([{opacity:1},{opacity:0}],{duration:200,fill:'forwards'});if(!p)history.back();a.onfinish=()=>m.remove();}},
async adminAct(a,i,p){let rq={action:a,id:i,viewMode:this.state.view};if(a==='delete'&&!confirm('永久删除？'))return;if(a==='rename'){const n=prompt('新名称：',p);if(!n||n===p)return;rq.name=n;}if(a==='move'){const n=prompt('目标目录：',p);if(!n||n===p)return;rq.folder=n;}if(a==='sync_d1_ghosts'&&!confirm('清死链？'))return;if(a==='sync_b2_orphans'&&!confirm('极度危险！会永久删除B2中未记录的文件！确定？'))return;if(a==='sync_b2_to_d1'&&!confirm('将B2中的游离文件同步到D1的[B2直传同步]目录？'))return;try{const r=await fetch('/api/admin/action',{method:'POST',body:JSON.stringify(rq)}),rs=await r.json();if(rs.msg)alert(rs.msg);this.fetchData();}catch(e){alert('操作失败');}},
async adminFolder(f){const p=prompt('目录['+f+']密码(留空清除)：');if(p===null)return;await fetch('/api/admin/action',{method:'POST',body:JSON.stringify({action:'lock_folder',folder:f,password:p})});this.fetchData();},
switchUploadMode(m){document.querySelectorAll('#up-nav .nav-tab').forEach(b=>b.classList.toggle('active',b.id==='mode-'+m));this.updInd('ind-up',document.getElementById('mode-'+m));const fl=document.getElementById('form-local'),fcli=document.getElementById('form-cli'),fset=document.getElementById('form-settings');fl.style.display=m==='local'?'flex':'none';fcli.style.display=m==='cli'?'flex':'none';fset.style.display=m==='settings'?'flex':'none';document.getElementById('uploadProgress').style.display='none';if(m==='cli'){const bn=this.state.view==='image'?'tangyani-tuchuang':'tangyani-ziyuan';document.getElementById('cli-bk1').innerText=bn;document.getElementById('cli-bk2').innerText=bn;}},
async generateCliUpload(){const fn=document.getElementById('cli-temp-name').value.trim();if(!fn)return alert('请输入要上传的文件名');try{const r=await fetch('/api/admin/cli_presign',{method:'POST',body:JSON.stringify({filename:fn,type:this.state.view})}),res=await r.json();if(res.url){const expHeader=this.settings.expect?atob('LUggIkV4cGVjdSIsI')+'':'';this.copyText(atob('Y3VybCAtIyAtWCBQVVQgLUggIkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vb2N0ZXQtc3RyZWFtIiA=')+expHeader+atob('LVQgIg==')+fn+'" "'+res.url+'"');alert('✅ 已生成并复制专属 '+atob('Q3VybA==')+' 命令！');}}catch(e){alert('生成失败');}},
async getFastHash(t){const b=new TextEncoder().encode(t),h=await crypto.subtle.digest('SHA-1',b);return Array.from(new Uint8Array(h)).map(x=>x.toString(16).padStart(2,'0')).join('');},
async getRealSha256(buf){const h=await crypto.subtle.digest('SHA-256',buf);return btoa(String.fromCharCode(...new Uint8Array(h)));},
async fetchWithTimeout(u,o,t=60000){const c=new AbortController(),i=setTimeout(()=>c.abort(),t);if(o.signal){o.signal.addEventListener('abort',()=>c.abort());if(o.signal.aborted)c.abort();}try{return await fetch(u,{...o,signal:c.signal});}catch(e){if(e.name==='AbortError'&&!o.signal?.aborted)throw new Error('Timeout');throw e;}finally{clearTimeout(i);}},
uploadQueue:[],isUploading:false,cancelFlag:false,activeControllers:{},
async enqueueFiles(items,isDrop){if(!items||!items.length)return;let files=[];if(isDrop&&items[0].webkitGetAsEntry){const traverse=async(entry,path)=>{if(entry.isFile){files.push(await new Promise(r=>entry.file(f=>{Object.defineProperty(f,'fullPath',{value:path+f.name});r(f);})));}else if(entry.isDirectory){const reader=entry.createReader(),entries=await new Promise(r=>reader.readEntries(r));for(let e of entries)await traverse(e,path+entry.name+'/');}};for(let i=0;i<items.length;i++){let entry=items[i].webkitGetAsEntry();if(entry)await traverse(entry,'');}}else{files=Array.from(items);}for(let i=0;i<files.length;i++){this.uploadQueue.push({file:files[i],id:'uq_'+Date.now()+'_'+Math.random().toString(36).substr(2,5),status:'pending'});}document.getElementById('file-name-display').innerText='已选中 '+this.uploadQueue.length+' 个文件，准备就绪';document.getElementById('queue-info').innerText='点击下方按钮开始并发上传';document.getElementById('up-file').value='';},
cancelQueue(){if(!confirm('确定取消全部队列？'))return;this.cancelFlag=true;Object.values(this.activeControllers).forEach(c=>{if(c)c.abort();});document.getElementById('uploadStatus').innerText='❌ 已强制中断';document.getElementById('uploadStatus').style.color='#ef4444';setTimeout(()=>{this.uploadQueue=[];document.getElementById('uploadProgress').style.display='none';document.getElementById('uploadBtn').style.display='flex';document.getElementById('file-name-display').innerText='➕ 点击选择多文件，或直接拖拽文件夹到此处';document.getElementById('queue-info').innerText='完美支持多文件、多级文件夹拖拽识别并发';this.fetchData();},2000);},
async startUploadQueue(){if(this.isUploading||this.uploadQueue.length===0)return;this.isUploading=true;this.cancelFlag=false;let total=this.uploadQueue.length,completed=0;document.getElementById('uploadBtn').style.display='none';document.getElementById('uploadProgress').style.display='block';document.getElementById('uploadStatus').innerText='🔥 多线程队列处理中...';document.getElementById('uploadStatus').style.color='var(--primary)';const updateOverall=()=>{document.getElementById('uploadPercent').innerText=completed+' / '+total;document.getElementById('uploadProgressBar').style.width=((completed/total)*100)+'%';};updateOverall();let qHtml='';for(let t of this.uploadQueue){let fName=t.file.fullPath||t.file.name;qHtml+='<div id="'+t.id+'" style="font-size:12px;background:rgba(255,255,255,0.4);padding:8px 12px;border-radius:8px;border:1px solid var(--cd);"><div style="display:flex;justify-content:space-between;margin-bottom:6px;"><span style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex:1;font-weight:bold;" title="'+fName+'">'+this.escapeHTML(fName)+'</span><span class="q-status" style="color:var(--primary);margin-left:10px;white-space:nowrap">排队中</span></div><div class="progress-container" style="height:6px;margin-top:0;"><div class="q-bar progress-bar" style="width:0%"></div></div></div>';}document.getElementById('queueList').innerHTML=qHtml;const concurrentLimit=6;let activePromises=[];const runner=async()=>{while(this.uploadQueue.length>0&&!this.cancelFlag){let task=this.uploadQueue.shift();await this.uploadSingleTask(task);completed++;updateOverall();}};for(let i=0;i<concurrentLimit;i++)activePromises.push(runner());await Promise.all(activePromises);if(!this.cancelFlag){document.getElementById('uploadStatus').innerText='🎉 队列全部完成！';setTimeout(()=>{document.getElementById('uploadProgress').style.display='none';document.getElementById('uploadBtn').style.display='flex';document.getElementById('file-name-display').innerText='➕ 点击选择多文件，或直接拖拽文件夹到此处';document.getElementById('queue-info').innerText='完美支持多文件、多级文件夹拖拽识别并发';this.fetchData();},2000);}this.isUploading=false;},
async uploadSingleTask(task){let f=task.file,baseFolder=document.getElementById('up-folder').value||'',relFolder='';if(f.fullPath){let parts=f.fullPath.split('/');if(parts.length>1){parts.pop();relFolder=parts.join('/');}}let finalFolder=baseFolder?baseFolder+(relFolder?'/'+relFolder:''):relFolder,tp=this.state.view,el=document.getElementById(task.id);if(!el)return;const updateEl=(msg,pct,color)=>{let st=el.querySelector('.q-status');st.innerText=msg;if(color)st.style.color=color;if(pct!==undefined)el.querySelector('.q-bar').style.width=pct+'%';};task.status='uploading';updateEl('预热中...',0);try{let cs=f.size<=52428800?f.size:f.size<=104857600?5242880:f.size<=524288000?10485760:20971520,fHash=await this.getFastHash(f.name+f.size+f.lastModified+cs),ctrl=new AbortController();this.activeControllers[task.id]=ctrl;if(f.size<=52428800){updateEl('极速直传...',0);await new Promise((resolve,reject)=>{const xhr=new XMLHttpRequest();xhr.open('POST','/api/upload/single',true);xhr.setRequestHeader('x-filename',encodeURIComponent(f.name));xhr.setRequestHeader('x-type',tp);xhr.setRequestHeader('x-folder',encodeURIComponent(finalFolder));xhr.setRequestHeader('content-type',f.type||'application/octet-stream');ctrl.signal.addEventListener('abort',()=>xhr.abort());xhr.upload.onprogress=(e)=>{if(e.lengthComputable&&!this.cancelFlag){let pct=Math.min(Math.round((e.loaded/e.total)*99),99);updateEl('直传 '+pct+'%',pct);}};xhr.onload=()=>{if(xhr.status>=200&&xhr.status<300){updateEl('✅ 完成',100,'#10b981');resolve();}else reject(new Error('失败'));};xhr.onerror=()=>reject(new Error('网络中断'));xhr.onabort=()=>reject(new DOMException('AbortError','AbortError'));xhr.send(f);});}else{updateEl('探测分片...',0);const ck=await(await this.fetchWithTimeout('/api/upload/check',{method:'POST',body:JSON.stringify({fileHash:fHash}),signal:ctrl.signal},15000)).json();let ui,bp,up=[];if(ck.exists){ui=ck.session.b2_file_id;bp=ck.session.b2_path;up=JSON.parse(ck.session.uploaded_parts||'[]');updateEl('续传中...',0);}else{const st=await(await this.fetchWithTimeout('/api/upload/start',{method:'POST',body:JSON.stringify({type:tp,filename:f.name,contentType:f.type||'application/octet-stream',fileHash:fHash,folder:finalFolder}),signal:ctrl.signal},15000)).json();ui=st.fileId;bp=st.b2Path;}let tc=Math.ceil(f.size/cs),ed={};up.forEach(p=>ed[p.partNumber]=p.etag);let tpList=[];for(let i=1;i<=tc;i++){if(!ed[i])tpList.push(i);}let pUrls={};if(tpList.length>0){updateEl('通道签名...',0);const bpr=await this.fetchWithTimeout('/api/upload/presign_batch',{method:'POST',body:JSON.stringify({type:tp,uploadId:ui,b2Path:bp,parts:tpList}),signal:ctrl.signal},30000);if(!bpr.ok)throw new Error('签名失败');pUrls=await bpr.json();}let uBytes=up.length*cs;if(uBytes>f.size)uBytes=f.size;let ue=null,pa={};const cw=async(ic)=>{let ct=ic;while(tpList.length>0&&!ue&&!this.cancelFlag){const pn=tpList.shift();if(!pn)break;const c=f.slice((pn-1)*cs,pn*cs);let sha256B64='';if(this.settings.sha256){updateEl('计算哈希...',Math.min(Math.round((uBytes/f.size)*100),99));sha256B64=await this.getRealSha256(await c.arrayBuffer());}let sc=false;pa[pn]=pa[pn]||0;while(!sc&&!ue&&!this.cancelFlag){try{let et;updateEl('灌入['+pn+'/'+tc+']',Math.min(Math.round((uBytes/f.size)*100),99));if(ct==='CF_PROXY'){const hdrs={'x-file-id':ui,'x-file-hash':fHash,'x-part-number':pn,'x-b2-path':encodeURIComponent(bp),'x-type':tp};if(sha256B64)hdrs['x-amz-checksum-sha256']=sha256B64;const r=await this.fetchWithTimeout('/api/upload/part',{method:'POST',headers:hdrs,body:c,signal:ctrl.signal},60000);if(!r.ok)throw new Error(await r.text());et=(await r.json()).etag;}else{const prUrl=pUrls[pn];if(!prUrl)throw new Error('P');const hdrs={'Content-Type':'application/octet-stream'};if(sha256B64)hdrs['x-amz-checksum-sha256']=sha256B64;const r=await this.fetchWithTimeout(prUrl,{method:'PUT',headers:hdrs,body:c,signal:ctrl.signal},60000);if(!r.ok)throw new Error('D');et=r.headers.get('ETag').replace(/"/g,'');fetch('/api/upload/sync_part',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({fileHash:fHash,partNumber:pn,etag:et})}).catch(()=>{});}ed[pn]=et;uBytes+=c.size;sc=true;updateEl('拼装中...',Math.min(Math.round((uBytes/f.size)*100),99));}catch(e){if(this.cancelFlag)break;pa[pn]++;if(pa[pn]>=6){ue=new Error('阻断');break;}ct=ct==='CF_PROXY'?'B2_DIRECT':'CF_PROXY';if(pa[pn]%2===0){tpList.push(pn);break;}await new Promise(r=>setTimeout(r,2000));}}}};let ws=[];for(let i=0;i<8;i++)ws.push(cw(i%3===0?'CF_PROXY':'B2_DIRECT'));await Promise.all(ws);if(ue)throw ue;if(this.cancelFlag)throw new DOMException("AbortError","AbortError");updateEl('合并分片...',99);let ea=[];for(let i=1;i<=tc;i++)ea.push(ed[i]);const fr=await this.fetchWithTimeout('/api/upload/finish',{method:'POST',body:JSON.stringify({type:tp,fileId:ui,etagArray:ea,name:f.name,b2_path:bp,size:f.size,folder:finalFolder,fileHash:fHash}),signal:ctrl.signal},30000);if(!fr.ok)throw new Error('合并失败');updateEl('✅ 完成',100,'#10b981');}}catch(err){if(err.name==='AbortError'||this.cancelFlag)updateEl('❌ 已取消',0,'#ef4444');else updateEl('❌ 失败',0,'#ef4444');}finally{delete this.activeControllers[task.id];}},
showSessionsModal(){history.pushState({mdl:'sM'},'');const m=document.createElement('div');m.className='modal-overlay';m.id='sM';m.style.opacity='0';m.innerHTML='<div class="modal-content" style="opacity:0;transform:scale(0.95) translateY(15px)"><h3 style="margin-top:0;margin-bottom:5px;text-align:center">🧹 碎片管理</h3><div id="sL" style="max-height:45vh;overflow-y:auto;margin-bottom:15px;padding-right:5px">...</div><button class="btn btn-outline" style="width:100%;padding:12px;border-radius:12px" onclick="app.closeModal(\\'sM\\')">❌ 关闭</button></div>';document.body.appendChild(m);document.body.classList.add('modal-open');fetch('/api/upload/sessions').then(r=>r.json()).then(d=>{let h=d.length?'':'<p style="text-align:center;color:gray">干净</p>';d.forEach(s=>{const p=JSON.parse(s.uploaded_parts||'[]');h+='<div style="padding:12px;border:1px solid var(--cd);margin-bottom:10px;border-radius:12px;background:rgba(0,0,0,0.03)"><div style="font-weight:bold;word-break:break-all;font-size:13px">'+this.escapeHTML(s.b2_path.split('_').slice(1).join('_'))+'</div><div style="font-size:12px;color:gray;margin:8px 0">缓冲 '+p.length+' 块</div><button class="btn btn-sm btn-danger" style="width:100%" data-fh="'+s.file_hash+'" data-ui="'+s.b2_file_id+'" data-bp="'+s.b2_path+'" data-bk="'+s.bucket+'" onclick="app.abortSession(this.dataset.fh,this.dataset.ui,this.dataset.bp,this.dataset.bk)">抹除</button></div>';});document.getElementById('sL').innerHTML=h;}).catch(()=>{});const mc=m.querySelector('.modal-content');mc.style.willChange='transform, opacity';m.animate([{opacity:0},{opacity:1}],{duration:200,fill:'forwards'});mc.animate([{transform:'scale(0.95) translateY(15px)',opacity:0},{transform:'scale(1) translateY(0)',opacity:1}],{duration:350,easing:'cubic-bezier(0.175,0.885,0.32,1.275)',fill:'forwards'});},
async abortSession(fh,ui,bp,bk){if(!confirm('抹除？'))return;await fetch('/api/upload/abort',{method:'POST',body:JSON.stringify({fileHash:fh,uploadId:ui,b2Path:bp,bucket:bk})});app.closeModal('sM');setTimeout(()=>this.showSessionsModal(),400);},
formatBytes(b){if(!b)return'0 B';const k=1024,s=['B','KB','MB','GB','TB'],i=Math.floor(Math.log(b)/Math.log(k));return parseFloat((b/Math.pow(k,i)).toFixed(2))+' '+s[i];}
};app.init();
</script></body></html>`;