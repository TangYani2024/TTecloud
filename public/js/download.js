Object.assign(app, {
  currentDlAbort: null,

  async smartDownload(fileId) {
    const f = this.state.fileList.find(x => x.id === fileId);
    if (!f) return;
    const pq = this.state.currentPwd ? '&pwd=' + encodeURIComponent(this.state.currentPwd) : '';
    const dlUrl = window.location.origin + '/file/' + f.id + '?dl=1' + pq;
    const fileSize = Number(f.size) || 0;

    const SIZE_20MB = 20 * 1024 * 1024;
    const SIZE_500MB = 500 * 1024 * 1024;

    const isMobile = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent) ||
                     (navigator.maxTouchPoints > 1 && /Macintosh/i.test(navigator.userAgent));

    // 1. 小于 20MB：无需分片，直接原生下载
    if (fileSize < SIZE_20MB) {
      const a = document.createElement('a');
      a.href = dlUrl;
      a.download = f.name;
      document.body.appendChild(a);
      a.click();
      a.remove();
      this.closeModal('fM');
      return;
    }

    // 2. 20MB ~ 500MB：3 线程并发分片下载至内存 Blob (就地卡片进度条)
    if (fileSize >= SIZE_20MB && fileSize <= SIZE_500MB) {
      return this.startMemoryChunkDownload(f, dlUrl);
    }

    // 3. 大于 500MB：仅在非移动端且具备 File System Access API 时使用流式直写
    if (fileSize > SIZE_500MB) {
      if (!isMobile && typeof window.showSaveFilePicker === 'function') {
        return this.startFileSystemStreamDownload(f, dlUrl);
      } else {
        // 移动端或不支持设备：直接弹出超大文件下载指引弹窗
        return this.showThirdPartyModal(f, dlUrl);
      }
    }
  },

  startMemoryChunkDownload(f, dlUrl) {
    const c = document.getElementById('file-action-container');
    if (!c) return;
    const fileSize = Number(f.size) || 0;
    const fileName = f.name;

    c.innerHTML = 
      '<div style="width:100%;padding:14px;background:rgba(0,0,0,.03);border-radius:12px;border:1px inset var(--cd);text-align:left">' +
        '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">' +
          '<span id="dl-status" style="color:var(--tx);font-weight:700;font-size:13px;display:flex;align-items:center;gap:6px">' +
            '<img class="om-emoji" src="/openmoji/1F4E5.svg" alt="📥"> 3 线程分片准备中...' +
          '</span>' +
          '<span class="dl-stat-badge">3 线程分片</span>' +
        '</div>' +
        '<div class="progress-container" style="height:12px;margin:0 0 6px">' +
          '<div id="dl-bar" class="progress-bar" style="width:0%"></div>' +
        '</div>' +
        '<div style="display:flex;justify-content:space-between;font-size:11px;color:gray">' +
          '<span id="dl-bytes">0 B / ' + this.formatBytes(fileSize) + '</span>' +
          '<span id="dl-speed" style="color:#10b981;font-weight:700">0.0 MB/s</span>' +
          '<span id="dl-pct" style="font-weight:700">0%</span>' +
        '</div>' +
        '<div id="dl-actions" style="display:flex;gap:10px;margin-top:12px">' +
          '<button type="button" class="btn btn-sm btn-soft-danger flex-1" onclick="app.abortCurrentDownload(\'' + f.id + '\')">取消下载</button>' +
        '</div>' +
      '</div>';

    const threadCount = 3;
    const chunkSize = Math.ceil(fileSize / threadCount);
    const chunks = new Array(threadCount);
    let downloadedBytes = 0;
    const startTime = Date.now();
    const ctrl = new AbortController();
    this.currentDlAbort = ctrl;

    const updateUI = () => {
      const pct = Math.min(Math.round((downloadedBytes / fileSize) * 100), 100);
      const elapsed = (Date.now() - startTime) / 1000;
      const speed = elapsed > 0 ? (downloadedBytes / 1024 / 1024 / elapsed).toFixed(1) : '0.0';
      const bar = document.getElementById('dl-bar');
      const st = document.getElementById('dl-status');
      const sp = document.getElementById('dl-speed');
      const by = document.getElementById('dl-bytes');
      const pc = document.getElementById('dl-pct');
      if (bar) bar.style.width = pct + '%';
      if (st) st.innerHTML = '<img class="om-emoji" src="/openmoji/1F4E5.svg" alt="📥"> ' + (pct >= 100 ? '拼装 3 分片 Blob 中...' : '3 线程接收中...');
      if (sp) sp.innerText = speed + ' MB/s';
      if (by) by.innerText = this.formatBytes(downloadedBytes) + ' / ' + this.formatBytes(fileSize);
      if (pc) pc.innerText = pct + '%';
    };

    const tasks = Array.from({ length: threadCount }, (_, i) => {
      const start = i * chunkSize;
      const end = Math.min(start + chunkSize - 1, fileSize - 1);
      if (start > end) {
        chunks[i] = new Blob([]);
        return Promise.resolve();
      }

      return fetch(dlUrl, {
        headers: { Range: `bytes=${start}-${end}` },
        signal: ctrl.signal
      }).then(async res => {
        if (res.status !== 206 && res.status !== 200) {
          throw new Error('分片请求响应异常: ' + res.status);
        }
        const reader = res.body.getReader();
        const partBuffers = [];
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          partBuffers.push(value);
          downloadedBytes += value.length;
          updateUI();
        }
        chunks[i] = new Blob(partBuffers);
      });
    });

    Promise.all(tasks).then(() => {
      const st = document.getElementById('dl-status');
      if (st) {
        st.innerHTML = '本地秒保存成功！';
        st.style.color = '#10b981';
      }
      const act = document.getElementById('dl-actions');
      if (act) {
        act.innerHTML = '<button type="button" class="btn btn-sm btn-success flex-1" onclick="app.closeModal(\'fM\')">完成并关闭</button>';
      }
      const finalBlob = new Blob(chunks, { type: 'application/octet-stream' });
      chunks.length = 0;
      const blobUrl = URL.createObjectURL(finalBlob);
      const a = document.createElement('a');
      a.href = blobUrl;
      a.download = fileName;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(blobUrl), 30000);
      this.toast('本地秒保存成功！');
    }).catch(err => {
      if (err.name === 'AbortError') {
        this.restoreFileActions(f.id);
        this.toast('已取消下载');
      } else {
        const st = document.getElementById('dl-status');
        if (st) {
          st.innerHTML = '<img class="om-emoji" src="/openmoji/26A0.svg" alt="⚠️"> 分片失败，转原生下载';
          st.style.color = '#ef4444';
        }
        const act = document.getElementById('dl-actions');
        if (act) {
          act.innerHTML = '<a href="' + dlUrl + '" class="btn btn-sm btn-primary flex-1" target="_blank" style="text-decoration:none;padding:8px">点击原生下载</a>' +
                          '<button type="button" class="btn btn-sm btn-outline flex-1" onclick="app.restoreFileActions(\'' + f.id + '\')">返回</button>';
        }
        window.open(dlUrl, '_blank');
      }
    }).finally(() => {
      this.currentDlAbort = null;
    });
  },

  async startFileSystemStreamDownload(f, dlUrl) {
    const c = document.getElementById('file-action-container');
    if (!c) return;
    const fileSize = Number(f.size) || 0;
    const fileName = f.name;

    let handle;
    try {
      handle = await window.showSaveFilePicker({ suggestedName: fileName });
    } catch (e) {
      if (e.name === 'AbortError') return;
      console.warn('showSaveFilePicker 异常，自动切换为第三方加速指引弹窗:', e);
      return this.showThirdPartyModal(f, dlUrl);
    }

    let writable;
    try {
      writable = await handle.createWritable();
    } catch (e) {
      console.warn('createWritable 异常，自动切换为第三方加速指引弹窗:', e);
      return this.showThirdPartyModal(f, dlUrl);
    }

    c.innerHTML = 
      '<div style="width:100%;padding:14px;background:rgba(0,0,0,.03);border-radius:12px;border:1px inset var(--cd);text-align:left">' +
        '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">' +
          '<span id="dl-status" style="color:var(--tx);font-weight:700;font-size:13px;display:flex;align-items:center;gap:6px">' +
            '<img class="om-emoji" src="/openmoji/1F4E5.svg" alt="📥"> 3 线程磁盘直写准备中...' +
          '</span>' +
          '<span class="dl-stat-badge">3 线程直写</span>' +
        '</div>' +
        '<div class="progress-container" style="height:12px;margin:0 0 6px">' +
          '<div id="dl-bar" class="progress-bar" style="width:0%"></div>' +
        '</div>' +
        '<div style="display:flex;justify-content:space-between;font-size:11px;color:gray">' +
          '<span id="dl-bytes">0 B / ' + this.formatBytes(fileSize) + '</span>' +
          '<span id="dl-speed" style="color:#10b981;font-weight:700">0.0 MB/s</span>' +
          '<span id="dl-pct" style="font-weight:700">0%</span>' +
        '</div>' +
        '<div id="dl-actions" style="display:flex;gap:10px;margin-top:12px">' +
          '<button type="button" class="btn btn-sm btn-soft-danger flex-1" onclick="app.abortCurrentDownload(\'' + f.id + '\')">取消下载</button>' +
        '</div>' +
      '</div>';

    const threadCount = 3;
    const chunkSize = Math.ceil(fileSize / threadCount);
    let downloadedBytes = 0;
    const startTime = Date.now();
    const ctrl = new AbortController();
    this.currentDlAbort = ctrl;

    let writeQueue = Promise.resolve();
    const safeWrite = (pos, buf) => {
      writeQueue = writeQueue.then(() => writable.write({ type: 'write', position: pos, data: buf }));
      return writeQueue;
    };

    const updateUI = () => {
      const pct = Math.min(Math.round((downloadedBytes / fileSize) * 100), 100);
      const elapsed = (Date.now() - startTime) / 1000;
      const speed = elapsed > 0 ? (downloadedBytes / 1024 / 1024 / elapsed).toFixed(1) : '0.0';
      const bar = document.getElementById('dl-bar');
      const st = document.getElementById('dl-status');
      const sp = document.getElementById('dl-speed');
      const by = document.getElementById('dl-bytes');
      const pc = document.getElementById('dl-pct');
      if (bar) bar.style.width = pct + '%';
      if (st) st.innerHTML = '<img class="om-emoji" src="/openmoji/1F4E5.svg" alt="📥"> ' + (pct >= 100 ? '正在刷盘固化...' : '3 线程流式直写磁盘中...');
      if (sp) sp.innerText = speed + ' MB/s';
      if (by) by.innerText = this.formatBytes(downloadedBytes) + ' / ' + this.formatBytes(fileSize);
      if (pc) pc.innerText = pct + '%';
    };

    const tasks = Array.from({ length: threadCount }, (_, i) => {
      const start = i * chunkSize;
      const end = Math.min(start + chunkSize - 1, fileSize - 1);
      if (start > end) return Promise.resolve();
      let currentPos = start;

      return fetch(dlUrl, {
        headers: { Range: `bytes=${start}-${end}` },
        signal: ctrl.signal
      }).then(async res => {
        if (res.status !== 206 && res.status !== 200) {
          throw new Error('分片请求响应异常: ' + res.status);
        }
        const reader = res.body.getReader();
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          await safeWrite(currentPos, value);
          currentPos += value.length;
          downloadedBytes += value.length;
          updateUI();
        }
      });
    });

    Promise.all(tasks).then(async () => {
      await writeQueue;
      await writable.close();
      const st = document.getElementById('dl-status');
      if (st) {
        st.innerHTML = '<img class="om-emoji" src="/openmoji/2705.svg" alt="✅"> 磁盘直写完成！';
        st.style.color = '#10b981';
      }
      const act = document.getElementById('dl-actions');
      if (act) {
        act.innerHTML = '<button type="button" class="btn btn-sm btn-success flex-1" onclick="app.closeModal(\'fM\')">完成并关闭</button>';
      }
      this.toast('<img class="om-emoji" src="/openmoji/2705.svg" alt="✅"> 磁盘直写保存完成！');
    }).catch(async err => {
      try { await writable.abort(); } catch (e) {}
      if (err.name === 'AbortError') {
        this.restoreFileActions(f.id);
        this.toast('已取消下载');
      } else {
        const st = document.getElementById('dl-status');
        if (st) {
          st.innerHTML = '<img class="om-emoji" src="/openmoji/26A0.svg" alt="⚠️"> 直写失败，转原生下载';
          st.style.color = '#ef4444';
        }
        const act = document.getElementById('dl-actions');
        if (act) {
          act.innerHTML = '<a href="' + dlUrl + '" class="btn btn-sm btn-primary flex-1" target="_blank" style="text-decoration:none;padding:8px">点击原生下载</a>' +
                          '<button type="button" class="btn btn-sm btn-outline flex-1" onclick="app.restoreFileActions(\'' + f.id + '\')">返回</button>';
        }
        window.open(dlUrl, '_blank');
      }
    }).finally(() => {
      this.currentDlAbort = null;
    });
  },

  abortCurrentDownload(fileId) {
    if (this.currentDlAbort) {
      this.currentDlAbort.abort();
      this.currentDlAbort = null;
    }
    if (fileId) {
      this.restoreFileActions(fileId);
    }
  },

  showThirdPartyModal(f, dlUrl) {
    try {
      this.copyText(dlUrl);
    } catch (e) {}

    const oldM = document.getElementById('tpM');
    if (oldM) oldM.remove();

    const sn = this.escapeHTML(f.name);
    const fSizeStr = this.formatBytes(f.size);

    const m = document.createElement('div');
    m.className = 'modal-overlay';
    m.id = 'tpM';
    m.style.zIndex = '2000';
    m.style.opacity = '0';
    m.innerHTML = 
      '<div class="modal-content" style="opacity:0;transform:scale(0.95) translateY(15px);max-width:400px;text-align:center">' +
        '<div style="font-size:42px;margin:5px auto 0"><img class="om-emoji om-emoji-lg" src="/openmoji/1F680.svg" alt="🚀"></div>' +
        '<h3 style="margin:8px 0 4px;font-size:17px">超大文件加速下载指引</h3>' +
        '<p style="color:gray;font-size:12px;margin:0 0 12px;word-break:break-all">' +
          '文件：<b style="color:var(--tx)">' + sn + '</b><br>' +
          '大小：<b style="color:var(--primary)">' + fSizeStr + '</b>（大于 500MB）' +
        '</p>' +
        '<div style="background:rgba(16,185,129,0.12);border:1px solid rgba(16,185,129,0.3);padding:10px 12px;border-radius:12px;margin-bottom:12px;font-size:12px;color:#065f46;display:flex;align-items:center;justify-content:center;gap:6px">' +
          '<img class="om-emoji" src="/openmoji/2705.svg" alt="✅">' +
          '<span><b>已自动将高速直链复制到剪贴板！</b></span>' +
        '</div>' +
        '<div style="text-align:left;background:rgba(0,0,0,0.03);border:1px solid var(--cd);padding:10px 12px;border-radius:12px;margin-bottom:14px;font-size:12px;line-height:1.5">' +
          '<p style="color:gray;margin:0 0 8px">当前设备/浏览器不支持磁盘流式直写，直接内存下载极易导致网页闪退崩溃。强烈建议粘贴直链至专业工具满速下载：</p>' +
          '<div style="display:flex;flex-direction:column;gap:5px">' +
            '<div class="app-badge-item">💻 <b>电脑推荐</b>: IDM / Motrix / FDM / 迅雷</div>' +
            '<div class="app-badge-item">📱 <b>手机推荐</b>: IDM+ / 迅雷 / 闪电下载</div>' +
          '</div>' +
        '</div>' +
        '<div style="display:flex;flex-direction:column;gap:8px">' +
          '<button type="button" class="btn btn-success" style="width:100%;padding:12px" data-url="' + dlUrl + '" onclick="app.copyText(this.dataset.url);app.toast(\'已重新复制直链！\')">' +
            '<img class="om-emoji" src="/openmoji/1F4CB.svg" alt="📋"> 再次复制直链' +
          '</button>' +
          '<a href="' + dlUrl + '" class="btn btn-soft-primary" target="_blank" style="text-decoration:none;padding:10px" onclick="app.closeModal(\'tpM\',1)">' +
            '<img class="om-emoji" src="/openmoji/1F4E5.svg" alt="📥"> 仍尝试浏览器原生下载' +
          '</a>' +
          '<button type="button" class="btn btn-outline" style="padding:10px" onclick="app.closeModal(\'tpM\',1)">关闭</button>' +
        '</div>' +
      '</div>';
    document.body.appendChild(m);
    document.body.classList.add('modal-open');
    document.documentElement.classList.add('modal-open');
    const mc = m.querySelector('.modal-content');
    m.style.willChange = 'opacity';
    mc.style.willChange = 'transform, opacity';
    const a1 = m.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 320, easing: 'cubic-bezier(0.16, 1, 0.3, 1)', fill: 'forwards' });
    const a2 = mc.animate(
      [{ transform: 'scale(0.92) translateY(18px)', opacity: 0 }, { transform: 'scale(1) translateY(0)', opacity: 1 }],
      { duration: 380, easing: 'cubic-bezier(0.16, 1, 0.3, 1)', fill: 'forwards' }
    );
    a2.onfinish = () => {
      mc.style.willChange = '';
      m.style.willChange = '';
    };
  },
});
