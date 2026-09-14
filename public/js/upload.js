Object.assign(app, {
  uploadQueue: [],
  isUploading: false,
  cancelFlag: false,
  activeControllers: {},

  async enqueueFiles(items, isDrop) {
    if (!items || !items.length) return;
    let files = [];
    if (isDrop && items[0].webkitGetAsEntry) {
      const traverse = async (entry, path) => {
        if (entry.isFile) {
          files.push(await new Promise(r => entry.file(f => {
            Object.defineProperty(f, 'fullPath', { value: path + f.name });
            r(f);
          })));
        } else if (entry.isDirectory) {
          const reader = entry.createReader();
          const entries = await new Promise(r => reader.readEntries(r));
          for (let e of entries) await traverse(e, path + entry.name + '/');
        }
      };
      for (let i = 0; i < items.length; i++) {
        let entry = items[i].webkitGetAsEntry();
        if (entry) await traverse(entry, '');
      }
    } else {
      files = Array.from(items);
    }

    for (let i = 0; i < files.length; i++) {
      this.uploadQueue.push({
        file: files[i],
        id: 'uq_' + Date.now() + '_' + Math.random().toString(36).substr(2, 5),
        status: 'pending'
      });
    }

    document.getElementById('file-name-display').innerText = '已选中 ' + this.uploadQueue.length + ' 个文件，准备就绪';
    document.getElementById('queue-info').innerText = '点击下方按钮开始并发上传';
    document.getElementById('up-file').value = '';
  },

  cancelQueue() {
    if (!confirm('确定取消全部队列？')) return;
    this.cancelFlag = true;
    Object.values(this.activeControllers).forEach(c => {
      if (c) c.abort();
    });
    document.getElementById('uploadStatus').innerHTML = '<img class="om-emoji" src="/openmoji/274C.svg" alt="❌"> 已强制中断';
    document.getElementById('uploadStatus').style.color = '#ef4444';
    setTimeout(() => {
      this.uploadQueue = [];
      const upProgress = document.getElementById('uploadProgress');
      if (upProgress) upProgress.style.display = 'none';
      const upBtn = document.getElementById('uploadBtn');
      if (upBtn) {
        upBtn.disabled = false;
        upBtn.style.opacity = '1';
        upBtn.innerHTML = '<img class="om-emoji" src="/openmoji/1F4E4.svg" alt="📤"> 开始并发上传';
      }
      document.getElementById('file-name-display').innerHTML = '<img class="om-emoji" src="/openmoji/2795.svg" alt="➕"> 点击选择多文件，或直接拖拽文件夹到此处';
      document.getElementById('queue-info').innerText = '完美支持多文件、多级文件夹拖拽识别并发';
      this.fetchData();
    }, 2000);
  },

  async startUploadQueue() {
    if (this.isUploading || this.uploadQueue.length === 0) return;
    this.closeModal('modal-upload');
    this.isUploading = true;
    this.cancelFlag = false;
    let total = this.uploadQueue.length, completed = 0;
    const upBtn = document.getElementById('uploadBtn');
    if (upBtn) {
      upBtn.disabled = true;
      upBtn.style.opacity = '0.6';
      upBtn.innerHTML = '<img class="om-emoji" src="/openmoji/1F525.svg" alt="🔥"> 上传进行中 (见主界面进度条)';
    }
    const upProgress = document.getElementById('uploadProgress');
    if (upProgress) upProgress.style.display = 'block';
    document.getElementById('uploadStatus').innerHTML = '<img class="om-emoji" src="/openmoji/1F525.svg" alt="🔥"> 多线程队列处理中...';
    document.getElementById('uploadStatus').style.color = 'var(--primary)';

    const updateOverall = () => {
      document.getElementById('uploadPercent').innerText = completed + ' / ' + total;
      document.getElementById('uploadProgressBar').style.width = ((completed / total) * 100) + '%';
    };
    updateOverall();

    let qHtml = '';
    for (let t of this.uploadQueue) {
      let fName = t.file.fullPath || t.file.name;
      qHtml += '<div id="' + t.id + '" style="font-size:12px;background:rgba(255,255,255,0.4);padding:8px 12px;border-radius:8px;border:1px solid var(--cd);">' +
               '<div style="display:flex;justify-content:space-between;margin-bottom:6px;">' +
               '<span style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex:1;font-weight:bold;" title="' + fName + '">' + this.escapeHTML(fName) + '</span>' +
               '<span class="q-status" style="color:var(--primary);margin-left:10px;white-space:nowrap">排队中</span>' +
               '</div>' +
               '<div class="progress-container" style="height:6px;margin-top:0;"><div class="q-bar progress-bar" style="width:0%"></div></div>' +
               '</div>';
    }
    document.getElementById('queueList').innerHTML = qHtml;

    const concurrentLimit = 6;
    let activePromises = [];
    const runner = async () => {
      while (this.uploadQueue.length > 0 && !this.cancelFlag) {
        let task = this.uploadQueue.shift();
        await this.uploadSingleTask(task);
        completed++;
        updateOverall();
      }
    };

    for (let i = 0; i < concurrentLimit; i++) activePromises.push(runner());
    await Promise.all(activePromises);

    if (!this.cancelFlag) {
      document.getElementById('uploadStatus').innerHTML = '<img class="om-emoji" src="/openmoji/1F389.svg" alt="🎉"> 队列全部完成！';
      setTimeout(() => {
        const upProgress = document.getElementById('uploadProgress');
        if (upProgress) upProgress.style.display = 'none';
        const upBtn = document.getElementById('uploadBtn');
        if (upBtn) {
          upBtn.disabled = false;
          upBtn.style.opacity = '1';
          upBtn.innerHTML = '<img class="om-emoji" src="/openmoji/1F4E4.svg" alt="📤"> 开始并发上传';
        }
        document.getElementById('file-name-display').innerHTML = '<img class="om-emoji" src="/openmoji/2795.svg" alt="➕"> 点击选择多文件，或直接拖拽文件夹到此处';
        document.getElementById('queue-info').innerText = '完美支持多文件、多级文件夹拖拽识别并发';
        this.fetchData();
      }, 2000);
    }
    this.isUploading = false;
  },

  async uploadSingleTask(task) {
    let f = task.file,
        baseFolder = document.getElementById('up-folder').value || '',
        relFolder = '';
    if (f.fullPath) {
      let parts = f.fullPath.split('/');
      if (parts.length > 1) {
        parts.pop();
        relFolder = parts.join('/');
      }
    }
    let finalFolder = baseFolder ? baseFolder + (relFolder ? '/' + relFolder : '') : relFolder,
        tp = this.state.view,
        el = document.getElementById(task.id);
    if (!el) return;

    const updateEl = (msg, pct, color) => {
      let st = el.querySelector('.q-status');
      if (st) {
        st.innerHTML = msg;
        if (color) st.style.color = color;
      }
      if (pct !== undefined) {
        const bar = el.querySelector('.q-bar');
        if (bar) bar.style.width = pct + '%';
      }
    };

    task.status = 'uploading';
    updateEl('预热中...', 0);

    try {
      let cs = f.size <= 20971520 ? f.size : f.size <= 104857600 ? 5242880 : f.size <= 524288000 ? 10485760 : 20971520,
          fHash = await this.getFastHash(f.name + f.size + f.lastModified + cs),
          ctrl = new AbortController();
      this.activeControllers[task.id] = ctrl;

      if (f.size <= 20971520) {
        updateEl('直传中...', 0);
        await new Promise((resolve, reject) => {
          const xhr = new XMLHttpRequest();
          xhr.open('POST', '/api/upload/single', true);
          xhr.setRequestHeader('x-filename', encodeURIComponent(f.name));
          xhr.setRequestHeader('x-type', tp);
          xhr.setRequestHeader('x-folder', encodeURIComponent(finalFolder));
          xhr.setRequestHeader('content-type', f.type || 'application/octet-stream');
          ctrl.signal.addEventListener('abort', () => xhr.abort());
          xhr.upload.onprogress = (e) => {
            if (e.lengthComputable && !this.cancelFlag) {
              let pct = Math.min(Math.round((e.loaded / e.total) * 99), 99);
              updateEl('直传 ' + pct + '%', pct);
            }
          };
          xhr.onload = () => {
            if (xhr.status >= 200 && xhr.status < 300) {
              updateEl('<img class="om-emoji" src="/openmoji/2705.svg" alt="✅"> 完成', 100, '#10b981');
              resolve();
            } else {
              reject(new Error('失败'));
            }
          };
          xhr.onerror = () => reject(new Error('网络中断'));
          xhr.onabort = () => reject(new DOMException('AbortError', 'AbortError'));
          xhr.send(f);
        });
      } else {
        updateEl('探测分片...', 0);
        const ck = await (await this.fetchWithTimeout('/api/upload/check', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ fileHash: fHash }),
          signal: ctrl.signal
        }, 15000)).json();

        let ui, bp, up = [];
        if (ck.exists) {
          ui = ck.session.b2_file_id;
          bp = ck.session.b2_path;
          up = JSON.parse(ck.session.uploaded_parts || '[]');
          updateEl('续传中...', 0);
        } else {
          const st = await (await this.fetchWithTimeout('/api/upload/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              type: tp,
              filename: f.name,
              contentType: f.type || 'application/octet-stream',
              fileHash: fHash,
              folder: finalFolder
            }),
            signal: ctrl.signal
          }, 15000)).json();
          ui = st.fileId;
          bp = st.b2Path;
        }

        let tc = Math.ceil(f.size / cs), ed = {};
        up.forEach(p => ed[p.partNumber] = p.etag);
        let tpList = [];
        for (let i = 1; i <= tc; i++) {
          if (!ed[i]) tpList.push(i);
        }

        let pUrls = {};
        if (tpList.length > 0) {
          updateEl('通道签名...', 0);
          const bpr = await this.fetchWithTimeout('/api/upload/presign_batch', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type: tp, uploadId: ui, b2Path: bp, parts: tpList }),
            signal: ctrl.signal
          }, 30000);
          if (!bpr.ok) throw new Error('签名失败');
          pUrls = await bpr.json();
        }

        let uBytes = up.length * cs;
        if (uBytes > f.size) uBytes = f.size;
        let ue = null, pa = {};

        // 串行队列保证 D1 数据库写入时不产生行锁和 JSON 覆写竞争
        let syncChain = Promise.resolve();
        const safeSyncPart = (partNum, etagVal) => {
          syncChain = syncChain.then(() => {
            if (this.cancelFlag) return;
            return fetch('/api/upload/sync_part', {
              method: 'POST',
              headers: { 'content-type': 'application/json' },
              body: JSON.stringify({ fileHash: fHash, partNumber: partNum, etag: etagVal })
            }).catch(() => {});
          });
          return syncChain;
        };

        const cw = async (ic) => {
          let ct = ic;
          while (tpList.length > 0 && !ue && !this.cancelFlag) {
            const pn = tpList.shift();
            if (!pn) break;
            const c = f.slice((pn - 1) * cs, pn * cs);
            let sha256B64 = '';
            if (this.settings.sha256) {
              updateEl('计算哈希...', Math.min(Math.round((uBytes / f.size) * 100), 99));
              sha256B64 = await this.getRealSha256(await c.arrayBuffer());
            }

            let sc = false;
            pa[pn] = pa[pn] || 0;
            while (!sc && !ue && !this.cancelFlag) {
              try {
                let et;
                updateEl('灌入[' + pn + '/' + tc + ']', Math.min(Math.round((uBytes / f.size) * 100), 99));
                if (ct === 'CF_PROXY') {
                  const hdrs = {
                    'x-file-id': ui,
                    'x-file-hash': fHash,
                    'x-part-number': pn,
                    'x-b2-path': encodeURIComponent(bp),
                    'x-type': tp
                  };
                  if (sha256B64) hdrs['x-amz-checksum-sha256'] = sha256B64;
                  const r = await this.fetchWithTimeout('/api/upload/part', {
                    method: 'POST',
                    headers: hdrs,
                    body: c,
                    signal: ctrl.signal
                  }, 60000);
                  if (!r.ok) throw new Error(await r.text());
                  et = (await r.json()).etag;
                } else {
                  const prUrl = pUrls[pn];
                  if (!prUrl) throw new Error('P');
                  const hdrs = { 'Content-Type': 'application/octet-stream' };
                  if (sha256B64) hdrs['x-amz-checksum-sha256'] = sha256B64;
                  const r = await this.fetchWithTimeout(prUrl, {
                    method: 'PUT',
                    headers: hdrs,
                    body: c,
                    signal: ctrl.signal
                  }, 60000);
                  if (!r.ok) throw new Error('D');
                  et = r.headers.get('ETag').replace(/"/g, '');
                  safeSyncPart(pn, et);
                }

                ed[pn] = et;
                uBytes += c.size;
                sc = true;
                updateEl('拼装中...', Math.min(Math.round((uBytes / f.size) * 100), 99));
              } catch (e) {
                if (this.cancelFlag) break;
                pa[pn]++;
                if (pa[pn] >= 6) {
                  ue = new Error('阻断');
                  break;
                }
                ct = ct === 'CF_PROXY' ? 'B2_DIRECT' : 'CF_PROXY';
                if (pa[pn] % 2 === 0) {
                  tpList.push(pn);
                  break;
                }
                await new Promise(r => setTimeout(r, 2000));
              }
            }
          }
        };

        let ws = [];
        for (let i = 0; i < 8; i++) ws.push(cw(i % 3 === 0 ? 'CF_PROXY' : 'B2_DIRECT'));
        await Promise.all(ws);
        await syncChain;
        if (ue) throw ue;
        if (this.cancelFlag) throw new DOMException('AbortError', 'AbortError');

        updateEl('合并分片...', 99);
        let ea = [];
        for (let i = 1; i <= tc; i++) ea.push(ed[i]);
        const fr = await this.fetchWithTimeout('/api/upload/finish', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            type: tp,
            fileId: ui,
            etagArray: ea,
            name: f.name,
            b2_path: bp,
            size: f.size,
            folder: finalFolder,
            fileHash: fHash
          }),
          signal: ctrl.signal
        }, 30000);
        if (!fr.ok) throw new Error('合并失败');
        updateEl('<img class="om-emoji" src="/openmoji/2705.svg" alt="✅"> 完成', 100, '#10b981');
      }
    } catch (err) {
      if (err.name === 'AbortError' || this.cancelFlag) updateEl('<img class="om-emoji" src="/openmoji/274C.svg" alt="❌"> 已取消', 0, '#ef4444');
      else updateEl('<img class="om-emoji" src="/openmoji/274C.svg" alt="❌"> 失败', 0, '#ef4444');
    } finally {
      delete this.activeControllers[task.id];
    }
  },

  showSessionsModal() {
    history.pushState({ mdl: 'sM' }, '');
    const m = document.createElement('div');
    m.className = 'modal-overlay';
    m.id = 'sM';
    m.style.opacity = '0';
    m.innerHTML = '<div class="modal-content" style="opacity:0;transform:scale(0.95) translateY(15px)">' +
                  '<h3 style="margin-top:0;margin-bottom:5px;text-align:center"><img class="om-emoji" src="/openmoji/1F9F9.svg" alt="🧹"> 碎片管理</h3>' +
                  '<div id="sL" style="max-height:45vh;overflow-y:auto;margin-bottom:15px;padding-right:5px">...</div>' +
                  '<button class="btn btn-outline" style="width:100%;padding:12px;border-radius:12px" onclick="app.closeModal(\'sM\')"><img class="om-emoji" src="/openmoji/274C.svg" alt="❌"> 关闭</button>' +
                  '</div>';
    document.body.appendChild(m);
    document.body.classList.add('modal-open');
    document.documentElement.classList.add('modal-open');

    fetch('/api/upload/sessions')
      .then(r => r.json())
      .then(d => {
        let h = d.length ? '' : '<p style="text-align:center;color:gray">干净</p>';
        d.forEach(s => {
          const p = JSON.parse(s.uploaded_parts || '[]');
          h += '<div style="padding:12px;border:1px solid var(--cd);margin-bottom:10px;border-radius:12px;background:rgba(0,0,0,0.03)">' +
               '<div style="font-weight:bold;word-break:break-all;font-size:13px">' + this.escapeHTML(s.b2_path.split('_').slice(1).join('_')) + '</div>' +
               '<div style="font-size:12px;color:gray;margin:8px 0">缓冲 ' + p.length + ' 块</div>' +
               '<button class="btn btn-sm btn-danger" style="width:100%" data-fh="' + s.file_hash + '" data-ui="' + s.b2_file_id + '" data-bp="' + s.b2_path + '" data-bk="' + s.bucket + '" onclick="app.abortSession(this.dataset.fh,this.dataset.ui,this.dataset.bp,this.dataset.bk)">抹除</button>' +
               '</div>';
        });
        document.getElementById('sL').innerHTML = h;
      })
      .catch(() => {});

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

  async abortSession(fh, ui, bp, bk) {
    if (!confirm('抹除？')) return;
    await fetch('/api/upload/abort', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ fileHash: fh, uploadId: ui, b2Path: bp, bucket: bk })
    });
    this.closeModal('sM');
    setTimeout(() => this.showSessionsModal(), 400);
  },
});
