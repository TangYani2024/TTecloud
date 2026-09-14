const app = {
  state: {
    view: 'resource',
    folder: null,
    q: '',
    isAdmin: false,
    currentPwd: '',
    fileList: []
  },
  configLoaded: false,
  settings: {
    expect: localStorage.getItem('cfg_expect') === 'true',
    sha256: localStorage.getItem('cfg_sha256') === 'true',
    bgPc: (window.__CFG__ && window.__CFG__.bgPc) || localStorage.getItem('cfg_bgPc') || '',
    bgMobile: (window.__CFG__ && window.__CFG__.bgMobile) || localStorage.getItem('cfg_bgMobile') || ''
  },
  lastWidth: window.innerWidth,

  updateAppHeight() {
    document.documentElement.style.setProperty('--app-height', window.innerHeight + 'px');
  },

  escapeHTML(s) {
    return String(s).replace(/[&<>'"]/g, t => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      "'": '&#39;',
      '"': '&quot;'
    }[t] || t));
  },

  updInd(i, el) {
    const d = document.getElementById(i);
    if (d && el) {
      d.style.width = el.offsetWidth + 'px';
      d.style.transform = 'translateX(' + el.offsetLeft + 'px)';
    }
  },

  fabExpanded: false,

  toggleFabOrUpload() {
    if (this.fabExpanded) {
      this.collapseFab();
      this.showUploadModal();
    } else {
      this.expandFab();
    }
  },

  expandFab() {
    this.fabExpanded = true;
    const c = document.getElementById('admin-fab-container');
    if (c) c.classList.add('expanded');
  },

  collapseFab() {
    this.fabExpanded = false;
    const c = document.getElementById('admin-fab-container');
    if (c) c.classList.remove('expanded');
  },

  openStaticModal(id) {
    this.collapseFab();
    history.pushState({ mdl: id }, '');
    const m = document.getElementById(id);
    if (!m) return;
    document.body.classList.add('modal-open');
    document.documentElement.classList.add('modal-open');
    m.style.display = 'flex';
    m.style.opacity = '1';
    const mc = m.querySelector('.modal-content');
    if (mc) {
      mc.style.opacity = '1';
      mc.style.transform = 'scale(1) translateY(0)';
    }
    try {
      m.style.willChange = 'opacity';
      if (mc) mc.style.willChange = 'transform, opacity';
      const a1 = m.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 150 });
      if (mc) {
        const a2 = mc.animate(
          [{ transform: 'scale(0.96) translateY(10px)', opacity: 0 }, { transform: 'scale(1) translateY(0)', opacity: 1 }],
          { duration: 200, easing: 'cubic-bezier(0.16, 1, 0.3, 1)' }
        );
        a2.onfinish = () => {
          if (mc) mc.style.willChange = '';
          m.style.willChange = '';
        };
      } else {
        a1.onfinish = () => { m.style.willChange = ''; };
      }
    } catch (e) {
      m.style.willChange = '';
      if (mc) mc.style.willChange = '';
    }
  },

  showUploadModal() {
    const uf = document.getElementById('up-folder');
    if (uf) uf.value = this.state.folder !== null ? this.state.folder : '';
    const btn = document.getElementById('uploadBtn');
    if (btn) {
      if (this.isUploading) {
        btn.disabled = true;
        btn.style.opacity = '0.6';
        btn.innerHTML = '<img class="om-emoji" src="/openmoji/1F525.svg" alt="🔥"> 上传进行中 (见主界面进度条)';
      } else {
        btn.disabled = false;
        btn.style.opacity = '1';
        btn.innerHTML = '<img class="om-emoji" src="/openmoji/1F4E4.svg" alt="📤"> 开始并发上传';
      }
    }
    this.openStaticModal('modal-upload');
  },

  showCliModal() {
    this.openStaticModal('modal-cli');
  },

  showSettingsModal() {
    this.refreshSettingsUI();
    this.openStaticModal('modal-settings');
  },


  async init() {
    document.querySelectorAll('.d-b64').forEach(e => e.innerText = atob(e.dataset.b));
    this.refreshSettingsUI();
    this.updateAppHeight();
    this.applyBg();
    window.addEventListener('hashchange', () => this.parseHash());
    this.parseHash();

    window.addEventListener('beforeunload', e => {
      if (this.isUploading) {
        e.preventDefault();
        e.returnValue = '上传中';
      }
    });

    window.addEventListener('popstate', e => {
      document.querySelectorAll('.modal-overlay').forEach(m => {
        if (m.style.display !== 'none') {
          app.closeModal(m.id, 1);
        }
      });
    });

    window.addEventListener('resize', () => {
      const cw = window.innerWidth;
      if (cw <= 768 && cw === this.lastWidth) return;
      this.lastWidth = cw;
      this.updateAppHeight();
      this.updInd('ind-main', document.querySelector('#main-nav .active'));
      this.applyBg();
    });

    const closeFabOnOutside = e => {
      const fab = document.getElementById('admin-fab-container');
      if (this.fabExpanded && fab && !fab.contains(e.target)) {
        this.collapseFab();
      }
    };
    document.addEventListener('click', closeFabOnOutside);
    document.addEventListener('touchstart', closeFabOnOutside, { passive: true });

    ['fab-sub-github', 'fab-sub-cli', 'fab-sub-settings'].forEach(bid => {
      const b = document.getElementById(bid);
      if (b) {
        let lastTouch = 0;
        b.addEventListener('touchend', e => {
          const now = Date.now();
          if (now - lastTouch < 500) return;
          lastTouch = now;
          e.preventDefault();
          b.click();
        }, { passive: false });
      }
    });

    // 阻止弹窗外鼠标滚轮穿透到背后的文件列表，同时确保弹窗内可滚动容器（如 GitHub 订阅列表）能正常滑动
    document.addEventListener('wheel', e => {
      if (document.body.classList.contains('modal-open')) {
        const mc = e.target.closest('.modal-content');
        if (!mc) {
          e.preventDefault();
          return;
        }
        // 查找从 e.target 向上至 mc 之间首个真正可滚动的容器
        let scrollEl = null;
        let cur = e.target;
        while (cur && cur !== document.body && cur !== document.documentElement) {
          const style = window.getComputedStyle(cur);
          const isScrollable = (style.overflowY === 'auto' || style.overflowY === 'scroll') && (cur.scrollHeight > cur.clientHeight);
          if (isScrollable) {
            scrollEl = cur;
            break;
          }
          if (cur === mc) break;
          cur = cur.parentElement;
        }

        if (!scrollEl) {
          e.preventDefault();
          return;
        }

        const { scrollTop, scrollHeight, clientHeight } = scrollEl;
        const delta = e.deltaY;
        const isAtTop = delta < 0 && scrollTop <= 0;
        const isAtBottom = delta > 0 && Math.ceil(scrollTop + clientHeight) >= scrollHeight;
        if (isAtTop || isAtBottom) {
          e.preventDefault();
        }
      }
    }, { passive: false });
  },

  refreshSettingsUI() {
    if (document.getElementById('cfg-expect')) {
      document.getElementById('cfg-expect').checked = this.settings.expect;
      document.getElementById('cfg-sha256').checked = this.settings.sha256;
      document.getElementById('cfg-bgPc').value = this.settings.bgPc;
      document.getElementById('cfg-bgMobile').value = this.settings.bgMobile;
    }
  },

  applyBg() {
    const isM = window.innerWidth <= 768;
    const u = isM ? this.settings.bgMobile : this.settings.bgPc;
    if (u) {
      document.documentElement.style.setProperty('--user-bg-url', 'url(' + u + ')');
      document.documentElement.style.setProperty('--bg-op', '1');
    } else {
      document.documentElement.style.removeProperty('--user-bg-url');
      document.documentElement.style.setProperty('--bg-op', '0');
    }
  },

  async loadCloudConfig() {
    try {
      const r = await fetch('/api/admin/config');
      const d = await r.json();
      if (d && Object.keys(d).length > 0) {
        this.settings = { ...this.settings, ...d };
        localStorage.setItem('cfg_expect', this.settings.expect);
        localStorage.setItem('cfg_sha256', this.settings.sha256);
        localStorage.setItem('cfg_bgPc', this.settings.bgPc || '');
        localStorage.setItem('cfg_bgMobile', this.settings.bgMobile || '');
        this.applyBg();
        this.refreshSettingsUI();
      }
    } catch (e) {}
  },

  async saveConfigToCloud() {
    localStorage.setItem('cfg_expect', this.settings.expect);
    localStorage.setItem('cfg_sha256', this.settings.sha256);
    localStorage.setItem('cfg_bgPc', this.settings.bgPc);
    localStorage.setItem('cfg_bgMobile', this.settings.bgMobile);
    this.applyBg();
    this.refreshSettingsUI();
    try {
      const b = document.getElementById('save-cfg-btn');
      if (b) b.innerText = '正在同步至云端...';
      await fetch('/api/admin/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(this.settings)
      });
      if (b) b.innerText = '💾 保存并同步云端配置';
      this.toast('☁️ 云端同步成功');
    } catch (e) {
      this.toast('❌ 云端同步失败');
    }
  },

  saveSettingsFromUI() {
    this.settings.expect = document.getElementById('cfg-expect').checked;
    this.settings.sha256 = document.getElementById('cfg-sha256').checked;
    this.settings.bgPc = document.getElementById('cfg-bgPc').value.trim();
    this.settings.bgMobile = document.getElementById('cfg-bgMobile').value.trim();
    this.saveConfigToCloud();
  },

  setWallpaper(id, type) {
    const url = window.location.origin + '/file/' + id;
    if (type === 'pc') this.settings.bgPc = url;
    else this.settings.bgMobile = url;
    this.saveConfigToCloud();
    this.closeModal('fM');
    this.toast(type === 'pc' ? '✅ 已设为 PC 横屏壁纸' : '✅ 已设为手机竖屏壁纸');
  },

  parseHash() {
    const h = window.location.hash.slice(1);
    const p = new URLSearchParams(h);
    this.state.view = p.get('view') || 'resource';
    this.state.folder = p.has('folder') ? p.get('folder') : null;
    this.state.q = p.get('q') || '';
    const searchInput = document.getElementById('search-input');
    if (searchInput) searchInput.value = this.state.q;

    document.querySelectorAll('#main-nav .nav-tab').forEach(b => {
      b.classList.toggle('active', b.id === 'tab-' + this.state.view);
    });
    this.updInd('ind-main', document.getElementById('tab-' + this.state.view));
    this.fetchData();
  },

  setHash() {
    let h = 'view=' + this.state.view;
    if (this.state.folder !== null) h += '&folder=' + encodeURIComponent(this.state.folder);
    if (this.state.q) h += '&q=' + encodeURIComponent(this.state.q);
    window.location.hash = h;
  },

  switchView(v) {
    this.state.view = v;
    this.state.folder = null;
    this.state.q = '';
    this.state.currentPwd = '';
    document.querySelectorAll('#main-nav .nav-tab').forEach(b => {
      b.classList.toggle('active', b.id === 'tab-' + v);
    });
    this.updInd('ind-main', document.getElementById('tab-' + v));
    const cliTab = document.getElementById('mode-cli');
    if (cliTab && cliTab.classList.contains('active')) this.switchUploadMode('cli');
    this.setHash();
  },

  goHome() {
    this.state.folder = null;
    this.state.currentPwd = '';
    this.setHash();
  },

  goToFolder(f, l) {
    const folderName = (f === null || f === undefined) ? '' : String(f);
    if (!this.state.isAdmin && l) {
      const displayName = folderName.trim() || '空白目录';
      const p = prompt('🔒 加密目录[' + displayName + ']密码：');
      if (!p) return;
      fetch('/api/unlock', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ folder: folderName, password: p })
      })
      .then(r => r.json())
      .then(rs => {
        if (rs.ok) {
          this.state.folder = folderName;
          this.state.currentPwd = p;
          this.setHash();
        } else {
          alert(rs.error);
        }
      });
      return;
    }
    this.state.folder = folderName;
    this.state.currentPwd = '';
    this.setHash();
  },

  debounceSearch() {
    clearTimeout(this.st);
    this.st = setTimeout(() => {
      this.state.q = document.getElementById('search-input').value.trim();
      this.setHash();
    }, 400);
  },

  async fetchData() {
    const a = document.getElementById('dynamic-area');
    if (!a) return;
    a.innerHTML = '<div style="display:flex;flex-direction:column;align-items:center;padding:60px 0;color:var(--primary);"><svg width="48" height="48" viewBox="0 0 50 50" style="animation:spin 2s linear infinite;"><circle cx="25" cy="25" r="20" fill="none" stroke="var(--cd)" stroke-width="4"></circle><circle cx="25" cy="25" r="20" fill="none" stroke="var(--primary)" stroke-width="4" stroke-linecap="round" stroke-dasharray="90 150" style="animation:dash 1.5s ease-in-out infinite;"></circle></svg><div style="margin-top:15px;font-size:13px;font-weight:bold;letter-spacing:1px;animation:pulse 1.5s ease-in-out infinite;">核心引擎跃迁中...</div></div>';
    
    try {
      let u = '/api/data?view=' + this.state.view;
      if (this.state.folder !== null) u += '&folder=' + encodeURIComponent(this.state.folder);
      if (this.state.q) u += '&q=' + encodeURIComponent(this.state.q);
      
      const r = await fetch(u);
      if (r.status === 401) {
        alert('权限验证失败，或管理员状态已失效');
        this.goHome();
        return;
      }
      
      const rs = await r.json();
      this.state.isAdmin = rs.isAdmin;
      
      const authBtn = document.getElementById('auth-btn');
      if (authBtn) {
        authBtn.innerHTML = rs.isAdmin 
          ? '<a href="/logout" class="btn btn-sm btn-outline">退出</a>' 
          : '<a href="/login" class="btn btn-sm btn-outline">管理登录</a>';
      }
      
      const inFolder = this.state.folder !== null;
      document.getElementById('main-nav').style.display = rs.isAdmin ? 'flex' : 'none';
      const fab = document.getElementById('admin-fab-container');
      if (fab) fab.style.display = rs.isAdmin ? 'flex' : 'none';
      document.getElementById('btn-back').style.display = inFolder ? 'inline-flex' : 'none';
      const folderDisplayName = inFolder ? (this.state.folder.trim() || '空白目录') : '根目录';
      document.getElementById('breadcrumb').innerHTML = inFolder 
        ? '<img class="om-emoji" src="/openmoji/1F4C2.svg" alt="📂"> ' + this.escapeHTML(folderDisplayName) 
        : '<img class="om-emoji" src="/openmoji/1F4C1.svg" alt="📁"> 根目录';
      
      if (rs.isAdmin) {
        document.getElementById('storage-card').style.display = 'block';
        const p = rs.maxSize > 0 ? Math.min((rs.totalSize / rs.maxSize) * 100, 100).toFixed(1) : 0;
        document.getElementById('storage-text').innerText = this.formatBytes(rs.totalSize) + ' / ' + this.formatBytes(rs.maxSize) + ' (' + p + '%)';
        const sb = document.getElementById('storage-bar');
        sb.style.width = p + '%';
        sb.style.background = p > 90 ? '#ef4444' : p > 75 ? '#f59e0b' : '';
        
        setTimeout(() => {
          this.updInd('ind-main', document.querySelector('#main-nav .active'));
        }, 50);
        
        if (!this.configLoaded) {
          this.configLoaded = true;
          this.loadCloudConfig();
        }
      } else {
        document.getElementById('storage-card').style.display = 'none';
      }
      
      this.state.fileList = rs.data || [];
      if (rs.mode === 'folders') {
        this.state.folderList = rs.data || [];
      }
      if (rs.mode === 'folders') this.renderFolders(rs.data);
      else this.renderFiles(rs.data);
    } catch (e) {
      console.error('fetchData error:', e);
      const a = document.getElementById('dynamic-area');
      if (a) {
        a.innerHTML = '<div style="text-align:center;padding:60px 20px;color:#ef4444;"><div style="font-size:28px;margin-bottom:10px;">⚠️</div><div style="font-weight:bold;margin-bottom:6px;">加载失败，请刷新重试</div><div style="font-size:12px;color:gray;">' + this.escapeHTML(e.message || e) + '</div></div>';
      }
    }
  },

  getFileIconSvg(fileName) {
    const ext = (fileName.split('.').pop() || '').toLowerCase();
    if (['zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz', 'iso', 'apk', 'ipa', 'pkg', 'dmg'].includes(ext)) {
      return ICONS.archive;
    }
    if (['mp4', 'mkv', 'avi', 'mov', 'wmv', 'flv', 'webm', 'm4v', 'rmvb', 'ts', '3gp'].includes(ext)) {
      return ICONS.video;
    }
    if (['mp3', 'flac', 'wav', 'aac', 'ogg', 'm4a', 'wma', 'ape', 'mid'].includes(ext)) {
      return ICONS.audio;
    }
    if (['js', 'ts', 'jsx', 'tsx', 'html', 'htm', 'css', 'json', 'py', 'java', 'c', 'cpp', 'cs', 'go', 'rs', 'php', 'sh', 'sql', 'yaml', 'yml', 'xml', 'vue'].includes(ext)) {
      return ICONS.code;
    }
    return ICONS.document;
  },

  renderFolders(arr) {
    this.state.folderList = arr || [];
    const a = document.getElementById('dynamic-area');
    if (!arr.length) {
      a.innerHTML = '<p style="text-align:center;color:gray;margin-top:40px">空空如也~</p>';
      return;
    }
    let h = '<div class="grid-view">';
    arr.forEach((f, idx) => {
      const rawName = (f.name === null || f.name === undefined) ? '' : String(f.name);
      const sn = this.escapeHTML(rawName);
      const isLocked = f.locked === 'true' || f.locked === '1' || f.locked === true || f.locked === 1;
      const iconSvg = isLocked ? ICONS.folderLocked : ICONS.folder;
      const displayTitle = rawName.trim() ? sn : '<span style="color:gray;font-style:italic">（空白目录）</span>';
      h += '<div class="folder-card" onclick="app.goToFolder(app.state.folderList[' + idx + '].name, ' + isLocked + ')">' +
           '<div><div class="folder-preview">' + iconSvg + '</div>' +
           '<div class="file-name" title="' + (rawName.trim() || '空白目录') + '">' + displayTitle + '</div></div>' +
           '<div><div class="file-meta" style="margin-top:8px">' + f.count + ' 项 | ' + this.formatBytes(f.size) + '</div>';
      if (this.state.isAdmin) {
        h += '<div style="margin-top:12px"><button class="btn btn-sm btn-outline" style="width:100%" onclick="event.stopPropagation();app.adminFolder(app.state.folderList[' + idx + '].name)"><img class="om-emoji" src="/openmoji/1F510.svg" alt="🔐"> 权限</button></div>';
      }
      h += '</div></div>';
    });
    a.innerHTML = h + '</div>';
  },

  toast(m) {
    const t = document.createElement('div');
    t.innerHTML = m;
    t.style.cssText = 'position:fixed;top:30px;left:50%;transform:translate(-50%,-20px);background:rgba(30,41,59,0.85);color:#fff;padding:12px 24px;border-radius:30px;font-size:14px;z-index:10000;box-shadow:0 10px 30px rgba(0,0,0,0.2);transition:all 0.4s;opacity:0;pointer-events:none;border:1px solid rgba(255,255,255,0.1);font-weight:bold;display:flex;align-items:center;gap:6px';
    document.body.appendChild(t);
    t.offsetHeight;
    t.style.opacity = '1';
    t.style.transform = 'translate(-50%,0)';
    setTimeout(() => {
      t.style.opacity = '0';
      t.style.transform = 'translate(-50%,-20px)';
      setTimeout(() => t.remove(), 400);
    }, 2500);
  },

  copyText(txt) {
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(txt).then(() => this.toast('<img class="om-emoji" src="/openmoji/2705.svg" alt="✅"> 复制成功！')).catch(() => prompt('手动复制:', txt));
    } else {
      const ta = document.createElement('textarea');
      ta.value = txt;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      try {
        document.execCommand('copy');
        this.toast('<img class="om-emoji" src="/openmoji/2705.svg" alt="✅"> 复制成功！');
      } catch (e) {
        prompt('手动复制:', txt);
      }
      document.body.removeChild(ta);
    }
  },

  copyImgLink(id) {
    this.copyText(window.location.origin + '/file/' + id);
  },

  copyImgMd(id, n) {
    this.copyText('![' + n + '](' + window.location.origin + '/file/' + id + ')');
  },

  renderFiles(arr) {
    const a = document.getElementById('dynamic-area');
    if (!arr.length) {
      a.innerHTML = '<p style="text-align:center;color:gray;margin-top:40px">暂无文件~</p>';
      return;
    }
    let h = '<div class="grid-view">';
    arr.forEach(f => {
      const sn = this.escapeHTML(f.name),
            ext = (f.name.split('.').pop() || '').toLowerCase(),
            sp = (this.state.view === 'image' || ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'svg', 'ico'].includes(ext)),
            ph = sp ? '<img src="/file/' + f.id + '" loading="lazy">' : this.getFileIconSvg(f.name),
            hb = f.is_hidden ? '<div style="position:absolute;top:6px;right:6px;font-size:10px;background:rgba(239,68,68,0.8);color:#fff;padding:2px 6px;border-radius:6px;font-weight:bold;box-shadow:0 2px 5px rgba(0,0,0,0.2)">隐藏</div>' : '';
      h += '<div class="file-card" data-id="' + f.id + '" onclick="app.showFileAction(this.dataset.id)" ' + (f.is_hidden ? 'style="opacity:0.6"' : '') + '>' +
           hb +
           '<div><div class="' + (sp ? 'file-preview file-preview-img' : 'file-preview') + '">' + ph + '</div><div class="file-name" title="' + sn + '">' + sn + '</div></div>' +
           '<div class="file-meta">' + this.formatBytes(f.size) + '</div></div>';
    });
    h += '</div>';
    a.innerHTML = h;
  },

  showFileAction(id) {
    const f = this.state.fileList.find(x => x.id === id);
    if (!f) return;
    history.pushState({ mdl: id }, '');
    const sn = this.escapeHTML(f.name),
          ext = (f.name.split('.').pop() || '').toLowerCase(),
          iv = this.state.view === 'image',
          sp = (iv || ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'svg', 'ico'].includes(ext)),
          pr = sp ? '<img src="/file/' + f.id + '" style="width:120px;height:120px;object-fit:cover;border-radius:14px;margin:0 auto;display:block;box-shadow:0 8px 20px rgba(0,0,0,0.15);border:1px solid var(--cd)">' : '<div style="width:84px;height:84px;margin:10px auto;display:flex;align-items:center;justify-content:center;">' + this.getFileIconSvg(f.name) + '</div>';

    const b = this.getFileActionButtons(f);

    const m = document.createElement('div');
    m.className = 'modal-overlay';
    m.id = 'fM';
    m.style.opacity = '0';
    m.innerHTML = '<div class="modal-content" style="opacity:0;transform:scale(0.95) translateY(15px)">' +
                  pr +
                  '<h3 style="text-align:center;margin:15px 0 5px;word-break:break-all;font-size:16px;line-height:1.4">' + sn + '</h3>' +
                  '<p style="text-align:center;color:gray;font-size:12px;margin:0 0 15px">' + this.formatBytes(f.size) + '</p>' +
                  '<div id="file-action-container" style="display:flex;flex-direction:column;gap:10px;width:100%">' + b + '</div>' +
                  '</div>';
    document.body.appendChild(m);
    document.body.classList.add('modal-open');
    document.documentElement.classList.add('modal-open');

    this.bindAdminCmdBtns(f);

    const mc = m.querySelector('.modal-content');
    const a1 = m.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 200, fill: 'forwards' });
    const a2 = mc.animate([{ transform: 'scale(0.95) translateY(15px)', opacity: 0 }, { transform: 'scale(1) translateY(0)', opacity: 1 }], { duration: 350, easing: 'cubic-bezier(0.175,0.885,0.32,1.275)', fill: 'forwards' });
    a2.onfinish = () => { mc.style.willChange = ''; };
  },

  getFileActionButtons(f) {
    const sn = this.escapeHTML(f.name),
          iv = this.state.view === 'image',
          pq = this.state.currentPwd ? '&pwd=' + encodeURIComponent(this.state.currentPwd) : '',
          ps = this.state.currentPwd ? '?pwd=' + encodeURIComponent(this.state.currentPwd) : '';
    const isSmall = (Number(f.size) || 0) < 20 * 1024 * 1024;
    const fastDlBtn = isSmall
      ? '<a href="/file/' + f.id + '?dl=1' + pq + '" download="' + sn + '" class="btn btn-outline flex-1" style="text-decoration:none;padding:12px;font-size:14px;min-width:130px" onclick="app.closeModal(\'fM\')"><img class="om-emoji" src="/openmoji/1F4E5.svg" alt="📥"> 网页下载</a>'
      : '<button type="button" class="btn btn-outline flex-1" style="padding:12px;font-size:14px;min-width:130px" data-id="' + f.id + '" onclick="app.smartDownload(this.dataset.id)"><img class="om-emoji" src="/openmoji/1F4E5.svg" alt="📥"> 网页下载</button>';

    let b = '';
    if (iv) {
      b += '<div id="primary-actions" style="display:flex;flex-direction:column;gap:10px;width:100%">' +
           '<div class="flex-row" style="width:100%">' +
           '<button class="btn btn-outline flex-1" style="padding:12px" data-id="' + f.id + '" onclick="app.copyImgLink(this.dataset.id);app.closeModal(\'fM\')"><img class="om-emoji" src="/openmoji/1F517.svg" alt="🔗"> 复制直链</button>' +
           '<button class="btn btn-outline flex-1" style="padding:12px" data-id="' + f.id + '" data-n="' + sn + '" onclick="app.copyImgMd(this.dataset.id,this.dataset.n);app.closeModal(\'fM\')"><img class="om-emoji" src="/openmoji/1F4DD.svg" alt="📝"> Markdown</button>' +
           '</div>' +
           '<div class="flex-row" style="width:100%">' +
           fastDlBtn +
           '<a href="/file/' + f.id + '?dl=1' + pq + '" class="btn btn-outline flex-1" target="_blank" style="text-decoration:none;padding:12px;font-size:14px" onclick="app.closeModal(\'fM\')"><img class="om-emoji" src="/openmoji/1F4E5.svg" alt="📥"> 原生</a>' +
           '</div>' +
           '<div class="flex-row" style="width:100%">' +
           '<a href="/share/' + f.id + ps + '" class="btn btn-outline flex-1" target="_blank" style="text-decoration:none;padding:12px;font-size:14px" onclick="app.closeModal(\'fM\')"><img class="om-emoji" src="/openmoji/1F4E4.svg" alt="📤"> 分享</a>' +
           '<button class="btn flex-1" style="padding:12px;background:#10b981" onclick="document.getElementById(\'primary-actions\').style.display=\'none\';document.getElementById(\'bg-options\').style.display=\'flex\'"><img class="om-emoji" src="/openmoji/1F5BC.svg" alt="🖼️"> 设为壁纸</button>' +
           '</div>' +
           '</div>' +
           '<div id="bg-options" style="display:none;flex-direction:column;gap:10px;width:100%">' +
           '<div class="flex-row" style="width:100%">' +
           '<button class="btn btn-success flex-1" style="padding:12px" data-id="' + f.id + '" onclick="app.setWallpaper(this.dataset.id,\'pc\')"><img class="om-emoji" src="/openmoji/1F4BB.svg" alt="💻"> 设为 PC 横屏</button>' +
           '<button class="btn btn-success flex-1" style="padding:12px" data-id="' + f.id + '" onclick="app.setWallpaper(this.dataset.id,\'mobile\')"><img class="om-emoji" src="/openmoji/1F4F1.svg" alt="📱"> 设为手机竖屏</button>' +
           '</div>' +
           '<button class="btn btn-outline" style="width:100%;padding:12px" onclick="document.getElementById(\'bg-options\').style.display=\'none\';document.getElementById(\'primary-actions\').style.display=\'flex\'">取消</button>' +
           '</div>';
    } else {
      b += '<div class="flex-row" style="width:100%">' +
           fastDlBtn +
           '<a href="/file/' + f.id + '?dl=1' + pq + '" class="btn btn-outline flex-1" target="_blank" style="text-decoration:none;padding:12px;font-size:14px" onclick="app.closeModal(\'fM\')"><img class="om-emoji" src="/openmoji/1F4E5.svg" alt="📥"> 原生下载</a>' +
           '</div>' +
           '<div class="flex-row" style="width:100%">' +
           '<a href="/share/' + f.id + ps + '" class="btn btn-outline flex-1" target="_blank" style="text-decoration:none;padding:12px;font-size:14px" onclick="app.closeModal(\'fM\')"><img class="om-emoji" src="/openmoji/1F4E4.svg" alt="📤"> 分享</a>' +
           '</div>';
    }

    if (this.state.isAdmin) {
      b += '<div style="width:100%;height:1px;background:var(--cd);margin:4px 0;opacity:0.5"></div>' +
           '<div class="flex-row" style="width:100%">' +
           '<button id="cmd_wg_btn" class="btn btn-outline btn-sm flex-1"><img class="om-emoji" src="/openmoji/1F4CB.svg" alt="📋"> 复制 ' + atob('V2dldA==') + ' 下载</button>' +
           '<button id="cmd_cu_btn" class="btn btn-outline btn-sm flex-1"><img class="om-emoji" src="/openmoji/1F4CB.svg" alt="📋"> 复制 ' + atob('Q3VybA==') + ' 下载</button>' +
           '</div>' +
           '<div class="flex-row" style="width:100%">' +
           '<button class="btn btn-outline btn-sm flex-1" data-id="' + f.id + '" data-n="' + sn + '" onclick="app.adminAct(\'rename\',this.dataset.id,this.dataset.n);app.closeModal(\'fM\')"><img class="om-emoji" src="/openmoji/270F.svg" alt="✏️"> 重命名</button>' +
           '<button class="btn btn-outline btn-sm flex-1" data-id="' + f.id + '" data-fd="' + this.escapeHTML(f.folder || '') + '" onclick="app.adminAct(\'move\',this.dataset.id,this.dataset.fd);app.closeModal(\'fM\')"><img class="om-emoji" src="/openmoji/2702.svg" alt="✂️"> 移动</button>' +
           '</div>' +
           '<div class="flex-row" style="width:100%">' +
           '<button class="btn ' + (f.is_hidden ? 'btn-warn' : 'btn-outline') + ' btn-sm flex-1" data-id="' + f.id + '" onclick="app.adminAct(\'toggle_hide\',this.dataset.id);app.closeModal(\'fM\')"><img class="om-emoji" src="/openmoji/1F441.svg" alt="👁️"> 显隐</button>' +
           '<button class="btn btn-danger btn-sm flex-1" data-id="' + f.id + '" onclick="app.adminAct(\'delete\',this.dataset.id);app.closeModal(\'fM\')"><img class="om-emoji" src="/openmoji/1F5D1.svg" alt="🗑️"> 删除</button>' +
           '</div>';
    }
    b += '<button class="btn btn-outline" style="width:100%;margin-top:4px;padding:12px;border-radius:12px" onclick="app.closeModal(\'fM\')"><img class="om-emoji" src="/openmoji/274C.svg" alt="❌"> 关闭面板</button>';
    return b;
  },

  bindAdminCmdBtns(f) {
    if (!this.state.isAdmin) return;
    const pq = this.state.currentPwd ? '&pwd=' + encodeURIComponent(this.state.currentPwd) : '';
    const dlUrl = window.location.origin + '/file/' + f.id + '?dl=1' + pq;
    const wgCmd = atob('d2dldCAtTyAi') + f.name + atob('IiAi') + dlUrl + atob('Ig==');
    const cuCmd = atob('Y3VybCAtTCAtbyAi') + f.name + atob('IiAi') + dlUrl + atob('Ig==');
    const wgBtn = document.getElementById('cmd_wg_btn');
    const cuBtn = document.getElementById('cmd_cu_btn');
    if (wgBtn) wgBtn.onclick = () => { app.copyText(wgCmd); app.closeModal('fM'); };
    if (cuBtn) cuBtn.onclick = () => { app.copyText(cuCmd); app.closeModal('fM'); };
  },

  restoreFileActions(fileId) {
    const f = this.state.fileList.find(x => x.id === fileId);
    const c = document.getElementById('file-action-container');
    if (f && c) {
      c.innerHTML = this.getFileActionButtons(f);
      this.bindAdminCmdBtns(f);
    }
  },

  closeModal(id, p) {
    if (id === 'fM' && this.currentDlAbort) {
      this.currentDlAbort.abort();
      this.currentDlAbort = null;
    }
    const m = document.getElementById(id);
    if (m) {
      let closed = false;
      const finishClose = () => {
        if (closed) return;
        closed = true;
        if (['modal-upload', 'modal-cli', 'modal-settings', 'modal-github'].includes(id)) {
          m.style.display = 'none';
          m.style.opacity = '';
          m.style.willChange = '';
          const mc = m.querySelector('.modal-content');
          if (mc) {
            mc.style.opacity = '';
            mc.style.transform = '';
            mc.style.willChange = '';
          }
        } else {
          m.remove();
        }
        // 确保退出动画完成后再解除滚动锁定，避免在动画开始的第一帧触发页面重新布局（Reflow）
        const visibleOverlays = Array.from(document.querySelectorAll('.modal-overlay'))
          .filter(x => x.id !== id && x.style.display !== 'none');
        if (visibleOverlays.length === 0) {
          document.body.classList.remove('modal-open');
          document.documentElement.classList.remove('modal-open');
        }
      };
      if (!p) history.back();
      try {
        const mc = m.querySelector('.modal-content');
        m.style.willChange = 'opacity';
        if (mc) {
          mc.style.willChange = 'transform, opacity';
          mc.animate(
            [{ transform: 'scale(1) translateY(0)', opacity: 1 }, { transform: 'scale(0.96) translateY(10px)', opacity: 0 }],
            { duration: 180, easing: 'cubic-bezier(0.25, 1, 0.5, 1)', fill: 'forwards' }
          );
        }
        const a = m.animate(
          [{ opacity: 1 }, { opacity: 0 }],
          { duration: 180, easing: 'ease-out', fill: 'forwards' }
        );
        a.onfinish = finishClose;
        setTimeout(finishClose, 210);
      } catch (e) {
        finishClose();
      }
    }
  },

  async getFastHash(t) {
    const b = new TextEncoder().encode(t);
    const h = await crypto.subtle.digest('SHA-1', b);
    return Array.from(new Uint8Array(h)).map(x => x.toString(16).padStart(2, '0')).join('');
  },

  async getRealSha256(buf) {
    const h = await crypto.subtle.digest('SHA-256', buf);
    return btoa(String.fromCharCode(...new Uint8Array(h)));
  },

  async fetchWithTimeout(u, o, t = 60000) {
    const c = new AbortController();
    const i = setTimeout(() => c.abort(), t);
    if (o.signal) {
      o.signal.addEventListener('abort', () => c.abort());
      if (o.signal.aborted) c.abort();
    }
    try {
      return await fetch(u, { ...o, signal: c.signal });
    } catch (e) {
      if (e.name === 'AbortError' && !o.signal?.aborted) throw new Error('Timeout');
      throw e;
    } finally {
      clearTimeout(i);
    }
  },


  formatBytes(b) {
    if (!b) return '0 B';
    const k = 1024,
          s = ['B', 'KB', 'MB', 'GB', 'TB'],
          i = Math.floor(Math.log(b) / Math.log(k));
    return parseFloat((b / Math.pow(k, i)).toFixed(2)) + ' ' + s[i];
  }
};

window.addEventListener('DOMContentLoaded', () => {
  app.init();
});
