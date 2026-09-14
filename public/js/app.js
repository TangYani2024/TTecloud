const ICONS = {
  folder: `<svg class="ui-svg-icon" viewBox="0 0 24 24" fill="none">
    <path d="M4 20h16a1 1 0 0 0 1-1V7a1 1 0 0 0-1-1h-7l-2-3H5a1 1 0 0 0-1 1v15a1 1 0 0 0 1 1Z" fill="#F59E0B" fill-opacity="0.26" stroke="#F59E0B" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/>
    <path d="M3 8h18v11a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V8Z" fill="#FFD23F" fill-opacity="0.32" stroke="#F59E0B" stroke-width="1.1" stroke-linecap="round" stroke-linejoin="round"/>
    <path d="M3 8h18" stroke="#FFE57F" stroke-width="0.9" stroke-opacity="0.8" stroke-linecap="round"/>
  </svg>`,

  folderLocked: `<svg class="ui-svg-icon" viewBox="0 0 24 24" fill="none">
    <path d="M4 20h16a1 1 0 0 0 1-1V7a1 1 0 0 0-1-1h-7l-2-3H5a1 1 0 0 0-1 1v15a1 1 0 0 0 1 1Z" fill="#C780E8" fill-opacity="0.15" stroke="#C780E8" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/>
    <path d="M3 8h18v11a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V8Z" fill="#E0A9F5" fill-opacity="0.18" stroke="#E0A9F5" stroke-width="1.1" stroke-linecap="round" stroke-linejoin="round"/>
    <rect x="9" y="13" width="6" height="5" rx="1" fill="#2C1B4E" fill-opacity="0.5" stroke="#A070D0" stroke-width="1" stroke-linecap="round"/>
    <path d="M12 13v-1.5a1.5 1.5 0 0 0-3 0V13" stroke="#A070D0" stroke-width="1.1" fill="none" stroke-linecap="round"/>
    <circle cx="12" cy="15.5" r="0.8" fill="#FFE499" fill-opacity="0.8" stroke="none"/>
  </svg>`,

  archive: `<svg class="ui-svg-icon" viewBox="0 0 24 24" fill="none">
    <path d="M4 20h16a1 1 0 0 0 1-1V7a1 1 0 0 0-1-1h-7l-2-3H5a1 1 0 0 0-1 1v15a1 1 0 0 0 1 1Z" fill="#4ECDC4" fill-opacity="0.15" stroke="#4ECDC4" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/>
    <path d="M3 8h18v11a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V8Z" fill="#A8E6E0" fill-opacity="0.18" stroke="#A8E6E0" stroke-width="1.1" stroke-linecap="round" stroke-linejoin="round"/>
    <path d="M12 6v12" stroke="#4ECDC4" stroke-width="1.4" stroke-dasharray="1.8 2.2" stroke-opacity="0.7" stroke-linecap="round"/>
    <rect x="11" y="9" width="2" height="2" rx="0.5" fill="#4ECDC4" fill-opacity="0.5" stroke="none"/>
    <rect x="11" y="13" width="2" height="2" rx="0.5" fill="#4ECDC4" fill-opacity="0.5" stroke="none"/>
  </svg>`,

  video: `<svg class="ui-svg-icon" viewBox="0 0 24 24" fill="none">
    <rect x="2" y="6" width="20" height="12" rx="2.5" fill="#1E3A5F" fill-opacity="0.35" stroke="#4A9EFF" stroke-width="1.2" stroke-linecap="round"/>
    <rect x="5" y="9" width="3" height="6" rx="0.8" fill="#4A9EFF" fill-opacity="0.2" stroke="none"/>
    <rect x="16" y="9" width="3" height="6" rx="0.8" fill="#4A9EFF" fill-opacity="0.2" stroke="none"/>
    <circle cx="12" cy="12" r="2.8" fill="#FF6B9D" fill-opacity="0.35" stroke="#FF6B9D" stroke-width="1" stroke-linecap="round"/>
    <path d="M11 10.8v2.4l2-1.2-2-1.2Z" fill="#FFB3D1" fill-opacity="0.7" stroke="none"/>
  </svg>`,

  audio: `<svg class="ui-svg-icon" viewBox="0 0 24 24" fill="none">
    <circle cx="8" cy="17" r="3.2" fill="#C445B5" fill-opacity="0.2" stroke="#C445B5" stroke-width="1.2" stroke-linecap="round"/>
    <circle cx="18" cy="15" r="3.2" fill="#C445B5" fill-opacity="0.2" stroke="#C445B5" stroke-width="1.2" stroke-linecap="round"/>
    <path d="M11 17V6l9-2v11" stroke="#C445B5" stroke-width="1.3" fill="none" stroke-opacity="0.7" stroke-linecap="round"/>
    <path d="M11 11l9-2" stroke="#C445B5" stroke-width="1.1" fill="none" stroke-opacity="0.5" stroke-linecap="round"/>
    <circle cx="8" cy="17" r="1" fill="#FFE066" fill-opacity="0.6" stroke="none"/>
    <circle cx="18" cy="15" r="1" fill="#FFE066" fill-opacity="0.6" stroke="none"/>
  </svg>`,

  document: `<svg class="ui-svg-icon" viewBox="0 0 24 24" fill="none">
    <path d="M6 3h8l5 5v13a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1Z" fill="#E0ECFF" fill-opacity="0.15" stroke="#8AB8E8" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/>
    <path d="M14 3v5h5" fill="none" stroke="#8AB8E8" stroke-width="1.2" stroke-opacity="0.7" stroke-linecap="round" stroke-linejoin="round"/>
    <path d="M9 13h6M9 17h4" stroke="#8AB8E8" stroke-width="1.1" stroke-linecap="round" stroke-opacity="0.5"/>
  </svg>`,

  code: `<svg class="ui-svg-icon" viewBox="0 0 24 24" fill="none">
    <path d="M6 3h8l5 5v13a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1Z" fill="#1E2A3A" fill-opacity="0.4" stroke="#61DAFB" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/>
    <path d="M14 3v5h5" fill="none" stroke="#61DAFB" stroke-width="1.2" stroke-opacity="0.6" stroke-linecap="round" stroke-linejoin="round"/>
    <path d="M10.5 13.5L8.5 16l2 2.5" stroke="#61DAFB" stroke-width="1.3" fill="none" stroke-linecap="round" stroke-linejoin="round" stroke-opacity="0.9"/>
    <path d="M13.5 13.5l2 2.5-2 2.5" stroke="#61DAFB" stroke-width="1.3" fill="none" stroke-linecap="round" stroke-linejoin="round" stroke-opacity="0.9"/>
    <circle cx="12" cy="9" r="1" fill="#F0DB4F" fill-opacity="0.6" stroke="none"/>
  </svg>`
};

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
        btn.innerHTML = '<img class="om-emoji" src="/openmoji/26A1.svg" alt="⚡"> 发起多线程疾速并发上传';
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

  githubSyncRules: [],

  githubTab: 'list',

  switchGithubTab(tab) {
    this.githubTab = tab;
    const listPanel = document.getElementById('gh-tab-list');
    const formPanel = document.getElementById('gh-tab-form');
    const listBtn = document.getElementById('gh-tab-list-btn');
    const formBtn = document.getElementById('gh-tab-form-btn');
    if (tab === 'form') {
      if (listPanel) listPanel.style.display = 'none';
      if (formPanel) formPanel.style.display = 'flex';
      if (listBtn) listBtn.classList.remove('active');
      if (formBtn) formBtn.classList.add('active');
    } else {
      if (listPanel) listPanel.style.display = 'flex';
      if (formPanel) formPanel.style.display = 'none';
      if (listBtn) listBtn.classList.add('active');
      if (formBtn) formBtn.classList.remove('active');
    }
  },

  showGithubModal() {
    if (this.githubSyncRules && this.githubSyncRules.length > 0) {
      this.renderGithubRules();
    }
    this.openStaticModal('modal-github');
    setTimeout(() => {
      this.loadGithubRules();
    }, 50);
  },

  hasGithubToken: false,

  async loadGithubRules() {
    try {
      const r = await fetch(`/api/admin/github/rules?t=${Date.now()}`, {
        cache: 'no-store',
        headers: { 'Cache-Control': 'no-cache' }
      });
      if (r.ok) {
        const data = await r.json();
        const prevJson = JSON.stringify(this.githubSyncRules || []);
        if (Array.isArray(data)) {
          this.githubSyncRules = data;
          this.hasGithubToken = false;
        } else {
          this.githubSyncRules = data.rules || [];
          this.hasGithubToken = !!data.hasToken;
        }
        if (this.githubSyncRules.length === 0 && !document.getElementById('gh-rule-id').value) {
          this.switchGithubTab('form');
        } else if (this.githubTab !== 'form') {
          this.switchGithubTab('list');
        }
        const listEl = document.getElementById('gh-rules-list');
        if (prevJson !== JSON.stringify(this.githubSyncRules) || !listEl || !listEl.hasChildNodes()) {
          this.renderGithubRules();
        } else {
          const tokenStatusEl = document.getElementById('gh-token-status');
          const countEl = document.getElementById('gh-count');
          if (countEl) countEl.innerText = (this.githubSyncRules || []).length;
          if (tokenStatusEl) {
            tokenStatusEl.innerHTML = this.hasGithubToken
              ? '<span style="color:#10b981;font-weight:bold;display:inline-flex;align-items:center;gap:4px">🟢 GITHUB_TOKEN 就绪 (5000次/时)</span>'
              : '<span style="color:#f59e0b;font-weight:bold;display:inline-flex;align-items:center;gap:4px">⚠️ 未配 TOKEN</span><span style="color:gray;font-size:11px">（防403限频）</span>';
          }
        }
      }
    } catch (e) {}
  },

  renderGithubRules() {
    const listEl = document.getElementById('gh-rules-list');
    const countEl = document.getElementById('gh-count');
    const tokenStatusEl = document.getElementById('gh-token-status');
    if (tokenStatusEl) {
      if (this.hasGithubToken) {
        tokenStatusEl.innerHTML = '<span style="color:#10b981;font-weight:bold;display:inline-flex;align-items:center;gap:4px">🟢 GITHUB_TOKEN 就绪 (5000次/时)</span>';
      } else {
        tokenStatusEl.innerHTML = '<span style="color:#f59e0b;font-weight:bold;display:inline-flex;align-items:center;gap:4px">⚠️ 未配 TOKEN</span><span style="color:gray;font-size:11px">（防403限频）</span>';
      }
    }
    if (!listEl) return;
    const rules = this.githubSyncRules || [];
    if (countEl) countEl.innerText = rules.length;
    if (rules.length === 0) {
      listEl.innerHTML = `<div style="text-align:center;padding:36px 16px;color:gray;background:rgba(0,0,0,0.02);border-radius:12px;border:1px dashed var(--cd)">
        <div style="font-size:32px;margin-bottom:8px">📦</div>
        <div style="font-size:14px;font-weight:bold;margin-bottom:6px;color:var(--tx)">暂无已订阅的 GitHub 项目</div>
        <div style="font-size:12px;margin-bottom:16px;line-height:1.5">添加订阅后，系统将自动检测最新 Release 并同步到您的网盘</div>
        <button type="button" class="btn btn-sm btn-primary" style="padding:6px 16px;font-size:13px" onclick="app.switchGithubTab('form')">➕ 立即添加追更项目</button>
      </div>`;
      return;
    }

    let h = '';
    rules.forEach(rule => {
      const inc = (rule.include || '').trim();
      const exc = (rule.exclude || '').trim();
      const lastTag = rule.lastTag || '未同步';
      const lastTime = rule.lastUpdatedAt || '从未更新';
      const folder = rule.folder || rule.repo.split('/')[1] || rule.repo;

      let incBadges = inc ? inc.split(/[,，\s]+/).filter(Boolean).map(w => `<span class="gh-badge gh-badge-inc">+ ${this.escapeHTML(w)}</span>`).join(' ') : '<span style="color:gray;font-size:11px">全部</span>';
      let excBadges = exc ? exc.split(/[,，\s]+/).filter(Boolean).map(w => `<span class="gh-badge gh-badge-exc">- ${this.escapeHTML(w)}</span>`).join(' ') : '';

      h += `<div class="gh-rule-card" id="gh-card-${rule.id}">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:10px">
          <div style="font-weight:bold;font-size:15px;word-break:break-all">
            <a href="https://github.com/${this.escapeHTML(rule.repo)}" target="_blank" style="color:var(--primary);text-decoration:none;display:inline-flex;align-items:center;gap:4px">
              ${this.escapeHTML(rule.repo)}
              <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
            </a>
          </div>
          <span class="gh-badge gh-badge-tag">${this.escapeHTML(lastTag)}</span>
        </div>
        <div style="font-size:12px;color:gray;display:flex;flex-wrap:wrap;align-items:center;gap:8px">
          <span>📂 存放目录: <b style="color:var(--tx)">${this.escapeHTML(folder)}</b></span>
          <span>•</span>
          <span>包含: ${incBadges}</span>
          ${excBadges ? `<span>•</span><span>排除: ${excBadges}</span>` : ''}
        </div>
        <div style="display:flex;justify-content:space-between;align-items:center;margin-top:4px;padding-top:8px;border-top:1px solid var(--cd);flex-wrap:wrap;gap:8px">
          <span class="gh-badge-time">🕒 更新时间: ${this.escapeHTML(lastTime)}</span>
          <div style="display:flex;gap:6px">
            <button class="btn btn-sm btn-outline" style="padding:4px 10px;font-size:12px" onclick="app.editGithubRule('${rule.id}')">✏️ 编辑</button>
            <button class="btn btn-sm btn-danger" style="padding:4px 10px;font-size:12px" onclick="app.deleteGithubRule('${rule.id}')">🗑️ 删除</button>
            <button class="btn btn-sm btn-success" style="padding:4px 12px;font-size:12px;font-weight:bold" onclick="app.syncGithubRelease('${rule.id}', true)">🔄 追更</button>
          </div>
        </div>
      </div>`;
    });
    listEl.innerHTML = h;
  },

  resetGithubForm() {
    document.getElementById('gh-rule-id').value = '';
    document.getElementById('gh-repo').value = '';
    document.getElementById('gh-folder').value = '';
    document.getElementById('gh-include').value = '';
    document.getElementById('gh-exclude').value = '';
    document.getElementById('gh-form-title').innerText = '➕ 添加追更项目';
    document.getElementById('gh-cancel-edit-btn').style.display = 'none';
  },

  editGithubRule(id) {
    const rule = (this.githubSyncRules || []).find(r => r.id === id);
    if (!rule) return;
    document.getElementById('gh-rule-id').value = rule.id;
    document.getElementById('gh-repo').value = rule.repo;
    document.getElementById('gh-folder').value = rule.folder || '';
    document.getElementById('gh-include').value = rule.include || '';
    document.getElementById('gh-exclude').value = rule.exclude || '';
    document.getElementById('gh-form-title').innerText = '✏️ 编辑追更项目';
    document.getElementById('gh-cancel-edit-btn').style.display = 'inline-block';
    this.switchGithubTab('form');
    const formEl = document.getElementById('gh-repo');
    if (formEl) formEl.focus();
  },

  async saveGithubRule() {
    let repo = (document.getElementById('gh-repo').value || '').trim();
    repo = repo.replace(/^https?:\/\/github\.com\//, '').replace(/\/$/, '');
    if (!repo || !repo.includes('/')) return alert('请输入有效的 GitHub 仓库，例如: topjohnwu/Magisk');

    const folder = (document.getElementById('gh-folder').value || '').trim() || repo.split('/')[1] || repo;
    const include = (document.getElementById('gh-include').value || '').trim();
    const exclude = (document.getElementById('gh-exclude').value || '').trim();
    const ruleId = document.getElementById('gh-rule-id').value;

    let rules = [...(this.githubSyncRules || [])];
    if (ruleId) {
      const idx = rules.findIndex(r => r.id === ruleId);
      if (idx !== -1) {
        rules[idx] = { ...rules[idx], repo, folder, include, exclude };
      }
    } else {
      rules.push({
        id: 'gh_' + Date.now() + '_' + Math.random().toString(36).substr(2, 4),
        repo,
        folder,
        include,
        exclude,
        lastTag: '',
        lastUpdatedAt: '',
        lastFiles: []
      });
    }

    try {
      const r = await fetch('/api/admin/github/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rules })
      });
      if (r.ok) {
        this.githubSyncRules = rules;
        this.renderGithubRules();
        this.resetGithubForm();
        this.switchGithubTab('list');
        this.toast('✅ 追更配置已保存');
      } else {
        alert('保存失败');
      }
    } catch (e) {
      alert('网络请求失败');
    }
  },

  async deleteGithubRule(id) {
    if (!confirm('确定删除该追更订阅？')) return;
    const rules = (this.githubSyncRules || []).filter(r => r.id !== id);
    try {
      const r = await fetch('/api/admin/github/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rules })
      });
      if (r.ok) {
        this.githubSyncRules = rules;
        this.renderGithubRules();
        this.resetGithubForm();
        this.toast('🗑️ 订阅已移除');
      }
    } catch (e) {}
  },

  async syncGithubRelease(ruleId, force = false) {
    const rule = (this.githubSyncRules || []).find(r => r.id === ruleId);
    if (!rule) return;

    this.closeModal('modal-github');
    const upEl = document.getElementById('uploadProgress');
    if (upEl) upEl.style.display = 'block';

    const cleanRepo = rule.repo.trim().replace(/^https?:\/\/github\.com\//, '').replace(/\/$/, '');
    document.getElementById('uploadStatus').innerHTML = `<img class="om-emoji" src="/openmoji/1F50D.svg" alt="🔍"> 正在检查 [${this.escapeHTML(cleanRepo)}] 最新 Release...`;
    document.getElementById('uploadPercent').innerText = '1 / 1';
    document.getElementById('uploadProgressBar').style.width = '30%';

    document.getElementById('queueList').innerHTML = `<div style="font-size:12px;background:rgba(255,255,255,0.4);padding:8px 12px;border-radius:8px;border:1px solid var(--cd);">
      <div style="display:flex;justify-content:space-between;">
        <span style="font-weight:bold;">${this.escapeHTML(cleanRepo)}</span>
        <span class="q-status" style="color:var(--primary)">云端分析中...</span>
      </div>
    </div>`;

    try {
      document.getElementById('uploadProgressBar').style.width = '60%';
      const r = await fetch('/api/admin/github/sync', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ruleId, force })
      });
      const res = await r.json();

      document.getElementById('uploadProgressBar').style.width = '100%';
      if (res.ok) {
        if (res.tag) rule.lastTag = res.tag;
        if (res.time) rule.lastUpdatedAt = res.time;
        this.renderGithubRules();

        if (res.skipped) {
          document.getElementById('uploadStatus').innerHTML = `<img class="om-emoji" src="/openmoji/2705.svg" alt="✅"> ${this.escapeHTML(res.msg)}`;
          document.getElementById('uploadStatus').style.color = '#10b981';
        } else {
          document.getElementById('uploadStatus').innerHTML = `<img class="om-emoji" src="/openmoji/1F389.svg" alt="🎉"> ${this.escapeHTML(res.msg)}`;
          document.getElementById('uploadStatus').style.color = '#10b981';
          this.toast('🎉 追更成功，旧版本已清理！');
        }
      } else {
        document.getElementById('uploadStatus').innerHTML = `<img class="om-emoji" src="/openmoji/274C.svg" alt="❌"> 追更失败: ${this.escapeHTML(res.error || '未知错误')}`;
        document.getElementById('uploadStatus').style.color = '#ef4444';
      }

      await this.loadGithubRules();
      this.fetchData();

      setTimeout(() => {
        if (upEl && !this.isUploading) upEl.style.display = 'none';
      }, 3500);
    } catch (e) {
      document.getElementById('uploadStatus').innerHTML = `<img class="om-emoji" src="/openmoji/274C.svg" alt="❌"> 网络中断`;
      document.getElementById('uploadStatus').style.color = '#ef4444';
      setTimeout(() => {
        if (upEl && !this.isUploading) upEl.style.display = 'none';
      }, 3000);
    }
  },

  async syncAllGithubReleases() {
    const rules = this.githubSyncRules || [];
    if (rules.length === 0) return alert('当前没有已添加的追更项目');

    this.closeModal('modal-github');
    const upEl = document.getElementById('uploadProgress');
    if (upEl) upEl.style.display = 'block';

    let total = rules.length;
    let completed = 0;
    document.getElementById('uploadStatus').innerHTML = `<img class="om-emoji" src="/openmoji/26A1.svg" alt="⚡"> 正在批量检查 GitHub 追更 (0/${total})...`;
    document.getElementById('uploadPercent').innerText = `0 / ${total}`;
    document.getElementById('uploadProgressBar').style.width = '5%';

    let qHtml = '';
    rules.forEach(r => {
      qHtml += `<div id="gh_q_${r.id}" style="font-size:12px;background:rgba(255,255,255,0.4);padding:8px 12px;border-radius:8px;border:1px solid var(--cd);margin-bottom:4px">
        <div style="display:flex;justify-content:space-between;">
          <span style="font-weight:bold;">${this.escapeHTML(r.repo)}</span>
          <span class="q-st" style="color:var(--primary)">排队中</span>
        </div>
      </div>`;
    });
    document.getElementById('queueList').innerHTML = qHtml;

    for (let r of rules) {
      const qRow = document.getElementById(`gh_q_${r.id}`);
      if (qRow) {
        const st = qRow.querySelector('.q-st');
        if (st) st.innerText = '检查更新中...';
      }
      try {
        const res = await (await fetch('/api/admin/github/sync', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ruleId: r.id })
        })).json();

        if (res.ok) {
          if (res.tag) r.lastTag = res.tag;
          if (res.time) r.lastUpdatedAt = res.time;
          this.renderGithubRules();
        }

        if (qRow) {
          const st = qRow.querySelector('.q-st');
          if (st) {
            if (res.ok) {
              st.innerHTML = res.skipped ? '已是最新' : '✅ 已同步更新';
              st.style.color = '#10b981';
            } else {
              st.innerHTML = '❌ 失败';
              st.style.color = '#ef4444';
            }
          }
        }
      } catch (err) {
        if (qRow) {
          const st = qRow.querySelector('.q-st');
          if (st) { st.innerHTML = '❌ 异常'; st.style.color = '#ef4444'; }
        }
      }
      completed++;
      document.getElementById('uploadPercent').innerText = `${completed} / ${total}`;
      document.getElementById('uploadProgressBar').style.width = `${Math.round((completed / total) * 100)}%`;
      document.getElementById('uploadStatus').innerHTML = `<img class="om-emoji" src="/openmoji/26A1.svg" alt="⚡"> 正在批量检查 GitHub 追更 (${completed}/${total})...`;
    }

    document.getElementById('uploadStatus').innerHTML = `<img class="om-emoji" src="/openmoji/1F389.svg" alt="🎉"> 全部追更检查完毕！`;
    await this.loadGithubRules();
    this.fetchData();
    setTimeout(() => {
      if (upEl && !this.isUploading) upEl.style.display = 'none';
    }, 3500);
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
      const renderDom = () => {
        if (rs.mode === 'folders') this.renderFolders(rs.data);
        else this.renderFiles(rs.data);
      };
      
      if (document.startViewTransition) document.startViewTransition(() => renderDom());
      else renderDom();
    } catch (e) {}
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
    mc.style.willChange = 'transform, opacity';
    m.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 200, fill: 'forwards' });
    mc.animate([{ transform: 'scale(0.95) translateY(15px)', opacity: 0 }, { transform: 'scale(1) translateY(0)', opacity: 1 }], { duration: 350, easing: 'cubic-bezier(0.175,0.885,0.32,1.275)', fill: 'forwards' });
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
      const visibleOverlays = Array.from(document.querySelectorAll('.modal-overlay'))
        .filter(x => x.id !== id && x.style.display !== 'none');
      if (visibleOverlays.length === 0) {
        document.body.classList.remove('modal-open');
        document.documentElement.classList.remove('modal-open');
      }
      const finishClose = () => {
        if (['modal-upload', 'modal-cli', 'modal-settings', 'modal-github'].includes(id)) {
          m.style.display = 'none';
          m.style.opacity = '';
          const mc = m.querySelector('.modal-content');
          if (mc) {
            mc.style.opacity = '';
            mc.style.transform = '';
          }
        } else {
          m.remove();
        }
      };
      if (!p) history.back();
      try {
        const mc = m.querySelector('.modal-content');
        if (mc) mc.animate([{ transform: 'scale(1) translateY(0)', opacity: 1 }, { transform: 'scale(0.95) translateY(12px)', opacity: 0 }], { duration: 150, easing: 'ease-in' });
        const a = m.animate([{ opacity: 1 }, { opacity: 0 }], { duration: 150 });
        a.onfinish = finishClose;
        setTimeout(finishClose, 180);
      } catch (e) {
        finishClose();
      }
    }
  },

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
          '<button type="button" class="btn btn-sm btn-outline flex-1" onclick="app.abortCurrentDownload(\'' + f.id + '\')">取消下载</button>' +
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
          '<button type="button" class="btn btn-sm btn-outline flex-1" onclick="app.abortCurrentDownload(\'' + f.id + '\')">取消下载</button>' +
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
          '<a href="' + dlUrl + '" class="btn btn-outline" target="_blank" style="text-decoration:none;padding:10px" onclick="app.closeModal(\'tpM\',1)">' +
            '<img class="om-emoji" src="/openmoji/1F4E5.svg" alt="📥"> 仍尝试浏览器原生下载' +
          '</a>' +
          '<button type="button" class="btn btn-outline" style="padding:10px" onclick="app.closeModal(\'tpM\',1)">关闭</button>' +
        '</div>' +
      '</div>';
    document.body.appendChild(m);
    document.body.classList.add('modal-open');
    document.documentElement.classList.add('modal-open');
    const mc = m.querySelector('.modal-content');
    mc.style.willChange = 'transform, opacity';
    m.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 200, fill: 'forwards' });
    mc.animate([{ transform: 'scale(0.95) translateY(15px)', opacity: 0 }, { transform: 'scale(1) translateY(0)', opacity: 1 }], { duration: 350, easing: 'cubic-bezier(0.175,0.885,0.32,1.275)', fill: 'forwards' });
  },

  async adminAct(a, i, p) {
    let rq = { action: a, id: i, viewMode: this.state.view };
    if (a === 'delete' && !confirm('永久删除？')) return;
    if (a === 'rename') {
      const n = prompt('新名称：', p);
      if (!n || n === p) return;
      rq.name = n;
    }
    if (a === 'move') {
      const n = prompt('目标目录 (留空为根目录/空白目录)：', p || '');
      if (n === null || n === p) return;
      rq.folder = n;
    }
    if (a === 'sync_d1_ghosts' && !confirm('清死链？')) return;
    if (a === 'sync_b2_orphans' && !confirm('极度危险！会永久删除B2中未记录的文件！确定？')) return;
    if (a === 'sync_b2_to_d1' && !confirm('将B2中的游离文件同步到D1的[B2直传同步]目录？')) return;

    try {
      const r = await fetch('/api/admin/action', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(rq)
      });
      const rs = await r.json();
      if (rs.msg) alert(rs.msg);
      this.fetchData();
    } catch (e) {
      alert('操作失败');
    }
  },

  async adminFolder(f) {
    const fName = (f === null || f === undefined) ? '' : String(f);
    const displayName = fName.trim() || '空白目录';
    const p = prompt('目录[' + displayName + ']密码(留空清除)：');
    if (p === null) return;
    await fetch('/api/admin/action', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'lock_folder', folder: fName, password: p })
    });
    this.fetchData();
  },

  switchUploadMode(m) {
    document.querySelectorAll('#up-nav .nav-tab').forEach(b => {
      b.classList.toggle('active', b.id === 'mode-' + m);
    });
    this.updInd('ind-up', document.getElementById('mode-' + m));
    const fl = document.getElementById('form-local'),
          fcli = document.getElementById('form-cli'),
          fset = document.getElementById('form-settings');
    fl.style.display = m === 'local' ? 'flex' : 'none';
    fcli.style.display = m === 'cli' ? 'flex' : 'none';
    fset.style.display = m === 'settings' ? 'flex' : 'none';
    document.getElementById('uploadProgress').style.display = 'none';

    if (m === 'cli') {
      const bn = this.state.view === 'image' ? 'tangyani-tuchuang' : 'tangyani-ziyuan';
      document.getElementById('cli-bk1').innerText = bn;
      document.getElementById('cli-bk2').innerText = bn;
    }
  },

  async generateCliUpload() {
    const fn = document.getElementById('cli-temp-name').value.trim();
    if (!fn) return alert('请输入要上传的本地文件路径与文件名');
    try {
      const r = await fetch('/api/admin/cli_presign', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ filename: fn, type: this.state.view })
      });
      const res = await r.json();
      if (res.url) {
        const expHeader = this.settings.expect ? atob('LUggIkV4cGVjdSIsI') + '' : '';
        this.copyText(atob('Y3VybCAtIyAtWCBQVVQgLUggIkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vb2N0ZXQtc3RyZWFtIiA=') + expHeader + atob('LVQgIg==') + fn + '" "' + res.url + '"');
        alert('✅ 已生成并复制专属 ' + atob('Q3VybA==') + ' 直传命令！在终端直接粘贴执行即可。');
      }
    } catch (e) {
      alert('生成失败');
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
    mc.style.willChange = 'transform, opacity';
    m.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 200, fill: 'forwards' });
    mc.animate([{ transform: 'scale(0.95) translateY(15px)', opacity: 0 }, { transform: 'scale(1) translateY(0)', opacity: 1 }], { duration: 350, easing: 'cubic-bezier(0.175,0.885,0.32,1.275)', fill: 'forwards' });
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
