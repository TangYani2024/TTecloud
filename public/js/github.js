Object.assign(app, {
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

      const shareId = rule.shareId || rule.id;
      const fixedUrl = `${window.location.origin}/share/${shareId}`;

      let updateNotice = '';
      if (rule.hasUpdateToActivate) {
        updateNotice = `<div style="background:rgba(245,158,11,0.12);border:1px dashed #f59e0b;padding:8px 12px;border-radius:8px;margin-top:8px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">
          <div style="font-size:12px;color:#d97706;font-weight:bold;display:flex;align-items:center;gap:4px">
            <span>🟡 新版本就绪</span>
            <span style="color:gray;font-weight:normal">(旧版本分享链接仍可用)</span>
          </div>
          <button type="button" class="btn btn-sm btn-primary" style="padding:4px 12px;font-size:12px;background:#f59e0b;border:none;font-weight:bold" onclick="app.activateGithubUpdate('${rule.id}')">✨ 激活新版本 (替代旧分享)</button>
        </div>`;
      }

      h += `<div class="gh-rule-card" id="gh-card-${rule.id}">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:10px">
          <div style="font-weight:bold;font-size:15px;word-break:break-all">
            ${/^https?:\/\//i.test(rule.repo) && !rule.repo.includes('github.com')
              ? `<a href="${this.escapeHTML(rule.repo)}" target="_blank" style="color:var(--primary);text-decoration:none;display:inline-flex;align-items:center;gap:4px">
                  🌐 ${this.escapeHTML(rule.repo)}
                  <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
                </a>`
              : `<a href="https://github.com/${this.escapeHTML(rule.repo)}" target="_blank" style="color:var(--primary);text-decoration:none;display:inline-flex;align-items:center;gap:4px">
                  ${this.escapeHTML(rule.repo)}
                  <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
                </a>`
            }
          </div>
          <span class="gh-badge gh-badge-tag">${this.escapeHTML(lastTag)}</span>
        </div>
        <div style="font-size:12px;color:gray;display:flex;flex-wrap:wrap;align-items:center;gap:8px">
          <span>📂 存放目录: <b style="color:var(--tx)">${this.escapeHTML(folder)}</b></span>
          <span>•</span>
          <span>包含: ${incBadges}</span>
          ${excBadges ? `<span>•</span><span>排除: ${excBadges}</span>` : ''}
        </div>
        <div style="font-size:12px;color:gray;display:flex;align-items:center;gap:8px;margin-top:2px">
          <span>🔗 8位固定直达: <code style="color:var(--primary);background:rgba(0,0,0,0.05);padding:2px 6px;border-radius:4px;font-family:monospace;font-weight:bold">${this.escapeHTML(shareId)}</code></span>
          <button type="button" class="btn btn-sm btn-outline" style="padding:2px 8px;font-size:11px" onclick="app.copyFixedShareLink('${shareId}')">📋 复制直链</button>
        </div>
        ${updateNotice}
        <div style="display:flex;justify-content:space-between;align-items:center;margin-top:6px;padding-top:8px;border-top:1px solid var(--cd);flex-wrap:wrap;gap:8px">
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

  copyFixedShareLink(shareId) {
    const url = `${window.location.origin}/share/${shareId}`;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(url).then(() => {
        this.toast('📋 已复制 8 位永久固定直达链接！');
      }).catch(() => {
        prompt('请手动复制固定直链:', url);
      });
    } else {
      prompt('请手动复制固定直链:', url);
    }
  },

  async activateGithubUpdate(ruleId) {
    if (!confirm('确认激活新版本并替代旧分享？\n此操作将生成新版分享，同时彻底废弃并清理上一代旧版本文件。')) return;
    try {
      const res = await fetch('/api/admin/github/activate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ruleId })
      });
      const data = await res.json();
      if (data.ok) {
        this.toast('✨ 新版本已激活！旧分享链接已失效');
        await this.loadGithubRules();
        if (typeof this.loadData === 'function') this.loadData();
      } else {
        alert(data.error || '激活失败');
      }
    } catch (e) {
      alert('网络请求失败');
    }
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
    const isDirect = /^https?:\/\//i.test(repo) && !/^https?:\/\/github\.com\/[^\/]+\/[^\/]+(?:\/)?$/i.test(repo);
    if (!isDirect) {
      repo = repo.replace(/^https?:\/\/github\.com\//, '').replace(/\/$/, '');
      if (!repo || !repo.includes('/')) return alert('请输入有效的 GitHub 仓库 (如: topjohnwu/Magisk) 或 http/https 文件下载直链');
    }

    let folder = (document.getElementById('gh-folder').value || '').trim();
    if (!folder) {
      if (isDirect) {
        try {
          folder = new URL(repo).hostname.replace(/[^a-zA-Z0-9_\u4e00-\u9fa5]/g, '_');
        } catch (_) {
          folder = '直链追更';
        }
      } else {
        folder = repo.split('/')[1] || repo;
      }
    }
    const include = (document.getElementById('gh-include').value || '').trim();
    const exclude = (document.getElementById('gh-exclude').value || '').trim();
    const ruleId = document.getElementById('gh-rule-id').value;

    let rules = [...(this.githubSyncRules || [])];
    if (ruleId) {
      const idx = rules.findIndex(r => r.id === ruleId);
      if (idx !== -1) {
        rules[idx] = { ...rules[idx], repo, folder, include, exclude };
        if (!rules[idx].shareId) {
          const chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
          let s = '';
          for (let i = 0; i < 8; i++) s += chars.charAt(Math.floor(Math.random() * chars.length));
          rules[idx].shareId = s;
        }
      }
    } else {
      const chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
      let shortId = '';
      for (let i = 0; i < 8; i++) shortId += chars.charAt(Math.floor(Math.random() * chars.length));
      rules.push({
        id: 'gh_' + Date.now() + '_' + Math.random().toString(36).substr(2, 4),
        shareId: shortId,
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

    const isDirect = /^https?:\/\//i.test(rule.repo) && !rule.repo.includes('github.com');
    const cleanRepo = isDirect ? rule.repo : rule.repo.trim().replace(/^https?:\/\/github\.com\//, '').replace(/\/$/, '');
    document.getElementById('uploadStatus').innerHTML = `<img class="om-emoji" src="/openmoji/1F50D.svg" alt="🔍"> 正在检查 [${this.escapeHTML(cleanRepo)}] 最新更新...`;
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
});
