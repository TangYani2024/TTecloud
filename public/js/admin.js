Object.assign(app, {
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
        const ua = (window.appConfig && window.appConfig.s3 && window.appConfig.s3.userAgent) || 'S3Drive';
        const expHeader = this.settings.expect ? '-H "Expect: " ' : '';
        this.copyText('curl -A "' + ua + '" -# -X PUT -H "Content-Type: application/octet-stream" ' + expHeader + '-T "' + fn + '" "' + res.url + '"');
        alert('✅ 已生成并复制专属 Curl 直传命令（内置 ' + ua + ' 伪装头）！在终端直接粘贴执行即可。');
      }
    } catch (e) {
      alert('生成失败');
    }
  },

});
