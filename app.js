(function(){
  'use strict';

  const headers=['ID Issue','Tanggal Temuan','Aplikasi / Sistem','Jenis Insiden','Deskripsi','Domain Kontrol','Severity','Faktor Penyebab','Remediasi','PIC','Target Selesai Pentest','Status Kerentanan','Tanggal Selesai Remediasi','Notifikasi','Status Rilis','Keterangan'];
  const fieldMeta={
    'ID Issue':{type:'text',required:true},'Tanggal Temuan':{type:'date',required:true},'Aplikasi / Sistem':{type:'text',required:true},'Jenis Insiden':{type:'text',required:true},
    'Deskripsi':{type:'textarea',required:true},'Domain Kontrol':{type:'text',required:true},'Severity':{type:'select',required:true,options:['High','Medium','Low','Info','Warning']},
    'Faktor Penyebab':{type:'textarea',required:false},'Remediasi':{type:'textarea',required:false},'PIC':{type:'text',required:false},'Target Selesai Pentest':{type:'date',required:false},
    'Status Kerentanan':{type:'select',required:true,options:['Open','Close']},'Tanggal Selesai Remediasi':{type:'date',required:false},
    'Notifikasi':{type:'select',required:false,options:['Tanggal Selesai Remediasi belum diisi','Melebihi Batas Waktu Remediasi (5-10 Hari Kerja)','Pengerjaan Pentest melebihi batas waktu Service Level Agreement yaitu 5 Hari Kerja','Remediasi Sesuai SLA']},
    'Status Rilis':{type:'select',required:false,options:['Sudah Rilis','Belum Rilis']},'Keterangan':{type:'textarea',required:false}
  };
  const state={records:[],role:'',username:'',csrf:'',expiresAt:0,editingIndex:null,network:null,geo:null,geoStatus:'pending',clientInfo:null,notifications:[],unreadNotifications:0,selectedColumns:headers.slice()};
  const $=s=>document.querySelector(s), $$=s=>Array.from(document.querySelectorAll(s));
  const esc=v=>String(v??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
  const clone=x=>JSON.parse(JSON.stringify(x));

  function formatDate(v){if(!v||v==='-')return v||'';const d=new Date(v+'T00:00:00');return Number.isNaN(d.getTime())?String(v):d.toLocaleDateString('id-ID',{day:'2-digit',month:'2-digit',year:'numeric'});}
  function formatDateTime(iso){const d=new Date(iso);return Number.isNaN(d.getTime())?String(iso||'-'):d.toLocaleString('id-ID',{dateStyle:'short',timeStyle:'medium'});}
  function updateClock(){const now=new Date();const label=now.toLocaleString('id-ID',{weekday:'long',day:'2-digit',month:'long',year:'numeric',hour:'2-digit',minute:'2-digit',second:'2-digit'});if($('#login-clock'))$('#login-clock').textContent=label;if($('#dashboard-clock'))$('#dashboard-clock').textContent=label;if($('#footer-year'))$('#footer-year').textContent=now.getFullYear();}
  function startClock(){updateClock();setInterval(updateClock,1000);}
  function toast(msg){const t=$('#toast');t.textContent=msg;t.classList.remove('hidden');clearTimeout(toast.timer);toast.timer=setTimeout(()=>t.classList.add('hidden'),2600);}
  function setDataStatus(label='Tersimpan lokal'){$('#data-status').textContent=label+' • '+new Date().toLocaleTimeString('id-ID');}

  function resetLoginForm(){
    const form=$('#login-form');
    if(form) form.reset();
    $('#login-role').value='Security Engineer';
    $('#login-username').value='';
    $('#login-password').value='';
    roleChange(); clearLoginErrors();
  }
  let auditQueue=Promise.resolve();
  async function auditUI(event,detail=''){
    if(!state.csrf||!state.role)return;
    auditQueue=auditQueue.then(async()=>{
      try{
        await api('/api/audit/event',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({event,detail,client:state.clientInfo||clientInfo(),geo:state.geo||null})});
      }catch(e){
        // One retry keeps normal UI actions auditable across transient request races.
        try{await new Promise(r=>setTimeout(r,150));await api('/api/audit/event',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({event,detail,client:state.clientInfo||clientInfo(),geo:state.geo||null})});}catch(_e){}
      }
    });
    return auditQueue;
  }

  function setLocked(locked){
    const shell=$('#app-shell'),wall=$('#login-wall');
    if(locked){
      wall.classList.remove('hidden','closing'); shell.classList.add('locked'); shell.classList.remove('unlocked'); shell.setAttribute('aria-hidden','true'); wall.setAttribute('aria-hidden','false'); $('#login-username').focus();
    }else{
      shell.setAttribute('aria-hidden','false'); shell.classList.remove('locked'); shell.classList.add('unlocked');
      wall.classList.add('closing');
      window.setTimeout(()=>{wall.classList.add('hidden');wall.classList.remove('closing');wall.setAttribute('aria-hidden','true');},500);
    }
  }

  function roleChange(){
    const visitor=$('#login-role').value==='Visitor';
    document.body.classList.toggle('visitor-mode',visitor);
    $('#login-username-label').textContent=visitor?'Nama lengkap beserta gelar':'Username';
    $('#login-username').placeholder=visitor?'Contoh: DR. RAISA ANDRIANA, S.KOM., M.KOM':'Masukkan username';
    $('#login-password').value='';
    $('#login-password').required=!visitor;
    clearLoginErrors();
  }
  function clearLoginErrors(){
    ['role','username','password'].forEach(k=>{$('#login-'+k)?.classList.remove('input-invalid');$('#'+k+'-error')?.replaceChildren();});
    $('#login-error').textContent='';
  }
  function markInvalid(id,msg){const el=$('#login-'+id);el?.classList.add('input-invalid');$('#'+id+'-error').textContent=msg;}
  function localValidate(){
    clearLoginErrors(); let ok=true;
    const role=$('#login-role').value,username=$('#login-username').value.trim(),password=$('#login-password').value;
    const engineer=/^[A-Za-z0-9._-]{3,32}$/,visitor=/^[A-Za-zÀ-ÖØ-öø-ÿ0-9 .,'’()/_-]{3,120}$/;
    if(!role){markInvalid('role','Role wajib dipilih.');ok=false;}
    if(!(role==='Visitor'?visitor:engineer).test(username)){markInvalid('username',role==='Visitor'?'Nama dan gelar tidak sesuai format.':'Username hanya boleh 3–32 karakter: huruf, angka, titik, underscore, atau tanda hubung.');ok=false;}
    if(role==='Security Engineer'&&!password.trim()){markInvalid('password','Kata sandi wajib diisi.');ok=false;}
    return ok;
  }

  async function api(path,options={}){
    const opts={...options,credentials:'same-origin',headers:{Accept:'application/json',...(options.headers||{})}};
    if(state.csrf && !opts.headers['X-CSRF-Token'])opts.headers['X-CSRF-Token']=state.csrf;
    let res;
    try{res=await fetch(path,opts);}catch(e){throw new Error('Server CABEPEDES tidak dapat dihubungi.');}
    let body=null;try{body=await res.json();}catch(e){}
    if(res.status===401&&path!=='/api/login'){resetLoginForm();state.role='';state.username='';state.csrf='';setLocked(true);throw new Error('Sesi login telah berakhir. Silakan login kembali.');}
    if(!res.ok)throw new Error(body?.error||'Permintaan tidak dapat diproses.');
    return body;
  }
  async function login(e){
    e.preventDefault();
    if(!localValidate())return;
    const role=$('#login-role').value,username=$('#login-username').value.trim(),password=$('#login-password').value;
    const btn=$('#login-submit');btn.disabled=true;btn.textContent='Memverifikasi akses…';
    try{
      const client=clientInfo();
      const data=await api('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({role,username,password,client})});
      state.role=data.role;state.username=data.username;state.csrf=data.csrf;state.expiresAt=data.expires_at;state.network=data.network;state.clientInfo=client; $('#login-password').value='';
      $('#login-status').textContent=data.role+' • '+data.username;
      applyPermissions();setLocked(false);clearLoginErrors();
      await loadRegister();await loadNotifications();if(state.role==='Security Engineer')await loadAuditLog();setDataStatus('Data tersimpan di server Mac • sinkronisasi aktif');
      startBackgroundTelemetry();
      toast('Akses CABEPEDES dibuka sebagai '+data.role+'.');
    }catch(err){
      const msg=err.message||'Login gagal.';
      $('#login-error').textContent=msg;
      if(/Username|role|password|valid/i.test(msg)){
        markInvalid('username','Username/role tidak cocok atau kredensial tidak valid.');
        markInvalid('role','Role tidak cocok dengan akun yang diizinkan.');
        if(role==='Security Engineer')markInvalid('password','Username, role, atau kata sandi tidak cocok.');
      }
    }finally{btn.disabled=false;btn.textContent='Buka Akses Central Audit & Bug Exploitation';}
  }
  async function loadSession(){
    try{
      const data=await api('/api/session');
      if(data.authenticated){state.role=data.role;state.username=data.username;state.csrf=data.csrf;state.expiresAt=data.expires_at;state.network=data.network;$('#login-status').textContent=data.role+' • '+data.username;applyPermissions();setLocked(false);await loadRegister();await loadNotifications();if(state.role==='Security Engineer')await loadAuditLog();startBackgroundTelemetry();}
      else setLocked(true);
    }catch(e){setLocked(true);}
  }
  async function logout(){
    try{await api('/api/logout',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});}catch(e){}
    stopBackgroundTelemetry();resetLoginForm();state.role='';state.username='';state.csrf='';state.expiresAt=0;state.records=[];state.notifications=[];state.unreadNotifications=0;state.selectedColumns=headers.slice();state.geo=null;state.geoStatus='pending';state.network=null;state.clientInfo=null;state.editingIndex=null;
    $('#notification-panel')?.classList.add('hidden');
    $('#login-status').textContent='Belum login';applyPermissions();renderRegister();setLocked(true);toast('Sesi ditutup.');
  }

  async function loadRegister(){const data=await api('/api/register');state.records=Array.isArray(data.records)?data.records:[];refreshDashboard();renderFilters();renderColumnPicker();renderRegister();setDataStatus('Tersimpan lokal • server Mac');}
  async function loadNotifications(){if(!state.csrf)return;try{const data=await api('/api/notifications');state.notifications=Array.isArray(data.notifications)?data.notifications:[];state.unreadNotifications=Number(data.unread_count||0);renderUserNotifications();}catch(e){}}
  async function markNotificationsRead(ids=[],all=false){if(!state.csrf)return;try{await api('/api/notifications/read',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ids,all})});await loadNotifications();}catch(e){}}
  function notificationTime(v){return formatDateTime(v||'');}
  function notificationText(item){if(item.kind==='va_created')return `<b>VA baru</b> ${esc(item.issue_id)} · ${esc(item.application)} · PIC: ${esc(item.pic||'-')} · ditambahkan oleh ${esc(item.actor_username)}`;const fields=(item.changed_fields||[]).map(esc).join(', ');return `<b>VA diubah</b> ${esc(item.issue_id)} · ${esc(item.application)} · oleh ${esc(item.actor_username)} · Data diubah: ${fields||'tidak ada'}`;}
  function renderUserNotifications(){const badge=$('#notification-badge'),list=$('#notification-list');if(!badge||!list)return;badge.textContent=state.unreadNotifications>99?'99+':String(state.unreadNotifications);badge.classList.toggle('hidden',state.unreadNotifications===0);if(!state.notifications.length){list.innerHTML='<div class="notification-empty">Belum ada notifikasi keamanan.</div>';return;}list.innerHTML=state.notifications.map(item=>`<button type="button" class="notification-item ${item.unread?'unread':''}" data-notification-id="${esc(item.id)}"><span class="notification-main">${notificationText(item)}</span><span class="notification-time">${esc(notificationTime(item.created_at))}</span></button>`).join('');$$('.notification-item').forEach(btn=>btn.addEventListener('click',()=>{const id=btn.dataset.notificationId;markNotificationsRead([id]);}));}
  async function createRecord(record){const data=await api('/api/register/create',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({record})});state.records=data.records;refreshDashboard();renderFilters();renderColumnPicker();renderRegister();await loadNotifications();setDataStatus('Tersimpan lokal • server Mac');}
  async function updateRecord(id,record){const data=await api('/api/register/update',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id,record})});state.records=data.records;refreshDashboard();renderFilters();renderColumnPicker();renderRegister();await loadNotifications();setDataStatus('Tersimpan lokal • server Mac');}

  function applyPermissions(){
    const engineer=state.role==='Security Engineer';
    $('#reset-data').disabled=!engineer;$('#add-record').disabled=!engineer;$('#add-record-2').disabled=!engineer;$('#export-csv').disabled=!engineer;$('#export-json').disabled=!engineer;
    $$('.engineer-only[data-tab]').forEach(b=>b.hidden=!engineer);
    if(!engineer&&['formula','security'].includes($('.tab-btn.active')?.dataset.tab)){document.querySelector('.tab-btn[data-tab="dashboard"]').click();}
  }

  function tag(v){const n=String(v||'').toLowerCase();const cls=n.startsWith('close')?'close':(['open','high','medium','low','info','warning'].includes(n)?n:'other');return `<span class="tag ${cls}">${esc(v||'')}</span>`;}
  function htmlCell(h,v){if(h==='Severity'||h==='Status Kerentanan')return tag(v);if(h.includes('Tanggal')||h.includes('Target'))return esc(formatDate(v));if(['Deskripsi','Faktor Penyebab','Remediasi','Notifikasi','Keterangan'].includes(h))return `<div class="ellipsis" title="${esc(v||'')}">${esc(v||'')}</div>`;return esc(v||'');}

  function refreshDashboard(){const m=CSIRT.calculate(state.records);$('#hero-count').textContent=m.total;$('#kpi-total').textContent=m.total;$('#kpi-open').textContent=m.open;$('#kpi-closed').textContent=m.closed;$('#kpi-high').textContent=m.high;renderSeverity(m.severity);renderStatus(m.status);renderBars($('#apps-chart'),m.apps,34);renderBars($('#domain-chart'),m.domains,42);renderAllApps(m.allApps);renderNotifications(m.notificationSummary);renderFormulaAudit();}
  function svgWrap(w,h,inner){return `<svg viewBox="0 0 ${w} ${h}" role="img" xmlns="http://www.w3.org/2000/svg">${inner}</svg>`;}
  const severityColors={High:'#D32F2F',Medium:'#F59E0B',Low:'#16A34A'};
  const kemkesPalette=['#00A79D','#C7D82D','#007F77','#55C6BC','#9FB214','#35AFA7','#7E8E31','#4E8B84','#B6C85D'];
  function renderSeverity(items){const max=Math.max(1,...items.map(x=>x.value)),w=640,h=310,p={l:55,r:25,t:24,b:60},pw=w-p.l-p.r,ph=h-p.t-p.b,slot=pw/items.length,bw=Math.min(92,slot*.48);let s='';for(let g=0;g<=5;g++){const y=p.t+ph-(ph*g/5),val=Math.round(max*g/5);s+=`<line x1="${p.l}" x2="${w-p.r}" y1="${y}" y2="${y}" class="grid-line"/><text x="${p.l-12}" y="${y+4}" text-anchor="end" font-size="10" fill="#87939b">${val}</text>`}items.forEach((it,i)=>{const bh=ph*(it.value/max),x=p.l+i*slot+(slot-bw)/2,y=p.t+ph-bh,c=severityColors[it.label]||'#94a3b8';s+=`<rect x="${x}" y="${y}" width="${bw}" height="${bh}" rx="5" fill="${c}"/><text x="${x+bw/2}" y="${y-8}" text-anchor="middle" class="bar-value">${it.value}</text><text x="${x+bw/2}" y="${h-27}" text-anchor="middle" class="bar-label">${esc(it.label)}</text>`});$('#severity-chart').innerHTML=svgWrap(w,h,s);}
  function renderStatus(items){const total=items.reduce((a,b)=>a+b.value,0)||1,cx=250,cy=150,r=91,inner=55,colors=['#00A79D','#C7D82D'];let s=`<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="#eaf0ef" stroke-width="38"/>`;const circ=2*Math.PI*r;let off=0;items.forEach((it,i)=>{const len=circ*(it.value/total),c=colors[i];if(it.value)s+=`<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="${c}" stroke-width="38" stroke-dasharray="${len} ${circ-len}" stroke-dashoffset="${-off}" transform="rotate(-90 ${cx} ${cy})"/>`;off+=len;});s+=`<circle cx="${cx}" cy="${cy}" r="${inner}" fill="#fff"/><text x="${cx}" y="${cy-5}" text-anchor="middle" class="donut-center-big">${Math.round((items[0].value/total)*100)}%</text><text x="${cx}" y="${cy+15}" text-anchor="middle" class="donut-center-small">OPEN</text>`;items.forEach((it,i)=>{const y=78+i*42,c=colors[i];s+=`<rect x="430" y="${y-8}" width="10" height="10" rx="2" fill="${c}"/><text x="447" y="${y}" class="legend-text">${esc(it.label)} · ${it.value}</text>`});$('#status-chart').innerHTML=svgWrap(650,300,s);}
  function renderBars(el,items,maxChars){const width=650,rowH=30,h=Math.max(290,items.length*rowH+40),max=Math.max(1,...items.map(x=>x.value));let s='';items.forEach((it,i)=>{const y=20+i*rowH,label=it.label.length>maxChars?it.label.slice(0,maxChars)+'…':it.label,barX=255,barW=300,bw=(it.value/max)*barW,c=kemkesPalette[i%kemkesPalette.length];s+=`<text x="0" y="${y+13}" class="bar-label">${esc(label)}</text><line x1="${barX}" x2="${barX+barW}" y1="${y+9}" y2="${y+9}" class="axis-line"/><rect x="${barX}" y="${y+2}" width="${bw}" height="14" rx="4" fill="${c}"/><text x="${barX+barW+10}" y="${y+13}" class="bar-value">${it.value}</text>`});[0,Math.ceil(max/4),Math.ceil(max/2),Math.ceil(3*max/4),max].forEach(v=>{const x=255+(v/max)*300;s+=`<text x="${x}" y="${h-7}" text-anchor="middle" font-size="10" fill="#87939b">${v}</text>`});el.innerHTML=svgWrap(width,h,s);}
  function renderAllApps(items){$('#all-app-count').textContent=items.length+' aplikasi';$('#all-apps-table').innerHTML='<table><thead><tr><th>Aplikasi / Sistem</th><th>Temuan</th></tr></thead><tbody>'+items.map(x=>`<tr><td>${esc(x.label)}</td><td><strong>${x.value}</strong></td></tr>`).join('')+'</tbody></table>';}
  function renderNotifications(items){$('#notification-table').innerHTML='<table><thead><tr><th>Notifikasi</th><th>Jumlah</th></tr></thead><tbody>'+items.map(x=>`<tr><td>${esc(x.label)}</td><td><strong>${x.value}</strong></td></tr>`).join('')+'</tbody></table>';}

  function monthKey(value){const match=/^(\d{4})-(\d{2})-\d{2}$/.exec(String(value||'').trim());if(!match)return '';return `${match[1]}-${match[2]}`;}
  function monthLabel(key){const [year,month]=key.split('-').map(Number);const date=new Date(year,month-1,1);return date.toLocaleDateString('id-ID',{month:'long',year:'numeric'});}
  function renderFilters(){const s=$('#filter-status'),v=$('#filter-severity'),m=$('#filter-month'),sv=s.value,vv=v.value,mv=m.value;const statuses=[...new Set(state.records.map(r=>r['Status Kerentanan']).filter(Boolean))].sort(),sevs=[...new Set(state.records.map(r=>r.Severity).filter(Boolean))].sort(),months=[...new Set(state.records.map(r=>monthKey(r['Tanggal Temuan'])).filter(Boolean))].sort().reverse();m.innerHTML='<option value="">Semua Bulan</option>'+months.map(x=>`<option value="${esc(x)}">${esc(monthLabel(x))}</option>`).join('');s.innerHTML='<option value="">Semua Status</option>'+statuses.map(x=>`<option value="${esc(x)}">${esc(x)}</option>`).join('');v.innerHTML='<option value="">Semua Severity</option>'+sevs.map(x=>`<option value="${esc(x)}">${esc(x)}</option>`).join('');m.value=months.includes(mv)?mv:'';s.value=statuses.includes(sv)?sv:'';v.value=sevs.includes(vv)?vv:'';}
  function renderColumnPicker(){const host=$('#column-filter-options'),count=$('#selected-column-count'),summary=$('#column-filter-summary');if(!host||!count||!summary)return;const selected=new Set(state.selectedColumns.filter(h=>headers.includes(h)));state.selectedColumns=headers.filter(h=>selected.has(h));count.textContent=`${state.selectedColumns.length}/${headers.length}`;summary.textContent=state.selectedColumns.length===headers.length?'Semua kolom ditampilkan':`${state.selectedColumns.length} kolom dipilih`;host.innerHTML=headers.map(h=>{const checked=selected.has(h);const disabled=checked&&selected.size===1;const id=`column-${headers.indexOf(h)}`;return `<label class="column-check" for="${id}"><input id="${id}" type="checkbox" value="${esc(h)}" ${checked?'checked':''} ${disabled?'disabled':''}><span>${esc(h)}</span></label>`;}).join('');}
  function filteredRecords(){const q=$('#search').value.trim().toLowerCase(),month=$('#filter-month').value,st=$('#filter-status').value,sev=$('#filter-severity').value;return state.records.map((r,index)=>({r,index})).filter(({r})=>{if(month&&monthKey(r['Tanggal Temuan'])!==month)return false;if(st&&r['Status Kerentanan']!==st)return false;if(sev&&r.Severity!==sev)return false;if(!q)return true;return headers.some(h=>String(r[h]??'').toLowerCase().includes(q));});}
  function renderRegister(){const list=filteredRecords(),visible=state.selectedColumns.filter(h=>headers.includes(h));$('#register-count').textContent=`${list.length} dari ${state.records.length} record`;const th=visible.map(h=>`<th class="${h==='ID Issue'?'sticky-column':''}">${esc(h)}</th>`).join('');const body=list.map(({r,index})=>`<tr data-index="${index}" class="${state.role==='Security Engineer'?'editable-row':'readonly-row'}">${visible.map(h=>`<td class="${h==='ID Issue'?'sticky-column':''}">${htmlCell(h,r[h])}</td>`).join('')}</tr>`).join('');$('#data-table thead').innerHTML=`<tr>${th}</tr>`;$('#data-table tbody').innerHTML=body||`<tr><td colspan="${Math.max(visible.length,1)}" class="empty-cell">Tidak ada data yang cocok.</td></tr>`;if(state.role==='Security Engineer')$$('#data-table tbody tr.editable-row').forEach(tr=>tr.addEventListener('click',async()=>{const idx=Number(tr.dataset.index);await auditUI('record_edit_open',`Index=${idx};ID=${state.records[idx]?.['ID Issue']||''}`);openRecord(idx);}));}

  function fieldControl(h,value){const meta=fieldMeta[h],id='f-'+btoa(unescape(encodeURIComponent(h))).replace(/=/g,'');let ctrl='';if(h==='ID Issue')ctrl=`<input id="${id}" name="${esc(h)}" type="text" value="${esc(value||'— otomatis oleh server —')}" readonly disabled class="readonly-field" aria-readonly="true" title="ID Issue dibuat otomatis oleh server berdasarkan tahun berjalan.">`;else if(meta.type==='select')ctrl=`<select id="${id}" name="${esc(h)}" ${meta.required?'required':''}><option value="">— Pilih —</option>${meta.options.map(v=>`<option value="${esc(v)}" ${v===value?'selected':''}>${esc(v)}</option>`).join('')}</select>`;else if(meta.type==='textarea')ctrl=`<textarea id="${id}" name="${esc(h)}" ${meta.required?'required':''}>${esc(value||'')}</textarea>`;else ctrl=`<input id="${id}" name="${esc(h)}" type="${meta.type}" value="${esc(value||'')}" ${meta.required?'required':''}>`;return `<div class="field ${meta.type==='textarea'?'full':''} ${h==='ID Issue'?'managed-field':''}"><label for="${id}">${esc(h)}${meta.required&&h!=='ID Issue'?' *':''}</label>${ctrl}<div class="field-error local-field-error"></div></div>`;}
  function openRecord(index){if(state.role!=='Security Engineer')return;state.editingIndex=index;const existing=state.records[index]||{},isNew=index===null,draft=clone(existing);if(isNew){draft['ID Issue']='';draft['Tanggal Temuan']=new Date().toISOString().slice(0,10);}$('##modal-title'.replace('#','')).textContent=isNew?'Tambah Temuan':`Edit ${esc(existing['ID Issue']||'Temuan')}`;$('#delete-record').style.visibility=isNew?'hidden':'visible';$('#record-form').innerHTML=headers.map(h=>fieldControl(h,draft[h]??'')).join('');$('#record-modal').classList.remove('hidden');const first=$('#record-form input:not([disabled]), #record-form select, #record-form textarea');setTimeout(()=>first?.focus(),0);}
  function closeRecord(){state.editingIndex=null;$('#record-modal').classList.add('hidden');}
  function formData(){const o={},fd=new FormData($('#record-form'));headers.forEach(h=>o[h]=fd.get(h)??'');if(state.editingIndex!==null)o['ID Issue']=state.records[state.editingIndex]?.['ID Issue']||'';else o['ID Issue']='';return o;}
  async function saveRecord(e){e.preventDefault();if(state.role!=='Security Engineer')return;const record=formData(),idx=state.editingIndex;if(!record['Aplikasi / Sistem']||!record['Deskripsi']||!record['Severity']||!record['Status Kerentanan'])return toast('Lengkapi kolom wajib.');try{if(idx===null){await createRecord(record);}else{const id=state.records[idx]?.['ID Issue'];if(!id)return toast('Record tidak ditemukan.');await updateRecord(id,record);}closeRecord();toast(idx===null?'Temuan baru disimpan.':'Perubahan temuan disimpan.');}catch(err){toast(err.message);}}
  async function deleteRecord(){if(state.role!=='Security Engineer'||state.editingIndex===null)return;const id=state.records[state.editingIndex]['ID Issue'];if(!window.confirm(`Hapus ${id}?`))return;try{const data=await api('/api/register/delete',{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({id})});state.records=data.records;closeRecord();refreshDashboard();renderFilters();renderColumnPicker();renderRegister();setDataStatus('Tersimpan lokal • server Mac');toast('Record dihapus.');}catch(err){toast(err.message);}}
  async function resetData(){if(state.role!=='Security Engineer'||!window.confirm('Kembalikan seluruh data ke 61 record awal workbook? Perubahan akan hilang.'))return;try{const data=await api('/api/register/reset',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});state.records=data.records;refreshDashboard();renderFilters();renderColumnPicker();renderRegister();setDataStatus('Tersimpan lokal • server Mac');toast('Data workbook dikembalikan.');}catch(err){toast(err.message);}}
  function csvEscape(v){const s=String(v??'');return /[",\n]/.test(s)?`"${s.replace(/"/g,'""')}"`:s;}
  function downloadBlob(text,name,type){const a=document.createElement('a');const url=URL.createObjectURL(new Blob([text],{type}));a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
  function exportCSV(){if(state.role!=='Security Engineer')return;const rows=[headers,...state.records.map(r=>headers.map(h=>r[h]??''))];downloadBlob('\uFEFF'+rows.map(row=>row.map(csvEscape).join(',')).join('\n'),'cabepedes-data-register.csv','text/csv;charset=utf-8');}
  function exportJSON(){if(state.role!=='Security Engineer')return;downloadBlob(JSON.stringify(state.records,null,2),'cabepedes-data-register-backup.json','application/json;charset=utf-8');}

  const releaseV110=[
    'Executive Dashboard menampilkan jumlah seluruh temuan, temuan terbuka, temuan selesai, dan temuan dengan tingkat keparahan tinggi.',
    'Grafik dashboard mengambil data dari sheet Calc untuk tingkat keparahan, status, sistem atau aplikasi, dan domain kontrol.',
    'Data Register memuat 16 kolom sesuai workbook dan 61 data awal yang digunakan sebagai data dasar.',
    'Pemeriksaan formula menampilkan formula Excel sumber sebagai bahan penelusuran dan pemeriksaan.',
    'Pengguna dengan hak akses Security Engineer dapat menambah, mengubah, dan menghapus data. Nomor ID Issue dibuat otomatis oleh server.',
    'Data Register menyediakan pencarian serta penyaringan berdasarkan status dan tingkat keparahan.',
    'Data dapat diekspor ke CSV dan dicadangkan dalam format JSON.',
    'Data tersimpan pada server aplikasi dan tetap dapat digunakan setelah pemindahan versi melalui mekanisme migrasi yang tersedia.',
    'Perhitungan COUNTIF mengikuti pencocokan teks Excel, termasuk pola Close*.',
    'Aplikasi menyediakan peluncur macOS dan berjalan tanpa Node.js, npm, atau kerangka kerja tambahan.'
  ];
  const releaseV120=[
    'Aplikasi lokal tersedia melalui http://localhost:1500/, sedangkan akses dari jaringan menggunakan HTTPS pada port 1501.',
    'Startup aplikasi dipindahkan ke LaunchAgent pengguna dengan RunAtLoad dan KeepAlive sehingga server tidak bergantung pada jendela Terminal.',
    'Lokasi pemasangan aplikasi dapat dipindahkan dan LaunchAgent menggunakan lokasi instalasi yang sebenarnya.',
    'Kata sandi Security Engineer disimpan menggunakan PBKDF2-HMAC-SHA256 dengan 600.000 iterasi dan salt yang berbeda untuk setiap akun.',
    'security-audit.log menyimpan kegiatan audit dalam bentuk tabel dan tidak mencatat kata sandi.',
    'Pencatatan audit mencakup login, logout, pemeriksaan hak akses, perubahan data, menu, filter, perangkat aktif, dan perubahan lokasi yang tersedia dari peramban.',
    'Pemeriksaan keamanan latar belakang memantau hak akses berkas, integritas aplikasi, sesi, API, struktur data, TLS, dan pencatatan audit.',
    'Logout dan kedaluwarsa sesi membatalkan sesi pada server serta menghapus isian kredensial pada halaman login.',
    'Rilis menggunakan pemeriksaan integritas SHA-256, penulisan data atomik dengan cadangan, penanganan kesalahan, pembatasan permintaan, validasi masukan, perlindungan CSRF, perlindungan sesi, dan daftar berkas statis yang diizinkan.'
  ];
  const releaseV130=[
    'Startup yang tetap berjalan melalui LaunchAgent sehingga server dapat aktif kembali setelah pengguna masuk ke macOS atau setelah Mac dinyalakan ulang.',
    'Log audit dibuat oleh server dengan 13 kolom: waktu, kegiatan, peran, nama pengguna, alamat IP, perangkat, jenis perangkat, lokasi, sistem operasi, peramban, sesi, hasil, dan keterangan.',
    'Pencatatan kegiatan mencakup autentikasi, sesi, dashboard, Data Register, notifikasi, Active Clients, pencarian, penyaringan, tambah, ubah, hapus, reset, penolakan hak akses, pemeriksaan keamanan, dan siklus hidup server.',
    'Penulisan log dilakukan secara berurutan, pemisah dan baris baru disanitasi, hak akses log dibatasi, rotasi log diterapkan, dan tersedia lokasi cadangan untuk pencatatan.',
    'Pencatatan kegiatan antarmuka menggunakan antrean berurutan dan percobaan ulang agar kegiatan tidak mudah hilang ketika beberapa permintaan terjadi bersamaan.',
    'Log runtime digunakan sebagai sumber audit setelah pemasangan sehingga operator tidak keliru memeriksa berkas contoh pada paket rilis.',
    'Nomor ID Issue dikelola oleh server dengan pola VA-YYYY-NNN dan kembali ke nomor 001 pada pergantian tahun.',
    'Notifikasi dibuat untuk data temuan baru bagi Security Engineer dan Visitor, serta untuk perubahan data temuan bagi Security Engineer.',
    'Waktu pada halaman login dan dashboard ditampilkan secara langsung hingga detik.',
    'Pemutakhiran berkala dibuat terbatas agar beban pada Mac tetap ringan.',
    'Pemeriksaan integritas hanya mengunci berkas rilis yang tidak berubah selama penggunaan; data, kredensial, log, dan keadaan TLS tetap dapat berubah sebagai data operasional.',
    'Ikon peramban menggunakan Logo Browser.png dan identitas aplikasi menggunakan Logo CabePedes.png.',
    'Grafik dashboard menggunakan warna yang dibedakan menurut tingkat keparahan dan kelompok data agar mudah dibaca.',
    'Halaman login menggunakan tampilan terkunci, validasi masukan, pesan kesalahan pada kolom, dan perlindungan terhadap interaksi sebelum autentikasi selesai.',
    'Visitor dapat masuk menggunakan nama lengkap beserta gelar tanpa kata sandi sesuai daftar yang tercatat.',
    'Akun Security Engineer dan Visitor dibaca dari seceng.txt dan visitor.txt tanpa menggunakan basis data.',
    'Pembatasan hak akses diterapkan di sisi server: Security Engineer memiliki hak pengelolaan, sedangkan Visitor hanya dapat membaca Dashboard dan Data Register.',
    'Informasi peran dan nama pengguna sesi ditampilkan pada bagian atas aplikasi.',
    'Akses jaringan menggunakan server Python bawaan, HTTPS untuk koneksi LAN, pembukaan peramban otomatis pada Mac, dan mekanisme startup yang aman digunakan berulang kali.',
    'Active Clients menampilkan alamat IP, nama perangkat, jenis perangkat, lokasi, sistem operasi, peramban, sesi, dan waktu terakhir aktif.',
    'Informasi lokasi menggunakan Geolocation API pada peramban dengan enableHighAccuracy; ketepatan bergantung pada perangkat, sistem operasi, izin, jaringan, dan kondisi lingkungan.',
    'Riwayat rilis menampilkan pengembangan 20 Agustus 2026 dan 23 September 2026.'
  ];
  const releaseV132=[
    'Data Register dapat disaring berdasarkan Bulan Temuan menggunakan kolom Tanggal Temuan.',
    'Pilihan bulan menampilkan bulan dan tahun agar data pada tahun yang berbeda tidak tercampur.',
    'Ditambahkan pemilih kolom berbasis checkbox untuk menampilkan atau menyembunyikan 16 kolom Data Register sesuai kebutuhan.',
    'Pemilihan kolom mempertahankan sedikitnya satu kolom agar tabel tetap dapat digunakan dan dapat dikembalikan melalui tombol Pilih semua.',
    'Kolom ID Issue hanya menjadi kolom tetap saat memang dipilih, sehingga perilaku tabel tetap benar setelah kolom lain disembunyikan.'
  ];
  const releaseV131=[
    'Server HTTP pada port 1500 menerima koneksi dari jaringan, bukan hanya dari komputer tempat server berjalan.',
    'Akses HTTP dari perangkat lain pada jaringan yang sama diarahkan secara otomatis ke HTTPS port 1501, sedangkan akses localhost tetap dapat digunakan melalui HTTP port 1500.',
    'Pemeriksaan Host diperbaiki agar alamat IP LAN dapat melewati tahap pengalihan ke HTTPS dengan benar.',
    'visitor.txt dan seceng.txt dibaca kembali setiap kali proses login sehingga akun yang baru ditambahkan dapat langsung digunakan tanpa menjalankan ulang server.',
    'Pembacaan file kredensial menerima spasi di sekitar tanda titik dua, baris kosong, komentar, UTF-8 BOM, dan format baris CRLF.',
    'Pemasangan ulang memperbarui berkas kredensial dari paket sumber apabila berkas tersebut lebih baru, tetapi tetap mempertahankan perubahan yang lebih baru pada instalasi yang sudah berjalan.',
    'Aplikasi menyediakan tampilan Log Keamanan untuk Security Engineer. Tampilan ini membaca log runtime yang aktif, termasuk log cadangan apabila lokasi utama tidak dapat ditulis.',
    'Pemeriksaan keamanan memperhitungkan lokasi log runtime yang benar sehingga penggunaan log cadangan tidak langsung dianggap sebagai kegagalan.',
    'Bahasa pada Riwayat Fitur CABEPEDES diperbaiki agar menggunakan Bahasa Indonesia yang formal, jelas, dan mudah dipahami.'
  ];
  function fillList(selector,items){const el=$(selector);if(el)el.innerHTML=items.map(x=>`<li>${esc(x)}</li>`).join('');}
  function renderReleaseNotes(){
    fillList('#release-v132',releaseV132);
    fillList('#release-v110',releaseV110);
    fillList('#release-v120',releaseV120);
    fillList('#release-v130',releaseV130);
    const hotfix=$('#release-v131');if(hotfix)fillList('#release-v131',releaseV131);
  }

  function renderFormulaAudit(){const kpis=[['Executive Dashboard · D14','TOTAL TEMUAN',CSIRT.EXCEL_FORMULAS.total],['Executive Dashboard · L14','STATUS: OPEN',CSIRT.EXCEL_FORMULAS.open],['Executive Dashboard · P14','STATUS: CLOSED',CSIRT.EXCEL_FORMULAS.closed],['Executive Dashboard · T14','RISIKO TINGGI (HIGH)',CSIRT.EXCEL_FORMULAS.high]];const calc=[['A2/B2','High',`=COUNTIF('Data Register'!G:G, "High")`],['A3/B3','Medium',`=COUNTIF('Data Register'!G:G, "Medium")`],['A4/B4','Low',`=COUNTIF('Data Register'!G:G, "Low")`],['D2/E2','Open',`=COUNTIF('Data Register'!L:L, "Open")`],['D3/E3','Closed',`=COUNTIF('Data Register'!L:L, "Close*")`]].concat(CSIRT.APP_SERIES.map((x,i)=>[`G${i+2}/H${i+2}`,x,`=COUNTIF('Data Register'!C:C, "${x}")`])).concat(CSIRT.DOMAIN_SERIES.map((x,i)=>[`J${i+2}/K${i+2}`,x,`=COUNTIF('Data Register'!F:F, "${x}")`]));const card=(title,rows)=>`<article class="formula-card"><h3>${esc(title)}</h3>${rows.map(x=>`<div class="formula-row"><div><div class="formula-cell">${esc(x[0])}</div></div><div><div class="formula-label">${esc(x[1])}</div><div class="formula-code">${esc(x[2])}</div></div></div>`).join('')}</article>`;$('#formula-grid').innerHTML=card('KPI Executive Dashboard',kpis)+card('Calc · Severity & Status',calc.slice(0,5))+card('Calc · Sistem / Aplikasi Terdampak',calc.slice(5,13))+card('Calc · Area Kelemahan Kontrol',calc.slice(13));}

  function clientInfo(){
    const ua=navigator.userAgent||'',platform=navigator.platform||'';
    let os='Unknown OS',browser='Unknown Browser',deviceType='Desktop';
    if(/iPhone|iPad|iPod/i.test(ua))os='iOS',deviceType='Mobile';else if(/Android/i.test(ua))os='Android',deviceType=/Mobile/i.test(ua)?'Mobile':'Tablet';else if(/Mac OS X/i.test(ua))os='macOS';else if(/Windows/i.test(ua))os='Windows';else if(/Linux/i.test(ua))os='Linux';
    if(/Edg\//i.test(ua))browser='Microsoft Edge';else if(/Chrome\//i.test(ua))browser='Google Chrome';else if(/Safari\//i.test(ua)&&!/Chrome\//i.test(ua))browser='Safari';else if(/Firefox\//i.test(ua))browser='Mozilla Firefox';
    const name=platform||os;
    return {device_name:name,device_type:deviceType,os,browser};
  }
  let geoWatch=null,heartbeatTimer=null,registerTimer=null,clientsTimer=null,notificationsTimer=null;
  function startBackgroundTelemetry(){stopBackgroundTelemetry();
    const send=()=>sendHeartbeat();
    heartbeatTimer=setInterval(send,30000);
    registerTimer=setInterval(()=>loadRegister().catch(()=>{}),45000);
    notificationsTimer=setInterval(()=>loadNotifications().catch(()=>{}),15000);
    if(state.role==='Security Engineer')clientsTimer=setInterval(()=>loadClients().catch(()=>{}),20000);
    send();
    if(navigator.geolocation){geoWatch=navigator.geolocation.watchPosition(pos=>{state.geo={latitude:pos.coords.latitude,longitude:pos.coords.longitude,accuracy:pos.coords.accuracy};state.geoStatus='granted';sendHeartbeat();},()=>{state.geoStatus='denied';sendHeartbeat();},{enableHighAccuracy:true,maximumAge:15000,timeout:10000});}else{state.geoStatus='unsupported';}
  }
  function stopBackgroundTelemetry(){if(geoWatch!==null&&navigator.geolocation)navigator.geolocation.clearWatch(geoWatch);geoWatch=null;if(heartbeatTimer)clearInterval(heartbeatTimer);if(registerTimer)clearInterval(registerTimer);if(clientsTimer)clearInterval(clientsTimer);if(notificationsTimer)clearInterval(notificationsTimer);heartbeatTimer=registerTimer=clientsTimer=notificationsTimer=null;}
  async function sendHeartbeat(){if(!state.csrf)return;try{await api('/api/heartbeat',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({client:state.clientInfo||clientInfo(),geo:state.geo||null})});}catch(e){}}
  async function loadClients(){if(state.role!=='Security Engineer')return;const data=await api('/api/clients');const rows=data.clients||[];$('#clients-table tbody').innerHTML=rows.map(c=>`<tr><td>${esc(c.username||'')}</td><td>${esc(c.role||'')}</td><td>${esc(c.ip||'')}</td><td>${esc(c.device_name||'')}</td><td>${esc(c.device_type||'')}</td><td>${locationText(c)}</td><td>${esc(c.os||'')}</td><td>${esc(c.browser||'')}</td><td>${esc(c.session||'')}</td><td>${esc(formatDateTime((c.last_active||0)*1000))}</td></tr>`).join('')||'<tr><td colspan="10" class="empty-cell">Tidak ada perangkat aktif.</td></tr>';renderNetwork();}
  async function loadAuditLog(){
    if(state.role!=='Security Engineer')return;
    const meta=$('#audit-log-meta'),table=$('#audit-log-table');
    if(!meta||!table)return;
    try{
      meta.textContent='Memuat log keamanan…';
      const data=await api('/api/audit/log');
      const columns=data.columns||[];
      table.querySelector('thead').innerHTML='<tr>'+columns.map(h=>`<th>${esc(h)}</th>`).join('')+'</tr>';
      const rows=data.rows||[];
      table.querySelector('tbody').innerHTML=rows.map(row=>`<tr>${row.map(cell=>`<td>${esc(cell)}</td>`).join('')}</tr>`).join('')||`<tr><td colspan="${Math.max(columns.length,1)}" class="empty-cell">Belum ada kegiatan yang tercatat.</td></tr>`;
      const path=String(data.path||'log/security-audit.log');
      const shown=path.replace(/^.*\\/,'');
      meta.textContent=`Berkas: ${shown} • ${Number(data.size||0).toLocaleString('id-ID')} byte • Diperbarui: ${formatDateTime(data.updated_at||'')} • Menampilkan ${rows.length} kegiatan terakhir.`;
    }catch(e){
      meta.textContent='Log keamanan belum dapat dimuat.';
      table.querySelector('thead').innerHTML='';
      table.querySelector('tbody').innerHTML='<tr><td class="empty-cell">'+esc(e.message||'Log tidak dapat dibaca.')+'</td></tr>';
    }
  }
  function locationText(c){if(typeof c.latitude==='number'&&typeof c.longitude==='number'){const url=`https://www.google.com/maps?q=${c.latitude.toFixed(6)},${c.longitude.toFixed(6)}`;return `<a href="${url}" target="_blank" rel="noopener noreferrer">${c.latitude.toFixed(6)}, ${c.longitude.toFixed(6)}</a><div class="accuracy">±${Math.round(c.accuracy||0)} m</div>`;}return `<span class="location-pending">${esc(c.location_status==='denied'?'Izin lokasi ditolak':'Menunggu lokasi')}</span>`;}
  function renderNetwork(){const box=$('#network-info'),n=state.network;if(!n){box.textContent='Menunggu sesi aktif…';return;}let s=`<b>Server:</b> ${esc(n.host_name||'CABEPEDES Mac')}<br><b>Local:</b> <a href="${esc(n.local_url)}" target="_blank" rel="noopener noreferrer">${esc(n.local_url)}</a><br>`;if(n.lan_http_urls?.length)s+=`<b>LAN Entry:</b> ${n.lan_http_urls.map(u=>`<a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(u)}</a>`).join('<br>')}<small class="muted">HTTP LAN otomatis diarahkan ke HTTPS.</small><br>`;s+=`<b>LAN HTTPS:</b> ${n.https_enabled&&n.lan_urls?.length?n.lan_urls.map(u=>`<a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(u)}</a>`).join('<br>'):'HTTPS LAN belum tersedia. Pastikan OpenSSL tersedia pada Mac.'}`;box.innerHTML=s;}

  let searchAuditTimer=null;
  function auditSearch(){
    clearTimeout(searchAuditTimer);
    searchAuditTimer=setTimeout(()=>{
      const q=$('#search').value.trim();
      auditUI('search_used',`QueryLength=${q.length};Month=${$('#filter-month').value||'Semua'};Status=${$('#filter-status').value||'Semua'};Severity=${$('#filter-severity').value||'Semua'}`);
    },900);
  }

  function bind(){
    $('#login-role').addEventListener('change',roleChange);$('#login-form').addEventListener('submit',login);$('#logout-btn').addEventListener('click',logout);$('#notification-button').addEventListener('click',async()=>{const panel=$('#notification-panel');const opening=panel.classList.contains('hidden');panel.classList.toggle('hidden');if(opening)await auditUI('notification_panel_open','Notification panel opened');});$('#notifications-read-all').addEventListener('click',()=>markNotificationsRead([],true));document.addEventListener('click',e=>{const panel=$('#notification-panel'),btn=$('#notification-button');if(panel&&!panel.classList.contains('hidden')&&!panel.contains(e.target)&&!btn.contains(e.target))panel.classList.add('hidden');});
    $('#add-record').addEventListener('click',async()=>{await auditUI('menu_click','Action=+ Tambah Temuan');openRecord(null);});$('#add-record-2').addEventListener('click',async()=>{await auditUI('menu_click','Action=+ Tambah');openRecord(null);});$('#reset-data').addEventListener('click',async()=>{await auditUI('menu_click','Action=Reset Workbook');resetData();});$('#delete-record').addEventListener('click',async()=>{await auditUI('menu_click','Action=Hapus Temuan');deleteRecord();});$('#record-form').addEventListener('submit',saveRecord);
    $('#search').addEventListener('input',()=>{renderRegister();auditSearch();});$$('[data-close-modal]').forEach(x=>x.addEventListener('click',closeRecord));$('#filter-month').addEventListener('change',async()=>{renderRegister();await auditUI('menu_click',`Filter=Bulan:${$('#filter-month').value||'Semua'}`);});$('#filter-status').addEventListener('change',async()=>{renderRegister();await auditUI('menu_click',`Filter=Status:${$('#filter-status').value||'Semua'}`);});$('#filter-severity').addEventListener('change',async()=>{renderRegister();await auditUI('menu_click',`Filter=Severity:${$('#filter-severity').value||'Semua'}`);});$('#column-filter-toggle').addEventListener('click',()=>{const menu=$('#column-filter-menu');const opening=menu.classList.contains('hidden');menu.classList.toggle('hidden');$('#column-filter-toggle').setAttribute('aria-expanded',String(opening));if(opening)renderColumnPicker();});$('#column-filter-all').addEventListener('click',async()=>{state.selectedColumns=headers.slice();renderColumnPicker();renderRegister();await auditUI('menu_click','Filter=Kolom:Semua');});$('#column-filter-options').addEventListener('change',async e=>{if(!(e.target instanceof HTMLInputElement)||e.target.type!=='checkbox')return;const field=e.target.value;if(e.target.checked){if(!state.selectedColumns.includes(field))state.selectedColumns=[...state.selectedColumns,field];}else{if(state.selectedColumns.length===1){e.target.checked=true;toast('Sedikitnya satu kolom harus tetap ditampilkan.');return;}state.selectedColumns=state.selectedColumns.filter(h=>h!==field);}state.selectedColumns=headers.filter(h=>state.selectedColumns.includes(h));renderColumnPicker();renderRegister();await auditUI('menu_click',`Filter=Kolom:${state.selectedColumns.join('|')}`);});document.addEventListener('click',e=>{const wrap=$('#column-filter');if(wrap&&!wrap.contains(e.target)){$('#column-filter-menu')?.classList.add('hidden');$('#column-filter-toggle')?.setAttribute('aria-expanded','false');}});$('#export-csv').addEventListener('click',async()=>{await auditUI('menu_click','Action=Export CSV');exportCSV();});$('#export-json').addEventListener('click',async()=>{await auditUI('menu_click','Action=Backup JSON');exportJSON();});$('#refresh-clients').addEventListener('click',async()=>{await auditUI('menu_click','Action=Refresh perangkat aktif');loadClients().catch(e=>toast(e.message));});$('#refresh-audit-log').addEventListener('click',async()=>{await auditUI('menu_click','Action=Muat Ulang Log Audit');loadAuditLog().catch(()=>{});});
    $$('.tab-btn').forEach(btn=>btn.addEventListener('click',async()=>{if(btn.hidden)return;$$('.tab-btn').forEach(b=>b.classList.remove('active'));btn.classList.add('active');$$('.tab-panel').forEach(p=>p.classList.remove('active'));$('#'+btn.dataset.tab+'-tab').classList.add('active');await auditUI('menu_click',`Menu=${btn.textContent.trim()}`);if(btn.dataset.tab==='security'){loadClients().catch(()=>{});loadAuditLog().catch(()=>{});}}));
    window.addEventListener('keydown',e=>{if(e.key==='Escape'&&!$('#record-modal').classList.contains('hidden'))closeRecord();});
  }

  renderReleaseNotes();bind();roleChange();renderFilters();renderColumnPicker();refreshDashboard();applyPermissions();startClock();loadSession();
})();
