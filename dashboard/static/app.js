'use strict';
const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];
const state = {view:'overview',page:1,limit:40,total:0,selectedFinding:null,jobId:null};
const labels = {overview:'Overview',findings:'Security Findings',investigations:'AI Investigations',evaluation:'Model Evaluation',events:'Event Stream',logs:'System Logs'};
const escapeHtml = x => String(x ?? '').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmt = n => Number(n||0).toLocaleString('en-US');
const pill = t => t ? `<span class="pill ${escapeHtml(t)}">${escapeHtml(t)}</span>` : '<span class="muted">—</span>';
const shortPath = s => (s||'—').split('/').slice(-2).join('/');
const since = date => date ? String(date).replace('T',' ').slice(0,19) : '—';

async function api(url,{method='GET',body}={}){
  const options={method,headers:{}};
  if(method!=='GET'){options.headers['Content-Type']='application/json';options.headers['X-AFI-CSRF']=window.AFI_CSRF;options.body=JSON.stringify(body||{});}
  let response;
  try {response=await fetch(url, options);}catch(e){throw new Error('Dashboard server unreachable');}
  let data;
  try{data=await response.json();}catch{throw new Error('Unexpected non-JSON response');}
  if(!response.ok)throw new Error(data.error||data.message||`HTTP ${response.status}`);
  return data;
}
function flash(message,error=false){const el=$('#flash');el.textContent=message;el.classList.toggle('error',error);el.hidden=false;clearTimeout(flash.timeout);flash.timeout=setTimeout(()=>el.hidden=true,6000);}
function safeError(err){flash(err.message||String(err),true);}
function navigate(view){
  if(!labels[view])return;
  state.view=view;
  $$('.view').forEach(e=>e.hidden=e.id!==`view-${view}`);
  $$('.navitem').forEach(e=>e.classList.toggle('active',e.dataset.view===view));
  $('#breadcrumb').textContent=labels[view];
  if(view==='findings')loadFindings();
  if(view==='investigations')loadInvestigations();
  if(view==='evaluation')loadEvaluation();
  if(view==='events')loadEvents();
  if(view==='overview')loadOverview();
}
function drawBars(container,data,kind){
  const root=$(container);const dict=Object.fromEntries((data||[]).map(x=>[(x.severity||x.classification),x.count]));
  const items=kind==='severity'?['CRITICAL','HIGH','MEDIUM','LOW']:['SUSPICIOUS','BENIGN','INCONCLUSIVE'];
  const max=Math.max(...items.map(x=>dict[x]||0),1);
  root.innerHTML=items.map(name=>`<div class="bar-item"><span>${name}</span><div class="track"><div class="fill ${name}" style="width:${(dict[name]||0)/max*100}%"></div></div><span class="count">${fmt(dict[name])}</span></div>`).join('');
}
function markState(id,value){const e=$(id);e.textContent=value||'unknown';e.classList.remove('active','failed');if(value==='active')e.classList.add('active');if(value==='failed')e.classList.add('failed');}
function reflectStates(s){markState('#monitorState',s.monitor);markState('#detectorState',s.detector);markState('#auditdState',s.auditd);const all=s.monitor==='active'&&s.detector==='active';$('#sideText').textContent=all?'Monitoring active':'Monitoring needs attention';$('#sidePulse').classList.toggle('off',!all);}
function findingRow(r,overview=false){return `<tr class="click-row" data-finding="${r.id}" tabindex="0" title="Open finding #${r.id}">
<td class="mono muted">#${r.id}</td><td>${escapeHtml(r.event_types)}</td>
<td class="path-col" title="${escapeHtml(r.file_path)}">${escapeHtml(shortPath(r.file_path))}</td><td>${escapeHtml(r.username)}</td>
<td>${pill(r.severity)}</td>${overview?'':`<td>${pill(r.status)}</td>`}<td>${pill(r.latest_classification)}</td>${overview?'<td class="muted">↗</td>':''}</tr>`;}
async function loadOverview(){
  try{
    const [d,f]=await Promise.all([api('/api/summary'),api('/api/findings?limit=9')]);
    $('#metricEvents').textContent=fmt(d.totals.events);$('#metricFindings').textContent=fmt(d.totals.findings);
    $('#metricOpen').textContent=fmt(d.totals.open_findings);$('#metricAI').textContent=fmt(d.totals.assessments);
    drawBars('#severityBars',d.severity,'severity');drawBars('#aiBars',d.assessments,'classification');reflectStates(d.services);
    $('#overviewFindings').innerHTML=f.rows.length?f.rows.map(r=>findingRow(r,true)).join(''):'<tr><td class="empty" colspan="7">No findings yet.</td></tr>';
    $('#lastUpdated').textContent=new Date().toLocaleTimeString();
  }catch(e){safeError(e);}
}
async function loadFindings(){
  const params=new URLSearchParams({page:state.page,limit:state.limit,q:$('#findSearch').value.trim(),severity:$('#findSeverity').value,status:$('#findStatus').value,classification:$('#findClass').value});
  try{
    const d=await api('/api/findings?'+params);state.total=d.count;
    $('#findingCount').textContent=`${fmt(d.count)} MATCHING FINDINGS`;
    $('#findingsBody').innerHTML=d.rows.length?d.rows.map(r=>findingRow(r)).join(''):'<tr><td colspan="7" class="empty">No matching findings.</td></tr>';
    const pages=Math.max(1,Math.ceil(d.count/d.limit));$('#pageInfo').textContent=`Page ${state.page} / ${pages}`;
    $('#prevPage').disabled=state.page<=1;$('#nextPage').disabled=state.page>=pages;
  }catch(e){safeError(e);}
}
async function loadInvestigations(){
  try{const d=await api('/api/assessments?limit=100');$('#assessmentsBody').innerHTML=d.rows.map(r=>`<tr class="click-row" data-assessment="${r.id}" tabindex="0"><td class="mono">#${r.id}</td><td class="mono">#${r.finding_id}</td><td>${pill(r.classification)}</td><td>${pill(r.severity)}</td><td>${escapeHtml(r.confidence)}</td><td>${pill(r.validation_status)}</td><td class="muted">${escapeHtml(since(r.created_at))}</td></tr>`).join('')||'<tr><td class="empty" colspan="7">No saved investigations.</td></tr>';}
  catch(e){safeError(e);}
}
async function loadEvents(){
  try{const d=await api('/api/events?limit=100');$('#eventsBody').innerHTML=d.rows.map(r=>`<tr><td class="mono muted">#${r.id}</td><td class="muted">${escapeHtml(r.timestamp)}</td><td>${pill(r.event_type)}</td><td class="path-col" title="${escapeHtml(r.file_path)}">${escapeHtml(r.file_path)}</td><td class="muted">${escapeHtml(r.details||'—')}</td></tr>`).join('')||'<tr><td class="empty" colspan="5">No recorded events.</td></tr>';}
  catch(e){safeError(e);}
}
async function loadEvaluation(){
  try{const d=await api('/api/evaluation');$('#evalRows').innerHTML=d.cases.map(x=>{
    const counts=x.counts||{};const runs=x.runs||0;
    const segments=['SUSPICIOUS','BENIGN','INCONCLUSIVE'].map(name=>`<div class="${name}" style="width:${runs?100*(counts[name]||0)/runs:0}%" title="${name}: ${counts[name]||0}"></div>`).join('');
    return `<div class="eval-row"><div class="eval-name">${escapeHtml(x.name)}<span class="eval-category">${escapeHtml(x.category)} · Finding #${x.finding_id}</span></div><div class="stacked-bar">${segments}</div><div class="eval-metric">${runs} runs · ${x.agreement===null?'—':x.agreement+'%'} agree</div></div>`;
  }).join('');}catch(e){safeError(e);}
}
function openDrawer(title,eyebrow,content){$('#drawerTitle').textContent=title;$('#drawerEyebrow').textContent=eyebrow;$('#drawerContent').innerHTML=content;$('#overlay').hidden=false;}
function closeDrawer(){$('#overlay').hidden=true;state.selectedFinding=null;state.jobId=null;}
async function openFinding(fid){
  try{const d=await api(`/api/findings/${fid}`),f=d.finding;state.selectedFinding=fid;
    let html=`<div class="detail-path mono">${escapeHtml(f.file_path)}</div><div class="detail-grid">
    <div><small>Event type</small><strong>${escapeHtml(f.event_types)}</strong></div><div><small>Risk severity</small><strong>${pill(f.severity)} · ${f.risk_score}</strong></div>
    <div><small>Attributed user</small><strong>${escapeHtml(f.username)}</strong></div><div><small>Audit event ID</small><strong>${escapeHtml(f.audit_event_id||'Unmatched')}</strong></div>
    <div><small>First observed</small><strong>${escapeHtml(f.first_seen)}</strong></div><div><small>Current status</small><strong>${pill(f.status)}</strong></div></div>
    <h3 class="section-title">Risk explanation</h3><div class="detail-reasons">${escapeHtml(f.reasons||'No stored explanation')}</div><h3 class="section-title">Kernel audit evidence</h3><button id="loadAudit" class="btn btn-quiet">View matched audit record</button><div id="auditDetails"></div>
    <h3 class="section-title">Actions</h3><div class="action-strip"><select id="detailStatus" aria-label="Finding status"><option>OPEN</option><option>INVESTIGATING</option><option>RESOLVED</option></select>
    <button id="saveStatus" class="btn btn-quiet">Update status</button><button id="investigateBtn" class="btn btn-primary">✧ Investigate with AI</button></div>
    <div class="footnote">Starting an AI investigation sends evidence to the configured OpenAI API and incurs a paid API request. Results are appended to SQLite.</div><div id="jobInfo"></div>
    <h3 class="section-title">Saved AI assessments (${d.assessments.length})</h3><div class="detail-rows">`;
    html+=d.assessments.map(a=>`<div class="assessment-card" data-assessment="${a.id}"><div class="line"><strong class="mono">Assessment #${a.id}</strong>${pill(a.classification)}</div><small>${escapeHtml(since(a.created_at))} · ${escapeHtml(a.confidence)} confidence · ${escapeHtml(a.validation_status||'NO_VALIDATION')}</small></div>`).join('')||'<div class="muted">This finding has not been investigated yet.</div>';
    html+='</div><h3 class="section-title">Recorded file history</h3><div class="detail-rows">'+(d.history.map(h=>`<div class="assessment-card"><div class="line"><strong>${escapeHtml(h.event_type)}</strong><small>${escapeHtml(h.timestamp)}</small></div><small>${escapeHtml(h.details||'')}</small></div>`).join('')||'<div class="muted">No Watchdog file history for this path.</div>')+'</div>';
    openDrawer(`Finding #${fid}`,'SECURITY FINDING',html);$('#detailStatus').value=f.status;
    $('#loadAudit').onclick=async()=>{
      $('#auditDetails').textContent='Loading audit record…';
      try{const d=await api(`/api/findings/${fid}/audit`);$('#auditDetails').innerHTML='<pre class="terminal">'+escapeHtml(JSON.stringify(d,null,2))+'</pre>';}
      catch(e){$('#auditDetails').textContent=e.message;safeError(e);}
    };
    $('#saveStatus').onclick=()=>confirmDialog('Update finding status',`Set finding #${fid} to ${$('#detailStatus').value}?`,()=>updateStatus(fid,$('#detailStatus').value));
    $('#investigateBtn').onclick=()=>confirmDialog('Launch AI investigation',`Run the existing AI investigator for finding #${fid}? This incurs an API charge and saves a new assessment.`,()=>investigate(fid));
  }catch(e){safeError(e);}
}
async function openAssessment(aid){
  try{const a=await api(`/api/assessments/${aid}`);const s=a.assessment||{},v=a.validation||{};
    const analysis=s.analysis||s.explanation||s.reasoning||s.summary||'';
    const coverage=v.incident_coverage||{};
    const fields=[['Finding',`#${a.finding_id}`],['Classification',a.classification],['Severity',a.severity],['Confidence',a.confidence],['Model',a.model],['Validation',a.validation_status||'NO_VALIDATION'],['Verified claims',`${a.verified_claims??'—'} / ${a.total_claims??'—'}`],['Incident coverage',coverage.status?`${coverage.status} (${coverage.covered??0}/${coverage.total??0})`:'N/A']];
    let html='<div class="detail-grid">'+fields.map(([k,val])=>`<div><small>${escapeHtml(k)}</small><strong>${escapeHtml(val)}</strong></div>`).join('')+'</div>';
    html+=`<h3 class="section-title">AI reasoning</h3><div class="analysis-box">${escapeHtml(typeof analysis==='string'?analysis:JSON.stringify(analysis,null,2)||'No analysis field')}</div>`;
    html+='<h3 class="section-title">Structured AI output</h3><details><summary>View assessment JSON</summary><pre class="terminal">'+escapeHtml(JSON.stringify(s,null,2))+'</pre></details>';
    html+='<h3 class="section-title">Independent evidence validation</h3><details><summary>View validation JSON</summary><pre class="terminal">'+escapeHtml(JSON.stringify(v,null,2))+'</pre></details>';
    html+=`<p class="footnote">VERIFIED_FIELDS only checks specified structured claims. It does not establish correct classification, verified authorization, or complete coverage.</p><div class="action-strip"><button id="openParent" class="btn btn-quiet">← Open finding #${a.finding_id}</button></div>`;
    openDrawer(`Assessment #${aid}`,'AI INVESTIGATION',html);$('#openParent').onclick=()=>openFinding(a.finding_id);
  }catch(e){safeError(e);}
}
let confirmCallback=null;
function confirmDialog(title,description,callback){$('#confirmTitle').textContent=title;$('#confirmDescription').textContent=description;confirmCallback=callback;$('#confirmOverlay').hidden=false;}
function closeConfirm(){$('#confirmOverlay').hidden=true;confirmCallback=null;}
async function updateStatus(fid,status){try{await api(`/api/findings/${fid}/status`,{method:'POST',body:{status}});flash(`Finding #${fid} updated to ${status}`);await openFinding(fid);loadFindings();}catch(e){safeError(e);}}
async function investigate(fid){
  try{const data=await api(`/api/findings/${fid}/investigate`,{method:'POST',body:{}});state.jobId=data.job.id;const el=$('#jobInfo');if(el)el.innerHTML='<div class="job-status">AI investigation queued. This page will update when it finishes.</div>';pollJob(data.job.id,fid);}catch(e){safeError(e);}
}
async function pollJob(jobId,fid){
  let done=false;
  for(let i=0;i<150&&!done;i++){
    await new Promise(resolve=>setTimeout(resolve,2000));
    if(state.jobId!==jobId)return;
    try{const d=await api(`/api/jobs/${encodeURIComponent(jobId)}`);const job=d.job;
      const el=$('#jobInfo');if(el)el.textContent=`AI job: ${job.status}${job.status==='failed'?': '+(job.result||''):''}`;
      if(job.status==='complete'||job.status==='failed'){
        done=true;flash(job.status==='complete'?`AI investigation completed for #${fid}`:`AI investigation failed: ${job.result||'unknown reason'}`,job.status==='failed');
        if(job.status==='complete'&&state.selectedFinding===fid){await openFinding(fid);}
      }
    }catch(e){safeError(e);return;}
  }
}
async function serviceAction(service,action){
  try{const d=await api(`/api/services/${service}/${action}`,{method:'POST',body:{}});flash(`${service}: ${action} successful`);reflectStates(d.services);}
  catch(e){safeError(e);}finally{loadOverview();}
}
async function loadLogs(){try{const d=await api(`/api/logs/${$('#logService').value}`);$('#logOutput').textContent=d.message||'No journal entries found.';}catch(e){$('#logOutput').textContent=e.message;safeError(e);}}
function refreshActive(){const views={overview:loadOverview,findings:loadFindings,investigations:loadInvestigations,evaluation:loadEvaluation,events:loadEvents,logs:loadLogs};views[state.view]();}
$$('.navitem').forEach(el=>el.addEventListener('click',()=>navigate(el.dataset.view)));
$$('[data-go]').forEach(el=>el.addEventListener('click',()=>navigate(el.dataset.go)));
$('#refreshBtn').onclick=refreshActive;$('#serviceRefresh').onclick=loadOverview;
$$('[data-service]').forEach(el=>el.addEventListener('click',()=>confirmDialog(`${el.dataset.action} ${el.dataset.service}`,`Are you sure you want to ${el.dataset.action} the ${el.dataset.service} service?`,()=>serviceAction(el.dataset.service,el.dataset.action))));
let searchTimer;
$('#findSearch').addEventListener('input',()=>{clearTimeout(searchTimer);searchTimer=setTimeout(()=>{state.page=1;loadFindings();},260);});
['#findSeverity','#findStatus','#findClass'].forEach(sel=>$(sel).addEventListener('change',()=>{state.page=1;loadFindings();}));
$('#prevPage').onclick=()=>{if(state.page>1){state.page--;loadFindings();}};
$('#nextPage').onclick=()=>{if(state.page*state.limit<state.total){state.page++;loadFindings();}};
$('#loadLogs').onclick=loadLogs;
$('#drawerClose').onclick=closeDrawer;
$('#overlay').addEventListener('click',e=>{if(e.target===$('#overlay'))closeDrawer();});
$('#cancelAction').onclick=closeConfirm;
$('#confirmOverlay').addEventListener('click',e=>{if(e.target===$('#confirmOverlay'))closeConfirm();});
$('#confirmAction').onclick=()=>{const callback=confirmCallback;closeConfirm();if(callback)callback();};
document.addEventListener('keydown',e=>{if(e.key==='Escape'){closeConfirm();closeDrawer();}});
document.addEventListener('click',e=>{
  const a=e.target.closest('[data-assessment]');if(a){openAssessment(+a.dataset.assessment);return;}
  const f=e.target.closest('[data-finding]');if(f){openFinding(+f.dataset.finding);}
});
document.addEventListener('keydown',e=>{if(e.key==='Enter'){const row=e.target.closest('tr.click-row');if(row)row.click();}});
loadOverview();
setInterval(()=>{if(document.visibilityState==='visible'&&state.view==='overview')loadOverview();},5000);
setInterval(()=>{if(document.visibilityState==='visible'&&state.view==='findings')loadFindings();},10000);
