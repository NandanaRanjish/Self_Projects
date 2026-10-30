(() => {
'use strict';
const modes=['none','guide','guard','both'];
const names={none:'NONE',guide:'SHUFFLER ONLY',guard:'GUARD ONLY',both:'COMBINED',clean:'CLEAN'};
const colors={none:'#ff8b9c',guide:'#eecb85',guard:'#76d8e9',both:'#66dab6',clean:'#97affb'};
const runs=(DATA.runs||[]).filter(r=>r&&r.source==='raw_project_files');
const accepted=runs.filter(r=>r.status==='PASS');
const $=x=>document.querySelector(x);
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const pct=(n,d)=>(d?((100*n/d).toFixed(1)+'%'):'—');
const label=r=>`${String(r.rate_policy||r.rate||'?')}ms · ${names[r.mode]||r.mode} · R${r.trial||'?'}`.replace('ALTms','ALT');
const selectRun=list=>list.map(r=>`<option value="${esc(r.id)}">${esc(label(r))} ${r.status==='PASS'?'✓':'('+esc(r.status)+')'}</option>`).join('');
const runByID=id=>runs.find(r=>r.id===id);
const countErr=r=>(r?.logWarnings||[]).length;
let active='results', chosen='', cursor=0, playTimer=null, selectedRate='20';

function navigate(name){active=name;stopPlay();document.querySelectorAll('nav button').forEach(b=>b.classList.toggle('active',b.dataset.page===name));render();}
document.querySelectorAll('nav button').forEach(b=>b.onclick=()=>navigate(b.dataset.page));
$('#data-status').textContent=`${accepted.length} accepted · ${runs.length-accepted.length} other runs`;

function header(title,subtitle){return `<div class="eyebrow">MAARS · Real ESP32-S3 measurements</div><h1>${title}</h1><p class="lead">${subtitle}</p>`;}
function empty(title,what){return `<div class="empty"><b>${esc(title)}</b>${esc(what)}</div>`;}
function group(rate,mode){const a=accepted.filter(r=>String(r.rate)===String(rate)&&r.mode===mode);
 const commands=a.reduce((n,r)=>n+r.count,0),bad=a.reduce((n,r)=>n+r.corrupted,0);
 return {n:a.length,commands,bad,rate,p:pct(bad,commands),percent:commands?100*bad/commands:null};}
function barChart(rate){
 const groups=modes.map(m=>group(rate,m));const w=750,h=330,x0=65,unit=165,plotTop=38,plotBottom=255;
 let lines='';[0,20,40,60,80,100].forEach(v=>{const y=plotBottom-(v/100)*(plotBottom-plotTop);
   lines+=`<line x1="${x0}" x2="740" y1="${y}" y2="${y}" class="gridline"/><text x="${x0-12}" y="${y+4}" class="ticks" text-anchor="end">${v}%</text>`;
 });
 const bars=groups.map((g,i)=>{const x=85+i*unit;const measured=g.percent??0,bh=measured/100*(plotBottom-plotTop);
   return `<rect x="${x}" y="${plotBottom-bh}" width="112" height="${Math.max(bh,0.1)}" rx="7" fill="${colors[modes[i]]}"/>
   <text x="${x+56}" y="${Math.max(plotBottom-bh-10,18)}" text-anchor="middle" class="chartlabel">${g.p}</text>
   <text x="${x+56}" y="282" class="chartlabel" text-anchor="middle">${names[modes[i]].replace(' ONLY','')}</text>
   <text x="${x+56}" y="302" class="ticks" text-anchor="middle">${g.n} trials</text>`;
 }).join('');
 return `<svg class="chart" viewBox="0 0 ${w} ${h}" role="img" aria-label="Command corruption across four defenses at ${rate} milliseconds">${lines}${bars}</svg>`;
}
function results(){
 const all=accepted.filter(r=>['none','guide','guard','both'].includes(r.mode)&&[20,25].includes(r.rate));
 const corrupt=all.reduce((n,r)=>n+r.corrupted,0),attacks=all.reduce((n,r)=>n+(r.attempts||0),0);
 const good=all.filter(r=>r.mode==='guard'||r.mode==='both');
 const gbad=good.reduce((n,r)=>n+r.corrupted,0);
 let html=header('Can randomized scheduling alone stop the attack?',
  'Four controlled modes keep the same dispatcher, controller rate and attacker. We turn schedule-bank guidance and the command-window guard on and off independently.');
 html+=`<div class="tiles">
 <div class="tile"><div class="label">Accepted attack runs</div><div class="value">${all.length}</div><div class="note">20 and 25 ms experiments</div></div>
 <div class="tile"><div class="label">Attacker attempts</div><div class="value">${attacks}</div><div class="note">Across accepted runs</div></div>
 <div class="tile"><div class="label">Corrupted commands</div><div class="value">${corrupt}</div><div class="note">Across all four modes</div></div>
 <div class="tile"><div class="label">Guarded corruptions</div><div class="value ${gbad===0?'good':'bad'}">${gbad}</div><div class="note">GUARD ONLY + COMBINED</div></div>
 </div>`;
 html+=`<section class="panel"><div class="panel-header"><div><h2>Observed command corruption</h2><div class="card-note">Only complete runs that passed the independent hardware audits</div></div><div class="filters"><label for="rate">Controller period</label><select id="rate"><option value="20" ${selectedRate==='20'?'selected':''}>20 ms</option><option value="25" ${selectedRate==='25'?'selected':''}>25 ms</option></select></div></div>`;
 html+=accepted.length?barChart(selectedRate):empty('No new experiments yet.','Run: python repro/experiment.py ablation --rate 20 --id 101');
 html+=`<div class="card-note">NONE = basic TaskShuffler active, offline bank guidance OFF. SHUFFLER ONLY = offline bank guidance, no command guard. GUARD ONLY = command-window grant guard without bank guidance. COMBINED = both. A zero measured rate does not prove universal security.</div></section>`;
 html+=`<section class="panel"><h2>Four-mode comparison · ${selectedRate} ms</h2><div class="tablewrap"><table><thead><tr><th>Mode</th><th>Guidance</th><th>Guard</th><th>Accepted runs</th><th>Corruptions</th><th>Rate</th></tr></thead><tbody>`;
 modes.forEach(m=>{const g=group(selectedRate,m);html+=`<tr><td><b>${names[m]}</b></td><td>${m==='guide'||m==='both'?'ON':'OFF'}</td><td>${m==='guard'||m==='both'?'ON':'OFF'}</td><td>${g.n}</td><td>${g.commands?`${g.bad}/${g.commands}`:'—'}</td><td class="${g.bad?'bad':'good'}">${g.p}</td></tr>`;});
 html+=`</tbody></table></div><p class="card-note">Descriptive pooled command fractions. Experimental replicate = one full trial; use paired per-trial analysis for uncertainty.</p></section>`;
 const failed=runs.filter(r=>r.status!=='PASS');
 if(failed.length)html+=`<section class="panel"><h2>Other runs (${failed.length})</h2><div class="tablewrap"><table><thead><tr><th>Run</th><th>Status</th><th>Reason</th></tr></thead><tbody>${failed.slice(0,30).map(r=>`<tr><td>${esc(r.id)}</td><td class="warn">${esc(r.status)}</td><td>${esc((r.logWarnings||[]).join('; ')||'Partial/missing independent verification')}</td></tr>`).join('')}</tbody></table></div></section>`;
 html+=`<p class="scope">This benchmark tests a cooperative UNTRUSTED worker. It does not provide memory isolation or guarantee resistance to arbitrary attackers. The online schedule uses offline model guidance, not exact slot replay.</p>`;
 return html;
}

function validTimelineRuns(){return runs.filter(r=>r.capture?.length&&r.capture_meta?.start_us!=null).sort((a,b)=>a.rate===b.rate?(a.trial||0)-(b.trial||0):String(a.rate).localeCompare(String(b.rate)));}
const W=['CONTROL','SAFETY','MONITOR','TX','UNTRUSTED'];
const WC={CONTROL:'#76d8e9',SAFETY:'#97affb',MONITOR:'#d4a9f4',TX:'#66dab6',UNTRUSTED:'#ff8b9c'};
function timeline(){
 const available=validTimelineRuns();if(!chosen||!available.some(r=>r.id===chosen))chosen=available[0]?.id||'';
 const run=runByID(chosen);
 let html=header('What happened in the scheduler?', 'Replay an actual 600 ms ESP32 capture: worker grants, command publication, transmission, and untrusted execution.');
 html+=`<section class="panel"><div class="panel-header"><h2>Captured execution sequence</h2><div class="filters"><label for="runpick">Experiment</label><select id="runpick">${selectRun(available)}</select></div></div>`;
 if(!run){html+=empty('No captures yet.','Run one clean or attack trial to populate the timeline.');return html+'</section>';}
 const start=Number(run.capture_meta.start_us),end=Number(run.capture_meta.end_us),range=end-start;
 if(!(range>0)){html+=empty('Capture timestamps unavailable','No valid ESP32 clock window.');return html+'</section>';}
 cursor=Math.max(0,Math.min(1000,cursor));const until=start+range*cursor/1000;
 const x=us=>110+((us-start)/range)*1045;
 const lanes=W.map((w,i)=>`<text x="8" y="${64+i*52}" class="ticks">${w}</text><line x1="110" x2="1155" y1="${69+i*52}" y2="${69+i*52}" class="gridline"/>`).join('');
 const bars=(run.capture||[]).filter(c=>c.kind==='G'&&W.includes(c.worker)&&c.s!=null&&c.e!=null).map(c=>{
  let a=Math.max(start,c.s),b=Math.min(end,c.e);if(a>=b)return '';const yy=51+W.indexOf(c.worker)*52;
  return `<rect x="${x(a).toFixed(1)}" y="${yy}" width="${Math.max(0.7,x(b)-x(a)).toFixed(2)}" height="17" rx="2" fill="${WC[c.worker]}" opacity=".91"><title>${esc(c.worker)} job ${c.job}: ${Math.round(a-start)}..${Math.round(b-start)}µs relative to frozen frame</title></rect>`;
 }).join('');
 const windows=(run.windows||[]).filter(w=>w.p!=null&&w.tx!=null).map(w=>{
  const a=Math.max(start,w.p),b=Math.min(end,w.tx);if(a>=b)return '';
  return `<rect x="${x(a)}" y="20" width="${Math.max(.7,x(b)-x(a))}" height="10" rx="2" fill="${w.overlap?'#ff8b9c':'#66dab6'}"><title>Command pending${w.overlap?' — UNTRUSTED overlap':''}</title></rect>`;
 }).join('');
 let ticks='';for(let ms=0;ms<=600;ms+=100){const px=110+ms/600*1045;ticks+=`<text x="${px}" y="330" class="ticks" text-anchor="middle">${ms}ms</text>`;}
 const cursorX=x(until);const visible=(run.capture||[]).filter(e=>e.s!=null&&e.s<=until).slice(-8).reverse();
 html+=`<div class="legend"><span><b style="background:#66dab6"></b>Protected window</span><span><b style="background:#ff8b9c"></b>Overlap / UNTRUSTED</span><span><b style="background:#76d8e9"></b>CONTROL grant</span></div>
 <svg class="timeline" viewBox="0 0 1180 345" role="img" aria-label="Five real-time task lanes and exposure windows">
 <text x="8" y="29" class="ticks">PENDING</text>${windows}${lanes}${bars}<line x1="${cursorX}" x2="${cursorX}" y1="12" y2="312" stroke="#fff" stroke-width="2" stroke-dasharray="5 4"/>${ticks}</svg>
 <div class="livebox"><button id="play" class="action">${playTimer?'Pause':'Play'}</button><button id="reset" class="action">Reset</button><input id="cursor" type="range" min="0" max="1000" value="${cursor}" aria-label="Move replay cursor"><span class="status">${(cursor*0.6).toFixed(0)} / 600 ms</span></div>
 <p class="card-note">Capture: ${run.capture.length} recorded events · ${esc(run.status)} · ${run.capture_audit?.job_count??'?'} complete jobs · ${run.capture_audit?.overlaps??'?'} overlapping complete command windows</p></section>`;
 html+=`<section class="panel"><h2>Latest recorded events at cursor</h2><div class="events">${visible.length?visible.map(e=>`<div><time>${((e.s-start)/1000).toFixed(2)}ms</time><b>${esc(e.kind)}</b> · ${esc(e.worker)} · job ${e.job}</div>`).join(''):'Move the cursor or press Play to inspect execution events.'}</div></section>`;
 html+=`<p class="scope">This is the ESP32's frozen scheduling frame. Motor measurements use a different host clock and are shown separately, without invented synchronization.</p>`;
 return html;
}

function lineChart(points,kind){
 const vals=points.filter(p=>p.t!=null&&(kind==='motor'?p.speed!=null&&p.ref!=null:p.applied!=null&&p.calculated!=null));
 if(!vals.length)return empty('No motor samples','Host trace lacks the requested numerical columns.');
 const w=1000,h=280,left=65,right=966,top=28,bottom=239;
 const t0=Math.min(...vals.map(p=>p.t)),t1=Math.max(...vals.map(p=>p.t));
 const ys=kind==='motor'?vals.flatMap(p=>[p.speed,p.ref]):vals.flatMap(p=>[p.applied,p.calculated]);
 let min=Math.min(...ys),max=Math.max(...ys);if(max===min){min-=1;max+=1;}const pad=(max-min)*.12;min-=pad;max+=pad;
 const x=t=>left+(t-t0)/Math.max(1e-8,t1-t0)*(right-left);
 const y=v=>bottom-(v-min)/(max-min)*(bottom-top);
 const poly=field=>vals.map((p,i)=>`${i?'L':'M'}${x(p.t).toFixed(1)},${y(p[field]).toFixed(1)}`).join(' ');
 let grid='';for(let i=0;i<=4;i++){let yy=top+(bottom-top)*i/4;grid+=`<line x1="${left}" x2="${right}" y1="${yy}" y2="${yy}" class="gridline"/><text x="${left-8}" y="${yy+4}" text-anchor="end" class="ticks">${(max-(max-min)*i/4).toFixed(1)}</text>`;}
 const attacks=vals.filter(p=>p.attack).map(p=>`<circle cx="${x(p.t)}" cy="${y(kind==='motor'?p.speed:p.applied)}" r="4" fill="#ff8b9c"><title>Corrupted transmitted command at t=${p.t}s</title></circle>`).join('');
 const key1=kind==='motor'?'speed':'calculated',key2=kind==='motor'?'ref':'applied';
 return `<svg class="chart" viewBox="0 0 ${w} ${h}" role="img" aria-label="${kind} chart">${grid}<path class="line" d="${poly(key1)}" stroke="#76d8e9"/><path class="line" d="${poly(key2)}" stroke="#66dab6"/>${attacks}<text x="${left}" y="269" class="ticks">${t0.toFixed(1)} s</text><text x="${right}" y="269" class="ticks" text-anchor="end">${t1.toFixed(1)} s</text></svg>`;
}
function motor(){
 const available=runs.filter(r=>r.points?.some(p=>p.speed!=null)).sort((a,b)=>(a.rate||0)-(b.rate||0));
 if(!chosen||!available.some(r=>r.id===chosen))chosen=available[0]?.id||'';
 const r=runByID(chosen);
 let html=header('How did the attack affect the motor?', 'Recorded host-model speed and voltage. Red markers indicate transmitted-command corruption; select any complete or partial trace.');
 html+=`<section class="panel"><div class="panel-header"><h2>Select an experiment</h2><div class="filters"><select id="runpick">${selectRun(available)}</select></div></div>`;
 if(!r)return html+empty('No motor data yet.','Complete a clean or attack experiment, then regenerate the dashboard.')+'</section>';
 const error=r.points.filter(p=>p.speed!=null&&p.ref!=null);
 const rmse=error.length?Math.sqrt(error.reduce((sum,p)=>sum+(p.speed-p.ref)**2,0)/error.length):null;
 html+=`<div class="tiles"><div class="tile"><div class="label">Result</div><div class="value" style="font-size:25px">${esc(r.status)}</div></div><div class="tile"><div class="label">Corrupted commands</div><div class="value">${r.corrupted}/${r.count}</div></div><div class="tile"><div class="label">Attacker attempts</div><div class="value">${r.attempts??'—'}</div></div><div class="tile"><div class="label">Motor RMSE</div><div class="value">${rmse===null?'—':rmse.toFixed(2)}</div><div class="note">rad/s · host simulation</div></div></div>`;
 html+=`<h3>Motor speed (rad/s)</h3><div class="legend"><span><b style="background:#76d8e9"></b>Actual simulated speed</span><span><b style="background:#66dab6"></b>Reference</span><span><b style="background:#ff8b9c"></b>Corruption</span></div>${lineChart(r.points,'motor')}
 <h3 style="margin-top:25px">Motor voltage (V)</h3><div class="legend"><span><b style="background:#76d8e9"></b>Computed voltage</span><span><b style="background:#66dab6"></b>Applied voltage</span><span><b style="background:#ff8b9c"></b>Corruption</span></div>${lineChart(r.points,'voltage')}</section>`;
 html+=`<p class="scope">The live host motor runner uses a nominal 20 ms integration step even during 25 ms and ALT configurations. These graphs illustrate command corruption and protection, not period-correct mixed-rate HIL stability.</p>`;
 return html;
}
function stopPlay(){if(playTimer!==null){clearInterval(playTimer);playTimer=null;}}
function render(){const root=$('#page');root.innerHTML=active==='results'?results():active==='timeline'?timeline():motor();
 const rate=$('#rate');if(rate)rate.onchange=e=>{selectedRate=e.target.value;render();};
 const selector=$('#runpick');if(selector){selector.value=chosen;selector.onchange=e=>{chosen=e.target.value;cursor=0;stopPlay();render();};}
 const slider=$('#cursor');if(slider)slider.oninput=e=>{cursor=Number(e.target.value);render();};
 const play=$('#play');if(play)play.onclick=()=>{if(playTimer!==null){stopPlay();render();return;}
   playTimer=setInterval(()=>{cursor+=10;if(cursor>1000){cursor=1000;stopPlay();}render();},80);render();};
 const reset=$('#reset');if(reset)reset.onclick=()=>{cursor=0;stopPlay();render();};
}
render();
})();
