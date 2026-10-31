
from __future__ import annotations
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
import argparse,csv,hashlib,json,math,random

DELTA_US=50; FRAME_US=600000; FRAME_SLOTS=12000
CODES={'CONTROL':0,'SAFETY':1,'MONITOR':2,'TX':3,'UNTRUSTED':4,'IDLE':5}
WORKERS=('CONTROL','SAFETY','MONITOR','TX','UNTRUSTED')

@dataclass(frozen=True)
class Task:
    name:str; period_slots:int; demand_slots:int; offset_slots:int; priority:int

@dataclass
class Job:
    task:Task; ordinal:int; start:int; deadline:int; remaining:int

def tasks_for(period_ms,params=None):
    if period_ms not in (20,25):raise ValueError('Only 20 and 25ms certified periods')
    demands={'CONTROL':1500,'SAFETY':1000,'MONITOR':750,'TX':550,'UNTRUSTED':2200}
    if params:demands.update(params)
    durations={'CONTROL':period_ms,'SAFETY':40,'MONITOR':60,'TX':period_ms,'UNTRUSTED':50}
    offsets={'CONTROL':0,'SAFETY':0,'MONITOR':0,'TX':8,'UNTRUSTED':0}
    return [Task(n,durations[n]*1000//DELTA_US,math.ceil(demands[n]/DELTA_US),offsets[n]*1000//DELTA_US,i) for i,n in enumerate(WORKERS)]

def generate_one(period_ms,seed,randomize=True,assumed_us=None,security_bias=0.0,aew_us=7000):
    rng=random.Random(seed)
    tasks=tasks_for(period_ms,assumed_us)
    slots=[]; jobs=[]; jcount={t.name:0 for t in tasks}; completed_control=set()
    hold=0;prev=None
    protected = {j for j in range(600//period_ms) if rng.random()<security_bias}
    last_protected_ctrl_tick = -1000000
    omega = math.ceil(aew_us/DELTA_US)
    for tick in range(FRAME_SLOTS):
        for t in tasks:
            if tick>=t.offset_slots and (tick-t.offset_slots)%t.period_slots==0:
                ordinal=jcount[t.name];jcount[t.name]+=1
                jobs.append(Job(t,ordinal,tick,tick+t.period_slots,t.demand_slots))
        if any(j.remaining and j.deadline<=tick for j in jobs):
            raise ValueError(f'deadline miss at slot {tick}')
        ready=[j for j in jobs if j.remaining and (j.task.name!='TX' or j.ordinal in completed_control)]
        if protected:
            control_pending = any(j.task.name=='CONTROL' and j.ordinal in protected for j in ready)
            if control_pending or tick-last_protected_ctrl_tick<=omega:
                ready=[j for j in ready if j.task.name!='UNTRUSTED']
        if not ready:
            slots.append('IDLE');hold=0;prev=None;continue
        urgent=[j for j in ready if j.deadline-tick <= j.remaining+6]
        if urgent:
            selected=min(urgent,key=lambda j:(j.deadline,j.task.priority))
        elif not randomize or rng.random()>.36:
            selected=min(ready,key=lambda j:j.task.priority)
        else:
            selected=rng.choice(ready)
        selected.remaining-=1
        slots.append(selected.task.name)
        if selected.task.name=='CONTROL' and selected.ordinal in protected:
            last_protected_ctrl_tick=tick
        if selected.remaining==0 and selected.task.name=='CONTROL':
            completed_control.add(selected.ordinal)
    unfinished=[(j.task.name,j.ordinal,j.remaining) for j in jobs if j.remaining]
    if unfinished:raise ValueError(f'frame boundary unsafe, unfinished jobs: {unfinished[:5]}')
    want={'CONTROL':600//period_ms,'SAFETY':15,'MONITOR':10,'TX':600//period_ms,'UNTRUSTED':12}
    if jcount!=want:raise ValueError(f'job release count mismatch {jcount}')
    verify(slots,period_ms,assumed_us)
    return slots

def verify(slots,period_ms,assumed_us=None):
    tasks=tasks_for(period_ms,assumed_us)
    if len(slots)!=FRAME_SLOTS or set(slots)-set(CODES):raise ValueError('bad full realized schedule')
    jobs=[];done_ctl=set();ordinal={t.name:0 for t in tasks}
    for tick,owner in enumerate(slots):
        for t in tasks:
            if tick>=t.offset_slots and (tick-t.offset_slots)%t.period_slots==0:
                j=ordinal[t.name];ordinal[t.name]+=1
                jobs.append(Job(t,j,tick,tick+t.period_slots,t.demand_slots))
        if any(j.remaining>0 and j.deadline<=tick for j in jobs):raise ValueError(f'deadline miss {tick}')
        if owner=='IDLE':continue
        options=[j for j in jobs if j.task.name==owner and j.remaining and (owner!='TX' or j.ordinal in done_ctl)]
        if len(options)!=1:raise ValueError(f'invalid owner/precedence at {tick}: {owner}')
        j=options[0];j.remaining-=1
        if owner=='CONTROL' and j.remaining==0:done_ctl.add(j.ordinal)
    if any(j.remaining for j in jobs):raise ValueError('unfinished jobs at frame boundary')
    return True

def metrics(slots,period_ms,aew_us=7000,circular=True):
    # Paper Eq.5 counts victim EXECUTION slots with an untrusted job somewhere
    # in next Omega, then AP=Cp*period/frame. May exceed 1; never clip.
    n=len(slots);omega=math.ceil(aew_us/DELTA_US)
    victim_slots=[j for j,owner in enumerate(slots) if owner=='CONTROL']
    U={j for j,owner in enumerate(slots) if owner=='UNTRUSTED'}
    cp=sum(any(((j+k)%n if circular else j+k) in U for k in range(1,omega+1)
               if circular or j+k<n) for j in victim_slots)
    p=period_ms*1000//DELTA_US
    ap=cp*p/n
    release_completions=[]
    ctl=tasks_for(period_ms)[0]
    for ordinal,release in enumerate(range(0,n,ctl.period_slots)):
        ctl_slots=[i for i in range(release, min(release+ctl.period_slots,n)) if slots[i]=='CONTROL']
        if len(ctl_slots)!=ctl.demand_slots:raise ValueError('CONTROL job execution count mismatch')
        release_completions.append(ctl_slots[-1])
    vulnerable_jobs=sum(any(((j+k)%n if circular else j+k) in U for k in range(1,omega+1)
                            if circular or j+k<n) for j in release_completions)
    job_exposure_fraction=vulnerable_jobs/len(release_completions)
    aai={r%p for r in range(0,n,50*1000//DELTA_US)}
    aei={j%p for j in U}
    ir=(len(aei)%len(aai))/len(aai) if aai else None
    return {'cp_eq5':cp,'paper_ap':ap,'paper_svi_control_only':ap,
        'vulnerable_control_jobs':vulnerable_jobs,'total_control_jobs':len(release_completions),
        'job_normalized_posterior_fraction_NOT_paper_eq5':job_exposure_fraction,
        'paper_ir':ir,'aai_columns':len(aai),'aei_columns':len(aei),
        'aew_slots_assumed':omega,'control_execution_slots':len(victim_slots),
        'criticality_scope':'CONTROL victim only','circular_frame':circular}

def rle(slots):
    starts=[]
    for i,s in enumerate(slots):
        if i==0 or s!=slots[i-1]:starts.append((i,CODES[s]))
    return starts

def generate_bank(out,per_rate=6,seed=637,aew_us=7000):
    out=Path(out);out.mkdir(parents=True,exist_ok=True)
    records=[]; seen=set()
    for p in (20,25):
        for k in range(per_rate):
            for retry in range(50):
                bias=k/max(1,per_rate-1)
                s=generate_one(p,seed+p*1000+k*173+retry*100000,security_bias=bias,aew_us=aew_us)
                sha=hashlib.sha256(bytes(CODES[x] for x in s)).hexdigest()
                if sha not in seen:break
            else:raise ValueError('Cannot produce distinct schedules')
            seen.add(sha)
            m=metrics(s,p,aew_us)
            records.append({'id':f'rate{p}_seed{k}','period_ms':p,'seed':seed+p*1000+k*173+retry*100000,
                       'sha256':sha,'slots_rle':rle(s),'metrics':m})
    for p in (20,25):
        subset=sorted((x for x in records if x['period_ms']==p),
             key=lambda x:(x['metrics']['job_normalized_posterior_fraction_NOT_paper_eq5'],
                           x['metrics']['paper_svi_control_only']))
        normal=max(1,math.ceil(len(subset)*.75));alert=max(1,math.ceil(len(subset)*.50))
        for i,x in enumerate(subset):
            x['normal_eligible']=i<normal
            x['alert_control_eligible']=i<alert
    lines=['/* Complete offline model schedules; firmware uses them as guidance. */',
     '#ifndef MAARS_SCHEDULE_BANK_H','#define MAARS_SCHEDULE_BANK_H','#include <stdint.h>',
     '#define S11_SLOT_US 50U','#define S11_FRAME_SLOTS 12000U',
     '#define S11_BANK_COUNT '+str(len(records))+'U',
     '/* owners: 0=CONTROL,1=SAFETY,2=MONITOR,3=TX,4=UNTRUSTED,5=ACTUAL MODEL IDLE */',
     'typedef struct { uint16_t first_slot; uint8_t owner; uint8_t reserved; } s11_run_t;',
     'typedef struct { uint8_t period_ms; uint8_t normal_ok; uint8_t alert_ok; const char *id; const s11_run_t *runs; uint16_t n_runs; float raw_eq5_ap_unclipped; float job_exposure_fraction; } s11_entry_t;']
    for i,r in enumerate(records):
        lines.append('static const s11_run_t s11_runs_'+str(i)+'[] = {')
        lines.extend('  {'+str(pos)+'U,'+str(code)+'U,0U},' for pos,code in r['slots_rle'])
        lines.append('};')
    lines.append('static const s11_entry_t s11_bank[S11_BANK_COUNT] = {')
    for i,r in enumerate(records):
        x=r['metrics']['paper_ap'];y=r['metrics']['job_normalized_posterior_fraction_NOT_paper_eq5']
        lines.append(f'  {{{r["period_ms"]}U,{int(r["normal_eligible"])}U,{int(r["alert_control_eligible"])}U,"{r["id"]}",s11_runs_{i},{len(r["slots_rle"])}U,{x:.9f}f,{y:.9f}f}},')
    lines.extend(['};','static inline uint8_t s11_expected_owner(uint8_t index,uint16_t slot) {',
        ' if(index>=S11_BANK_COUNT || slot>=S11_FRAME_SLOTS)return 255U;',
        ' const s11_entry_t *b=&s11_bank[index]; uint16_t lo=0U,hi=b->n_runs;',
        ' while(lo+1U<hi){uint16_t mid=(uint16_t)(lo+(hi-lo)/2U);if(b->runs[mid].first_slot<=slot)lo=mid;else hi=mid;}',
        ' return b->runs[lo].owner;','}','#endif'])
    (out/'maars_schedule_bank.h').write_text('\n'.join(lines)+'\n')
    manifest={'stage':'COMPLETE_OFFLINE_MODEL_NOT_REALIZED_ESP32',
      'frame_us':FRAME_US,'slot_us':DELTA_US,'bank_count':len(records),'seed':seed,
      'model_execution_demands_us':{'CONTROL':1500,'SAFETY':1000,'MONITOR':750,'TX':550,'UNTRUSTED':2200},
      'attack_aew_us_assumed':aew_us,
      'qualification':'Feasible in modeled 50us single-core slots; no scheduling overhead, USB latency or physical PI stability cert.',
      'selection':'lowest 75% job-overlap fraction per rate in Normal; lowest 50% in Alert (NOT paper-calibrated TAP/SVT)' ,
      'important_metric_warning':'Raw literal Eq5 Cp counts 50us victim-execution slots, so Cp*period/frame can EXCEED 1 and MUST NOT be interpreted as a probability without the paper-compatible victim occurrence abstraction. An additional one-count-per-CONTROL-job normalized exposure fraction is reported separately.',
      'records':records}
    (out/'bank_manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    with (out/'bank_summary.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=['id','period_ms','sha256','cp_eq5','ap_eq5','job_exposure_fraction','ir','svi','normal_eligible','alert_control_eligible','rle_segments'])
        w.writeheader()
        for r in records:
            m=r['metrics'];w.writerow({'id':r['id'],'period_ms':r['period_ms'],'sha256':r['sha256'],
              'cp_eq5':m['cp_eq5'],'ap_eq5':m['paper_ap'],
              'job_exposure_fraction':m['job_normalized_posterior_fraction_NOT_paper_eq5'], 'ir':m['paper_ir'],
              'svi':m['paper_svi_control_only'],'normal_eligible':r['normal_eligible'],
              'alert_control_eligible':r['alert_control_eligible'],'rle_segments':len(r['slots_rle'])})
    return manifest

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,default=Path('generated'));p.add_argument('--seed',type=int,default=637);p.add_argument('--per-rate',type=int,default=6)
    a=p.parse_args();r=generate_bank(a.out,a.per_rate,a.seed);print('Generated',r['bank_count'],'fully specified model schedules')
