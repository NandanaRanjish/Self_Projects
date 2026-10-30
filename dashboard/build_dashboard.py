#!/usr/bin/env python3
import argparse
import csv
import datetime as dt
import json
import math
import re
import sys
from pathlib import Path

HERE=Path(__file__).resolve().parent
VALID_STATUS={'PASS','PARTIAL','INVALID','UNVERIFIED','AUDIT_FAILURE','GUARD_FAILURE','MISSING'}
WORKERS=['CONTROL','SAFETY','MONITOR','TX','UNTRUSTED']
EXPECTED={20:97,25:85}
SUFFIXES=('_capture','_events','_attacker','_own','_ladder','_aew','_config','_shuffler','_guard',
          '_schedule','_timing','_counts','_summary','_window','_report')
RX_FIXED=re.compile(r'^stage11_(20|25)_(unprotected|protected)_attack_r(\d+)$')
RX_V2=re.compile(r'^maars_(20|25)_(none|guide|guard|both|clean)_r(\d+)$')
RX_V2_ALT=re.compile(r'^maars_alt_prior(20|25)_(none|guide|guard|both)_r(\d+)$')


def to_number(x):
    try:
        v=float(x)
        return v if math.isfinite(v) else None
    except (ValueError, TypeError, OverflowError):
        return None


def to_int(x, default=0):
    n=to_number(x)
    return int(n) if n is not None else default


def csv_read(path, limit=100000):
    if not path.exists() or path.stat().st_size>100*1024*1024:
        return [],[]
    with path.open('r',encoding='utf-8-sig',newline='',errors='replace') as f:
        reader=csv.DictReader(f)
        return (reader.fieldnames or []),list(row for _,row in zip(range(limit),reader))


def read_json(path):
    try: return json.loads(path.read_text(encoding='utf8'))
    except (OSError, ValueError, UnicodeError): return None


def paths_for_root(root):
    root=root.resolve()
    projects=[root,root/'01_Working_Project']
    trace_dirs=[root/'traces',root/'02_Experimental_Data'/'traces',root/'01_Working_Project'/'traces']
    report_dirs=[root/'reports',root/'03_Analysis_and_Reports'/'reports',root/'01_Working_Project'/'reports']
    uniq=lambda seq:list({str(x.resolve()):x.resolve() for x in seq if x.is_dir()}.values())
    return uniq(projects),uniq(trace_dirs),uniq(report_dirs)


def choose_child(path, extension):
    p=path.with_name(path.stem+extension)
    return p if p.exists() else None


def parse_run(path):
    name=path.stem
    v2=RX_V2.fullmatch(name)
    if v2:
        return {'stage':'Unified','rate':int(v2.group(1)), 'mode':v2.group(2),
                'trial':int(v2.group(3)),'rate_policy':v2.group(1)}
    v2alt=RX_V2_ALT.fullmatch(name)
    if v2alt:
        return {'stage':'Unified','rate':None,'mode':v2alt.group(2),
                'trial':int(v2alt.group(3)),'rate_policy':'ALT', 'attacker_prior_ms':int(v2alt.group(1))}
    m=RX_FIXED.fullmatch(name)
    if m:
        return {'stage':'Stage 11','rate':int(m.group(1)), 'mode':m.group(2),
                'trial':int(m.group(3)),'rate_policy':str(m.group(1))}
    low=name.lower()
    if not any(s in low for s in ('stage','maars','attack','clean','demo')):
        return None
    stage='Stage 11' if 'stage11' in low else 'Other'
    if 'alt' in low:rate_policy='ALT'
    elif '25' in low:rate_policy='25'
    elif '20' in low:rate_policy='20'
    else:rate_policy='unspecified'
    rate=int(rate_policy) if rate_policy.isdigit() else None
    mode= ('protected' if 'protected' in low or 'both' in low or 'guard' in low else
           'unprotected' if 'unprotected' in low or 'none' in low else
           'guide' if 'guide' in low else 'clean' if 'clean' in low else 'other')
    trial=re.search(r'(?:^|[_-])r(\d+)(?:$|[_-])',low)
    return {'stage':stage,'rate':rate,'mode':mode,'trial':int(trial.group(1)) if trial else None,'rate_policy':rate_policy}


def is_candidate(path):
    if path.suffix.lower()!='.csv':return False
    if path.stem.endswith(SUFFIXES):return False
    if path.name.startswith('.') or '_audit' in path.parts:return False
    return True


def extract_run(path):
    info=parse_run(path)
    if info is None:return None
    cols,rows=csv_read(path,limit=50000)
    if not {'seq','attacked'}.issubset(cols) or not rows:return None
    n=len(rows)
    seq=[to_int(r.get('seq'),-1) for r in rows]
    seq_ok=seq==list(range(n))
    corrupted=sum(1 for r in rows if to_int(r.get('attacked'))!=0)
    alarms=sum(1 for r in rows if to_int(r.get('alarm'))!=0)
    misses=sum(1 for r in rows if to_int(r.get('deadline_miss'))!=0)
    rates=[]
    cfg=path.with_name(path.stem+'_config.csv')
    cf,cr=csv_read(cfg,limit=3000)
    for r in cr:
        val=to_number(r.get('control_period_ms'))
        if val is not None:rates.append({'frame':to_int(r.get('hyperperiod_number')),
                                         'ms':int(val),'planned_us':to_number(r.get('planned_us'))})
    rate_values=sorted(set(x['ms'] for x in rates))
    if len(rate_values)>1:info['rate_policy']='ALT'
    elif len(rate_values)==1 and info['rate_policy']=='unspecified':info['rate_policy']=str(rate_values[0])
    cap_path=path.with_name(path.stem+'_capture.csv')
    meta=read_json(cap_path.with_suffix('.meta.json')) or {}
    audit=read_json(path.with_name(path.stem+'_capture_audit')/'audit.json') or {}
    # Explicit validation: never count a partial/incomplete run as accepted.
    fixed=RX_FIXED.fullmatch(path.stem) or (RX_V2.fullmatch(path.stem) if info['mode']!='clean' else None)
    if fixed and (n!=150 or not seq_ok):status='PARTIAL'
    elif not seq_ok:status='PARTIAL'
    elif not audit or not cap_path.exists():status='UNVERIFIED'
    elif audit.get('valid') is not True or misses>0:status='AUDIT_FAILURE'
    elif info['rate'] in EXPECTED and to_int(audit.get('job_completion_count'),-1)!=EXPECTED[info['rate']]:status='AUDIT_FAILURE'
    elif info['mode'] in ('guard','both','protected') and (to_int(audit.get('valid_vulnerable_commands'))>0 or corrupted>0):status='GUARD_FAILURE'
    elif to_int(meta.get('loss'))!=0:status='AUDIT_FAILURE'
    else:status='PASS'
    # UTC markers not fabricated. Host time is nominal t_s. Capture has separate board clock.
    points=[]
    for i,r in enumerate(rows):
        if len(rows)>600 and i%max(1,len(rows)//500)!=0 and to_int(r.get('attacked'))==0 and to_int(r.get('alarm'))==0:continue
        points.append({'seq':seq[i], 't':to_number(r.get('time_s')),
          'ref':to_number(r.get('reference_rad_s')),
          'speed':to_number(r.get('true_speed_rad_s') or r.get('measured_rad_s')),
          'calculated':to_number(r.get('commanded_voltage_v')),
          'applied':to_number(r.get('applied_voltage_v')),
          'attack':to_int(r.get('attacked')),
          'alarm':to_int(r.get('alarm')),
          'rtt':to_number(r.get('rtt_ms'))})
    attempts=[]
    af,ar=csv_read(path.with_name(path.stem+'_attacker.csv'),limit=15000)
    for r in ar:
        if not r.get('kind'):continue
        attempts.append({'kind':str(r.get('kind',''))[:42],
         't_us':to_number(r.get('time_us')),
         'a':str(r.get('value1',''))[:38], 'b':str(r.get('value2',''))[:38]})
    aew=[]
    _,ar=csv_read(path.with_name(path.stem+'_aew.csv'),limit=2000)
    for r in ar:
        aew.append({'seq':to_int(r.get('seq')),'us':to_number(r.get('aew_duration_us')),
                    'attacked':to_int(r.get('attacked'))})
    cap=[]
    cc,cr=csv_read(cap_path,limit=20000)
    if {'kind','worker','start_us','end_us'}.issubset(cc):
        for r in cr:
            w=to_int(r.get('worker'),-1)
            cap.append({'i':to_int(r.get('index')),'kind':str(r.get('kind'))[:2],
                        'worker':WORKERS[w] if 0<=w<len(WORKERS) else 'OTHER',
                        'job':to_int(r.get('job')),
                        's':to_number(r.get('start_us')),
                        'e':to_number(r.get('end_us')),
                        'flag':to_int(r.get('flag'))})
    windows=[]
    _,wr=csv_read(path.with_name(path.stem+'_capture_audit')/'control_tx_windows.csv',limit=2000)
    for r in wr:
        if not to_int(r.get('valid_command')):continue
        windows.append({'p':to_number(r.get('published_us')),
                        'tx':to_number(r.get('tx_read_us')),
                        'overlap':to_int(r.get('actual_attacker_overlap'))})
    log=path.with_suffix('.log')
    text=log.read_text(errors='replace') if log.exists() and log.stat().st_size<2*1024*1024 else ''
    attempts_count=re.search(r'Attacker predicted-window attempts:\s*(\d+)',text)
    deferrals=re.search(r'Stage11 hardware status:\s*S11STAT,([^\n]+)',text)
    protocol=re.search(r'Firmware protocol counters:\s*(PROTOSTAT,[^\n]+)',text)
    warn=re.search(r'Breakdown: bad_ack=(\d+) elapsed_overrun=(\d+) budget_underflow=(\d+)',text)
    alg=re.search(r'Run FAILED|No CMD|FAILED:',text)
    tags=[]
    if warn and any(to_int(x)>0 for x in warn.groups()):tags.append('Scheduler diagnostic warning')
    if protocol:
        pieces=protocol.group(1).split(',')
        if len(pieces)>=9 and to_int(pieces[8])>0:tags.append('Rejected sensor sample(s)')
    if alg:
        tags.append('Run logged a failure')
        if status=='PASS':status='INVALID'
    validation=read_json(path.parent.parent/'reports'/'validation'/(path.stem+'.json'))
    if RX_V2.fullmatch(path.stem) or RX_V2_ALT.fullmatch(path.stem):
        if not isinstance(validation,dict) or validation.get('status')!='PASS':
            status='UNVERIFIED' if validation is None else str(validation.get('status','INVALID'))
    if isinstance(validation,dict) and validation.get('status') not in ('PASS',None):
        tags.append('Experiment suite status: '+str(validation.get('status')))
        reason=validation.get('failure') or validation.get('reason')
        if reason: tags.append(str(reason)[:150])
        if validation.get('status')=='PARTIAL': status='PARTIAL'
        elif status=='PASS':status='INVALID'
    meta_run={**info, 'id':path.stem,'name':path.stem,'source':'raw_project_files',
           'status':status, 'count':n,'corrupted':corrupted,'attempts':to_int(attempts_count.group(1)) if attempts_count else None,
           'alarms':alarms,'misses':misses,'logWarnings':tags,
           'rates':rates,'rate_set':rate_values,'capture_audit':{
             'valid':audit.get('valid'),'period_ms':audit.get('period_ms'),
             'job_count':audit.get('job_completion_count'),'grant_count':audit.get('grant_count'),
             'overlaps':audit.get('valid_vulnerable_commands'),
             'valid_windows':audit.get('total_valid_commands'),
             'potential_windows':audit.get('potential_vulnerable_jobs'),
             'capture_loss':meta.get('loss'), 'errors':audit.get('errors',[])[:12] if isinstance(audit.get('errors',[]),list) else []},
           'capture_meta':{'start_us':meta.get('start_us'),'end_us':meta.get('end_us'),
                           'period_ms':meta.get('period_ms'),'count':meta.get('count'),'loss':meta.get('loss')},
           'capture':cap,'windows':windows,'points':points,'events':attempts[:700],
           'aew':aew,'config':rates,
           'host_protostat':protocol.group(1) if protocol else None,
           'deferrals':to_int(deferrals.group(1).split(',')[10]) if deferrals and len(deferrals.group(1).split(','))>9 else None,
           'relative_path':str(path.name)}
    return meta_run


def read_schedules(project_roots,report_roots):
    candidates=[]
    for p in project_roots:
        candidates.extend([p/'model'/'generated'/'bank_summary.csv',
                           p/'stage11_package'/'maars_stage11_full'/'generated'/'bank_summary.csv',
                           p/'stage11'/'generated'/'bank_summary.csv'])
    for p in report_roots:
        candidates.extend([p/'stage11'/'final'/'bank_summary.csv',p/'stage11'/'bank_summary.csv'])
    candidates.append(HERE/'evidence'/'bank_summary_reference.csv')
    for p in candidates:
        h,rows=csv_read(p,limit=200)
        if {'id','period_ms','ir','svi','ap_eq5','job_exposure_fraction'}.issubset(h):
            return [{k:(to_number(v) if k in ('period_ms','ir','svi','ap_eq5','job_exposure_fraction','cp_eq5') else v)
                     for k,v in r.items() if k in ('id','period_ms','ir','svi','ap_eq5','job_exposure_fraction','cp_eq5','normal_eligible','alert_control_eligible')} for r in rows],p.name
    return [],''


def read_certificate_and_offline_motor(project_roots,report_roots):
    certpaths=[];motorpaths=[];summarypaths=[]
    for p in project_roots:
        b=p/'model'/'generated' if (p/'model'/'generated').is_dir() else p/'stage11_package'/'maars_stage11_full'/'generated'
        certpaths.extend([b/'ideal_linear_certificate.json',p/'stage11'/'generated'/'ideal_linear_certificate.json'])
        motorpaths.append(b/'offline_plant'/'multirate_motor_response.csv')
        summarypaths.append(b/'offline_plant'/'multirate_motor_summary.csv')
    for p in report_roots:
        certpaths.extend([p/'stage11'/'final'/'cqlf_certificate.json',p/'stage11'/'ideal_linear_cqlf_certificate.json'])
        motorpaths.append(p/'stage11'/'final'/'period_correct_motor'/'multirate_motor_response.csv')
        summarypaths.append(p/'stage11'/'final'/'period_correct_motor'/'multirate_motor_summary.csv')
    certpaths.append(HERE/'evidence'/'ideal_linear_certificate_reference.json')
    motorpaths.append(HERE/'evidence'/'offline_motor_reference.csv')
    summarypaths.append(HERE/'evidence'/'offline_motor_summary_reference.csv')
    cert={};certificate_source=''
    for p in certpaths:
        c=read_json(p)
        if isinstance(c,dict) and c.get('modes') and c.get('P_float'):
            cert={'status':c.get('status',''), 'positive_P_min_eig':c.get('P_min_eigenvalue_display'),
              'modes':[{'hold':m.get('plant_next_hold_period_ms'),
                        'previous':m.get('pi_previous_sample_interval_ms'),
                        'max_delta':m.get('max_eigenvalue_delta'),
                        'spectral_radius':m.get('spectral_radius'),
                        'checked':m.get('exact_rational_negative_definite_checked')} for m in c['modes']],
              'boundary':c.get('boundary','')}
            certificate_source=p.name;break
    motor=[];motor_source='';summary=[]
    for p in motorpaths:
        columns,rows=csv_read(p,limit=4000)
        if {'mode','time_s','speed_rad_s','reference_rad_s'}.issubset(columns):
            motor=[{'mode':r.get('mode'),'t':to_number(r.get('time_s')),
                    'speed':to_number(r.get('speed_rad_s')),
                    'ref':to_number(r.get('reference_rad_s')),
                    'period':to_number(r.get('period_ms'))} for r in rows]
            motor_source=p.name;break
    for p in summarypaths:
        columns,rows=csv_read(p,limit=30)
        if {'mode','timeweighted_rmse_rad_s'}.issubset(columns):
            summary=[{'mode':r.get('mode'), 'rmse':to_number(r.get('timeweighted_rmse_rad_s')),
                      'samples':to_int(r.get('samples'))} for r in rows]
            break
    return cert,certificate_source,motor,motor_source,summary


def compile_data(root):
    projs,traces,reports=paths_for_root(root)
    errors=[]
    seen=set();runs=[]
    for directory in traces:
        for p in sorted(directory.glob('*.csv')):
            if not is_candidate(p):continue
            if p.resolve() in seen:continue
            seen.add(p.resolve())
            try:
                run=extract_run(p)
                if run:runs.append(run)
            except Exception as exc:
                errors.append(f'{p.name}: {type(exc).__name__}: {str(exc)[:180]}')
    #
    history=[]
    stage10,s10source=[],'' 
    schedules,schsource=read_schedules(projs,reports)
    cert,certsource,motor,motorsource,motorsummary=read_certificate_and_offline_motor(projs,reports)
    return {'version':'3.0-four-way-simplified','generated':dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%d %H:%M UTC'),
      'root_type':'organized Desktop' if (root/'01_Working_Project').is_dir() else 'ESP-IDF project',
      'traces_scanned':len(seen),'run_count':len(runs),'runs':runs,'historical':history,
      'stage10':stage10,'stage10_source':s10source,'schedules':schedules,'schedule_source':schsource,
      'certificate':cert,'certificate_source':certsource,'offline_motor':motor,
      'offline_motor_source':motorsource,'offline_motor_summary':motorsummary,
      'errors':errors,'trace_dirs':[str(x) for x in traces],
      'scope':[
       'Only the current unified-release experiments are loaded;',
       'The screenshot/demo fixture is not experimental evidence.',
       'Only complete runs with valid independent audits count as verified raw experiment results.',
       'Host model time (seconds) and ESP32 capture time (microseconds) are different clocks; charts are not automatically synchronized.',
       'Guard means the cooperative UNTRUSTED worker is deferred during exposed commands; it is not memory isolation.',
       'Offline Equation 5 slot-count statistics are not hardware corruption probabilities; some raw values exceed 1.',
       'The common Lyapunov result applies only to the idealized delay-free unsaturated motor model.' ]}


def render_html(data):
    html=(HERE/'template.html').read_text(encoding='utf8')
    css=(HERE/'style.css').read_text(encoding='utf8')
    js=(HERE/'app.js').read_text(encoding='utf8')
    dump=json.dumps(data,separators=(',',':'),ensure_ascii=False,allow_nan=False).replace('<','\\u003c')
    html=html.replace('/*__INLINE_STYLE__*/',css)
    html=html.replace('/*__INLINE_DATA__*/',f'const DATA = {dump};')
    html=html.replace('/*__INLINE_APP__*/',js)
    return html


def main(argv=None):
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--root',type=Path,default=Path('.'),help='Path to the MAARS ESP-IDF project root')
    ap.add_argument('--out',type=Path,default=None,help='Output self-contained index.html (default: <root>/dashboard/site/index.html)')
    ap.add_argument('--demo-fixture',action='store_true',help='Only for package tests: force synthetic fixture in --root (not production)')
    args=ap.parse_args(argv)
    root=args.root.expanduser().resolve()
    if not root.is_dir():ap.error(f'Root does not exist: {root}')
    data=compile_data(root)
    out=args.out.expanduser().resolve() if args.out else root/'dashboard'/'site'/'index.html'
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(render_html(data),encoding='utf8')
    print('MAARS PRESENTATION DASHBOARD BUILT')
    print('  HTML:',out)
    print('  Raw host runs:',data['run_count'])
    print('  Scanned candidate CSV files:',data['traces_scanned'])
    print('  Historical study rows: NONE (fresh release)')
    print('  Offline schedule rows:',len(data['schedules']))
    print('  Ideal-model certificate modes:',len(data['certificate'].get('modes',[])))
    print('  Period-correct offline motor samples:',len(data['offline_motor']))
    print('  Console-only historical summaries: NONE')
    if data['errors']:print('  Import warnings:',*data['errors'][:10],sep='\n    ')
    print('Open the HTML file in Chromium/Firefox; internet connection not needed.')
    return 0


if __name__=='__main__':sys.exit(main())
