#!/usr/bin/env python3
from __future__ import annotations
import argparse,csv,hashlib,json,math,os,re,subprocess,sys
from datetime import datetime,timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
TRACES=ROOT/'traces';REPORTS=ROOT/'reports';MODES=('none','guide','guard','both')
EXPECTED_JOBS={20:97,25:85}
MODE_FLAGS={'none':(0,0),'guide':(1,0),'guard':(0,1),'both':(1,1)}


def checksum(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as file:
        for buf in iter(lambda:file.read(1048576),b''):h.update(buf)
    return h.hexdigest()


def execute(cmd,log=None,allow_fail=False):
    print('RUN:', ' '.join(map(str,cmd)),flush=True)
    if log is None:code=subprocess.run([str(x) for x in cmd],cwd=ROOT).returncode
    else:
        log.parent.mkdir(parents=True,exist_ok=True)
        with log.open('x',encoding='utf8') as output:
            child=subprocess.Popen([str(x) for x in cmd],cwd=ROOT,stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT,text=True,errors='replace',bufsize=1)
            for line in child.stdout:
                output.write(line);print(line,end='',flush=True)
            code=child.wait()
    if code and not allow_fail:raise RuntimeError(f'Command returned {code}; preserve partial files and investigate')
    return code


def stem(rate,mode,trial,prior=None):
    if rate=='ALT':
        return f'maars_alt_{mode}_r{trial}' if mode=='clean' else f'maars_alt_prior{prior}_{mode}_r{trial}'
    return f'maars_{rate}_{mode}_r{trial}'


def trial_id(x):
    if not re.fullmatch('[1-9][0-9]{0,7}',str(x)):raise ValueError('Trial ID must be a positive integer up to 8 digits')
    return str(x)


def metadata(st):return REPORTS/'validation'/(st+'.json')


def write_meta(st,record):
    dest=metadata(st);dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_text(json.dumps(record,indent=2)+'\n')


def verify(st,rate,mode,duration,prior=None):
    base=TRACES/st;path=base.with_suffix('.csv');cap=TRACES/(st+'_capture.csv')
    aud=TRACES/(st+'_capture_audit' )/'audit.json'
    capmeta=TRACES/(st+'_capture.meta.json');log=base.with_suffix('.log')
    try:
        if not path.is_file():return {'status':'MISSING','reason':'Host CSV missing'}
        with path.open(newline='') as f:
            read=csv.DictReader(f);fields=set(read.fieldnames or ());rows=list(read)
        if not {'seq','attacked','deadline_miss'}.issubset(fields):
            return {'status':'INVALID','reason':'Host CSV columns missing'}
        expected=int(duration*50)
        if len(rows)!=expected or [int(x['seq']) for x in rows]!=list(range(expected)):
            return {'status':'PARTIAL','reason':f'Expected seq 0..{expected-1}, found {len(rows)} samples'}
        corrupt=sum(int(x['attacked']) for x in rows)
        misses=sum(int(x['deadline_miss']) for x in rows)
        if not aud.is_file() or not cap.is_file() or not capmeta.is_file():
            return {'status':'UNVERIFIED','reason':'Independent capture audit or metadata missing'}
        a=json.loads(aud.read_text());m=json.loads(capmeta.read_text())
        if a.get('valid') is not True or m.get('loss')!=0:
            return {'status':'AUDIT_FAILURE','reason':'Invalid scheduling audit or lost capture records'}
        cp=a.get('period_ms')
        if cp not in EXPECTED_JOBS or a.get('job_completion_count')!=EXPECTED_JOBS[cp]:
            return {'status':'AUDIT_FAILURE','reason':'Wrong number of captured worker completions'}
        if rate!='ALT' and cp!=int(rate):
            return {'status':'AUDIT_FAILURE','reason':'Captured CONTROL period differs from experiment'}
        if misses:return {'status':'AUDIT_FAILURE','reason':f'{misses} observed missed deadlines'}
        if rate=='ALT':
            config=TRACES/(st+'_config.csv')
            if not config.exists():return {'status':'AUDIT_FAILURE','reason':'ALT rate-change trace missing'}
            with config.open(newline='') as f:rates={int(x['control_period_ms']) for x in csv.DictReader(f)}
            if not {20,25}.issubset(rates):return {'status':'AUDIT_FAILURE','reason':'ALT did not show both rates'}
        else:rates={int(rate)}
        text=log.read_text(errors='replace') if log.exists() else ''
        if 'No CMD for ' in text or 'RUN FAILED:' in text:
            return {'status':'PARTIAL','reason':'Host reported missing command'}
        proto=re.search(r'Firmware protocol counters:\s*PROTOSTAT,([^\n]+)',text)
        if not proto:return {'status':'UNVERIFIED','reason':'PROTOSTAT diagnostics missing: check host diagnostics'}
        values=[int(v) for v in proto.group(1).strip().split(',')]
        if len(values)<8 or values[7]!=0:
            return {'status':'PROTOCOL_FAILURE','reason':'Firmware rejected sensor samples or PROTOSTAT incomplete'}
        breakdown=re.search(r'Breakdown: bad_ack=(\d+) elapsed_overrun=(\d+) budget_underflow=(\d+)',text)
        if not breakdown:return {'status':'UNVERIFIED','reason':'Worker accounting diagnostics missing'}
        if any(int(v) for v in breakdown.groups()):
            return {'status':'SCHEDULER_WARNING','reason':'Scheduling diagnostic nonzero (preserve, investigate)'}
        attempts=re.search(r'Attacker predicted-window attempts:\s*(\d+)',text)
        if mode!='clean' and (not attempts or int(attempts.group(1))<=0):
            return {'status':'NO_ATTACK','reason':'No verified attacker attempts'}
        if mode=='none':
            if 'Stage11 mode:' in text or 'MAARS ablation mode verified:' in text:
                return {'status':'MODE_FAILURE','reason':'NONE must keep Stage11 disabled'}
        elif mode!='clean':
            expected_ack=f'MAARS ablation mode verified: ACK,S11,MODE,{mode.upper()},GUIDANCE={MODE_FLAGS[mode][0]},GUARD={MODE_FLAGS[mode][1]}'
            if expected_ack not in text:
                return {'status':'MODE_FAILURE','reason':'Board did not confirm both mode bits: '+mode}
        if mode!='none' and 'Stage11 active before attack: S11STAT,1,1,' not in text:
            return {'status':'MODE_FAILURE','reason':'Stage11 was not verified active before the trial'}
        overlaps=int(a.get('valid_vulnerable_commands',-1))
        if overlaps<0:return {'status':'AUDIT_FAILURE','reason':'Exposure overlap count missing'}
        if (mode=='clean' or MODE_FLAGS.get(mode,(0,0))[1]) and (overlaps or corrupt):
            return {'status':'GUARD_FAILURE','reason':f'Guarded result: {overlaps} overlaps, {corrupt} corruptions'}
        rmse=None
        if {'true_speed_rad_s','reference_rad_s'}.issubset(fields):
            diffs=[float(r['true_speed_rad_s'])-float(r['reference_rad_s']) for r in rows]
            rmse=math.sqrt(sum(x*x for x in diffs)/len(diffs))
        return {'status':'PASS','samples':len(rows),'corrupted':corrupt,
                'corruption_fraction':corrupt/len(rows),'attempts':int(attempts.group(1)) if attempts else 0,
                'captured_jobs':a['job_completion_count'],'overlap_windows':overlaps,
                'capture_period_ms':cp,'rates_seen_ms':sorted(rates),
                'motor_rmse_rad_s':round(rmse,6) if rmse is not None else None}
    except (ValueError,KeyError,TypeError,OSError,json.JSONDecodeError) as e:
        return {'status':'INVALID','reason':str(e)[:240]}


def run_one(rate,mode,trial,prior=None):
    port=os.environ.get('PORT','/dev/ttyACM0')
    if not Path(port).exists():raise RuntimeError(f'Board serial port missing: {port}')
    st=stem(rate,mode,trial,prior);TRACES.mkdir(exist_ok=True)
    if list(TRACES.glob(st+'*')) or metadata(st).exists():
        raise RuntimeError(f'Trial {st} already exists, including possible partial results; choose NEW ID')
    duration=6 if rate=='ALT' else 3
    flags=MODE_FLAGS.get(mode,(1,1))
    cmd=[sys.executable,'tools/hardware_experiment.py','--port',port,'--rate',rate,
         '--attacker-prior',str(prior or (rate if rate!='ALT' else 20)),
         '--ts','on','--attack','off' if mode=='clean' else 'on',
         '--duration',str(duration),'--capture','--capture-at','1',
         '--stage9-shadow','off','--stage9c','off','--stage9f','off',
         '--stage11','off' if mode=='none' else 'on',
         '--stage11-ablation','both' if mode=='clean' else mode if mode!='none' else 'both',
         '--out',f'traces/{st}.csv']
    if mode!='clean':cmd+=['--window-start','0','--window-end',str(duration)]
    fw=ROOT/'firmware/firmware_manifest.json'
    manifest=json.loads(fw.read_text()) if fw.exists() else {}
    doc={'id':st,'rate':rate,'mode':mode,'trial':trial,'prior':prior,
         'guidance_enabled':flags[0],'guard_enabled':flags[1],
         'firmware_sha256':manifest.get('sha256'),
         'source_sha256':checksum(ROOT/'main/main.c'),
         'host_sha256':checksum(ROOT/'tools/hardware_experiment.py'),
         'started_utc':datetime.now(timezone.utc).isoformat(),'status':'STARTED'}
    write_meta(st,doc)
    try:
        execute(cmd,TRACES/(st+'.log'))
        execute([sys.executable,'tools/scheduling_audit.py',f'traces/{st}_capture.csv'],TRACES/(st+'_audit.log'))
        exposure=execute([sys.executable,'tools/command_window_audit.py',f'traces/{st}_capture.csv'],
                         TRACES/(st+'_exposure_audit.log'),allow_fail=True)
        if exposure and flags[1]:raise RuntimeError('Guard is enabled but independent exposure audit FAILED')
        if rate=='ALT' and (mode=='clean' or mode=='both'):
            execute([sys.executable,'model/multirate_capture_audit.py',f'traces/{st}.csv'],
                    TRACES/(st+'_mixed_audit.log'))
        result=verify(st,rate,mode,duration,prior)
        doc.update(result)
        if doc['status']!='PASS':raise RuntimeError(f'Strict verification: {result}')
        write_meta(st,doc)
        print(f'PASS {st}: {result["corrupted"]}/{result["samples"]} corruptions; {result["attempts"]} attempts')
    except Exception as e:
        result=verify(st,rate,mode,duration,prior)
        doc.update(result)
        if doc['status']=='PASS':doc['status']='INCOMPLETE_AUDIT'
        doc['failure']=str(e);write_meta(st,doc)
        raise


def summarize():
    REPORTS.mkdir(exist_ok=True);recs=[];pairs=[];groups=[]
    for p in sorted((REPORTS/'validation').glob('maars_*.json')) if (REPORTS/'validation').is_dir() else []:
        rec=json.loads(p.read_text())
        rate=rec.get('rate');mode=rec.get('mode');trial=rec.get('trial')
        if rate in ('20','25') and mode in MODES:
            current=verify(p.stem,rate,mode,3)
            if rec.get('status')=='PASS' and current['status']!='PASS':
                rec['status']='STALE_'+current['status']
                rec['reason']=current.get('reason','Files changed since accepted trial')
            recs.append({'rate_ms':rate,'trial':trial,'mode':mode,'status':rec.get('status'),
                         'guidance':MODE_FLAGS[mode][0],'guard':MODE_FLAGS[mode][1],
                         'samples':rec.get('samples',''),'corrupted':rec.get('corrupted',''),
                         'attack_attempts':rec.get('attempts',''),
                         'overlaps':rec.get('overlap_windows',''),
                         'motor_rmse_rad_s':rec.get('motor_rmse_rad_s',''),
                         'firmware_sha256':rec.get('firmware_sha256',''),
                         'reason':rec.get('failure',rec.get('reason',''))})
    def write(path,fields,rows):
        with path.open('w',newline='') as f:
            writer=csv.DictWriter(f,fieldnames=fields);writer.writeheader();writer.writerows(rows)
    fields=['rate_ms','trial','mode','status','guidance','guard','samples','corrupted','attack_attempts','overlaps','motor_rmse_rad_s','firmware_sha256','reason']
    write(REPORTS/'ablation_inventory.csv',fields,recs)
    for rate in ('20','25'):
        for mode in MODES:
            acc=[r for r in recs if r['rate_ms']==rate and r['mode']==mode and r['status']=='PASS']
            count=sum(int(r['samples']) for r in acc)
            corrupt=sum(int(r['corrupted']) for r in acc)
            groups.append({'rate_ms':rate,'mode':mode,'runs':len(acc),'commands':count,
                           'corrupted':corrupt,'corruption_percent':round(100*corrupt/count,3) if count else ''})
        for trial in sorted({r['trial'] for r in recs if r['rate_ms']==rate}):
            found={r['mode']:r for r in recs if r['rate_ms']==rate and r['trial']==trial and r['status']=='PASS'}
            if set(MODES)<=set(found):
                hashes={found[mode]['firmware_sha256'] for mode in MODES}
                if len(hashes)!=1:continue
                pairs.append({'rate_ms':rate,'trial':trial,
                              **{f'{m}_corrupt_fraction':round(int(found[m]['corrupted'])/int(found[m]['samples']),6) for m in MODES},
                              'guide_minus_none_pp':round(100*(int(found['guide']['corrupted'])-int(found['none']['corrupted']))/int(found['none']['samples']),3),
                              'guard_minus_guide_pp':round(100*(int(found['guard']['corrupted'])-int(found['guide']['corrupted']))/int(found['guard']['samples']),3),
                              'firmware_sha256':next(iter(hashes))})
    write(REPORTS/'ablation_by_mode.csv',list(groups[0]) if groups else ['rate_ms','mode','runs','commands','corrupted','corruption_percent'],groups)
    write(REPORTS/'matched_four_way_trials.csv',list(pairs[0]) if pairs else ['rate_ms','trial','none_corrupt_fraction','guide_corrupt_fraction','guard_corrupt_fraction','both_corrupt_fraction','guide_minus_none_pp','guard_minus_guide_pp','firmware_sha256'],pairs)
    print('SUMMARY: accepted fixed-rate runs',sum(r['status']=='PASS' for r in recs),'matched four-mode blocks',len(pairs))
    print('SAVED: reports/ablation_inventory.csv, reports/ablation_by_mode.csv, reports/matched_four_way_trials.csv')


def check_environment():
    need = [
        'CMakeLists.txt',
        'sdkconfig',
        'main/main.c',
        'main/maars_schedule_bank.h',
        'firmware/MAARS_ESP32S3_Unified.bin',
        'firmware/firmware_manifest.json',
        'tools/hardware_experiment.py',
        'tools/scheduling_audit.py',
        'tools/command_window_audit.py',
        'dashboard/build_dashboard.py',
        'model/offline_analysis.py',
    ]

    missing = [x for x in need if not (ROOT / x).is_file()]

    for item in need:
        print('OK' if item not in missing else 'MISSING', item)

    for pkg in ('serial', 'numpy', 'scipy', 'matplotlib'):
        try:
            __import__(pkg)
            print('OK: Python', pkg)
        except ImportError:
            missing.append('Python ' + pkg)

    fw = ROOT / 'firmware/firmware_manifest.json'
    binary = ROOT / 'firmware/MAARS_ESP32S3_Unified.bin'

    if fw.exists() and binary.exists():
        data = json.loads(fw.read_text())
        if data.get('sha256') != checksum(binary):
            missing.append('Merged firmware SHA256 mismatch')
        if data.get('independent_ablation_modes') != list(MODES):
            missing.append('Firmware missing four-mode manifest')

    main_file = ROOT / 'main/main.c'
    host_file = ROOT / 'tools/hardware_experiment.py'

    c = main_file.read_text() if main_file.exists() else ''
    host = host_file.read_text() if host_file.exists() else ''

    source_checks = {
        'guidance flag': 's11_guidance_enabled' in c,
        'guard flag': 's11_guard' in c,
        'GUIDE command': 'S11,MODE,GUIDE' in c,
        'GUARD command': 'S11,MODE,GUARD' in c,
        'BOTH command': 'S11,MODE,BOTH' in c,
        'guidance selection':
            'if(!s11_guidance_enabled ||' in c,
        'guard eligibility filter':
            '(s11_guard && s11_active && s11_requested)' in c,
        'host ablation argument': '--stage11-ablation' in host,
        'host mode verification':
            'MAARS ablation mode verified:' in host,
    }

    for label, passed in source_checks.items():
        if passed:
            print('OK: Source feature:', label)
        else:
            print('MISSING: Source feature:', label)
            missing.append(label)

    if missing:
        raise RuntimeError(
            'Preflight FAILED: ' + ', '.join(missing)
        )

    print('PASS: complete four-mode unified release')

def offline():
    folder=REPORTS/'offline';folder.mkdir(parents=True,exist_ok=True)
    cli=ROOT/'model/offline_analysis.py'
    execute([sys.executable,cli,'self-test'])
    execute([sys.executable,cli,'certify','--project',ROOT,'--out',folder/'cqlf_certificate.json'])
    execute([sys.executable,cli,'bank-verify','--bank',ROOT/'model/generated'])
    execute([sys.executable,cli,'motor-demo','--out',folder/'motor'])
    print('PASS offline ideal-model certificate and offline schedules (not physical HIL proof)')


def graphs():
    summarize()
    dest=ROOT/'dashboard/site/index.html'
    execute([sys.executable,ROOT/'dashboard/build_dashboard.py','--root',ROOT,'--out',dest])
    print('OPEN:',dest)


def main():
    cli=argparse.ArgumentParser(description=__doc__)
    subs=cli.add_subparsers(dest='command',required=True)
    for c in ('doctor','offline','summary','graphs'):subs.add_parser(c)
    c=subs.add_parser('clean');c.add_argument('--rate',required=True,choices=['20','25','ALT']);c.add_argument('--id',required=True)
    c=subs.add_parser('one');c.add_argument('--rate',required=True,choices=['20','25']);c.add_argument('--mode',required=True,choices=MODES);c.add_argument('--id',required=True)
    c=subs.add_parser('ablation');c.add_argument('--rate',required=True,choices=['20','25']);c.add_argument('--id',required=True)
    c=subs.add_parser('matrix');c.add_argument('--start',type=int,default=101);c.add_argument('--count',type=int,default=5)
    c=subs.add_parser('suite');c.add_argument('--start',type=int,default=101);c.add_argument('--count',type=int,default=5)
    c=subs.add_parser('alt');c.add_argument('--prior',type=int,required=True,choices=[20,25]);c.add_argument('--mode',required=True,choices=MODES);c.add_argument('--id',required=True)
    args=cli.parse_args()
    try:
        os.chdir(ROOT)
        if args.command=='doctor':check_environment()
        if args.command=='offline':offline()
        if args.command=='summary':summarize()
        if args.command=='graphs':graphs()
        if args.command=='clean':run_one(args.rate,'clean',trial_id(args.id))
        if args.command=='one':run_one(args.rate,args.mode,trial_id(args.id))
        if args.command=='ablation':
            for mode in MODES:run_one(args.rate,mode,trial_id(args.id))
            graphs()
        if args.command in ('matrix','suite'):
            if not 1<=args.count<=100 or args.start<1:raise ValueError('Count 1..100 and positive start required')
            if args.command=='suite':
                for rate in ('20','25','ALT'):run_one(rate,'clean',str(args.start))
            for trial in range(args.start,args.start+args.count):
                for rate in ('20','25'):
                    for mode in MODES:run_one(rate,mode,str(trial))
                summarize()
            if args.command=='suite':
                for prior in (20,25):
                    for mode in ('none','guide','guard','both'):
                        run_one('ALT',mode,str(args.start),prior)
            graphs()
        if args.command=='alt':run_one('ALT',args.mode,trial_id(args.id),args.prior)
        return 0
    except (RuntimeError,ValueError,OSError) as e:
        print('STOP:',e,file=sys.stderr);return 2

if __name__=='__main__':sys.exit(main())
