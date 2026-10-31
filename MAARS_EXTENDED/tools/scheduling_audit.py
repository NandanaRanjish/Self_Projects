#!/usr/bin/env python3
import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

NAMES=('CONTROL','SAFETY','MONITOR','TX','UNTRUSTED')
PERIODS={0:None,1:40,2:60,3:None,4:50}
OFFSET={0:0,1:0,2:0,3:8,4:0}
FIELDS=('index','kind','worker','job','start_us','end_us','arg','flag')


def load_capture(filename):
    filename=Path(filename)
    meta=json.loads(filename.with_suffix('.meta.json').read_text())
    with filename.open(newline='',encoding='utf8') as handle:
        rdr=csv.DictReader(handle)
        if tuple(rdr.fieldnames)!=FIELDS:
            raise ValueError(f'Bad capture CSV header: {rdr.fieldnames}')
        rows=[]
        for row in rdr:
            item={k:(v if k=='kind' else int(v)) for k,v in row.items()}
            rows.append(item)
    return meta,rows


def validate(meta, rows):
    errors=[]
    notes=[]
    def check(condition,message):
        if not condition: errors.append(message)
    start=int(meta['start_us']); end=int(meta['end_us'])
    period=int(meta['period_ms'])
    check(meta['state']==3,'Capture not frozen')
    check(meta['loss']==0,'On-device buffer overflow')
    check(end-start==600000,'Capture not exactly 600 ms')
    check(period in (20,25),'Unsupported captured CONTROL period')
    check(len(rows)==meta['count'],'Record count mismatch')
    check(len(rows)<=1024,'Capacity exceeded')
    check([r['index'] for r in rows]==list(range(len(rows))), 'Missing / duplicated record indices')
    check(all(0<=r['worker']<5 for r in rows),'Unknown worker index')
    check(all(r['kind'] in ('R','D','G','J','P','X') for r in rows),'Unknown record type')
    for r in rows:
        if not (start <= r['start_us'] < end):
            errors.append(f"{r['kind']}[{r['index']}] timestamp outside capture frame")
        if r['end_us']<r['start_us']:
            errors.append(f"{r['kind']}[{r['index']}] negative duration")
        if r['kind']=='G' and r['end_us']>end:
            errors.append(f"G[{r['index']}] extends beyond capture frame")

    releases={}; completed={}; grants=defaultdict(list)
    publishes={}; tx_reads={}; p_by_seq={}
    for r in rows:
        key=(r['worker'],r['job'])
        kind=r['kind']
        if kind=='R':
            check(key not in releases, f'Duplicate release {key}')
            releases[key]=r
        elif kind=='D':
            errors.append(f'Dropped release {key}')
        elif kind=='G': grants[key].append(r)
        elif kind=='J':
            check(key not in completed,f'Duplicate job completion {key}')
            completed[key]=r
        elif kind=='P':
            check(key not in publishes,f'Duplicate CONTROL publication {key}')
            publishes[key]=r
            check(r['arg'] not in p_by_seq,f'Duplicate command sequence {r["arg"]}')
            p_by_seq[r['arg']]=r
        elif kind=='X':
            check(key not in tx_reads,f'Duplicate TX read {key}')
            tx_reads[key]=r

    for i in range(5):
        pi=period if i in (0,3) else PERIODS[i]
        expected_count=600//pi
        actual=[r for key,r in releases.items() if key[0]==i]
        check(len(actual)==expected_count,
              f'{NAMES[i]} releases: expected {expected_count}, observed {len(actual)}')
        expected_set={start+v*1000 for v in range(OFFSET[i],600,pi)}
        seen_set={r['start_us'] for r in actual}
        check(seen_set==expected_set,
              f'{NAMES[i]} release grid differs from expected period/offset')
        for r in actual:
            check(r['arg']==pi,f'{NAMES[i]} release period mismatch at job {r["job"]}')

    for key, r in releases.items():
        check(key in completed, f'Missing completion for job {key}')
        check(bool(grants[key]), f'Missing grant for job {key}')
        if key in completed:
            done=completed[key]
            check(done['start_us']>=r['end_us'],f'Job {key} completed before actual release')
            check(done['start_us']<=r['start_us']+r['arg']*1000,
                  f'Deadline miss for job {key}')
            check(done['flag']==0, f'Firmware deadline miss flag for {key}')
        for grant in grants[key]:
            check(grant['start_us']>=r['end_us'],f'Grant before release for {key}')
            check(grant['end_us']<=r['start_us']+r['arg']*1000,
                  f'Grant after deadline for {key}')

    all_grants=sorted((g for g_list in grants.values() for g in g_list),key=lambda r:r['start_us'])
    for left,right in zip(all_grants,all_grants[1:]):
        if left['end_us']>right['start_us']:
            errors.append(f'Overlapping worker grants: indices {left["index"]}, {right["index"]}')
    for key in completed:
        check(key in releases,f'Completed job missing release {key}')
    for key in grants:
        check(key in releases,f'Grant belongs to missing release {key}')
    for key, p in publishes.items():
        check(key[0]==0,f'Non-CONTROL publication {key}')
        if key in completed:
            check(p['start_us']>=completed[key]['start_us'],f'Publication before CONTROL completion {key}')
        check(any(g['start_us']<=p['start_us']<=g['end_us'] for g in grants[key]),
              f'Publication not within its grant {key}')
    for key, x in tx_reads.items():
        check(key[0]==3,f'Non-TX read {key}')
        check(any(g['start_us']<=x['start_us']<=g['end_us'] for g in grants[key]),
              f'TX read not within its grant {key}')
        if x['flag']:
            check(x['arg'] in p_by_seq, f'TX command seq {x["arg"]} missing publication')
            if x['arg'] in p_by_seq:
                check(p_by_seq[x['arg']]['start_us'] < x['start_us'],
                      f'TX read preceded publication seq {x["arg"]}')
    check(len(tx_reads)==sum(key[0]==3 for key in releases),
          'Not all TX jobs recorded a buffer read')
    check(sum(x['flag'] for x in tx_reads.values())==len(publishes),
          'Valid TX count does not match CONTROL publications')

    
    tx_by_planned={r['start_us']:key for key,r in releases.items() if key[0]==3}
    attackers=sorted((g['start_us'],g['end_us'])
                     for key,v in grants.items() if key[0]==4 for g in v)
    all_windows=[]
    for key,r in sorted(releases.items(),key=lambda kv:kv[1]['start_us']):
        if key[0]!=0: continue
        tx_key=tx_by_planned.get(r['start_us']+8000)
        if tx_key is None or key not in completed or tx_key not in tx_reads:
            errors.append(f'Missing CONTROL->TX pair for CONTROL job {key}')
            continue
        tx=tx_reads[tx_key]
        finish=completed[key]['start_us']
        a=finish; b=tx['start_us']
        if not a<b:
            errors.append(f'Invalid potential CONTROL->TX window {key}')
        overlap=any(a<right and left<b for left,right in attackers)
        actual_publish=publishes.get(key)
        valid=bool(actual_publish and tx['flag'])
        actual_overlap=None
        actual_start=None
        if valid:
            actual_start=actual_publish['start_us']
            actual_overlap=any(actual_start<right and left<b for left,right in attackers)
        all_windows.append({'control_job':key[1], 'tx_job':tx_key[1],
                            'control_planned_us':r['start_us'],
                            'control_completed_us':a, 'tx_read_us':b,
                            'potential_window_us':b-a, 'potential_attacker_overlap':int(overlap),
                            'valid_command':int(valid),
                            'published_us':actual_start if valid else '',
                            'actual_attacker_overlap':int(actual_overlap) if valid else ''})
    check(len(all_windows)==600//period, 'Incomplete per-arrival vulnerability denominator')
    total_worker_us=sum(g['end_us']-g['start_us'] for g in all_grants)
    check(total_worker_us<=600000,'Worker wall intervals exceed hyperperiod')
    unaccounted_us=600000-total_worker_us
    notes.append('UNATTRIBUTED is dispatcher/interrupt/non-worker wall time, not proven CPU idle.')
    notes.append('Attacker overlap is a potential job-based opportunity, NOT MAARS literal Eq.5 AP.')
    check(all(r['flag']==1 for r in releases.values()),'Invalid accepted-release flag')
    per_job_grant_wall={key:sum(g['end_us']-g['start_us'] for g in gs)
                        for key,gs in grants.items()}
    response_us={key:completed[key]['start_us']-r['start_us']
                 for key,r in releases.items() if key in completed}
    result={
        'all_grants':all_grants,
        'start_us':start,'end_us':end,
        'per_worker_max_job_grant_wall_us':{
            NAMES[i]:max((value for (idx,job),value in per_job_grant_wall.items() if idx==i),default=0)
            for i in range(5)},
        'per_worker_max_response_us':{
            NAMES[i]:max((value for (idx,job),value in response_us.items() if idx==i),default=0)
            for i in range(5)},
        'valid':not errors,'errors':errors,'notes':notes,
        'frame':meta['frame'],'period_ms':period,'record_count':len(rows),
        'record_kind_counts':dict(Counter(r['kind'] for r in rows)),
        'job_release_counts':{NAMES[i]:sum(k[0]==i for k in releases) for i in range(5)},
        'job_completion_count':len(completed),'grant_count':len(all_grants),
        'worker_grant_wall_us':total_worker_us,'unattributed_wall_us':unaccounted_us,
        'valid_publications':len(publishes),
        'potential_vulnerable_jobs':sum(x['potential_attacker_overlap'] for x in all_windows),
        'total_control_arrivals':600//period,
        'potential_overlap_fraction':sum(x['potential_attacker_overlap'] for x in all_windows)/(600//period),
        'valid_vulnerable_commands':sum(x['actual_attacker_overlap']==1 for x in all_windows),
        'total_valid_commands':sum(x['valid_command'] for x in all_windows),
        'windows':all_windows,
    }
    return result


def write_outputs(report, out):
    out=Path(out);out.mkdir(parents=True,exist_ok=True)
    (out/'audit.json').write_text(json.dumps({k:v for k,v in report.items()
                                              if k not in ('windows','all_grants')},indent=2)+'\n')
    with (out/'control_tx_windows.csv').open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=['control_job','tx_job','control_planned_us','control_completed_us',
                                            'tx_read_us','potential_window_us','potential_attacker_overlap',
                                            'valid_command','published_us','actual_attacker_overlap'])
        writer.writeheader();writer.writerows(report['windows'])
    with (out/'grants.csv').open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=['index','kind','worker','job',
                                            'start_us','end_us','arg','flag'])
        writer.writeheader();writer.writerows(report['all_grants'])
    gs=report['all_grants'];cursor=0
    with (out/'timeline_50us.csv').open('w',newline='') as f:
        writer=csv.writer(f)
        writer.writerow(['slot','start_us','end_us','classification','grant_covered_us'])
        for slot,t in enumerate(range(report['start_us'],report['end_us'],50)):
            e=t+50
            while cursor<len(gs) and gs[cursor]['end_us']<=t:cursor+=1
            covered=0;present=set();k=cursor
            while k<len(gs) and gs[k]['start_us']<e:
                g=gs[k]
                n=max(0,min(e,g['end_us'])-max(t,g['start_us']))
                if n:
                    covered+=n;present.add(g['worker'])
                k+=1
            if not present: label='UNATTRIBUTED'
            elif len(present)>1: label='MIXED'
            elif covered!=50: label='PARTIAL_'+NAMES[next(iter(present))]
            else:label=NAMES[next(iter(present))]
            writer.writerow([slot,t,e,label,covered])


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('capture_csv',type=Path)
    ap.add_argument('--out-dir',type=Path)
    args=ap.parse_args()
    meta,rows=load_capture(args.capture_csv)
    result=validate(meta,rows)
    output=args.out_dir or args.capture_csv.with_name(args.capture_csv.stem+'_audit')
    write_outputs(result,output)
    print('Stage 6B complete hardware worker-grant audit')
    print('State:', 'VALID' if result['valid'] else 'INVALID', 'period:', result['period_ms'],'ms')
    print('Records:',result['record_count'],result['record_kind_counts'])
    print('Release counts:',result['job_release_counts'])
    print('Grants:',result['grant_count'],'completions:',result['job_completion_count'])
    print('Max job grant-wall us:',result['per_worker_max_job_grant_wall_us'])
    print('Max release-to-completion us:',result['per_worker_max_response_us'])
    print('Worker-grant wall occupancy:',result['worker_grant_wall_us'],'us / 600000 us')
    print('Unattributed wall time:',result['unattributed_wall_us'],'us')
    print('CONTROL->TX potentially exposed jobs:',result['potential_vulnerable_jobs'],'/',result['total_control_arrivals'],
          f"({result['potential_overlap_fraction']:.2%})")
    print('Valid commands with actual attacker overlap:',result['valid_vulnerable_commands'],'/',result['total_valid_commands'])
    print('NOTE: Job-overlap vulnerability is NOT MAARS Eq.5 AP.')
    if result['errors']:
        print('FAILURES:')
        for error in result['errors'][:30]:print(' -',error)
        if len(result['errors'])>30: print(' +',len(result['errors'])-30,'more')
    print('Reports:',output/'audit.json',output/'control_tx_windows.csv', output/'grants.csv', output/'timeline_50us.csv')
    if not result['valid']: raise SystemExit(2)


if __name__=='__main__':
    main()
