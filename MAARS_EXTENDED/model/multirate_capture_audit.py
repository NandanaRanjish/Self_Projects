#!/usr/bin/env python3
from __future__ import annotations
import argparse,csv,json
from pathlib import Path

def rows(path):
    with Path(path).open(newline='') as f:return list(csv.DictReader(f))

def audit(basename):
    base=Path(basename)
    if base.suffix=='.csv':base=base.with_suffix('')
    cfg=rows(base.with_name(base.name+'_config.csv'))
    rates={int(x['control_period_ms']) for x in cfg}
    if rates!={20,25}:raise ValueError(f'FAIL: no on-device multi-rate switching in CFG: {rates}')
    status=json.loads(base.with_name(base.name+'_stage11.json').read_text())
    raw=status['raw_status'].split(',')
    if raw[0]!='S11STAT' or len(raw)!=14:raise ValueError('Invalid Stage11 status format')
    nums=list(map(int,raw[1:]))
    requested,active,rate,index,alert,guard,boundaries,switches,guided,rejected,deferrals,violations,alarms=nums
    if not requested or not active or rate not in rates or index==255 or not guard:raise ValueError('Stage11 not fully active and guarded')
    if switches<1 or boundaries<2 or guided<1 or violations!=0:
        raise ValueError(f'Stage11 counters fail: switches={switches} guided={guided} guard_violations={violations}')
    capture=base.with_name(base.name+'_capture.csv')
    records=rows(capture)
    if not records:raise ValueError('Empty captured frame')
    meta=json.loads(base.with_name(base.name+'_capture.meta.json').read_text())
    if meta.get('state')!=3 or meta.get('loss')!=0:raise ValueError('Capture invalid or lost events')
    if any(x['kind']=='D' for x in records):raise ValueError('Observed dropped job release')
    expected_jobs={20:{'CONTROL':30,'SAFETY':15,'MONITOR':10,'TX':30,'UNTRUSTED':12},
                   25:{'CONTROL':24,'SAFETY':15,'MONITOR':10,'TX':24,'UNTRUSTED':12}}
    period=int(meta['period_ms']);want=expected_jobs[period]
    counts={name:0 for name in want};completes={name:0 for name in want}
    for x in records:
        if x['kind'] not in ('R','J'):continue
        names=list(want);i=int(x['worker'])
        if i>=len(names):raise ValueError('Unknown worker')
        name=names[i]
        if x['kind']=='R':counts[name]+=1
        else:completes[name]+=1
    if counts!=want or completes!=want:raise ValueError(f'Job counts invalid: releases={counts}, completions={completes}, want={want}')
    output={'status':'PASS_STAGE11_MIXED_RATE_MODEL_GUIDANCE_HARDWARE_SMOKE',
            'run':str(base),'observed_rates_ms':sorted(rates),
            'schedule_switches':switches,'guided_worker_decisions':guided,
            'cooperative_guard_deferrals':deferrals,'guard_violations':violations,
            'capture_period_ms':period,'capture_job_counts':counts,
            'limitations':'Does not prove equal offline-slot replay, real-plant CQLF stability, or detector validity.'}
    path=base.with_name(base.name+'_stage11_audit.json')
    path.write_text(json.dumps(output,indent=2)+'\n')
    return output

def main():
    p=argparse.ArgumentParser();p.add_argument('run_csv');a=p.parse_args()
    try:
        r=audit(a.run_csv);print('STAGE11 HARDWARE SMOKE PASS',r)
    except Exception as e:
        print('STAGE11 HARDWARE SMOKE FAIL:',e);raise SystemExit(2)
if __name__=='__main__':main()
