#!/usr/bin/env python3
from __future__ import annotations
import argparse,json,re,sys
from pathlib import Path
from analysis.certificate import certify,PARAMS
from analysis.schedules import generate_bank,verify,metrics,CODES,FRAME_SLOTS
from analysis.runtime_selector import trace_selection
from analysis.offline_plant import simulate_plant

ROOT=Path(__file__).resolve().parent

def project_match(project):
    project=Path(project)
    c=project/'main/main.c';motor=project/'tools/motor_model.py'
    if not c.exists() or not motor.exists():
        raise ValueError('Need actual ESP-IDF main/main.c and tools/motor_model.py for source-bound certificate')
    source=c.read_text()
    for symbol,expected in [('MOTOR_KP',PARAMS['KP']),('MOTOR_KI',PARAMS['KI'])]:
        match=re.search(r'^#define\s+'+symbol+r'\s+([0-9.eE+-]+)f?\s*$',source,re.M)
        if match is None or abs(float(match.group(1))-expected)>1e-10:
            raise ValueError(f'Firmware {symbol} differs from expected certificate parameter: {expected}')
    for symbol,value in [('CONTROL_PERIOD_MS',20),('ALT_CONTROL_PERIOD_MS',25)]:
        match=re.search(r'^#define\s+'+symbol+r'\s+(\d+)',source,re.M)
        if match is None or int(match.group(1))!=value:raise ValueError(f'Firmware {symbol} mismatch')
    return motor

def expand(rle):
    decode={v:k for k,v in CODES.items()};slots=[]
    for i,(start,code) in enumerate(rle):
        finish=rle[i+1][0] if i+1<len(rle) else FRAME_SLOTS
        if start!=len(slots):raise ValueError('noncontiguous RLE')
        slots.extend([decode[code]]*(finish-start))
    return slots

def check_generated(folder):
    d=json.loads((folder/'bank_manifest.json').read_text());recomputed=[]
    from hashlib import sha256
    for record in d['records']:
        slots=expand(record['slots_rle'])
        verify(slots,record['period_ms'])
        actual_sha=sha256(bytes(CODES[x] for x in slots)).hexdigest()
        if actual_sha!=record['sha256']:raise ValueError('Schedule digest mismatch')
        m=metrics(slots,record['period_ms'],d['attack_aew_us_assumed'])
        if m!=record['metrics']:raise ValueError('Offline paper metrics do not reproduce')
        recomputed.append(m)
    if set(x['period_ms'] for x in d['records'])!={20,25}:raise ValueError('Missing multi-rate bank')
    if not any(x['normal_eligible'] for x in d['records']):raise ValueError('No Normal pool')
    if not any(x['alert_control_eligible'] for x in d['records']):raise ValueError('No Alert pool')
    return d

def selftest():
    # Unified release: no historical source overlays are required or bundled.
    actual_motor = ROOT.parent / 'tools' / 'motor_model.py'
    if actual_motor.exists():
        certify(model_source=actual_motor)
    else:
        certify()
    d = check_generated(ROOT / 'generated')
    if len(d['records']) != 12:
        raise AssertionError('Expected twelve complete offline candidates')
    selection = trace_selection(d, frames=12, alerts=(3, 4))
    if len(selection) != 12 or set(x['period_ms'] for x in selection) != {20, 25}:
        raise AssertionError('Rate-selectable Normal/Alert modeled candidates')
    print('UNIFIED MODEL SELF-TEST PASS: CQLF, 12 full schedules, rate-aware selector')


def main():
    a=argparse.ArgumentParser(description=__doc__);s=a.add_subparsers(dest='command',required=True)
    s.add_parser('self-test')
    cc=s.add_parser('certify');cc.add_argument('--project',required=True);cc.add_argument('--out',type=Path,default=Path('reports/offline/ideal_certificate.json'))
    bb=s.add_parser('bank-generate');bb.add_argument('--out',type=Path,default=Path('reports/offline/offline_bank'));bb.add_argument('--seed',type=int,default=637);bb.add_argument('--per-rate',type=int,default=6)
    bb.add_argument('--aew-us',type=int,default=7000)
    vv=s.add_parser('bank-verify');vv.add_argument('--bank',type=Path,default=ROOT/'generated')
    pp=s.add_parser('motor-demo');pp.add_argument('--out',type=Path,default=Path('reports/offline/period_correct_motor'));pp.add_argument('--duration',type=float,default=6.)
    args=a.parse_args()
    try:
        if args.command=='self-test':selftest()
        elif args.command=='certify':
            model=project_match(args.project)
            r=certify(model_source=model,out=args.out)
            print('CERTIFIED: exact-rational enclosure for IDEAL linear 20/25ms PI, NOT physical closed loop')
            print('P min eigenvalue display:',r['P_min_eigenvalue_display'])
            for mode in r['modes']:print('Plant',mode['plant_next_hold_period_ms'],'ms / PI dt',mode['pi_previous_sample_interval_ms'],'ms:',mode['max_eigenvalue_delta'])
            print('Proof artifact:',args.out)
        elif args.command=='bank-generate':
            d=generate_bank(args.out,args.per_rate,args.seed,args.aew_us)
            check_generated(args.out)
            print('OFFLINE MODEL FULL BANK PASS:',len(d['records']),'fully specified feasible schedules; 20/25 ms')
            print('Paper Eq5 model results:',args.out/'bank_summary.csv')
            print('Firmware C header:',args.out/'maars_schedule_bank.h')
        elif args.command=='bank-verify':
            d=check_generated(args.bank);print('OFFLINE BANK VERIFY PASS',len(d['records']))
        elif args.command=='motor-demo':
            results=simulate_plant(args.out,duration_s=args.duration)
            for r in results:print(r)
            print('Offline motor results:',args.out)
    except Exception as e:
        print('OFFLINE ANALYSIS ERROR:',e,file=sys.stderr);raise SystemExit(2)
if __name__=='__main__':main()
