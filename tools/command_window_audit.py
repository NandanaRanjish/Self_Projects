#!/usr/bin/env python3
import argparse
import csv
import json
from pathlib import Path


def audit(rows):
    pubs={}
    reads={}
    grants=[]
    for r in rows:
        kind=r['kind']
        w=int(r['worker']); t0=int(r['start_us']); t1=int(r['end_us']);seq=int(r['arg']);flag=int(r['flag'])
        if kind=='P' and w==0 and flag:
            pubs.setdefault(seq,[]).append(t0)
        if kind=='X' and w==3 and flag:
            reads.setdefault(seq,[]).append(t0)
        if kind=='G' and w==4:
            grants.append((t0,t1))
    pairs=[]
    for seq,p_times in pubs.items():
        for p in p_times:
            later=sorted(x for x in reads.get(seq,[]) if x>=p)
            if later:
                pairs.append((seq,p,later[0]))
    overlaps=[]
    for seq,p,x in pairs:
        for g0,g1 in grants:
            if g0 < x and g1 > p:
                overlaps.append({'seq':seq,'published_us':p,'tx_snapshot_us':x,
                                 'untrusted_start_us':g0,'untrusted_end_us':g1})
    return {'complete_control_tx_pairs':len(pairs),
            'publication_events':sum(map(len,pubs.values())),
            'untrusted_grants':len(grants),
            'overlap_count':len(overlaps), 'overlaps':overlaps,
            'partial_intervals_not_certified':sum(map(len,pubs.values()))-len(pairs)}

def main():
    p=argparse.ArgumentParser()
    p.add_argument('capture',type=Path)
    p.add_argument('--min-pairs',type=int,default=10)
    a=p.parse_args()
    with a.capture.open(newline='') as f:r=audit(list(csv.DictReader(f)))
    print(json.dumps(r,indent=2))
    if r['complete_control_tx_pairs']<a.min_pairs:
        raise SystemExit('INVALID: too few complete P->X intervals in capture')
    if r['overlap_count']:
        raise SystemExit('FAIL: real untrusted grant overlaps pending actuator command')
    print('PASS: zero UNTRUSTED grant overlap in complete captured command windows')
if __name__=='__main__':main()
