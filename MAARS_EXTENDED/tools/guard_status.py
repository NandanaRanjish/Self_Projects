"""Stage9F1 status parser"""
from pathlib import Path
import json
FIELDS=('tag','requested','active','alert','index','candidate','digest12',
        'boundaries','switches','guided','equal','rejected','deferrals',
        'sleeps','alarm_events','grant_violations')
def parse_status(line):
    cells=line.strip().split(',')
    if len(cells)!=len(FIELDS) or cells[0]!='S9FSTAT':
        raise ValueError('Malformed S9FSTAT (possible truncation)')
    d=dict(zip(FIELDS,cells))
    for k in FIELDS[1:]:
        if k not in ('candidate','digest12'):
            d[k]=int(d[k])
            if d[k]<0:raise ValueError('negative '+k)
    if d['requested'] or d['active']: raise ValueError('status fetched before OFF')
    if not (0<=d['index']<8):raise ValueError('no verified selected candidate')
    if d['candidate']!=f'aware25_seed{(11,22,33,44,55,66,77,88)[d["index"]]}':
        raise ValueError('selected candidate mismatch')
    if len(d['digest12'])!=12:raise ValueError('digest missing')
    return d

def save_status(line,path):
    d=parse_status(line)
    p=Path(path); p.parent.mkdir(parents=True,exist_ok=True)
    p.write_text(json.dumps(d,indent=2,sort_keys=True)+'\n')
    return d
