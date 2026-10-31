#!/usr/bin/env python3
from __future__ import annotations
import json
from pathlib import Path

FIELDS=('tag','enabled','candidate','digest12','decisions','nonworker_slots',
        'unready_proposals','budget_blocked','runnable_proposals','matches','mismatches',
        'rate_skips','last_frame','last_slot','last_proposed','last_actual')

def parse_status(line):
    x=line.strip().split(',')
    if len(x)!=len(FIELDS) or x[0]!='S9SHSTAT':
        raise ValueError(f'Expected {len(FIELDS)} S9SHSTAT columns, got {len(x)}: {line!r}')
    d=dict(zip(FIELDS,x))
    for k in FIELDS[1:]:
        if k not in ('candidate','digest12'):
            d[k]=int(d[k])
            if d[k]<0:raise ValueError(f'negative {k}')
    if len(d['digest12'])!=12 or not all(c in '0123456789abcdef' for c in d['digest12']):
        raise ValueError('Malformed candidate SHA prefix')
    if d['matches']+d['mismatches']!=d['runnable_proposals']:
        raise ValueError('Match/mismatch counters do not sum to actionable proposals')
    if sum(d[k] for k in ('nonworker_slots','unready_proposals','budget_blocked','runnable_proposals','rate_skips'))>d['decisions']:
        raise ValueError('Inconsistent total decisions')
    d['actionable_fraction_of_all_decisions']=(d['runnable_proposals']/d['decisions'] if d['decisions'] else None)
    d['same_choice_fraction_of_actionable']=(d['matches']/d['runnable_proposals'] if d['runnable_proposals'] else None)
    d['nonclaims']='Timing-phase alignment only; not executed schedule, AP, attack success, or schedulability proof.'
    return d

def save_status(line,path):
    data=parse_status(line)
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(data,indent=2)+'\n',encoding='utf8')
    return data
