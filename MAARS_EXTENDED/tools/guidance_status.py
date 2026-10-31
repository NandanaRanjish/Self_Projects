"""Stage9C lab-only status parser"""
import json
from pathlib import Path

FIELDS = ('tag','requested','active','alert','candidate','digest12','boundaries',
          'guided','equal','not_ready','not_eligible','deadline_guard',
          'budget_guard','no_worker','alert_fallback','mode_fallback','alarm_events')

def parse_status(line):
    parts=line.strip().split(',')
    if len(parts)!=len(FIELDS) or parts[0]!='S9CSTAT':
        raise ValueError('Stage9C status malformed or truncated')
    data=dict(zip(FIELDS,parts))
    for key in FIELDS[1:]:
        if key not in ('candidate','digest12'):
            data[key]=int(data[key])
            if data[key]<0:raise ValueError('Negative counter '+key)
    if data['candidate']!='ts25_seed88' or data['digest12']!='0d778e40d309':
        raise ValueError('Unexpected unqualified candidate identity')
    if data['requested'] or data['active']:
        raise ValueError('Status requested before clean OFF')
    return data

def save_status(line,path):
    data=parse_status(line)
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(data,indent=2,sort_keys=True)+'\n')
    return data
