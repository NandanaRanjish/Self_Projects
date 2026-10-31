from __future__ import annotations
import random

def select(records,period_ms,alert,previous=None,seed=0):
    possible=[x for x in records if x['period_ms']==period_ms and
       (x['alert_control_eligible'] if alert else x['normal_eligible'])]
    if not possible:raise ValueError('Empty Normal/Alert lookup pool: fail closed')
    different=[x for x in possible if x['id']!=previous]
    return random.Random(seed).choice(different or possible)

def trace_selection(manifest,frames=12,seed=637,alerts=()):
    old=None;history=[]
    for i in range(frames):
        rate=20 if i%2==0 else 25
        active=i in alerts
        entry=select(manifest['records'],rate,active,old,seed+i)
        history.append({'frame':i,'period_ms':rate,'alert':active,'id':entry['id'],
            'ap_eq5':entry['metrics']['paper_ap'],'svi':entry['metrics']['paper_svi_control_only']})
        old=entry['id']
    return history
