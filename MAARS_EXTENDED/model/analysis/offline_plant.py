from __future__ import annotations
import csv,json,math,random
from pathlib import Path
import numpy as np
from .certificate import PARAMS,certify,sampled_float

def rk4_step(current,omega,u,T,load=0.):
    p=PARAMS
    def deriv(i,w):return ((u-p['R']*i-p['Ke']*w)/p['L'],(p['Kt']*i-p['b']*w-load)/p['J'])
    h=T/10
    for _ in range(10):
        a,b=deriv(current,omega)
        c,d=deriv(current+.5*h*a,omega+.5*h*b)
        e,f=deriv(current+.5*h*c,omega+.5*h*d)
        g,k=deriv(current+h*e,omega+h*f)
        current+=h*(a+2*c+2*e+g)/6
        omega+=h*(b+2*d+2*f+k)/6
    return current,omega

def simulate_plant(out,seed=637,duration_s=6.,plot=True):
    out=Path(out);out.mkdir(parents=True,exist_ok=True)
    rng=random.Random(seed)
    records=[];metrics=[]
    for mode in ('fixed20','fixed25','alternate','random_frame'):
        now=0.;current=0.;omega=0.;integral=0.;frame=-1;period=20;control_count=0;err2=0.;saturated=0
        while now<duration_s-1e-10:
            newframe=math.floor((now+1e-9)/0.6)
            if newframe!=frame:
                frame=newframe
                period=20 if mode=='fixed20' else 25 if mode=='fixed25' else (20 if frame%2==0 else 25) if mode=='alternate' else rng.choice((20,25))
            # All rates divide 600ms; limit to boundary exactly (no step straddles).
            dt=min(period/1000., duration_s-now, (frame+1)*.6-now)
            if dt<1e-8: now=(frame+1)*.6;continue
            reference=80. if now<5.-1e-9 else 60.
            error=reference-omega
            candidate=integral+PARAMS['KI']*dt*error
            u_pre=PARAMS['KP']*error+candidate
            if abs(u_pre)<=12 or (u_pre>12 and error<0) or (u_pre< -12 and error>0):integral=candidate
            u=max(-12.,min(12.,PARAMS['KP']*error+integral))
            saturated+=int(abs(u)>=11.99999)
            records.append({'mode':mode,'time_s':round(now,6),'period_ms':period,'reference_rad_s':reference,
               'speed_rad_s':omega,'current_A':current,'voltage_V':u,'sample_dt_ms':round(dt*1000,3)})
            current,omega=rk4_step(current,omega,u,dt,0. if now<3.5 else 0.010)
            err2+=error*error*dt;now+=dt;control_count+=1
        metrics.append({'mode':mode,'samples':control_count,'timeweighted_rmse_rad_s':math.sqrt(err2/duration_s),
                        'saturated_sample_count':saturated,'final_speed_rad_s':omega})
    with (out/'multirate_motor_response.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=records[0].keys());w.writeheader();w.writerows(records)
    with (out/'multirate_motor_summary.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=metrics[0].keys());w.writeheader();w.writerows(metrics)
    if plot:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        fig,ax=plt.subplots(figsize=(9,4.5))
        for mode in ('fixed20','fixed25','alternate','random_frame'):
            subset=[r for r in records if r['mode']==mode]
            ax.plot([r['time_s'] for r in subset],[r['speed_rad_s'] for r in subset],label=mode)
        ax.set(title='Offline period-correct simulated DC motor (not physical HIL)',xlabel='Model time (s)',ylabel='Speed (rad/s)')
        ax.legend();ax.grid(True,alpha=.2);fig.tight_layout();fig.savefig(out/'multirate_motor_response.png',dpi=180);plt.close(fig)
    (out/'scope.txt').write_text('Period-correct offline RK4 motor model with PI and saturation. Does NOT certify nonlinear/saturated stability; source parameters from the original Stage2 motor_model.py.\n')
    return metrics

if __name__=='__main__':
    print(simulate_plant('generated/offline_plant'))
