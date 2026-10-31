from __future__ import annotations
import json, math
from fractions import Fraction as Q
from pathlib import Path
import numpy as np
from scipy.linalg import expm, solve_discrete_lyapunov

PARAMS = {"R":2.0,"L":0.02,"Kt":0.1,"Ke":0.1,"J":0.002,"b":0.001,"KP":0.18,"KI":0.60}
PERIODS=(20,25)

def f(v): return Q(str(v))
def matadd(a,b):return [[x+y for x,y in zip(ra,rb)] for ra,rb in zip(a,b)]
def mul(a,b):return [[sum((a[i][k]*b[k][j] for k in range(len(b))),Q(0)) for j in range(len(b[0]))] for i in range(len(a))]
def trans(a):return [list(x) for x in zip(*a)]
def eye(n):return [[Q(int(i==j)) for j in range(n)] for i in range(n)]
def scaled(a,v):return [[x*v for x in row] for row in a]
def maxnorm(a):return max(sum(abs(x) for x in row) for row in a)
def is_pd(a):
    """Exact rational Sylvester/LDL^T test, no floating point eigensolver."""
    n=len(a)
    if any(a[i][j]!=a[j][i] for i in range(n) for j in range(n)):
        return False
    d=[]; L=eye(n)
    for j in range(n):
        x=a[j][j]-sum((L[j][k]**2*d[k] for k in range(j)),Q(0))
        if x<=0:return False
        d.append(x)
        for i in range(j+1,n):
            L[i][j]=(a[i][j]-sum((L[i][k]*L[j][k]*d[k] for k in range(j)),Q(0)))/x
    return True

def physical_matrices():
    p={k:f(v) for k,v in PARAMS.items()}
    A=[[-p['R']/p['L'],-p['Ke']/p['L'],1/p['L']],
       [p['Kt']/p['J'],-p['b']/p['J'],Q(0)],
       [Q(0),Q(0),Q(0)]]
    return A

def taylor_exp_enclosure(T_ms:int, degree:int=45):
    # Exact rational Taylor center, plusabsolute entry-wise bound.
    # exp(X)-sum_0^N X^k/k! <= e^||X|| * ||X||^(N+1)/(N+1)!
    # e^x <= (1-x/m)^(-m) for x<m, using -ln(1-z)>=z.
    X=scaled(physical_matrices(),Q(T_ms,1000))
    s=eye(3);term=eye(3)
    for k in range(1,degree+1):
        term=scaled(mul(term,X),Q(1,k)); s=matadd(s,term)
    x=maxnorm(X); m=max(10,math.ceil(float(x))+5)
    expupper=(1-x/Q(m))**(-m)
    err=expupper*x**(degree+1)/Q(math.factorial(degree+1))
    return s,err

def closed_loop_from_hold(hold,T_ms,pi_dt_ms=None):
    # same as firmware: Inew=Iold-KI*T*omega,
    # u=Inew-KP*omega; xnew=Ad*x+Bd*u.
    T=Q(T_ms if pi_dt_ms is None else pi_dt_ms,1000); kp=f(PARAMS['KP']);ki=f(PARAMS['KI'])
    Ad=[r[:2] for r in hold[:2]]; Bd=[r[2] for r in hold[:2]]
    A=[[Ad[i][0],Ad[i][1]-Bd[i]*(kp+ki*T),Bd[i]] for i in range(2)]
    A.append([Q(0),-ki*T,Q(1)])
    return A

def sampled_float(t,pi_dt_ms=None):
    m=np.array([[float(x) for x in row] for row in physical_matrices()])
    E=expm(m*(t/1000.))
    dt=t if pi_dt_ms is None else pi_dt_ms
    return np.array([[E[i,0],E[i,1]-E[i,2]*(PARAMS['KP']+PARAMS['KI']*dt/1000.),E[i,2]] for i in range(2)]
         + [[0.,-PARAMS['KI']*dt/1000.,1.]])

def certify(periods=PERIODS,model_source=None,out=None,precision=6):
    if tuple(periods)!=(20,25):raise ValueError('Only validated 20/25 ms set supported by this certificate')
    if model_source is not None:
        from importlib.util import spec_from_file_location,module_from_spec
        spec=spec_from_file_location('maars_real_motor_model',str(model_source))
        if spec is None or spec.loader is None:raise ValueError('Cannot load user motor_model.py')
        import sys
        module=module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
        motor=module.Motor()
        mapping={'R':'R','L':'L','Kt':'Kt','Ke':'Ke','J':'J','b':'b'}
        for k,attr in mapping.items():
            if abs(float(getattr(motor,attr))-PARAMS[k])>1e-12:raise ValueError(f'Plant {k} mismatches certificate')
        for k in ('KP','KI'):
            if abs(float(getattr(module,k))-PARAMS[k])>1e-12:raise ValueError(f'PI {k} mismatches certificate')
    AA={t:sampled_float(t) for t in periods}
    avg=sum(AA.values())/len(AA)
    P0=solve_discrete_lyapunov(avg.T,np.eye(3))
    Pr=[[Q(round(float(x),precision)).limit_denominator(10**precision) for x in row] for row in (P0+P0.T)/2]
    if not is_pd(Pr):raise ValueError('Common P candidate is not positive definite')
    mode=[]
    for t in periods:
      for pi_dt in periods:
        E,err=taylor_exp_enclosure(t)
        A=closed_loop_from_hold(E,t,pi_dt)
        factor=max(Q(1),1+abs(f(PARAMS['KP']))+abs(f(PARAMS['KI'])*Q(pi_dt,1000)))
        delta=3*factor*err
        a_upper=3*max(abs(x) for row in A for x in row)
        p_upper=3*max(abs(x) for row in Pr for x in row)
        perturb=p_upper*(2*a_upper*delta+delta**2)
        AtPA=mul(mul(trans(A),Pr),A)
        Qmat=[[Pr[i][j]-AtPA[i][j]- (perturb if i==j else Q(0)) for j in range(3)] for i in range(3)]
        if not is_pd(Qmat):raise ValueError(f'NO VALID CQLF for plant {t}ms / PI dt {pi_dt}ms')
        Pf=np.array([[float(x) for x in row] for row in Pr]);Af=sampled_float(t,pi_dt)
        M=Af.T@Pf@Af-Pf
        mode.append({'plant_next_hold_period_ms':t,'pi_previous_sample_interval_ms':pi_dt,
          'A_cl':Af.tolist(),'spectral_radius':float(max(abs(np.linalg.eigvals(Af)))),
          'max_eigenvalue_delta':float(np.linalg.eigvalsh(M).max()),
          'matrix_exp_error_bound':float(err),'delta_A_operator_bound':float(delta),
          'delta_quadratic_operator_bound':float(perturb),
          'exact_rational_negative_definite_checked':True})
    result={'status':'CERTIFIED_IDEAL_LINEAR_SAMPLED_MODEL_ONLY','plant_parameters':PARAMS,
       'source_motor_model_verified':str(model_source) if model_source else None,
       'periods_ms':list(periods),'P_rational':[[str(x) for x in row] for row in Pr],
       'P_float':[[float(x) for x in row] for row in Pr],
       'P_min_eigenvalue_display':float(np.linalg.eigvalsh(np.array([[float(x) for x in row] for row in Pr])).min()),
       'modes':mode,'proof':'Exact rational Sylvester test of P>0 and P-A^T P A-eta I>0 using a rigorous Taylor matrix exponential enclosure for EACH OF FOUR combinations of previous PI dt and next plant hold period.',
       'boundary':'ONLY zero-delay, unsaturated, disturbance-free, linear sampled-data PI regulation about a constant reference. The four modes include rate-transition PI dt mismatches. DOES NOT prove stability for physical ESP32/USB-loop, saturation, sample loss, time-varying references, latency or arbitrary controller implementations.'}
    if out:
        out=Path(out);out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(result,indent=2)+'\n')
    return result

if __name__=='__main__':
    x=certify(out='stage11_certificate.json');print(x['status']);print([(d['period_ms'],d['max_eigenvalue_delta']) for d in x['modes']])
