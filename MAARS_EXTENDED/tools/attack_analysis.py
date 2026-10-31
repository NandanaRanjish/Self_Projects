#!/usr/bin/env python3
import argparse
from collections import deque
import csv
import math
from pathlib import Path
import random
import statistics
import sys

from motor_model import DT, DemoPI, Motor, disturbance_at, reference_at
from simulate_motor import Board

COLUMNS = [
    'mode','attack_mode','seq','time_s','reference_rad_s','measured_rad_s',
    'true_speed_rad_s','commanded_voltage_v','applied_voltage_v','current_a',
    'attacked','expected_control_slot','esp_planned_us','esp_started_us',
    'esp_finished_us','deadline_miss','rtt_ms','residual_rad_s',
    'chi_square','windowed_chi_square','alarm',
]
EVENT_COLUMNS = ['task','job','period_ms','planned_us','release_us',
                 'start_us','finish_us','miss']


def plot_results(path: Path):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    with path.open(newline='') as fh:
        rows = list(csv.DictReader(fh))
    if not rows:
        return
    t = [float(r['time_s']) for r in rows]
    reference = [float(r['reference_rad_s']) for r in rows]
    omega = [float(r['true_speed_rad_s']) for r in rows]
    requested = [float(r['commanded_voltage_v']) for r in rows]
    applied = [float(r['applied_voltage_v']) for r in rows]
    z = [float(r['windowed_chi_square']) for r in rows]
    fired = [int(r['attacked']) for r in rows]
    alarms = [int(r['alarm']) for r in rows]

    fig, ax = plt.subplots(figsize=(10,4.5))
    ax.plot(t, reference, '--', label='Setpoint')
    ax.plot(t, omega, label='Motor speed')
    ax.set_xlabel('Simulated time (s)')
    ax.set_ylabel('Angular speed (rad/s)')
    ax.grid(alpha=.25)
    ax.legend()
    fig.tight_layout()
    target = path.with_name(path.stem + '_speed.png')
    fig.savefig(target, dpi=160)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(10,4.5))
    ax.plot(t, requested, label='ESP32 computed voltage')
    ax.plot(t, applied, '--', label='Applied plant voltage')
    for j in (i for i, v in enumerate(fired) if v):
        ax.axvline(t[j], alpha=.1)
    ax.set_xlabel('Simulated time (s)')
    ax.set_ylabel('Voltage (V)')
    ax.grid(alpha=.25)
    ax.legend()
    fig.tight_layout()
    target2 = path.with_name(path.stem + '_voltage.png')
    fig.savefig(target2, dpi=160)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(10,4.5))
    ax.plot(t,z,label='Windowed normalized residual')
    ax.axhline(6.0,linestyle='--',label='Demo alarm threshold')
    for j in (i for i, v in enumerate(alarms) if v):
        ax.plot(t[j],z[j],'.',markersize=2)
    ax.set_xlabel('Simulated time (s)')
    ax.set_ylabel('Window statistic (not calibrated)')
    ax.grid(alpha=.25)
    ax.legend()
    fig.tight_layout()
    target3 = path.with_name(path.stem + '_detector.png')
    fig.savefig(target3, dpi=160)
    plt.close(fig)
    print('Plots:', target, target2, target3)


def run(args):
    if not (0.02 <= args.duration <= 120.0):
        raise ValueError('Duration must be between 0.02 and 120 seconds')
    if args.window_end <= args.window_start:
        raise ValueError('Attack end must be after attack start')
    if args.every <= 0:
        raise ValueError('--every must be positive')
    if not (-12 <= args.attack_voltage <= 12):
        raise ValueError('Voltage outside motor limits (-12 to 12)')
    if args.noise_sigma <= 0:
        raise ValueError('Noise sigma must be > 0')

    args.out.parent.mkdir(parents=True,exist_ok=True)
    event_path=args.out.with_name(args.out.stem+'_events.csv')
    rng=random.Random(args.seed)
    plant=Motor()
    nominal=Motor()
    pi=DemoPI() if args.demo else None
    recent=deque(maxlen=5)
    first_planned_us=None
    attack_count=0
    alarm_count=0
    first_alarm=None
    first_attack=None
    latency=[]
    sample_count=round(args.duration/DT)

    with args.out.open('w',newline='',encoding='utf-8') as data_f, \
         event_path.open('w',newline='',encoding='utf-8') as events_f:
        writer=csv.DictWriter(data_f,fieldnames=COLUMNS)
        writer.writeheader()
        event_writer=csv.writer(events_f)
        event_writer.writerow(EVENT_COLUMNS)

        board=None
        ser=None
        if not args.demo:
            try:
                import serial
            except ImportError as ex:
                raise RuntimeError('pyserial missing; pip install -r tools/requirements.txt') from ex
            ser=serial.Serial(args.port,baudrate=args.baud,timeout=.12,write_timeout=1.0)
            board=Board(ser,event_writer)
        try:
            if board:
                board.handshake()
            prior_ref=None
            for seq in range(sample_count):
                t=seq*DT
                ref=reference_at(t)
                omega_measured=plant.omega
                detector_y=plant.omega+rng.gauss(0,args.noise_sigma)
                residual=detector_y-nominal.omega
                z=(residual/args.noise_sigma)**2
                recent.append(z)
                window_stat=sum(recent)/len(recent)
                alarm=int(len(recent)==recent.maxlen and window_stat>6.0)
                if alarm:
                    alarm_count+=1
                    if first_alarm is None:
                        first_alarm=t
                if board:
                    if ref!=prior_ref:
                        board.set_reference(ref)
                        print(f'Time {t:.2f}s setpoint -> {ref:.1f} rad/s')
                        prior_ref=ref
                    response=board.calculate(seq,omega_measured)
                    u=response['voltage_v']
                    planned=response['esp_planned_us']
                    if first_planned_us is None:
                        first_planned_us=planned
                    delta=planned-first_planned_us
                    slot=round(delta/20000)
                    on_slot=abs(delta-slot*20000)<=5000
                    latency.append(response['rtt_ms'])
                else:
                    u=pi.update(ref,omega_measured)
                    planned=seq*20000
                    slot=seq
                    on_slot=True
                    response={'esp_started_us':'','esp_finished_us':'',
                              'deadline_miss':'','rtt_ms':''}

                # ATTACK MODEL: control computation finishes before an emulated buffer overwrite, then plant consumes the value. One 20 ms controller job out of every 5 (100 ms cadence).
                in_attack_window=args.window_start<=t<args.window_end
                can_attack=seq>=50 and on_slot and slot%args.every==0
                attacked=int(args.attack=='posterior' and in_attack_window and can_attack)
                u_applied=args.attack_voltage if attacked else u
                if attacked:
                    attack_count+=1
                    if first_attack is None:
                        first_attack=t
                writer.writerow({
                    'mode':'python_only' if args.demo else 'esp32_hil',
                    'attack_mode':args.attack,
                    'seq':seq,'time_s':f'{t:.3f}',
                    'reference_rad_s':f'{ref:.5f}',
                    'measured_rad_s':f'{omega_measured:.5f}',
                    'true_speed_rad_s':f'{plant.omega:.5f}',
                    'commanded_voltage_v':f'{u:.5f}',
                    'applied_voltage_v':f'{u_applied:.5f}',
                    'current_a':f'{plant.current:.6f}',
                    'attacked':attacked,
                    'expected_control_slot':slot,
                    'esp_planned_us':planned,
                    'esp_started_us':response['esp_started_us'],
                    'esp_finished_us':response['esp_finished_us'],
                    'deadline_miss':response['deadline_miss'],
                    'rtt_ms':response['rtt_ms'],
                    'residual_rad_s':f'{residual:.6f}',
                    'chi_square':f'{z:.6f}',
                    'windowed_chi_square':f'{window_stat:.6f}',
                    'alarm':alarm,
                })
                load=disturbance_at(t)
                plant.step(u_applied,dt=DT,load=load)
                nominal.step(u,dt=DT,load=load)
                if seq%50==0:
                    print(f't={t:4.1f}s speed={omega_measured:7.2f} '
                          f'commanded={u:6.2f}V applied={u_applied:6.2f}V '
                          f'attack={attacked} alarm={alarm} g={window_stat:6.2f}')
        finally:
            if ser is not None:
                ser.close()

    print('\nRUN:', 'Python-only sanity test' if args.demo else 'ESP32-S3 hardware controller')
    print('Attack:', args.attack)
    print('Final motor speed: %.2f rad/s'%plant.omega)
    print('Tampered samples:',attack_count,'out of',sample_count)
    print('Detector alarm samples:',alarm_count)
    print('First tamper:',first_attack,'s; first alarm:',first_alarm,'s')
    if latency:
        print('Median serial round-trip: %.2f ms'%statistics.median(latency))
    print('Data:',args.out)
    print('Task events:',event_path)
    plot_results(args.out)
    return args.out


def main():
    p=argparse.ArgumentParser(description=__doc__)
    mode=p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--port',help='ESP32-S3 USB port, e.g. /dev/ttyACM0')
    mode.add_argument('--demo',action='store_true',help='Python-only sanity test, NOT hardware')
    p.add_argument('--attack',choices=['off','posterior'],default='off')
    p.add_argument('--duration',type=float,default=10.0)
    p.add_argument('--window-start',type=float,default=2.0)
    p.add_argument('--window-end',type=float,default=7.0)
    p.add_argument('--every',type=int,default=5,help='One attacked CONTROL slot per N slots')
    p.add_argument('--attack-voltage',type=float,default=-12.0)
    p.add_argument('--noise-sigma',type=float,default=.25,help='Detector measurement noise (rad/s)')
    p.add_argument('--seed',type=int,default=42)
    p.add_argument('--baud',type=int,default=115200)
    p.add_argument('--out',type=Path,default=Path('traces/stage3_baseline.csv'))
    args=p.parse_args()
    try:
        run(args)
    except (OSError,ValueError,TimeoutError,RuntimeError,KeyboardInterrupt) as ex:
        print(f'RUN FAILED: {ex}',file=sys.stderr)
        print(f'Partial results, if any: {args.out}',file=sys.stderr)
        sys.exit(1)

if __name__=='__main__':
    main()
