#!/usr/bin/env python3
import argparse
from collections import deque
import csv
import math
from pathlib import Path
import random
import statistics
import sys
import time

from motor_model import DT, Motor, disturbance_at, reference_at
from simulate_motor import Board, _write
from attack_analysis import COLUMNS, EVENT_COLUMNS, plot_results


class AttackBoard(Board):
    """Capture actuator and attacker records from the board protocol."""
    def __init__(self, ser, event_writer, attack_writer, own_writer, ladder_writer,
                 aew_writer):
        super().__init__(ser, event_writer)
        self.attack_writer = attack_writer
        self.own_writer = own_writer
        self.ladder_writer = ladder_writer
        self.aew_writer = aew_writer
        self.aew_by_seq = {}
        self.aew_durations_us = []
        self.tx_attacks = 0
        self.successful_attempts = []
        self.own_jobs = 0
        self.ladder_updates = 0
        self.observations = 0
        self.attempts = 0
        self.attempt_success = 0
        self.latest_inference = None
        self.act_by_seq = {}
        self.attack_events = []
        self.control_misses = 0
        self.untrusted_misses = 0
        self.line_errors = 0
        self.config_events = []
        self.ts_decisions = []
        self.last_ts_status = None

    def _next(self, seconds):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            raw = self.ser.readline()
            if not raw:
                continue
            line = raw.decode('utf-8', errors='replace').strip()
            if line.startswith(('CAPSTAT,','CAPREC,','CAPEND,','ERR,CAP,')):
                return line
            if line.startswith('CFG,'):
                cells = line.split(',')
                if len(cells) == 5:
                    try:
                        self.config_events.append(tuple(int(x) for x in cells[1:]))
                    except ValueError:
                        self.line_errors += 1
                else:
                    self.line_errors += 1
                continue
            if line.startswith('TSDEC,'):
                parts=line.split(',')
                if len(parts)==7:
                    try:
                        self.ts_decisions.append((int(parts[1]),int(parts[2]),
                                                  int(parts[3],16),int(parts[4],16),
                                                  int(parts[5]),int(parts[6])))
                    except ValueError: self.line_errors += 1
                else: self.line_errors += 1
                continue
            if line.startswith(('S9SHSTAT,', 'S9CSTAT,', 'S9FSTAT,', 'S9FMODE,', 'S11STAT,', 'PROTOSTAT,')):
                return line
            if line.startswith('TSSTAT,'):
                self.last_ts_status=line
                return line
            if line.startswith('TSDIAG,'):
                return line
            if line.startswith('TSTRACE,'):
                return line
            if line.startswith('RATESTAT,'):
                return line
            if line.startswith('EVT,'):
                parts = line.split(',')
                if len(parts) == 9:
                    try:
                        vals = [int(x) for x in parts[2:]]
                        self.evt_writer.writerow([parts[1]] + vals)
                        if parts[1] == 'CONTROL':
                            self.control_misses += vals[-1]
                        elif parts[1] == 'UNTRUSTED':
                            self.untrusted_misses += vals[-1]
                    except ValueError:
                        self.line_errors += 1
                continue
            if line.startswith('OWN,'):
                parts = line.split(',')
                if len(parts) == 8:
                    try:
                        int(parts[1]); int(parts[2]); int(parts[3]); int(parts[4])
                        for m in parts[5:]: int(m,16)
                        self.own_writer.writerow(parts[1:])
                        self.own_jobs += 1
                    except ValueError: self.line_errors += 1
                else: self.line_errors += 1
                continue
            if line.startswith('LAD,'):
                parts = line.split(',')
                if len(parts) == 8:
                    try:
                        int(parts[2]); int(parts[3]); int(parts[7])
                        for m in parts[4:7]: int(m,16)
                        self.ladder_writer.writerow(parts[1:])
                        self.ladder_updates += 1
                    except ValueError: self.line_errors += 1
                else: self.line_errors += 1
                continue
            if line.startswith(('OBS,','INF,','TRY,')):
                parts = line.split(',')
                if len(parts) == 4 and parts[0] in ('OBS','INF'):
                    self.attack_writer.writerow([parts[0],*parts[1:], ''])
                    if parts[0] == 'OBS': self.observations += 1
                    else:
                        try: self.latest_inference = (int(parts[1]),int(parts[2]),int(parts[3]))
                        except ValueError: self.line_errors += 1
                elif len(parts) == 5 and parts[0] == 'TRY':
                    self.attack_writer.writerow(parts)
                    try:
                        self.attempts += 1
                        success = int(parts[4])
                        self.attempt_success += success
                        if success:
                            self.successful_attempts.append((int(parts[1]),int(parts[3])))
                    except ValueError: self.line_errors += 1
                else:
                    self.line_errors += 1
                continue
            if line.startswith('AEW,'):
                parts = line.split(',')
                if len(parts) == 7:
                    try:
                        seq, cjob, txjob, published, read_at, attacked = map(int, parts[1:])
                        if read_at < published:
                            raise ValueError('negative measured AEW')
                        self.aew_writer.writerow([seq,cjob,txjob,published,read_at,
                                                   read_at-published,attacked])
                        self.aew_by_seq[seq] = (published,read_at,attacked)
                    except ValueError:
                        self.line_errors += 1
                else:
                    self.line_errors += 1
                continue
            if line.startswith('ACT,'):
                parts = line.split(',')
                if len(parts) == 5:
                    try:
                        seq = int(parts[1])
                        self.act_by_seq[seq] = (float(parts[2]), float(parts[3]), int(parts[4]))
                    except ValueError:
                        self.line_errors += 1
                continue
            if line.startswith('ATK,'):
                self.attack_events.append(line)
                continue
            if line.startswith('STAT,'):
                self.last_stat = line
                continue
            if line.startswith(('PONG,','READY,','CMD,','ACK,','ERR,','INFO,')):
                return line
        raise TimeoutError('No firmware reply in %.2f s' % seconds)

    def arm_capture(self):
        _write(self.ser, 'CAP,ARM')
        return self.wait_for('ACK,CAP,ARM',timeout=4.0)

    def capture_status(self):
        _write(self.ser, 'CAP,STATUS')
        response=self.wait_for('CAPSTAT,',timeout=4.0)
        fields=[int(v) for v in response.split(',')[1:]]
        if len(fields)!=7:
            raise RuntimeError(f'Malformed CAPSTAT: {response}')
        return dict(zip(('state','count','loss','frame','period_ms','start_us','end_us'), fields))

    def download_capture(self, destination):
        import json
        status=self.capture_status()
        if status['state']!=3:
            raise RuntimeError(f'Capture not frozen: {status}')
        if status['loss']:
            raise RuntimeError(f'Capture overflow: {status}')
        destination.parent.mkdir(parents=True,exist_ok=True)
        rows=[]
        for offset in range(0,status['count'],8):
            qty=min(8,status['count']-offset)
            _write(self.ser,f'CAP,READ,{offset},{qty}')
            for expected in range(offset,offset+qty):
                line=self.wait_for('CAPREC,',timeout=6.0)
                parts=line.split(',')
                if len(parts)!=9 or int(parts[1])!=expected:
                    raise RuntimeError(f'Out of order CAP record: {line}, expected={expected}')
                rows.append([int(parts[1]),parts[2],*map(int,parts[3:])])
            end=self.wait_for('CAPEND,',timeout=6.0)
            if end!=f'CAPEND,{offset},{qty}':
                raise RuntimeError(f'Unexpected capture batch footer: {end}')
        import csv
        with destination.open('w',newline='',encoding='utf8') as f:
            writer=csv.writer(f)
            writer.writerow(['index','kind','worker','job','start_us','end_us','arg','flag'])
            writer.writerows(rows)
        meta=destination.with_suffix('.meta.json')
        meta.write_text(json.dumps(status,indent=2)+'\n',encoding='utf8')
        if len(rows)!=status['count']:
            raise RuntimeError('Capture row count mismatch')
        return status, meta

    def confirm_stage(self):
        _write(self.ser, 'INFO')
        return self.wait_for('INFO,MAARS_STAGE5D,', timeout=4.0)

    def set_shuffler(self, enabled):
        mode = 'ON' if enabled else 'OFF'
        _write(self.ser, f'TS,{mode}')
        return self.wait_for(f'ACK,TS,{mode}', timeout=4.0)

    def reset_shuffler_stats(self):
        _write(self.ser, 'TS,RESETSTATS')
        return self.wait_for('ACK,TS,RESETSTATS', timeout=4.0)

    def get_shuffler_status(self):
        _write(self.ser, 'TS,STATUS')
        return self.wait_for('TSSTAT,', timeout=4.0)

    def get_shuffler_diagnostic(self):
        _write(self.ser, 'TS,DETAIL')
        return self.wait_for('TSDIAG,', timeout=4.0)

    def get_trace_status(self):
        _write(self.ser, 'TS,TRACE')
        return self.wait_for('TSTRACE,', timeout=4.0)

    def set_rate(self, choice):
        # A request is committed at a 600-ms ESP32 hyperperiod boundary.
        _write(self.ser, f'RATE,{choice}')
        return self.wait_for(f'ACK,RATE,{choice}', timeout=4.0)

    def get_rate_status(self):
        _write(self.ser, 'RATE,STATUS')
        return self.wait_for('RATESTAT,', timeout=4.0)

    def wait_rate_commit(self, choice, timeout=5.0):
        wanted_mode = {'20': 0, '25': 1, 'ALT': 2}[choice]
        expected_period = {'20': 20, '25': 25, 'ALT': None}[choice]
        old_events = len(self.config_events)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                self._next(min(0.5, max(.01, deadline - time.monotonic())))
            except TimeoutError:
                pass
            for rec in self.config_events[old_events:]:
                _, period, mode, planned_us = rec
                if mode == wanted_mode and (expected_period is None or period == expected_period):
                    return rec
        raise TimeoutError(f'No matching CFG boundary event for RATE,{choice}; check ESP32 timer')

    def set_attack(self, enabled):
        text = 'ON' if enabled else 'OFF'
        _write(self.ser, f'ATTACK,{text}')
        return self.wait_for(f'ACK,ATTACK,{text}', timeout=4.0)

    def calculate(self, seq, omega):
        data = super().calculate(seq, omega)
        info = self.act_by_seq.pop(seq, None)
        if info is None:
            raise RuntimeError(f'Missing ACT record for CMD seq={seq}; cannot validate on-board tampering')
        aew = self.aew_by_seq.pop(seq, None)
        if aew is None:
            raise RuntimeError(f'Missing AEW for CMD seq={seq}; incorrect firmware or dropped telemetry')
        published, tx_read, aew_attacked = aew
        computed, applied, tampered = info
        if aew_attacked != tampered:
            raise RuntimeError(f'ACT/AEW tamper flag mismatch for seq={seq}')
        self.aew_durations_us.append(tx_read-published)
        self.tx_attacks += tampered
        data['aew_published_us'] = published
        data['aew_tx_read_us'] = tx_read
        if not math.isclose(data['voltage_v'], applied, abs_tol=0.0002):
            raise RuntimeError(f'CMD/ACT voltage mismatch at seq={seq}: {data["voltage_v"]} vs {applied}')
        data['computed_v'] = computed
        data['applied_v'] = applied
        data['tampered'] = tampered
        return data


def run(args):
    try:
        import serial
    except ImportError as ex:
        raise RuntimeError('pyserial missing; activate Stage 1 venv') from ex
    if not 0.1 <= args.duration <= 120.0:
        raise ValueError('Duration must be 0.1 to 120 seconds')
    if args.capture and not 0 <= args.capture_at < args.duration-1.5:
        raise ValueError('Use --capture-at earlier than duration-1.5 simulated seconds')
    if args.window_start < 0 or args.window_end <= args.window_start:
        raise ValueError('Bad window start/end')
    if args.stage9f == 'off' and args.s9f_mode != 'both':
        raise ValueError('--s9f-mode guide/guard requires --stage9f on')

    args.out.parent.mkdir(parents=True, exist_ok=True)
    events_path = args.out.with_name(args.out.stem+'_events.csv')
    attack_path = args.out.with_name(args.out.stem+'_attacker.csv')
    own_path = args.out.with_name(args.out.stem+'_own.csv')
    ladder_path = args.out.with_name(args.out.stem+'_ladder.csv')
    aew_path = args.out.with_name(args.out.stem+'_aew.csv')
    cfg_path = args.out.with_name(args.out.stem+'_config.csv')
    ts_path = args.out.with_name(args.out.stem+'_shuffler.csv')
    plant, nominal = Motor(), Motor()
    rng = random.Random(42)
    recent = deque(maxlen=5)
    alarms = 0
    successful = 0
    first_success = None
    first_alarm = None
    rtt = []
    board = None
    stage9_shadow_status_valid = False
    stage9c_status_valid = False
    stage9f_status_valid = False

    with args.out.open('w', newline='', encoding='utf8') as f, \
         events_path.open('w',newline='',encoding='utf8') as e, \
         attack_path.open('w',newline='',encoding='utf8') as a, \
         own_path.open('w',newline='',encoding='utf8') as own_f, \
         ladder_path.open('w',newline='',encoding='utf8') as ladder_f, \
         aew_path.open('w',newline='',encoding='utf8') as aew_f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        event_writer = csv.writer(e)
        event_writer.writerow(EVENT_COLUMNS)
        attack_writer = csv.writer(a)
        attack_writer.writerow(['kind','time_us','value1','value2','value3'])
        own_writer = csv.writer(own_f)
        own_writer.writerow(['job','planned_us','start_us','finish_us',
                             f'run_mask_{args.attacker_prior}ms',
                             'run_mask_40ms','run_mask_60ms'])
        ladder_writer = csv.writer(ladder_f)
        ladder_writer.writerow(['task','period_us','bin_us','aai_hex','aei_hex',
                                'candidate_hex','observations'])
        aew_writer = csv.writer(aew_f)
        aew_writer.writerow(['seq','control_job','tx_job','published_us',
                             'tx_read_us','aew_duration_us','attacked'])
        ser = serial.Serial()
        ser.port = args.port
        ser.baudrate = args.baud
        ser.timeout = .12
        ser.write_timeout = 1.0
        ser.dtr = False
        ser.rts = False
        ser.open()
        try:
            board = AttackBoard(ser, event_writer, attack_writer,
                                own_writer, ladder_writer, aew_writer)
            board.handshake()
            print('Firmware:',board.confirm_stage())
            print('Requested rate policy:',board.set_rate(args.rate))
            print('Committed 600ms boundary:',board.wait_rate_commit(args.rate))
            print('TaskShuffler mode:', board.set_shuffler(args.ts == 'on'))
            print('TaskShuffler stats reset:',board.reset_shuffler_stats())
            print('Attack disabled:', board.set_attack(False))
            _write(ser, f'ATKPRIOR,{args.attacker_prior}')
            print('Attacker prior:',board.wait_for(
                f'ACK,ATKPRIOR,{args.attacker_prior}',timeout=4.0))
            if args.stage9f == 'on':
                if args.rate!='25' or args.ts!='on' or args.stage9c!='off' or args.stage9_shadow!='off':
                    raise ValueError('Stage9F requires --rate 25 --ts on --stage9c off --stage9-shadow off')
                _write(ser,'CHI8,SHADOW')
                print('Stage9F detector:',board.wait_for('ACK,CHI8,SHADOW',timeout=4.0))
                _write(ser,'S9F,ON')
                print('Stage9F request:',board.wait_for('ACK,S9F,REQUESTED_MODEL_ONLY',timeout=4.0))
                selected_mode=args.s9f_mode.upper()
                _write(ser,f'S9F,MODE,{selected_mode}')
                print('Stage10 selected ablation:',board.wait_for(
                    f'ACK,S9F,MODE,{selected_mode}',timeout=4.0))
                _write(ser,'S9F,MODE,STATUS')
                raw_mode=board.wait_for('S9FMODE,',timeout=4.0)
                expected_flags={'BOTH':(1,1),'GUIDE':(1,0),'GUARD':(0,1)}[selected_mode]
                mode_fields=[int(x) for x in raw_mode.split(',')[1:]]
                if tuple(mode_fields[:2]) != expected_flags:
                    raise RuntimeError(f'Stage10 mode mismatch: {raw_mode}')
                import json
                args.out.with_name(args.out.stem+'_stage10_mode.json').write_text(
                    json.dumps({'mode':selected_mode.lower(),
                                'guide_enabled':mode_fields[0],
                                'guard_enabled':mode_fields[1],
                                'hardware_confirmation':raw_mode},indent=2)+'\n',
                    encoding='utf8')
            if args.stage11 == 'on':
                if args.stage9f!='off' or args.stage9c!='off' or args.stage9_shadow!='off' or args.ts!='on':
                    raise ValueError('Stage11 requires --ts on --stage9f off --stage9c off --stage9-shadow off')
                _write(ser,'CHI8,SHADOW')
                print('Stage11 research detector:',board.wait_for('ACK,CHI8,SHADOW',timeout=4.0))
                _write(ser,'S11,ON')
                print('Stage11 mode:',board.wait_for('ACK,S11,ON,MODEL_GUIDANCE',timeout=4.0))
                selected_mode=args.stage11_ablation.upper()
                _write(ser,'S11,MODE,'+selected_mode)
                ack=board.wait_for('ACK,S11,MODE,'+selected_mode+',',timeout=4.0)
                expected_bits={'GUIDE':'GUIDANCE=1,GUARD=0',
                               'GUARD':'GUIDANCE=0,GUARD=1',
                               'BOTH':'GUIDANCE=1,GUARD=1'}[selected_mode]
                if ack!='ACK,S11,MODE,'+selected_mode+','+expected_bits:
                    raise RuntimeError('Stage11 ablation mode mismatch: '+ack)
                print('MAARS ablation mode verified:',ack)
                _write(ser,'S11,STATUS')
                initial=board.wait_for('S11STAT,',timeout=4.0)
                if int(initial.split(',')[1])!=1:
                    raise RuntimeError(f'Stage11 mode not activated: {initial}')
                print('Stage11 initial hardware status:',initial)
                activation_deadline=time.monotonic()+3.0
                while True:
                    _write(ser,'S11,STATUS')
                    active_status=board.wait_for('S11STAT,',timeout=4.0)
                    activation_fields=active_status.split(',')
                    if len(activation_fields)==14 and activation_fields[1]=='1' and activation_fields[2]=='1':
                        print('Stage11 active before attack:',active_status)
                        break
                    if time.monotonic()>activation_deadline:
                        raise RuntimeError('Stage11 did not become active before trial: '+active_status)
                    time.sleep(0.05)
            if args.stage9c == 'on':
                _write(ser,'CHI8,SHADOW')
                print('Stage9C detector:',board.wait_for('ACK,CHI8,SHADOW',timeout=4.0))
                _write(ser,'S9C,ON')
                print('Stage9C laboratory guide:',board.wait_for('ACK,S9C,REQUESTED_LAB_ONLY',timeout=4.0))
            if args.stage9_shadow == 'on':
                _write(ser, 'S9SH,ON')
                print('Stage9 shadow enabled:', board.wait_for('ACK,S9SH,ON',timeout=4.0))
            enabled = False
            previous_ref = None
            capture_armed=False
            for seq in range(round(args.duration/DT)):
                t = seq*DT
                if args.capture and not capture_armed and t >= args.capture_at:
                    print('Capture arm:', board.arm_capture())
                    capture_armed=True
                desired = bool(args.attack == 'on' and args.window_start <= t < args.window_end)
                if desired != enabled:
                    print(f'Time {t:.2f}s: on-device UNTRUSTED attack -> {"ON" if desired else "OFF"}')
                    print(board.set_attack(desired))
                    enabled = desired
                ref = reference_at(t)
                if ref != previous_ref:
                    board.set_reference(ref)
                    print(f'Time {t:.2f}s: setpoint -> {ref:.1f} rad/s')
                    previous_ref = ref

                speed = plant.omega
                sample_y = speed + rng.gauss(0, .25)
                residual = sample_y - nominal.omega
                chi_sq = (residual/.25)**2
                recent.append(chi_sq)
                z = sum(recent)/len(recent)
                alarm = int(len(recent) == 5 and z>6)
                if alarm:
                    alarms += 1
                    if first_alarm is None: first_alarm = t

                result = board.calculate(seq, speed)
                orig = result['computed_v']
                applied = result['applied_v']
                attacked = result['tampered']
                if attacked:
                    successful += 1
                    if first_success is None: first_success = t
                rtt.append(result['rtt_ms'])
                writer.writerow({
                    'mode':'esp32_schedule_ladder_attack', 'attack_mode':args.attack,
                    'seq':seq, 'time_s':f'{t:.3f}',
                    'reference_rad_s':f'{ref:.5f}',
                    'measured_rad_s':f'{speed:.5f}',
                    'true_speed_rad_s':f'{plant.omega:.5f}',
                    'commanded_voltage_v':f'{orig:.5f}',
                    'applied_voltage_v':f'{applied:.5f}',
                    'current_a':f'{plant.current:.6f}',
                    'attacked':attacked,
                    'expected_control_slot':'',
                    'esp_planned_us':result['esp_planned_us'],
                    'esp_started_us':result['esp_started_us'],
                    'esp_finished_us':result['esp_finished_us'],
                    'deadline_miss':result['deadline_miss'],
                    'rtt_ms':f'{result["rtt_ms"]:.4f}',
                    'residual_rad_s':f'{residual:.6f}',
                    'chi_square':f'{chi_sq:.6f}',
                    'windowed_chi_square':f'{z:.6f}',
                    'alarm':alarm,
                })
                load = disturbance_at(t)
                plant.step(applied, dt=DT, load=load)
                nominal.step(orig, dt=DT, load=load)
                if seq%50 == 0:
                    print(f't={t:5.2f}s speed={speed:7.2f} '
                          f'computed={orig:6.2f}V applied={applied:6.2f}V '
                          f'overwrite={attacked} alarm={alarm} RTT={result["rtt_ms"]:.1f}ms')
        finally:
            if board:
                try:
                    try:
                        _write(ser, 'PROTO,STATUS')
                        print('Firmware protocol counters:', board.wait_for('PROTOSTAT,', timeout=4.0))
                    except Exception as proto_exc:
                        print('Firmware protocol counters unavailable:', proto_exc, file=sys.stderr)
                    print('Hardware rate status:', board.get_rate_status())
                    print('TaskShuffler hardware status:', board.get_shuffler_status())
                    diag = board.get_shuffler_diagnostic()
                    print('TaskShuffler detailed status:', diag)
                    parts = [int(x) for x in diag.split(',')[1:]]
                    if len(parts) == 14:
                        print('Breakdown: bad_ack=%d elapsed_overrun=%d budget_underflow=%d max_elapsed_excess_us=%d' % tuple(parts[:4]))
                        print('Elapsed overruns by worker (CONTROL,SAFETY,MONITOR,TX,UNTRUSTED):', parts[4:9])
                        print('Budget underflows by blocked worker (CONTROL,SAFETY,MONITOR,TX,UNTRUSTED):', parts[9:14])
                    if args.stage9f == 'on':
                        _write(ser,'S9F,OFF')
                        board.wait_for('ACK,S9F,OFF',timeout=4.0)
                        _write(ser,'S9F,STATUS')
                        raw=board.wait_for('S9FSTAT,',timeout=4.0)
                        print('Stage9F status:',raw)
                        from guard_status import save_status as save_s9f
                        save_s9f(raw,args.out.with_name(args.out.stem+'_stage9f.json'))
                        stage9f_status_valid=True
                    if args.stage11 == 'on':
                        _write(ser,'S11,STATUS')
                        s11status=board.wait_for('S11STAT,',timeout=4.0)
                        print('Stage11 hardware status:',s11status)
                        import json
                        args.out.with_name(args.out.stem+'_stage11.json').write_text(
                           json.dumps({'raw_status':s11status,'rate_policy':args.rate,
                           'warning':'Motor host still advances a nominal 20ms step per CMD; do not claim period-accurate HIL plant.'},indent=2)+'\n')
                    if args.stage9c == 'on':
                        _write(ser,'S9C,OFF')
                        board.wait_for('ACK,S9C,OFF',timeout=4.0)
                        _write(ser,'S9C,STATUS')
                        s9cline=board.wait_for('S9CSTAT,',timeout=4.0)
                        print('Stage9C status:',s9cline)
                        from guidance_status import save_status as save_s9c_status
                        save_s9c_status(s9cline,args.out.with_name(args.out.stem+'_stage9c.json'))
                        stage9c_status_valid=True
                    if args.stage9_shadow == 'on':
                        _write(ser,'S9SH,OFF')
                        board.wait_for('ACK,S9SH,OFF',timeout=4.0)
                        _write(ser,'S9SH,STATUS')
                        s9line=board.wait_for('S9SHSTAT,',timeout=4.0)
                        print('Stage9 shadow hardware status:',s9line)
                        from shadow_detector_status import save_status
                        save_status(s9line,args.out.with_name(args.out.stem+'_stage9_shadow.json'))
                        stage9_shadow_status_valid = True
                    if args.capture:
                        cap_file=args.out.with_name(args.out.stem+'_capture.csv')
                        status, meta=board.download_capture(cap_file)
                        print('Frozen scheduling capture:', status)
                        print('Full capture records:',cap_file)
                        print('Capture metadata:',meta)
                    trace = board.get_trace_status()
                    print('Deferred trace status:', trace)
                    drops = [int(x) for x in trace.split(',')[1:]]
                    if any(drops): print('WARNING: trace/line/event loss occurred; timing audit may be incomplete')
                except Exception as ex:
                    print('Could not read hardware rate status:', ex, file=sys.stderr)
                if args.stage9_shadow == 'on':
                    try:
                        _write(ser, 'S9SH,OFF')
                        board.wait_for('ACK,S9SH,OFF',timeout=4.0)
                    except Exception as ex:
                        print('WARNING: Stage9 shadow OFF cleanup failed:', ex, file=sys.stderr)
                if args.stage11 == 'on':
                    try:
                        _write(ser,'S11,OFF')
                        print('Stage11 cleanup:',board.wait_for('ACK,S11,OFF',timeout=4.0))
                    except Exception as ex:
                        print('WARNING: Stage11 OFF cleanup failed:',ex,file=sys.stderr)
                if args.stage9f == 'on':
                    try:
                        _write(ser,'S9F,OFF')
                        board.wait_for('ACK,S9F,OFF',timeout=4.0)
                    except Exception as ex:
                        print('WARNING: Stage9F OFF cleanup failed:',ex,file=sys.stderr)
                if args.stage9c == 'on':
                    try:
                        _write(ser,'S9C,OFF')
                        board.wait_for('ACK,S9C,OFF',timeout=4.0)
                    except Exception as ex:
                        print('WARNING: Stage9C OFF cleanup failed:',ex,file=sys.stderr)
                try:
                    print('Cleanup:', board.set_attack(False))
                except Exception as ex:
                    print('Could not disable attack during cleanup:', ex, file=sys.stderr)
            ser.close()

    print('\nStage 5D TaskShuffler:', 'ARMED' if args.attack == 'on' else 'PASSIVE')
    with cfg_path.open('w', newline='', encoding='utf8') as cfg_file:
        cfg_writer = csv.writer(cfg_file)
        cfg_writer.writerow(['hyperperiod_number','control_period_ms','rate_mode','planned_us'])
        cfg_writer.writerows(board.config_events)
    with ts_path.open('w', newline='', encoding='utf8') as ts_file:
        ts_writer=csv.writer(ts_file)
        ts_writer.writerow(['decision','selected_idx','ready_mask','candidates_mask',
                            'grant_us','elapsed_us'])
        ts_writer.writerows(board.ts_decisions)
    print('TaskShuffler requested:', args.ts)
    print('Sampled TaskShuffler decisions:', len(board.ts_decisions))
    print('Rate requested:', args.rate)
    print('Observed rate configurations:', len(board.config_events))
    print('Samples:',round(args.duration/DT))
    print('Confirmed on-device actuator overwrites:',successful)
    print('On-board ATK events received:',len(board.attack_events))
    print('Valid transmitted control jobs (measured AEWs):',len(board.aew_durations_us))
    print('TX-consumed corrupted jobs:',board.tx_attacks)
    print('Observed corrupt fraction per valid transmitted job:',
          f'{board.tx_attacks/len(board.aew_durations_us):.3f}'
          if board.aew_durations_us else '-')
    print('Median measured AEW (ms):',
          round(statistics.median(board.aew_durations_us)/1000,3)
          if board.aew_durations_us else '-')
    print('Measured AEW range (ms):',
          (round(min(board.aew_durations_us)/1000,3),
           round(max(board.aew_durations_us)/1000,3))
          if board.aew_durations_us else '-')
    print('Attacker-only OWN execution records:',board.own_jobs)
    print('On-board LAD schedule summaries:',board.ladder_updates)
    print('Attacker predicted-window attempts:',board.attempts)
    print('Attacker predicted-window successes:',board.attempt_success)
    print('Final inferred (ready, phase_us, own_jobs):',board.latest_inference)
    print('Telemetry parse errors:',board.line_errors)
    print('Detector alarm samples:',alarms)
    print('Observed CONTROL deadline misses:',board.control_misses)
    print('Observed UNTRUSTED deadline misses:',board.untrusted_misses)
    print('Median host round-trip (ms):',round(statistics.median(rtt),2) if rtt else '-')
    print('Data:',args.out)
    if args.stage9_shadow == 'on' and not stage9_shadow_status_valid:
        raise RuntimeError('Stage9 shadow status not verified; trial INVALID')
    if args.stage9f == 'on' and not stage9f_status_valid:
        raise RuntimeError('Stage9F status not verified; run INVALID')
    if args.stage9c == 'on' and not stage9c_status_valid:
        raise RuntimeError('Stage9C status not verified; run INVALID')
    plot_results(args.out)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--port',default='/dev/ttyACM0')
    ap.add_argument('--baud',type=int,default=115200)
    ap.add_argument('--duration',type=float,default=18.0)
    ap.add_argument('--attack',choices=['off','on'],required=True)
    ap.add_argument('--ts',choices=['off','on'],required=True, help='TaskShuffler OFF=highest-priority, ON=bounded-inversion random')
    ap.add_argument('--rate',choices=['20','25','ALT'],required=True, help='20/25 fixed, or ALT alternating at 600ms boundaries')
    ap.add_argument('--attacker-prior',choices=['20','25'],default='20',
                    help='Attacker\'s hypothesized CONTROL period in ms (default: 20); '
                         'set to 25 for a period-aligned attack')
    ap.add_argument('--window-start',type=float,default=6.0)
    ap.add_argument('--window-end',type=float,default=17.0)
    ap.add_argument('--stage9f',choices=['off','on'],default='off',
                    help='Legacy model guidance and cooperative buffer guard')
    ap.add_argument('--s9f-mode',choices=['both','guide','guard'],default='both',
                    help='Legacy guidance/guard mode: both (default), '
                         'guidance only, or cooperative buffer guard only')
    ap.add_argument('--stage11-ablation',choices=['guide','guard','both'],default='both',
                    help='Independent guidance and guard; requires --stage11 on. NONE uses --stage11 off.')
    ap.add_argument('--stage11',choices=['off','on'],default='off',
                    help='Experimental multi-rate offline bank guidance; not certified HIL')
    ap.add_argument('--stage9c',choices=['off','on'],default='off',
                    help='EXPERIMENTAL unqualified 25ms guarded worker-choice guide')
    ap.add_argument('--stage9-shadow',choices=['off','on'],default='off',
                    help='Non-enforcing 25ms phase observation')
    ap.add_argument('--capture',action='store_true',help='Record and download one complete 600ms hardware frame')
    ap.add_argument('--capture-at',type=float,default=2.0,help='Simulated seconds before capture arm (>=0)')
    ap.add_argument('--out',type=Path,required=True)
    args = ap.parse_args()
    try:
        run(args)
    except (ValueError,RuntimeError,TimeoutError,KeyboardInterrupt,OSError) as ex:
        print(f'RUN FAILED: {ex}',file=sys.stderr)
        print('Any partial samples:',args.out,file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
