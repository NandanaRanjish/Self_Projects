#!/usr/bin/env python3
import argparse
import csv
from pathlib import Path
import sys
import time

from motor_model import DT, DemoPI, Motor, disturbance_at, reference_at
from plot_motor import plot

LOG_FIELDS = [
    'mode', 'seq', 'time_s', 'reference_rad_s', 'omega_rad_s',
    'voltage_v', 'current_a', 'load_torque_nm', 'rtt_ms',
    'esp_planned_us', 'esp_started_us', 'esp_finished_us', 'deadline_miss',
]
EVT_FIELDS = [
    'task', 'job', 'period_ms', 'planned_us', 'release_us',
    'start_us', 'finish_us', 'miss'
]


def _write(ser, line):
    ser.write((line + '\n').encode('ascii'))
    ser.flush()


class Board:
    def __init__(self, ser, evt_writer):
        self.ser = ser
        self.evt_writer = evt_writer
        self.last_stat = None

    def _next(self, seconds):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            raw = self.ser.readline()
            if not raw:
                continue
            line = raw.decode('utf-8', errors='replace').strip()
            if line.startswith('EVT,'):
                fields = line.split(',')
                if len(fields) == 9:
                    try:
                        self.evt_writer.writerow([fields[1]] + [int(v) for v in fields[2:]])
                    except ValueError:
                        pass
                continue
            if line.startswith('STAT,'):
                self.last_stat = line
                continue
            if line.startswith(('PONG,', 'READY,', 'CMD,', 'ACK,', 'ERR,')):
                return line
        raise TimeoutError('No valid firmware reply. Check primary USB console / serial port.')

    def wait_for(self, prefix: str, timeout: float = 3.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                line = self._next(min(0.5, max(.01, deadline-time.monotonic())))
            except TimeoutError:
                continue
            if line.startswith(prefix):
                return line
            if line.startswith('ERR,'):
                raise RuntimeError(f'Firmware rejected input: {line}')
        raise TimeoutError(f'Did not receive {prefix!r} within {timeout:.1f} seconds')

    def handshake(self):
        print('Opening serial connection; waiting for ESP32-S3 PONG...')
        for attempt in range(15):
            _write(self.ser, 'PING')
            try:
                response = self.wait_for('PONG,MAARS_STAGE2', 0.6)
                print('Connected:', response)
                break
            except TimeoutError:
                if attempt == 14:
                    raise TimeoutError(
                        'No PONG after ~9 seconds. Check USB Serial/JTAG as PRIMARY '
                        'console via idf.py menuconfig and close idf.py monitor.')
        _write(self.ser, 'RESET')
        self.wait_for('ACK,RESET')
        print('PI state reset.')

    def set_reference(self, value: float):
        _write(self.ser, f'R,{value:.3f}')
        self.wait_for('ACK,R,')

    def calculate(self, seq: int, omega: float):
        start = time.monotonic_ns()
        _write(self.ser, f'S,{seq},{omega:.5f}')
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            try:
                answer = self._next(min(.5, max(.01, deadline - time.monotonic())))
            except TimeoutError:
                continue
            if answer.startswith('ERR,'):
                raise RuntimeError(f'Bad serial request: {answer}')
            if not answer.startswith('CMD,'):
                continue
            cells = answer.split(',')
            if len(cells) != 9:
                continue
            try:
                result = {
                    'seq': int(cells[1]),
                    'reference_rad_s': float(cells[2]),
                    'measured_rad_s': float(cells[3]),
                    'voltage_v': float(cells[4]),
                    'esp_planned_us': int(cells[5]),
                    'esp_started_us': int(cells[6]),
                    'esp_finished_us': int(cells[7]),
                    'deadline_miss': int(cells[8]),
                    'rtt_ms': (time.monotonic_ns()-start)/1e6,
                }
            except ValueError:
                continue
            if result['seq'] == seq:
                return result
            print(f'Ignored CMD from different job {result["seq"]} (expected {seq})')
        raise TimeoutError(
            f'No CMD for S,{seq}. Check primary console, serial reliability, '
            'or firmware reset. Try tools/probe_serial.py.')


def run_demo(motor: Motor, csv_writer, duration: float):
    pi = DemoPI()
    for seq in range(round(duration / DT)):
        t = seq * DT
        ref = reference_at(t)
        speed, current = motor.omega, motor.current
        voltage = pi.update(ref, speed)
        csv_writer.writerow([
            'demo', seq, f'{t:.3f}', ref, speed, voltage, current,
            disturbance_at(t), '', '', '', '', 0,
        ])
        motor.step(voltage, dt=DT, load=disturbance_at(t))
    print(f'Python-only check complete: final speed {motor.omega:.2f} rad/s')


def run_hardware(motor: Motor, csv_writer, event_writer, duration, port, baud):
    try:
        import serial
    except ImportError as exc:
        raise SystemExit('pyserial missing: pip install -r tools/requirements.txt') from exc

    with serial.Serial(port, baudrate=baud, timeout=0.12, write_timeout=1.0) as ser:
        board = Board(ser, event_writer)
        board.handshake()
        previous_ref = None
        for seq in range(round(duration / DT)):
            t = seq * DT
            ref = reference_at(t)
            if ref != previous_ref:
                board.set_reference(ref)
                print(f'Time {t:4.2f} s: setpoint -> {ref:.1f} rad/s')
                previous_ref = ref
            speed, current = motor.omega, motor.current
            result = board.calculate(seq, speed)
            voltage = result['voltage_v']
            csv_writer.writerow([
                'esp32', seq, f'{t:.3f}', result['reference_rad_s'],
                speed, voltage, current, disturbance_at(t),
                f'{result["rtt_ms"]:.4f}', result['esp_planned_us'],
                result['esp_started_us'], result['esp_finished_us'],
                result['deadline_miss'],
            ])
            motor.step(voltage, dt=DT, load=disturbance_at(t))
            if seq % 50 == 0:
                print(f't={t:5.2f}s | speed={speed:7.2f} rad/s | '
                      f'voltage={voltage:6.2f} V | '
                      f'USB roundtrip={result["rtt_ms"]:.1f} ms')
        print(f'Hardware-in-loop simulation complete: final speed {motor.omega:.2f} rad/s')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument('--port', help='ESP32 console port, e.g. /dev/ttyACM0')
    mode.add_argument('--demo', action='store_true', help='Python-only test (not hardware)')
    ap.add_argument('--duration', type=float, default=10.0)
    ap.add_argument('--baud', type=int, default=115200)
    ap.add_argument('--out', type=Path, default=Path('traces/stage2_motor.csv'))
    args = ap.parse_args()
    if not 0.02 <= args.duration <= 120.0:
        ap.error('--duration must be between 0.02 and 120 seconds')

    args.out.parent.mkdir(parents=True, exist_ok=True)
    event_path = args.out.with_name(args.out.stem + '_events.csv')
    motor = Motor()
    try:
        with args.out.open('w', newline='', encoding='utf-8') as data_file, \
             event_path.open('w', newline='', encoding='utf-8') as evt_file:
            writer = csv.writer(data_file)
            writer.writerow(LOG_FIELDS)
            event_writer = csv.writer(evt_file)
            event_writer.writerow(EVT_FIELDS)
            if args.demo:
                run_demo(motor, writer, args.duration)
            else:
                run_hardware(motor, writer, event_writer,
                             args.duration, args.port, args.baud)
    except (KeyboardInterrupt, TimeoutError, OSError, RuntimeError) as exc:
        print(f'\nStopped early: {exc}', file=sys.stderr)
        print(f'Partial data saved to {args.out}', file=sys.stderr)
    try:
        with args.out.open(newline='', encoding='utf-8') as f:
            if not next(csv.DictReader(f), None):
                print('No motor samples were recorded; plotting skipped.')
                return
        plot(args.out)
    except Exception as exc:
        print(f'Could not create plot: {exc}', file=sys.stderr)
    print(f'Motor log: {args.out}')
    if not args.demo:
        print(f'Downsampled ESP32 task trace: {event_path}')


if __name__ == '__main__':
    main()
