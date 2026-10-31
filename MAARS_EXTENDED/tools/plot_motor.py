#!/usr/bin/env python3
import argparse
import csv
from pathlib import Path
import matplotlib.pyplot as plt


def plot(csv_path: Path, image_path: Path | None = None):
    with csv_path.open(newline='', encoding='utf8') as f:
        records = list(csv.DictReader(f))
    if not records:
        raise SystemExit(f'No rows in {csv_path}')
    def data(field):
        return [float(r[field]) for r in records]
    t = data('time_s')
    fig, axes = plt.subplots(3, 1, figsize=(11, 8), sharex=True)
    axes[0].plot(t, data('omega_rad_s'), label='Motor speed (Python plant)')
    axes[0].plot(t, data('reference_rad_s'), '--', label='Target')
    axes[0].set_ylabel('Angular speed (rad/s)')
    axes[0].legend(loc='best')
    axes[0].grid(alpha=.25)
    axes[1].plot(t, data('voltage_v'), label='Voltage (ESP32 PI or Python demo)')
    axes[1].set_ylabel('Voltage (V)')
    axes[1].legend(loc='best')
    axes[1].grid(alpha=.25)
    axes[2].plot(t, data('load_torque_nm'), label='Applied load torque')
    axes[2].set_ylabel('Load torque (N m)')
    axes[2].set_xlabel('Simulated plant time (s)')
    axes[2].legend(loc='best')
    axes[2].grid(alpha=.25)
    mode = records[0].get('mode', 'unknown')
    fig.suptitle('DC motor control — ' + ('PYTHON-ONLY DEMO' if mode == 'demo' else 'ESP32-S3 in loop'))
    fig.tight_layout()
    image_path = image_path or csv_path.with_suffix('.png')
    image_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(image_path, dpi=160)
    plt.close(fig)
    print(f'Saved plot: {image_path}')


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('input', type=Path)
    ap.add_argument('--output', type=Path)
    args = ap.parse_args()
    plot(args.input, args.output)
