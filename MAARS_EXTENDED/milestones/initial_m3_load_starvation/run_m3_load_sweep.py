import os
#!/usr/bin/env python3
"""
MAARS Milestone 3: SchedGuard CPU Starvation vs Adaptive Detector-Triggered Guard
Sweeps synthetic CPU load (50%, 75%, 90%) across:
  1. ALWAYS_ON GUARD (Static SchedGuard baseline)
  2. ADAPTIVE GUARD (Detector-triggered dynamic guard)
  3. GUIDE_ONLY (Baseline MAARS without guard)
Measures:
  - Untrusted Worker WCRT (Worst-Case Response Time in us)
  - Untrusted Worker Deadline Miss Count & Rate (%)
  - Actuation Command Corruption Rate (%)
  - Motor Speed Tracking RMSE (rad/s)
"""

import sys
import time
import json
import csv
from pathlib import Path
import serial
import numpy as np
import matplotlib.pyplot as plt

# Motor Model Parameters (Table 12.1)
R, L = 2.0, 0.02
Kt, Ke = 0.1, 0.1
J, b = 0.002, 0.001
V_LIMIT = 12.0

class DCMotorSim:
    def __init__(self):
        self.i = 0.0
        self.w = 0.0
        
    def step_rk4(self, u, dt, load=0.0):
        u = max(-V_LIMIT, min(V_LIMIT, u))
        def deriv(curr, speed):
            di = (u - R * curr - Ke * speed) / L
            dw = (Kt * curr - b * speed - load) / J
            return di, dw
            
        h = dt / 5.0
        for _ in range(5):
            k1_i, k1_w = deriv(self.i, self.w)
            k2_i, k2_w = deriv(self.i + 0.5*h*k1_i, self.w + 0.5*h*k1_w)
            k3_i, k3_w = deriv(self.i + 0.5*h*k2_i, self.w + 0.5*h*k2_w)
            k4_i, k4_w = deriv(self.i + h*k3_i, self.w + h*k3_w)
            self.i += (h / 6.0) * (k1_i + 2*k2_i + 2*k3_i + k4_i)
            self.w += (h / 6.0) * (k1_w + 2*k2_w + 2*k3_w + k4_w)
        return self.w

class ChiSquareDetector:
    """
    Host-side Anomaly / Residual Detector.
    Tracks speed deviation from nominal expected plant speed.
    Trips alarm when cumulative chi-square residual exceeds threshold.
    """
    def __init__(self, window_size=5, threshold=9.21, sigma=0.5):
        self.window = []
        self.window_size = window_size
        self.threshold = threshold
        self.sigma = sigma
        self.in_alarm = False
        self.nominal_counter = 0

    def update(self, measured_speed, ref_speed):
        res = (measured_speed - ref_speed) / self.sigma
        res_sq = res * res
        self.window.append(res_sq)
        if len(self.window) > self.window_size:
            self.window.pop(0)
            
        stat = sum(self.window)
        if stat > self.threshold:
            self.in_alarm = True
            self.nominal_counter = 0
        else:
            self.nominal_counter += 1
            if self.nominal_counter > 20: # 20 consecutive nominal steps to clear
                self.in_alarm = False
                
        return self.in_alarm, stat

def run_single_m3_trial(port, condition_mode, load_pct, duration_s=10.0):
    """
    condition_mode: "ALWAYS_ON", "ADAPTIVE", or "GUIDE_ONLY"
    load_pct: 50, 75, 90
    """
    print(f"\n==================================================================")
    print(f"M3 RUN: Defense Mode = {condition_mode} | CPU Load = {load_pct}%")
    print(f"==================================================================")
    
    ser = serial.Serial(port, 115200, timeout=0.1)
    time.sleep(0.8)
    ser.reset_input_buffer()
    ser.reset_output_buffer()
    
    def send_cmd(cmd_str):
        ser.write((cmd_str + "\n").encode())
        time.sleep(0.04)

    # Base configuration
    send_cmd("ATTACK,OFF")
    send_cmd("TS,ON")
    send_cmd("S11,OFF")
    send_cmd("CHI8,SHADOW")
    send_cmd("RATE,ALT")
    send_cmd("ATKPRIOR,ADAPTIVE")
    send_cmd(f"LOAD,{load_pct}")
    send_cmd("S11,ON")
    
    if condition_mode == "ALWAYS_ON":
        send_cmd("S11,MODE,BOTH") # Guard is always active
    elif condition_mode == "ADAPTIVE":
        send_cmd("S11,MODE,GUIDE") # Guard starts nominal; triggered by detector
    else: # GUIDE_ONLY
        send_cmd("S11,MODE,GUIDE") # No guard
        
    send_cmd("ATTACK,ON")
    
    time.sleep(0.2)
    ser.reset_input_buffer()
    
    motor = DCMotorSim()
    detector = ChiSquareDetector(window_size=4, threshold=8.0, sigma=0.8)
    ref_speed = 80.0
    measured_speed = 0.0
    
    commands_log = []
    resp_log = []
    detector_events = []
    
    t_start = time.time()
    next_send_time = t_start
    sensor_dt = 0.020
    seq = 0
    currently_alerted = False
    
    while time.time() - t_start < duration_s:
        now = time.time()
        if now >= next_send_time:
            # Send sensor update
            sensor_msg = f"S,{seq},{measured_speed:.4f}\n"
            ser.write(sensor_msg.encode())
            seq += 1
            next_send_time += sensor_dt
            
        # Read incoming lines
        while ser.in_waiting > 0:
            raw_line = ser.readline().decode('utf-8', errors='replace').strip()
            if not raw_line:
                continue
                
            if raw_line.startswith("RESP,"):
                # RESP,<mode>,<load>,UNTRUSTED,<planned_us>,<resp_us>,<deadline_us>,<miss>
                parts = raw_line.split(',')
                if len(parts) >= 8:
                    planned_us = int(parts[4])
                    resp_us = int(parts[5])
                    deadline_us = int(parts[6])
                    miss = int(parts[7])
                    resp_log.append({
                        "t_wall": time.time() - t_start,
                        "planned_us": planned_us,
                        "resp_us": resp_us,
                        "deadline_us": deadline_us,
                        "miss": miss
                    })
                    
            elif raw_line.startswith("ACT,"):
                # ACT,seq,computed_v,applied_v,attacked
                parts = raw_line.split(',')
                if len(parts) >= 5:
                    c_seq = int(parts[1])
                    u_comp = float(parts[2])
                    u_app = float(parts[3])
                    attacked = int(parts[4])
                    is_corrupted = 1 if (attacked == 1 or abs(u_app - u_comp) > 1.0) else 0
                    
                    measured_speed = motor.step_rk4(u_app, sensor_dt)
                    
                    # Run host detector
                    in_alarm, stat = detector.update(measured_speed, ref_speed)
                    
                    if condition_mode == "ADAPTIVE":
                        if in_alarm and not currently_alerted:
                            ser.write(b"S11,ALERT,CONTROL\n")
                            currently_alerted = True
                            detector_events.append({"t": time.time() - t_start, "type": "ALERT_TRIGGERED", "stat": stat})
                            # print(f"  [DETECTOR] Trip alert! Speed={measured_speed:.2f}, stat={stat:.2f}")
                        elif not in_alarm and currently_alerted:
                            ser.write(b"S11,ALERT,CLEAR\n")
                            currently_alerted = False
                            detector_events.append({"t": time.time() - t_start, "type": "ALERT_CLEARED", "stat": stat})
                            # print(f"  [DETECTOR] Clear alert. Speed={measured_speed:.2f}")
                            
                    commands_log.append({
                        "t_wall": time.time() - t_start,
                        "seq": c_seq,
                        "u_applied": u_app,
                        "u_computed": u_comp,
                        "corrupted": is_corrupted,
                        "speed": measured_speed
                    })
                    
        time.sleep(0.001)
        
    send_cmd("ATTACK,OFF")
    if condition_mode == "ADAPTIVE" and currently_alerted:
        send_cmd("S11,ALERT,CLEAR")
    ser.close()
    
    # Process Metrics
    total_cmds = len(commands_log)
    corrupt_cmds = sum(c["corrupted"] for c in commands_log)
    corrupt_rate = (corrupt_cmds / max(1, total_cmds)) * 100.0
    
    speed_errors = [(c["speed"] - ref_speed)**2 for c in commands_log if c["t_wall"] > 2.0] # Post warm-up
    rmse = np.sqrt(np.mean(speed_errors)) if len(speed_errors) > 0 else 0.0
    
    resp_times = [r["resp_us"] for r in resp_log]
    wcrt_us = max(resp_times) if len(resp_times) > 0 else 0
    mean_resp_us = np.mean(resp_times) if len(resp_times) > 0 else 0
    deadline_misses = sum(r["miss"] for r in resp_log)
    total_jobs = len(resp_log)
    miss_rate = (deadline_misses / max(1, total_jobs)) * 100.0
    
    print(f"\nRESULTS [{condition_mode} | Load {load_pct}%]:")
    print(f"  Untrusted Jobs:      {total_jobs}")
    print(f"  Deadline Misses:     {deadline_misses} ({miss_rate:.2f}%)")
    print(f"  Mean Resp Time:      {mean_resp_us:.1f} us")
    print(f"  WCRT:                {wcrt_us} us")
    print(f"  Actuation Commands:  {total_cmds}")
    print(f"  Corrupted Commands:  {corrupt_cmds} ({corrupt_rate:.1f}%)")
    print(f"  Speed Tracking RMSE: {rmse:.2f} rad/s")
    print(f"  Detector Alerts:     {len(detector_events)}")
    
    return {
        "mode": condition_mode,
        "load_pct": load_pct,
        "total_jobs": total_jobs,
        "deadline_misses": deadline_misses,
        "miss_rate_pct": miss_rate,
        "mean_resp_us": mean_resp_us,
        "wcrt_us": wcrt_us,
        "total_commands": total_cmds,
        "corrupted_commands": corrupt_cmds,
        "corruption_rate_pct": corrupt_rate,
        "rmse_rad_s": rmse,
        "detector_alerts": detector_events,
        "resp_log": resp_log,
        "commands_log": commands_log
    }

def main():
    import argparse
    parser = argparse.ArgumentParser(description="M3 CPU Load Sweep Experiment")
    parser.add_argument("--port", default=os.environ.get("PORT", "COM7"), help="Serial port")
    parser.add_argument("--duration", type=float, default=9.0, help="Duration per trial in seconds")
    parser.add_argument("--data-dir", default=None, help="Directory to save CSVs")
    parser.add_argument("--reports-dir", default=None, help="Directory to save summary and plots")
    args = parser.parse_args()

    port = args.port
    out_dir = Path(__file__).resolve().parent
    data_dir = Path(args.data_dir) if args.data_dir else out_dir / "data"
    reports_dir = Path(args.reports_dir) if args.reports_dir else out_dir / "reports"
    dur = args.duration
    data_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)
    
    modes = ["ALWAYS_ON", "ADAPTIVE", "GUIDE_ONLY"]
    loads = [50, 75, 90]
    
    all_results = []
    
    print("==================================================================")
    print("STARTING MILESTONE 3: 3x3 LOAD SWEEP & CPU STARVATION EVALUATION")
    print("==================================================================")
    
    for mode in modes:
        for load in loads:
            res = run_single_m3_trial(port, mode, load, duration_s=dur)
            all_results.append(res)
            
            # Save raw trace CSV
            csv_path = data_dir / f"m3_raw_{mode}_load{load}.csv"
            with open(csv_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["t_wall", "planned_us", "resp_us", "deadline_us", "miss"])
                for r in res["resp_log"]:
                    writer.writerow([r["t_wall"], r["planned_us"], r["resp_us"], r["deadline_us"], r["miss"]])
                    
            time.sleep(1.5)
            
    # Serialize summary JSON
    summary_path = reports_dir / "m3_summary.json"
    clean_summary = []
    for r in all_results:
        clean_summary.append({
            "mode": r["mode"],
            "load_pct": r["load_pct"],
            "total_jobs": r["total_jobs"],
            "deadline_misses": r["deadline_misses"],
            "miss_rate_pct": round(r["miss_rate_pct"], 2),
            "mean_resp_us": round(r["mean_resp_us"], 1),
            "wcrt_us": r["wcrt_us"],
            "total_commands": r["total_commands"],
            "corrupted_commands": r["corrupted_commands"],
            "corruption_rate_pct": round(r["corruption_rate_pct"], 2),
            "rmse_rad_s": round(r["rmse_rad_s"], 2)
        })
        
    with open(summary_path, 'w') as f:
        json.dump(clean_summary, f, indent=2)
    print(f"\nSaved summary to: {summary_path}")
    
    # Generate 3-Panel Publication Plot
    generate_m3_plots(clean_summary, reports_dir)

def generate_m3_plots(summary_data, reports_dir):
    plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
    fig, axes = plt.subplots(1, 3, figsize=(16, 5))
    
    loads = [50, 75, 90]
    modes = ["ALWAYS_ON", "ADAPTIVE", "GUIDE_ONLY"]
    colors = {"ALWAYS_ON": "#d9534f", "ADAPTIVE": "#2ca02c", "GUIDE_ONLY": "#1f77b4"}
    markers = {"ALWAYS_ON": "s", "ADAPTIVE": "o", "GUIDE_ONLY": "^"}
    labels = {
        "ALWAYS_ON": "Always-On SchedGuard",
        "ADAPTIVE": "Adaptive Guard (Ours)",
        "GUIDE_ONLY": "MAARS Guide Only"
    }
    
    # Panel 1: WCRT (us) vs CPU Load
    ax1 = axes[0]
    for m in modes:
        wcrt_vals = [next(item["wcrt_us"] for item in summary_data if item["mode"] == m and item["load_pct"] == l) for l in loads]
        ax1.plot(loads, wcrt_vals, marker=markers[m], color=colors[m], label=labels[m], linewidth=2.2, markersize=8)
    ax1.axhline(50000, color='gray', linestyle='--', linewidth=1.5, label='Untrusted Deadline (50ms)')
    ax1.set_title("Untrusted Task WCRT vs CPU Load", fontsize=12, fontweight='bold')
    ax1.set_xlabel("Synthetic CPU Load (%)", fontsize=11)
    ax1.set_ylabel("WCRT (microseconds)", fontsize=11)
    ax1.set_xticks(loads)
    ax1.legend(loc='upper left', fontsize=9)
    ax1.grid(True, alpha=0.3)
    
    # Panel 2: Deadline Misses vs CPU Load
    ax2 = axes[1]
    for m in modes:
        miss_vals = [next(item["deadline_misses"] for item in summary_data if item["mode"] == m and item["load_pct"] == l) for l in loads]
        ax2.plot(loads, miss_vals, marker=markers[m], color=colors[m], label=labels[m], linewidth=2.2, markersize=8)
    ax2.set_title("Untrusted Deadline Misses vs CPU Load", fontsize=12, fontweight='bold')
    ax2.set_xlabel("Synthetic CPU Load (%)", fontsize=11)
    ax2.set_ylabel("Total Deadline Misses (Count)", fontsize=11)
    ax2.set_xticks(loads)
    ax2.legend(loc='upper left', fontsize=9)
    ax2.grid(True, alpha=0.3)
    
    # Panel 3: Corruption Rate vs CPU Load
    ax3 = axes[2]
    for m in modes:
        corr_vals = [next(item["corruption_rate_pct"] for item in summary_data if item["mode"] == m and item["load_pct"] == l) for l in loads]
        ax3.plot(loads, corr_vals, marker=markers[m], color=colors[m], label=labels[m], linewidth=2.2, markersize=8)
    ax3.set_title("Attack Corruption Rate vs CPU Load", fontsize=12, fontweight='bold')
    ax3.set_xlabel("Synthetic CPU Load (%)", fontsize=11)
    ax3.set_ylabel("Corruption Rate (%)", fontsize=11)
    ax3.set_xticks(loads)
    ax3.set_ylim(-2, 40)
    ax3.legend(loc='center right', fontsize=9)
    ax3.grid(True, alpha=0.3)
    
    plt.tight_layout()
    chart_path = reports_dir / "m3_tradeoff_curves.png"
    plt.savefig(chart_path, dpi=300)
    plt.close()
    print(f"Generated comparison figure: {chart_path}")

if __name__ == "__main__":
    main()
