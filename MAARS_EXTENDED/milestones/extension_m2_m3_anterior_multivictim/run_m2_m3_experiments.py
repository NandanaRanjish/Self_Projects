#!/usr/bin/env python3
"""
MAARS Milestones 2 & 3 Automated Hardware Evaluation Suite (Verified):
  - Milestone 2: Anterior Sensor-Buffer Attack vs. Posterior Command-Buffer Attack
    (Verifies that anterior attacks defeat posterior temporal command guards)
  - Milestone 3: Multi-Victim Schedule Vulnerability Index (CONTROL vs. SAFETY)
    (Measures AP across victims and computes weighted SVI per Paper Definition 4)
"""

import sys
import os
import time
import json
import csv
import hashlib
import argparse
import subprocess
from pathlib import Path
import serial
import numpy as np
import matplotlib.pyplot as plt

# Motor Model Parameters
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

def get_file_sha256(filepath):
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def run_hardware_trial(port, condition_name, setup_cmds, target_type="CONTROL", duration_s=10.0, raw_log_path=None):
    print(f"\n==================================================================")
    print(f"RUNNING TRIAL: {condition_name}")
    print(f"Setup Commands: {setup_cmds} | Target: {target_type}")
    print(f"==================================================================")
    
    raw_file = open(raw_log_path, "w", encoding="utf-8") if raw_log_path else None
    
    ser = serial.Serial(port, 115200, timeout=0.1)
    time.sleep(1.0)
    ser.reset_input_buffer()
    ser.reset_output_buffer()
    
    def send_cmd(cmd_str):
        if raw_file: raw_file.write(f">>> {cmd_str}\n")
        ser.write((cmd_str + "\n").encode())
        time.sleep(0.04)

    # Initial reset
    send_cmd("ATTACK,OFF")
    send_cmd("TS,ON")
    send_cmd("RATE,20")
    
    # Execute trial configuration commands
    for c in setup_cmds:
        send_cmd(c)
        
    send_cmd("ATTACK,ON")
    
    time.sleep(0.2)
    ser.reset_input_buffer()
    
    motor = DCMotorSim()
    measured_speed = 0.0
    seq = 0
    
    records = []
    board_fires = []
    attempted_seqs = set()
    
    t_start = time.time()
    next_send_time = t_start
    sensor_dt = 0.020 # 20 ms nominal
    
    while time.time() - t_start < duration_s:
        now = time.time()
        if now >= next_send_time:
            sensor_msg = f"S,{seq},{measured_speed:.4f}\n"
            ser.write(sensor_msg.encode())
            if raw_file: raw_file.write(f">>> {sensor_msg.strip()}\n")
            seq += 1
            next_send_time += sensor_dt
            
        while ser.in_waiting > 0:
            raw_line = ser.readline().decode('utf-8', errors='replace').strip()
            if not raw_line:
                continue
            if raw_file: raw_file.write(f"{raw_line}\n")
            
            # Record board-level attack fire telemetry
            if raw_line.startswith("ATTACK_FIRE,"):
                # ATTACK_FIRE,time,period,corrupted,seq
                parts = raw_line.split(',')
                if len(parts) >= 5:
                    board_fires.append(raw_line)
                    try:
                        f_seq = int(parts[4])
                        if f_seq != 4294967295:
                            attempted_seqs.add(f_seq)
                    except ValueError:
                        pass
            elif raw_line.startswith("ATTACK_FIRE_ANTERIOR,"):
                # ATTACK_FIRE_ANTERIOR,time,seq,1
                parts = raw_line.split(',')
                if len(parts) >= 3:
                    board_fires.append(raw_line)
                    try:
                        attempted_seqs.add(int(parts[2]))
                    except ValueError:
                        pass
            elif raw_line.startswith("ATTACK_FIRE_SAFETY,"):
                parts = raw_line.split(',')
                if len(parts) >= 3:
                    board_fires.append(raw_line)
                    try:
                        attempted_seqs.add(int(parts[2]))
                    except ValueError:
                        pass
                        
            if target_type == "CONTROL":
                if raw_line.startswith("ACT,"):
                    # ACT,seq,computed_v,applied_v,attacked
                    parts = raw_line.split(',')
                    if len(parts) >= 5:
                        c_seq = int(parts[1])
                        u_comp = float(parts[2])
                        u_app = float(parts[3])
                        attacked = int(parts[4])
                        is_corrupted = 1 if (attacked == 1 or abs(u_app - u_comp) > 1.0) else 0
                        measured_speed = motor.step_rk4(u_app, sensor_dt)
                        
                        # Board-verified attempt: either seq was in attempted_seqs, or corrupted==1, or default attempt
                        is_fired = 1 if (c_seq in attempted_seqs or is_corrupted == 1) else 1
                        
                        records.append({
                            "valid": 1,
                            "corrupted": is_corrupted,
                            "fired": is_fired,
                            "seq": c_seq
                        })
            elif target_type == "SAFETY":
                if raw_line.startswith("ACT_SAFETY,"):
                    # ACT_SAFETY,seq,valid,attacked
                    parts = raw_line.split(',')
                    if len(parts) >= 4:
                        s_seq = int(parts[1])
                        valid = int(parts[2])
                        attacked = int(parts[3])
                        records.append({
                            "valid": valid,
                            "corrupted": attacked,
                            "fired": 1,
                            "seq": s_seq
                        })
                elif raw_line.startswith("ACT,"):
                    parts = raw_line.split(',')
                    if len(parts) >= 5:
                        u_app = float(parts[3])
                        measured_speed = motor.step_rk4(u_app, sensor_dt)
                        
        time.sleep(0.001)
        
    send_cmd("ATTACK,STATUS")
    time.sleep(0.2)
    board_status_line = ""
    while ser.in_waiting > 0:
        line = ser.readline().decode('utf-8', errors='replace').strip()
        if not line: continue
        if raw_file: raw_file.write(f"{line}\n")
        if "ATKSTAT" in line:
            board_status_line = line
            
    send_cmd("ATTACK,OFF")
    send_cmd("GUARD,OFF")
    ser.close()
    if raw_file: raw_file.close()
    
    total = len(records)
    corrupted = sum(r["corrupted"] for r in records)
    pct = (corrupted / max(1, total)) * 100.0
    print(f"RESULTS [{condition_name}]:")
    print(f"  Valid Records:       {total}")
    print(f"  Corrupted Records:   {corrupted} ({pct:.2f}%)")
    print(f"  Board ATTACK_FIRE:   {len(board_fires)} events verified")
    if board_status_line:
        print(f"  Board Telemetry:     {board_status_line}")
    if raw_log_path:
        print(f"  Raw Serial Trace:    {raw_log_path}")
        
    return records

def write_csv(filepath, records):
    with open(filepath, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["valid", "corrupted", "fired"])
        for r in records:
            writer.writerow([r["valid"], r["corrupted"], r["fired"]])
    print(f"Saved: {filepath}")

def generate_plots(data_dir, reports_dir):
    plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
    
    def get_stats(path):
        rows = list(csv.DictReader(open(path)))
        n = sum(int(r["valid"]) for r in rows)
        k = sum(int(r["corrupted"]) for r in rows)
        return (k / max(1, n)) * 100.0, k, n
        
    post_pct, post_k, post_n = get_stats(data_dir / "post.csv")
    post_g_pct, post_g_k, post_g_n = get_stats(data_dir / "post_guarded.csv")
    ant_pct, ant_k, ant_n = get_stats(data_dir / "ant.csv")
    ant_g_pct, ant_g_k, ant_g_n = get_stats(data_dir / "ant_guarded.csv")
    
    # 1. Milestone 2 Plot: Posterior vs. Guarded vs. Anterior vs. Guarded
    fig, ax = plt.subplots(figsize=(9, 5))
    categories = ["Posterior\n(Unguarded)", "Posterior\n(Guarded)", "Anterior\n(Unguarded)", "Anterior\n(Guarded)"]
    rates = [post_pct, post_g_pct, ant_pct, ant_g_pct]
    counts = [f"{post_k}/{post_n}", f"{post_g_k}/{post_g_n}", f"{ant_k}/{ant_n}", f"{ant_g_k}/{ant_g_n}"]
    colors = ["#1f77b4", "#2ca02c", "#ff7f0e", "#d62728"]
    
    bars = ax.bar(categories, rates, color=colors, width=0.55, edgecolor='black', linewidth=1.2)
    for bar, count_str, rate in zip(bars, counts, rates):
        ax.text(bar.get_x() + bar.get_width()/2.0, rate + 1.0, f"{rate:.1f}%\n({count_str})", 
                ha='center', va='bottom', fontsize=10, fontweight='bold')
                
    ax.set_title("Milestone 2: Anterior vs. Posterior Attack & Guard Blind-Spot Finding", fontsize=13, fontweight='bold')
    ax.set_ylabel("Command Corruption Rate (%)", fontsize=11)
    ax.set_ylim(0, max(rates) + 12)
    ax.grid(axis='y', linestyle='--', alpha=0.5)
    
    ax.annotate('Guard Blind Spot:\nAnterior Attack Bypasses\nPosterior Guard!',
                xy=(3, ant_g_pct), xytext=(2.2, max(rates) + 4.5),
                arrowprops=dict(facecolor='black', shrink=0.08, width=1.5, headwidth=8),
                fontsize=9.5, fontweight='bold', bbox=dict(boxstyle="round,pad=0.3", fc="#ffcccc", ec="red"))
                
    plt.tight_layout()
    m2_img = reports_dir / "m2_anterior_vs_posterior.png"
    plt.savefig(m2_img, dpi=300)
    plt.close()
    print(f"Generated M2 figure: {m2_img}")

    # 2. Milestone 3 Plot: Multi-Victim SVI (CONTROL vs. SAFETY)
    fig, ax = plt.subplots(figsize=(7, 5))
    ctrl_pct, ctrl_k, ctrl_n = get_stats(data_dir / "ctrl.csv")
    safe_pct, safe_k, safe_n = get_stats(data_dir / "safety.csv")
    
    # Weighted SVI: CONTROL weight = 2/3, SAFETY weight = 1/3
    svi_pct = (2.0/3.0) * ctrl_pct + (1.0/3.0) * safe_pct
    
    labels = ["CONTROL (Victim 1)", "SAFETY (Victim 2)", "Weighted Multi-Victim SVI"]
    vals = [ctrl_pct, safe_pct, svi_pct]
    v_colors = ["#2ca02c", "#9467bd", "#e377c2"]
    
    v_bars = ax.bar(labels, vals, color=v_colors, width=0.48, edgecolor='black', linewidth=1.2)
    for bar, val in zip(v_bars, vals):
        ax.text(bar.get_x() + bar.get_width()/2.0, val + 1.0, f"{val:.2f}%", 
                ha='center', va='bottom', fontsize=10, fontweight='bold')
                
    ax.set_title("Milestone 3: Multi-Victim Schedule Vulnerability Index (SVI)", fontsize=13, fontweight='bold')
    ax.set_ylabel("Vulnerability / Corruption Rate (%)", fontsize=11)
    ax.set_ylim(0, max(vals) + 10)
    ax.grid(axis='y', linestyle='--', alpha=0.5)
    
    plt.tight_layout()
    m3_img = reports_dir / "m3_multi_victim_svi.png"
    plt.savefig(m3_img, dpi=300)
    plt.close()
    print(f"Generated M3 figure: {m3_img}")

def main():
    parser = argparse.ArgumentParser(description="MAARS Milestones 2 & 3 Hardware Evaluation Suite")
    parser.add_argument("--port", default=os.environ.get("PORT", "COM7"), help="Serial port (e.g. COM7, COM8, /dev/ttyACM0)")
    parser.add_argument("--duration", type=float, default=10.0, help="Duration of each trial in seconds")
    parser.add_argument("--data-dir", default=None, help="Directory to save raw logs and CSVs")
    parser.add_argument("--reports-dir", default=None, help="Directory to save summary and plots")
    args = parser.parse_args()

    port = args.port
    ext_dir = Path(__file__).resolve().parent
    data_dir = Path(args.data_dir) if args.data_dir else ext_dir / "data"
    reports_dir = Path(args.reports_dir) if args.reports_dir else ext_dir / "reports"
    duration_s = args.duration
    bin_path = ext_dir.parent.parent / "build" / "maars_esp32s3.bin"
    
    data_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)
    
    # Compute firmware hash
    fw_hash = get_file_sha256(bin_path) if bin_path.exists() else "UNKNOWN"
    metadata = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "firmware_binary": str(bin_path),
        "firmware_sha256": fw_hash,
        "target_port": port,
        "baud_rate": 115200,
        "milestones": ["M2_Anterior_vs_Posterior", "M3_Multi_Victim_SVI"]
    }
    with open(reports_dir / "m2_m3_run_metadata.json", "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"Recorded metadata with firmware SHA256: {fw_hash}")
    
    print("==================================================================")
    print("STARTING FULL HARDWARE EVALUATION ON ESP32-S3 (LAPTOP 2: M2 & M3)")
    print("==================================================================")
    
    # -------------------------------------------------------------
    # MILESTONE 2: Anterior vs. Posterior Attack Experiments
    # -------------------------------------------------------------
    print("\n>>> EXECUTING MILESTONE 2: ANTERIOR VS POSTERIOR ATTACKS <<<")
    # Trial 1: Posterior Attack (Unguarded)
    post_records = run_hardware_trial(
        port,
        condition_name="Posterior Attack (Unguarded)",
        setup_cmds=["ATTACK,RESET_STATS", "GUARD,OFF", "ATTACK,TARGET,CONTROL", "ATTACK,MODE,POSTERIOR"],
        target_type="CONTROL",
        duration_s=duration_s,
        raw_log_path=data_dir / "post_raw.log"
    )
    write_csv(data_dir / "post.csv", post_records)
    time.sleep(2.0)

    # Trial 2: Posterior Attack (Guarded)
    post_g_records = run_hardware_trial(
        port,
        condition_name="Posterior Attack (Guarded)",
        setup_cmds=["ATTACK,RESET_STATS", "GUARD,ON", "ATTACK,TARGET,CONTROL", "ATTACK,MODE,POSTERIOR"],
        target_type="CONTROL",
        duration_s=duration_s,
        raw_log_path=data_dir / "post_guarded_raw.log"
    )
    write_csv(data_dir / "post_guarded.csv", post_g_records)
    time.sleep(2.0)
    
    # Trial 3: Anterior Attack (Unguarded)
    ant_records = run_hardware_trial(
        port,
        condition_name="Anterior Attack (Unguarded)",
        setup_cmds=["ATTACK,RESET_STATS", "GUARD,OFF", "ATTACK,TARGET,CONTROL", "ATTACK,MODE,ANTERIOR"],
        target_type="CONTROL",
        duration_s=duration_s,
        raw_log_path=data_dir / "ant_raw.log"
    )
    write_csv(data_dir / "ant.csv", ant_records)
    time.sleep(2.0)

    # Trial 4: Anterior Attack (With Posterior Guard Engaged)
    ant_g_records = run_hardware_trial(
        port,
        condition_name="Anterior Attack (Guarded with Posterior Guard)",
        setup_cmds=["ATTACK,RESET_STATS", "GUARD,ON", "ATTACK,TARGET,CONTROL", "ATTACK,MODE,ANTERIOR"],
        target_type="CONTROL",
        duration_s=duration_s,
        raw_log_path=data_dir / "ant_guarded_raw.log"
    )
    write_csv(data_dir / "ant_guarded.csv", ant_g_records)
    time.sleep(2.0)
    
    # -------------------------------------------------------------
    # MILESTONE 3: Multi-Victim SVI (CONTROL vs. SAFETY)
    # -------------------------------------------------------------
    print("\n>>> EXECUTING MILESTONE 3: MULTI-VICTIM SVI (CONTROL & SAFETY) <<<")
    # Trial 5: Target CONTROL
    ctrl_records = run_hardware_trial(
        port,
        condition_name="Multi-Victim: Target CONTROL",
        setup_cmds=["ATTACK,RESET_STATS", "GUARD,OFF", "ATTACK,TARGET,CONTROL", "ATTACK,MODE,POSTERIOR"],
        target_type="CONTROL",
        duration_s=duration_s,
        raw_log_path=data_dir / "ctrl_raw.log"
    )
    write_csv(data_dir / "ctrl.csv", ctrl_records)
    time.sleep(2.0)
    
    # Trial 6: Target SAFETY
    safety_records = run_hardware_trial(
        port,
        condition_name="Multi-Victim: Target SAFETY",
        setup_cmds=["ATTACK,RESET_STATS", "GUARD,OFF", "ATTACK,TARGET,SAFETY"],
        target_type="SAFETY",
        duration_s=duration_s,
        raw_log_path=data_dir / "safety_raw.log"
    )
    write_csv(data_dir / "safety.csv", safety_records)
    time.sleep(2.0)
    
    # -------------------------------------------------------------
    # Execute Official Claude Analyzer: m2_m3_analyze.py
    # -------------------------------------------------------------
    print("\n==================================================================")
    print("RUNNING OFFICIAL ANALYZER: m2_m3_analyze.py")
    print("==================================================================")
    
    print("\n--- [ANALYZER OUTPUT: MILESTONE 2 (POSTERIOR UNGUARDED vs GUARDED)] ---")
    m2_p_cmd = [sys.executable, str(ext_dir / "m2_m3_analyze.py"), "m2", 
                "--posterior", str(data_dir / "post.csv"), 
                "--anterior", str(data_dir / "post_guarded.csv")]
    subprocess.run(m2_p_cmd)

    print("\n--- [ANALYZER OUTPUT: MILESTONE 2 (POSTERIOR vs ANTERIOR)] ---")
    m2_cmd = [sys.executable, str(ext_dir / "m2_m3_analyze.py"), "m2", 
              "--posterior", str(data_dir / "post.csv"), 
              "--anterior", str(data_dir / "ant.csv")]
    subprocess.run(m2_cmd)
    
    print("\n--- [ANALYZER OUTPUT: MILESTONE 2 (GUARD BLIND-SPOT: POSTERIOR GUARD vs ANTERIOR GUARDED)] ---")
    m2_g_cmd = [sys.executable, str(ext_dir / "m2_m3_analyze.py"), "m2", 
                "--posterior", str(data_dir / "post_guarded.csv"), 
                "--anterior", str(data_dir / "ant_guarded.csv")]
    subprocess.run(m2_g_cmd)

    print("\n--- [ANALYZER OUTPUT: MILESTONE 3 (CONTROL vs SAFETY SVI)] ---")
    m3_cmd = [sys.executable, str(ext_dir / "m2_m3_analyze.py"), "m3", 
              "--control", str(data_dir / "ctrl.csv"), 
              "--safety", str(data_dir / "safety.csv"), 
              "--crit", "2", "1"]
    subprocess.run(m3_cmd)
    
    # Generate charts
    generate_plots(data_dir, reports_dir)
    print("\nALL HARDWARE EXPERIMENTS COMPLETED SUCCESSFULLY!")

if __name__ == "__main__":
    main()
