import os
#!/usr/bin/env python3
"""
MAARS Milestone 1 Experiment: Rate-Adaptive Attacker vs Multi-Rate Scheduling
Evaluates Naive (Fixed-Prior) Attacker vs Dual-Ladder Rate-Adaptive Attacker
across Multi-Rate ALT mode (20ms <-> 25ms switching) on ESP32-S3.
"""

import sys
import time
import json
import csv
from pathlib import Path
import serial
import numpy as np
import matplotlib.pyplot as plt

# Motor Model Parameters (Table 12.1 of MAARS Technical Report)
R, L = 2.0, 0.02
Kt, Ke = 0.1, 0.1
J, b = 0.002, 0.001
V_LIMIT = 12.0

class DCMotorSim:
    def __init__(self):
        self.i = 0.0
        self.w = 0.0
        
    def step_rk4(self, u, dt, load=0.0):
        # Clip voltage
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

def run_single_trial(port, condition_name, rate_mode, atk_prior_cmd, s11_mode, duration_s=10.0):
    print(f"\n==================================================================")
    print(f"STARTING RUN: {condition_name}")
    print(f"Rate: {rate_mode} | Attacker: {atk_prior_cmd} | Defense: {s11_mode}")
    print(f"==================================================================")
    
    ser = serial.Serial(port, 115200, timeout=0.1)
    time.sleep(1.0)
    ser.reset_input_buffer()
    ser.reset_output_buffer()
    
    # Configure Board
    def send_cmd(cmd_str):
        ser.write((cmd_str + "\n").encode())
        time.sleep(0.05)
        
    send_cmd("ATTACK,OFF")
    send_cmd("TS,ON")
    send_cmd("S11,OFF")
    send_cmd("CHI8,SHADOW")
    send_cmd(f"RATE,{rate_mode}")
    send_cmd(atk_prior_cmd) # e.g. "ATKPRIOR,20" or "ATKPRIOR,ADAPTIVE"
    send_cmd("S11,ON")
    send_cmd(f"S11,MODE,{s11_mode}") # "GUIDE" or "BOTH"
    send_cmd("ATTACK,ON")
    
    # Drain initial lines
    time.sleep(0.2)
    ser.reset_input_buffer()
    
    motor = DCMotorSim()
    ref_speed = 80.0
    measured_speed = 0.0
    
    t_start = time.time()
    next_send_time = t_start
    seq = 0
    
    commands_log = []
    locks_log = []
    fires_log = []
    
    # Nominal sensor loop at ~20ms base
    sensor_dt = 0.020
    
    while time.time() - t_start < duration_s:
        now = time.time()
        if now >= next_send_time:
            # Send sensor update to controller (format: S,<seq>,<measured_speed>\n)
            sensor_msg = f"S,{seq},{measured_speed:.4f}\n"
            ser.write(sensor_msg.encode())
            seq += 1
            next_send_time += sensor_dt
            
        # Read incoming lines
        while ser.in_waiting > 0:
            raw_line = ser.readline().decode('utf-8', errors='replace').strip()
            if not raw_line:
                continue
                
            if raw_line.startswith("ACT,"):
                # Format: ACT,seq,computed_v,applied_v,attacked
                parts = raw_line.split(',')
                if len(parts) >= 5:
                    c_seq = int(parts[1])
                    u_comp = float(parts[2])
                    u_app = float(parts[3])
                    attacked = int(parts[4])
                    is_corrupted = 1 if (attacked == 1 or abs(u_app - u_comp) > 1.0) else 0
                    
                    # Step the physical motor with applied voltage
                    measured_speed = motor.step_rk4(u_app, sensor_dt)
                    
                    commands_log.append({
                        "t_wall": time.time() - t_start,
                        "seq": c_seq,
                        "u_applied": u_app,
                        "u_computed": u_comp,
                        "corrupted": is_corrupted,
                        "speed": measured_speed
                    })
                    
            elif raw_line.startswith("ATTACK_LOCK,"):
                # ATTACK_LOCK,<now_us>,<period_us>,<confidence>
                parts = raw_line.split(',')
                if len(parts) >= 4:
                    locks_log.append({
                        "now_us": int(parts[1]),
                        "period_us": int(parts[2]),
                        "confidence": float(parts[3])
                    })
                    print(f"  [ATTACKER LOCK] Inferred rate: {parts[2]} us, Conf: {parts[3]}")
                    
            elif raw_line.startswith("ATTACK_FIRE,"):
                # ATTACK_FIRE,<now_us>,<window_period_us>,<corrupted>,<seq>
                # (seq = 4294967295 when no command was pending)
                parts = raw_line.split(',')
                if len(parts) >= 5:
                    fires_log.append({
                        "now_us": int(parts[1]),
                        "period_us": int(parts[2]),
                        "corrupted": int(parts[3]),
                        "seq": int(parts[4])
                    })
                    
        time.sleep(0.001)
        
    send_cmd("ATTACK,OFF")
    ser.close()
    
    total_cmds = len(commands_log)
    corrupt_cmds = sum(c["corrupted"] for c in commands_log)
    corrupt_rate = (corrupt_cmds / max(1, total_cmds)) * 100.0
    
    print(f"\nRESULTS [{condition_name}]:")
    print(f"  Total Commands:   {total_cmds}")
    print(f"  Corrupted:        {corrupt_cmds}")
    print(f"  Corruption Rate:  {corrupt_rate:.1f}%")
    print(f"  Attack Locks:     {len(locks_log)}")
    print(f"  Attack Fires:     {len(fires_log)}")
    
    return {
        "condition": condition_name,
        "total_commands": total_cmds,
        "corrupted_commands": corrupt_cmds,
        "corruption_rate_pct": corrupt_rate,
        "locks": locks_log,
        "fires": fires_log,
        "commands": commands_log
    }

def main():
    import argparse
    parser = argparse.ArgumentParser(description="M1 Adaptive Attacker Experiment")
    parser.add_argument("--port", default=os.environ.get("PORT", "COM7"), help="Serial port")
    parser.add_argument("--duration", type=float, default=8.0, help="Duration per trial in seconds")
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
    
    # 3 Experimental Conditions:
    # 1. Multi-Rate ALT with Naive Attacker (Fixed Prior 20ms) under MAARS Schedule Randomization (GUIDE)
    # 2. Multi-Rate ALT with Rate-Adaptive Attacker (Dual-Ladder) under MAARS Schedule Randomization (GUIDE)
    # 3. Multi-Rate ALT with Rate-Adaptive Attacker under MAARS Schedule Randomization + GUARD (BOTH)
    
    results = []
    
    # Trial 1: Naive Attacker vs MAARS Multi-rate (GUIDE)
    res_naive = run_single_trial(
        port, 
        condition_name="MAARS (Multi-rate) vs Naive Attacker",
        rate_mode="ALT", 
        atk_prior_cmd="ATKPRIOR,20", 
        s11_mode="GUIDE", 
        duration_s=dur
    )
    results.append(res_naive)
    time.sleep(2.0)
    
    # Trial 2: Rate-Adaptive Attacker vs MAARS Multi-rate (GUIDE)
    res_adaptive = run_single_trial(
        port, 
        condition_name="MAARS (Multi-rate) vs Rate-Adaptive Attacker",
        rate_mode="ALT", 
        atk_prior_cmd="ATKPRIOR,ADAPTIVE", 
        s11_mode="GUIDE", 
        duration_s=dur
    )
    results.append(res_adaptive)
    time.sleep(2.0)
    
    # Trial 3: Rate-Adaptive Attacker vs MAARS + Temporal GUARD (BOTH)
    res_guarded = run_single_trial(
        port, 
        condition_name="MAARS + GUARD vs Rate-Adaptive Attacker",
        rate_mode="ALT", 
        atk_prior_cmd="ATKPRIOR,ADAPTIVE", 
        s11_mode="BOTH", 
        duration_s=dur
    )
    results.append(res_guarded)
    
    # Save CSV Data
    for r in results:
        csv_file = data_dir / f"m1_raw_{r['condition'].replace(' ', '_').replace('+', 'plus')}.csv"
        with open(csv_file, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["t_wall", "seq", "u_applied", "u_computed", "corrupted", "speed"])
            writer.writeheader()
            writer.writerows(r["commands"])
        print(f"Saved: {csv_file}")
        
    # Save Summary JSON
    summary = {
        "milestone": "M1 - Rate-Adaptive Dual-Ladder Attacker vs MAARS",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "runs": [
            {
                "condition": r["condition"],
                "total_commands": r["total_commands"],
                "corrupted_commands": r["corrupted_commands"],
                "corruption_rate_pct": round(r["corruption_rate_pct"], 2),
                "lock_events": len(r["locks"]),
                "fire_events": len(r["fires"])
            }
            for r in results
        ]
    }
    json_path = reports_dir / "m1_summary.json"
    with open(json_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nSaved Summary: {json_path}")
    
    # Generate Publication Comparison Charts
    fig, axes = plt.subplots(1, 2, figsize=(13, 5))
    
    # Bar Chart: Corruption Rates
    cond_labels = ["Naive Attacker\n(MAARS Multi-rate)", "Rate-Adaptive\n(MAARS Multi-rate)", "Rate-Adaptive\n(MAARS + GUARD)"]
    rates = [r["corruption_rate_pct"] for r in results]
    colors = ["#4a90e2", "#d9534f", "#5cb85c"]
    
    bars = axes[0].bar(cond_labels, rates, color=colors, width=0.55, edgecolor="black", linewidth=1.2)
    axes[0].set_ylabel("Command Corruption Rate (%)", fontsize=11, fontweight="bold")
    axes[0].set_title("M1: Attacker Success Rate across Defenses", fontsize=12, fontweight="bold")
    axes[0].set_ylim(0, 100)
    axes[0].grid(axis="y", linestyle="--", alpha=0.7)
    
    for bar in bars:
        height = bar.get_height()
        axes[0].text(bar.get_x() + bar.get_width()/2., height + 2.0,
                     f"{height:.1f}%", ha="center", va="bottom", fontsize=11, fontweight="bold")
                     
    # Annotate Discovery
    axes[0].annotate('MAARS Vulnerability:\nMulti-rate bypassed\nby Dual-Ladder!',
                     xy=(1, rates[1]), xytext=(0.8, rates[1] + 25),
                     arrowprops=dict(facecolor='black', shrink=0.08, width=1.5, headwidth=8),
                     fontsize=10, fontweight="bold", color="#d9534f",
                     bbox=dict(boxstyle="round,pad=0.3", fc="#fdf7f7", ec="#d9534f", lw=1.5))

    # Time series of Commands for Adaptive Attacker (showing -12V overrides vs Clean PI)
    res_ad = results[1]
    df_cmds = res_ad["commands"][:80]
    t_vals = [c["t_wall"] for c in df_cmds]
    u_app = [c["u_applied"] for c in df_cmds]
    u_comp = [c["u_computed"] for c in df_cmds]
    
    axes[1].plot(t_vals, u_comp, label="Controller Computed (V)", color="blue", linewidth=1.5, linestyle="--")
    axes[1].plot(t_vals, u_app, label="Actuator Applied (V)", color="red", linewidth=1.5)
    axes[1].set_xlabel("Time (seconds)", fontsize=11)
    axes[1].set_ylabel("Actuator Voltage (V)", fontsize=11, fontweight="bold")
    axes[1].set_title("Trace: Adaptive Attacker Overwriting Actuation to -12V", fontsize=12, fontweight="bold")
    axes[1].legend(loc="lower left", framealpha=0.9)
    axes[1].grid(True, linestyle="--", alpha=0.7)
    axes[1].set_ylim(-14, 14)
    
    plt.tight_layout()
    chart_path = reports_dir / "m1_corruption_comparison.png"
    plt.savefig(chart_path, dpi=200)
    print(f"Saved Chart: {chart_path}")
    print("\nMILESTONE 1 EXECUTION COMPLETE!")

if __name__ == "__main__":
    main()
