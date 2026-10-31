#!/usr/bin/env python3
import time
import serial
from pathlib import Path
import numpy as np

# Motor model
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

def main():
    port = "COM7"
    raw_log_path = Path("D:/milestone extension/data/post_isolation_raw.log")
    raw_log_path.parent.mkdir(parents=True, exist_ok=True)
    raw_file = open(raw_log_path, "w", encoding="utf-8")
    
    print(f"Opening port {port}...")
    ser = serial.Serial(port, 115200, timeout=0.1)
    time.sleep(1.0)
    ser.reset_input_buffer()
    ser.reset_output_buffer()
    
    def send(c):
        raw_file.write(f">>> {c}\n")
        ser.write((c + "\n").encode())
        time.sleep(0.04)
        
    print("Configuring board...")
    send("ATTACK,OFF")
    send("TS,ON")
    send("RATE,20")
    send("ATTACK,TARGET,CONTROL")
    send("ATTACK,MODE,POSTERIOR")
    send("S11,OFF")
    send("ATTACK,ON")
    
    time.sleep(0.2)
    ser.reset_input_buffer()
    
    motor = DCMotorSim()
    measured_speed = 0.0
    seq = 0
    t_start = time.time()
    next_send = t_start
    sensor_dt = 0.020
    
    act_count = 0
    corrupt_count = 0
    fires = []
    
    print("Running 10s isolation run for Posterior Unguarded...")
    while time.time() - t_start < 10.0:
        now = time.time()
        if now >= next_send:
            msg = f"S,{seq},{measured_speed:.4f}\n"
            ser.write(msg.encode())
            raw_file.write(f">>> {msg.strip()}\n")
            seq += 1
            next_send += sensor_dt
            
        while ser.in_waiting > 0:
            line = ser.readline().decode('utf-8', errors='replace').strip()
            if not line:
                continue
            raw_file.write(f"{line}\n")
            if line.startswith("ACT,"):
                parts = line.split(',')
                if len(parts) >= 5:
                    act_count += 1
                    u_comp = float(parts[2])
                    u_app = float(parts[3])
                    atk = int(parts[4])
                    if atk == 1 or abs(u_app - u_comp) > 1.0:
                        corrupt_count += 1
                    measured_speed = motor.step_rk4(u_app, sensor_dt)
            elif line.startswith("ATTACK_FIRE,"):
                fires.append(line)
        time.sleep(0.001)
        
    send("ATTACK,OFF")
    ser.close()
    raw_file.close()
    
    rate_pct = (corrupt_count / max(1, act_count)) * 100.0
    print(f"\n=======================================================")
    print(f"POSTERIOR UNGUARDED ISOLATION RESULTS:")
    print(f"  Total Commands:  {act_count}")
    print(f"  Corrupted:       {corrupt_count} ({rate_pct:.2f}%)")
    print(f"  ATTACK_FIRE:     {len(fires)} events logged")
    print(f"  Raw log written: {raw_log_path}")
    print(f"=======================================================")

if __name__ == "__main__":
    main()
