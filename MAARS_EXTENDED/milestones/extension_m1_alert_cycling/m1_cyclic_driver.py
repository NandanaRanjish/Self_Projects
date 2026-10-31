"""MILESTONE 1: Normal<->Alert cycling test.
Runs repeated clean/attack phases over one continuous session and asks the board to
clear/engage the detector's alert hook at phase boundaries, then analyzes latency,
corrupted-before-engage count, disengage time and false alarms from the resulting trace.
"""
import argparse, collections, csv, sys, time, serial

class Motor:
    def __init__(self):
        self.i = 0.0
        self.w = 0.0
    def step(self, u, dt=0.02):
        u = max(-12.0, min(12.0, u))
        h = dt / 5.0
        for _ in range(5):
            di = (u - 2.0 * self.i - 0.1 * self.w) / 0.02
            dw = (0.1 * self.i - 0.001 * self.w) / 0.002
            self.i += h * di
            self.w += h * dw
        return self.w

def run(port, baud, cycles, clean_s, attack_s, out_csv):
    ser = serial.Serial(port, baud, timeout=0.02)
    time.sleep(1.5)  # board reset settle
    ser.reset_input_buffer()
    ser.reset_output_buffer()

    rows = []
    ctx = {"phase": "SETUP", "cycle": -1}
    t0 = time.time()

    def send_cmd(cmd, expected_ack=None, wait=0.08):
        ser.write((cmd + "\n").encode())
        time.sleep(wait)
        acks = []
        while ser.in_waiting:
            line = ser.readline().decode(errors="ignore").strip()
            if line:
                acks.append(line)
                rows.append((time.time() - t0, ctx.get("phase", "SETUP"), ctx.get("cycle", -1), line))
        reply = " | ".join(a for a in acks if a.startswith(("ACK", "ERR", "S11STAT")))
        print(f">>> {cmd} --> {reply}")
        if expected_ack:
            assert any(expected_ack in a for a in acks), f"Failed {cmd}, expected {expected_ack}, got: {reply}"
        return acks

    # Initialize firmware configuration with S11 fully activated
    print("=== Initializing Firmware S11 Schedule & Detector Protection ===")
    send_cmd("RESET")
    time.sleep(0.8)
    ser.reset_input_buffer()
    send_cmd("TS,ON", expected_ack="ACK,TS,ON")
    send_cmd("CHI8,SHADOW", expected_ack="ACK,CHI8,SHADOW")
    send_cmd("S11,ON", expected_ack="ACK,S11,ON")
    send_cmd("S11,MODE,GUIDE", expected_ack="ACK,S11,MODE,GUIDE")
    send_cmd("ATKPRIOR,20")
    send_cmd("R,80.0")
    send_cmd("S11,STATUS", wait=0.15)

    plant = Motor()
    nominal = Motor()
    applied_v = 0.0
    nominal_v = 0.0
    seq = 0
    recent_z = collections.deque(maxlen=5)

    next_send = time.time()

    for c in range(cycles):
        # --- clean phase ---
        ctx["phase"], ctx["cycle"] = "CLEAN", c
        send_cmd("ATTACK,OFF")
        send_cmd("S11,ALERT,CLEAR")
        recent_z.clear()
        # Re-sync the reference model to the plant so divergence left over from the
        # previous attack phase is not counted as a false alarm.
        nominal.i, nominal.w = plant.i, plant.w
        clean_false_alarms = 0
        in_alarm = False
        phase_start = time.time()
        while time.time() - phase_start < clean_s:
            now = time.time()
            if now >= next_send:
                ser.write(f"S,{seq},{plant.w:.4f}\n".encode())
                seq += 1
                next_send += 0.02

            while ser.in_waiting:
                line = ser.readline().decode(errors="ignore").strip()
                if line:
                    rows.append((time.time() - t0, "CLEAN", c, line))
                    if line.startswith("ACT,"):
                        parts = line.split(",")
                        if len(parts) >= 5:
                            nominal_v = float(parts[2])
                            applied_v = float(parts[3])

            plant.step(applied_v, dt=0.02)
            nominal.step(nominal_v, dt=0.02)
            res = plant.w - nominal.w
            recent_z.append((res / 0.25) ** 2)
            z_avg = sum(recent_z) / len(recent_z) if recent_z else 0.0
            alarm_now = len(recent_z) == 5 and z_avg > 6.0
            if alarm_now and not in_alarm:
                clean_false_alarms += 1
                rows.append((time.time() - t0, "CLEAN", c, f"ALARM,FALSE_ALARM,z_avg={z_avg:.2f}"))
            in_alarm = alarm_now
            time.sleep(0.001)

        # --- attack phase ---
        ctx["phase"], ctx["cycle"] = "ATTACK", c
        send_cmd("ATTACK,ON")
        recent_z.clear()
        attack_t0 = time.time()
        alert_sent = False
        while time.time() - attack_t0 < attack_s:
            now = time.time()
            if now >= next_send:
                ser.write(f"S,{seq},{plant.w:.4f}\n".encode())
                seq += 1
                next_send += 0.02

            while ser.in_waiting:
                line = ser.readline().decode(errors="ignore").strip()
                if line:
                    rows.append((time.time() - t0, "ATTACK", c, line))
                    if line.startswith("ACT,"):
                        parts = line.split(",")
                        if len(parts) >= 5:
                            nominal_v = float(parts[2])
                            applied_v = float(parts[3])

            plant.step(applied_v, dt=0.02)
            nominal.step(nominal_v, dt=0.02)
            res = plant.w - nominal.w
            recent_z.append((res / 0.25) ** 2)
            z_avg = sum(recent_z) / len(recent_z) if recent_z else 0.0
            if len(recent_z) == 5 and z_avg > 6.0 and not alert_sent:
                ser.write(b"S11,ALERT,CONTROL\n")
                rows.append((time.time() - t0, "ATTACK", c, f"ALARM,ATTACK_DETECTED,z_avg={z_avg:.2f}"))
                alert_sent = True

            time.sleep(0.001)

        send_cmd("S11,STATUS", wait=0.15)
        print(f"cycle {c+1}/{cycles} done (clean false-alarm episodes: {clean_false_alarms})", file=sys.stderr)

    ctx["phase"] = "END"
    send_cmd("ATTACK,OFF")
    send_cmd("S11,ALERT,CLEAR")
    ser.close()

    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["t_s", "phase", "cycle", "raw_line"])
        w.writerows(rows)
    print(f"wrote {len(rows)} lines to {out_csv}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", required=True)
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--cycles", type=int, default=8)
    ap.add_argument("--clean-s", type=float, default=8)
    ap.add_argument("--attack-s", type=float, default=8)
    ap.add_argument("--out", default="m1_cyclic_raw.csv")
    a = ap.parse_args()
    run(a.port, a.baud, a.cycles, a.clean_s, a.attack_s, a.out)
