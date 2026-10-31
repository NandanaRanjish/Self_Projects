"""Collector script for MAARS Milestone 4: Guard-Leakage Analysis.
Collects continuous UNTRUSTED execution grants over a hardware run
for unguarded (none) vs guarded (guard) conditions to produce >=500 grant captures.

Each record keeps the job's planned release time (planned_us) as well as its start and
finish, so m4_delay_leakage.py can measure the delay the attacker itself observes.
A <out>.meta.json file next to the CSV stores the CONTROL release grid offset and the
board's S11 status before and after the run (deferrals prove the guard was active).
"""
import argparse, csv, json, sys, time, serial
from pathlib import Path

class Motor:
    def __init__(self): self.i = 0.0; self.w = 0.0
    def step(self, u, dt=0.02):
        u = max(-12.0, min(12.0, u))
        h = dt / 5.0
        for _ in range(5):
            di = (u - 2.0*self.i - 0.1*self.w) / 0.02
            dw = (0.1*self.i - 0.001*self.w) / 0.002
            self.i += h*di; self.w += h*dw
        return self.w

def collect_run(port, baud, mode, duration_s, out_csv):
    print(f"\n--- Starting collection for mode '{mode}' ({duration_s}s) -> {out_csv} ---")
    ser = serial.Serial(port, baud, timeout=0.02)
    time.sleep(1.5)
    ser.reset_input_buffer()
    ser.reset_output_buffer()

    def send(c, expected=None, wait=0.06):
        ser.write((c + "\n").encode())
        time.sleep(wait)
        acks = []
        while ser.in_waiting:
            line = ser.readline().decode("utf-8", errors="ignore").strip()
            if line: acks.append(line)
        res = " | ".join(a for a in acks if a.startswith(("ACK", "ERR", "S11STAT")))
        print(f">>> {c} --> {res}")
        if expected:
            assert any(expected in a for a in acks), f"Failed {c}: expected {expected}, got {res}"
        return acks

    def s11_status():
        # S11STAT,requested,active,period,index,alert,guard,boundaries,switches,guided,rejected,deferrals,...
        for a in send("S11,STATUS", wait=0.1):
            if a.startswith("S11STAT,"):
                f = a.split(",")
                return {"requested": int(f[1]), "active": int(f[2]), "alert": int(f[5]),
                        "guard": int(f[6]), "deferrals": int(f[11])}
        return None

    send("RESET")
    time.sleep(0.5)
    send("TS,ON", expected="ACK,TS,ON")
    send("RATE,20", expected="ACK,RATE,20")
    send("ATTACK,OFF", expected="ACK,ATTACK,OFF")

    if mode == "guard":
        send("CHI8,SHADOW", expected="ACK,CHI8,SHADOW")
        send("S11,ON", expected="ACK,S11,ON")
        send("S11,MODE,GUARD", expected="ACK,S11,MODE,GUARD")
    elif mode == "guide":
        send("CHI8,SHADOW", expected="ACK,CHI8,SHADOW")
        send("S11,ON", expected="ACK,S11,ON")
        send("S11,MODE,GUIDE", expected="ACK,S11,MODE,GUIDE")
    elif mode == "both":
        send("CHI8,SHADOW", expected="ACK,CHI8,SHADOW")
        send("S11,ON", expected="ACK,S11,ON")
        send("S11,MODE,BOTH", expected="ACK,S11,MODE,BOTH")
    else: # none
        send("S11,OFF", expected="ACK,S11,OFF")

    send("R,80.0")

    # Confirm the requested defense is really in effect before collecting.
    deadline = time.time() + 3.0
    st_before = s11_status()
    want_active = mode != "none"
    while st_before is None or st_before["active"] != int(want_active):
        assert time.time() < deadline, f"S11 state not as requested for mode '{mode}': {st_before}"
        time.sleep(0.1)
        st_before = s11_status()
    print(f"S11 before run: {st_before}")

    plant = Motor()
    applied_v = 0.0
    seq = 0
    records = []
    seen_jobs = set()
    grant_index = 0
    control_planned = None   # one CONTROL release, to place UNTRUSTED releases on CONTROL's grid

    t0 = time.time()
    next_send = time.time()

    while time.time() - t0 < duration_s:
        now = time.time()
        if now >= next_send:
            ser.write(f"S,{seq},{plant.w:.4f}\n".encode())
            seq += 1
            next_send += 0.02

        while ser.in_waiting:
            line = ser.readline().decode("utf-8", errors="ignore").strip()
            if not line: continue

            if line.startswith("ACT,"):
                p = line.split(",")
                if len(p) >= 5: applied_v = float(p[3])

            # Parse OWN lines: OWN,job,planned,started,finished,run[0],run[1],run[2]
            if line.startswith("OWN,"):
                parts = line.split(",")
                if len(parts) >= 5:
                    job = int(parts[1])
                    if job not in seen_jobs:
                        seen_jobs.add(job)
                        records.append({
                            "index": grant_index,
                            "kind": "G",
                            "worker": 4, # UNTRUSTED worker index
                            "job": job,
                            "planned_us": int(parts[2]),
                            "start_us": int(parts[3]),
                            "end_us": int(parts[4]),
                            "arg": 50,
                            "flag": 0
                        })
                        grant_index += 1

            # EVT,<task>,job,period,planned,release,start,finish,miss
            elif line.startswith("EVT,CONTROL,") and control_planned is None:
                parts = line.split(",")
                if len(parts) >= 9:
                    control_planned = int(parts[4])

            # Fallback to EVT,UNTRUSTED if OWN not received for a job
            elif line.startswith("EVT,UNTRUSTED,"):
                parts = line.split(",")
                if len(parts) >= 9:
                    job = int(parts[2])
                    if job not in seen_jobs:
                        seen_jobs.add(job)
                        records.append({
                            "index": grant_index,
                            "kind": "G",
                            "worker": 4,
                            "job": job,
                            "planned_us": int(parts[4]),
                            "start_us": int(parts[6]),
                            "end_us": int(parts[7]),
                            "arg": 50,
                            "flag": int(parts[8])
                        })
                        grant_index += 1

        plant.step(applied_v, dt=0.02)
        time.sleep(0.001)

    st_after = s11_status()
    ser.close()
    print(f"S11 after run: {st_after}")
    if mode in ("guard", "both"):
        assert st_after and st_after["deferrals"] > st_before["deferrals"], \
            f"guard never deferred UNTRUSTED (before {st_before}, after {st_after}) -- guard not active"

    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["index", "kind", "worker", "job", "planned_us",
                                               "start_us", "end_us", "arg", "flag"])
        writer.writeheader()
        writer.writerows(records)
    meta = {"mode": mode, "duration_s": duration_s, "control_period_us": 20000,
            "control_planned_us": control_planned, "s11_before": st_before, "s11_after": st_after,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}
    Path(out_csv).with_suffix(".meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    print(f"Completed '{mode}': captured {len(records)} UNTRUSTED grants -> {out_csv}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default="COM3")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--mode", choices=["none", "guard", "guide", "both"], required=True)
    ap.add_argument("--duration", type=float, default=40.0)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    collect_run(args.port, args.baud, args.mode, args.duration, args.out)
