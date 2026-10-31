"""MILESTONE 1 analysis: detection latency per attack onset, corruption before/after
the alert, whether the alert actually engaged the guard, and false alarms during clean
phases.

Corruption is counted once per transmitted command, from ACT lines only
(ACT,seq,computed_v,applied_v,attacked). CMD/ATK/AEW lines describe the same command
and must not be added on top.

Usage: python m1_cyclic_analyze.py m1_raw.csv [--plot reports/m1_alert_cycling.png]
"""
import csv, argparse, collections, numpy as np

def s11stat(line):
    f = line.split(",")
    return {"alert": int(f[5]), "guard": int(f[6]), "deferrals": int(f[11])}

def analyze(path):
    rows = list(csv.DictReader(open(path, encoding="utf-8", errors="replace")))
    cycles = sorted({int(r["cycle"]) for r in rows if int(r["cycle"]) >= 0})
    # S11STAT replies can arrive after the next phase has started, so locate them by
    # position: the deferral change across an attack phase is (first status after it)
    # minus (last status before it).
    stat_pos = [(i, s11stat(r["raw_line"])["deferrals"]) for i, r in enumerate(rows)
                if r["raw_line"].startswith("S11STAT,")]
    results = []
    for c in cycles:
        idx = [i for i, r in enumerate(rows) if int(r["cycle"]) == c and r["phase"] == "ATTACK"]
        deferral_delta = None
        if idx:
            # only use statuses that bracket THIS attack phase and no other
            prev_end = max((i for i, r in enumerate(rows[:idx[0]])
                            if r["phase"] == "ATTACK"), default=-1)
            next_start = next((i for i in range(idx[-1] + 1, len(rows))
                               if rows[i]["phase"] == "ATTACK"), len(rows))
            before = [d for i, d in stat_pos if i < idx[0]]
            after = [d for i, d in stat_pos if idx[0] <= i < next_start]
            if before and after:
                deferral_delta = after[-1] - before[-1]
        crows = [r for r in rows if int(r["cycle"]) == c]
        attack = [r for r in crows if r["phase"] == "ATTACK"]
        clean = [r for r in crows if r["phase"] == "CLEAN"]
        if not attack:
            continue
        t_attack_start = float(attack[0]["t_s"])
        alert_t = None
        pre_n = pre_k = post_n = post_k = 0
        resp_alert = resp_other = 0
        for r in attack:
            line = r["raw_line"]
            # the host-side ALARM marker is never lost; the board's ACK can be on a noisy link
            if line.startswith(("ACK,S11,ALERT,CONTROL", "ALARM,ATTACK_DETECTED")) and alert_t is None:
                alert_t = float(r["t_s"])
            elif line.startswith("ACT,"):
                p = line.split(",")
                if len(p) >= 5:
                    bad = p[4] == "1" or abs(float(p[3]) - float(p[2])) > 1.0
                    if alert_t is None:
                        pre_n += 1; pre_k += bad
                    else:
                        post_n += 1; post_k += bad
            elif line.startswith("RESP,") and alert_t is not None:
                if line.startswith("RESP,ALERT"): resp_alert += 1
                else: resp_other += 1
        clean_k = sum(1 for r in clean if r["raw_line"].startswith("ACT,") and r["raw_line"].split(",")[4] == "1")
        clean_n = sum(1 for r in clean if r["raw_line"].startswith("ACT,"))
        false_alarms = sum(1 for r in clean if r["raw_line"].startswith("ALARM,FALSE_ALARM"))
        results.append(dict(cycle=c,
                            detect_latency_s=(alert_t - t_attack_start) if alert_t else None,
                            pre_n=pre_n, pre_k=pre_k, post_n=post_n, post_k=post_k,
                            clean_n=clean_n, clean_k=clean_k, false_alarms=false_alarms,
                            deferral_delta=deferral_delta,
                            resp_alert=resp_alert, resp_other=resp_other))
    return results

def pct(k, n):
    return 100.0 * k / n if n else float("nan")

def plot(res, out):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    x = np.arange(len(res)); w = 0.38
    pre = [pct(r["pre_k"], r["pre_n"]) for r in res]
    post = [pct(r["post_k"], r["post_n"]) if r["post_n"] else 0 for r in res]
    fig, ax = plt.subplots(figsize=(11, 4.8))
    ax.bar(x - w/2, pre, w, label="Before alert", color="#d9534f", edgecolor="black")
    ax.bar(x + w/2, post, w, label="After alert", color="#5cb85c", edgecolor="black")
    for i, r in enumerate(res):
        if r["post_n"] == 0:
            ax.text(x[i] + w/2, 1, "no alert", ha="center", fontsize=8, rotation=90)
    ax.set_xticks(x); ax.set_xticklabels([f"Cycle {r['cycle']}" for r in res])
    ax.set_ylabel("Corrupted commands (% of commands in window)")
    ax.set_title("M1: Corruption rate before vs after the Normal->Alert switch")
    ax.legend(); ax.grid(axis="y", linestyle="--", alpha=0.5)
    plt.tight_layout()
    try:
        plt.savefig(out, dpi=200)
        print(f"saved {out}")
    except PermissionError:
        alt_out = out.replace(".png", "_new.png")
        plt.savefig(alt_out, dpi=200)
        print(f"saved {alt_out} (note: {out} was locked by another process)")
    plt.close()

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("raw_csv")
    ap.add_argument("--plot", default=None)
    a = ap.parse_args()
    res = analyze(a.raw_csv)
    print(f"{'cyc':4}{'latency':>9}{'before':>14}{'after':>14}{'deferrals':>11}{'RESP alert/other':>18}{'false':>7}")
    for r in res:
        lat = f"{r['detect_latency_s']*1000:.0f}ms" if r["detect_latency_s"] is not None else "NO-ALARM"
        dd = "?" if r["deferral_delta"] is None else str(r["deferral_delta"])
        print(f"{r['cycle']:<4}{lat:>9}{r['pre_k']:>6}/{r['pre_n']:<4}({pct(r['pre_k'],r['pre_n']):3.0f}%)"
              f"{r['post_k']:>4}/{r['post_n']:<4}({pct(r['post_k'],r['post_n']):3.0f}%)"
              f"{dd:>11}{r['resp_alert']:>9}/{r['resp_other']:<8}{r['false_alarms']:>7}")
    lat = [r["detect_latency_s"] for r in res if r["detect_latency_s"] is not None]
    PK, PN = sum(r["pre_k"] for r in res), sum(r["pre_n"] for r in res)
    QK, QN = sum(r["post_k"] for r in res), sum(r["post_n"] for r in res)
    CK, CN = sum(r["clean_k"] for r in res), sum(r["clean_n"] for r in res)
    print()
    if lat:
        print(f"detection latency (host detector): mean {1000*np.mean(lat):.0f} ms, std {1000*np.std(lat):.0f} ms, "
              f"alarm in {len(lat)}/{len(res)} cycles")
    print(f"corruption before alert: {PK}/{PN} = {pct(PK,PN):.1f}%")
    print(f"corruption after alert:  {QK}/{QN} = {pct(QK,QN):.1f}%")
    print(f"corruption in clean phases: {CK}/{CN}")
    print(f"false-alarm episodes in clean phases: {sum(r['false_alarms'] for r in res)}")
    # Serial-link health: garbled host lines and commands missing from the trace.
    all_rows = list(csv.DictReader(open(a.raw_csv, encoding="utf-8", errors="replace")))
    errs = collections.Counter(r["raw_line"] for r in all_rows if r["raw_line"].startswith("ERR"))
    seqs = [int(r["raw_line"].split(",")[1]) for r in all_rows if r["raw_line"].startswith("ACT,")]
    if seqs:
        logged = len(set(seqs)); span = max(seqs) - min(seqs) + 1
        print(f"serial link: {sum(errs.values())} ERR lines {dict(errs)}; "
              f"ACT lines logged for {logged}/{span} command sequence numbers ({100*logged/span:.0f}%)")
        if sum(errs.values()) > 0.02 * span:
            print("WARNING: many garbled host->board lines; sensor samples were lost during the run.")
    if PN and QN:
        from scipy.stats import fisher_exact
        print(f"Fisher exact before vs after: p = {fisher_exact([[PK, PN-PK], [QK, QN-QK]])[1]:.3g}")
    # Did the alert actually engage protection on the board?
    alerted = [r for r in res if r["post_n"]]
    no_defer = [r["cycle"] for r in alerted if r["deferral_delta"] == 0]
    no_resp = all(r["resp_alert"] + r["resp_other"] == 0 for r in res)
    if no_resp:
        print("WARNING: no RESP lines in the trace -> board is NOT running the milestone firmware "
              "(original unified build: an alert only switches schedule pools, it does not engage the guard).")
    if no_defer:
        print(f"WARNING: zero guard deferrals after the alert in cycles {no_defer} -> the alert did not engage the guard.")
    if a.plot:
        plot(res, a.plot)
