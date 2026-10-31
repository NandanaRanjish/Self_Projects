"""MILESTONE 4 (revised): does the command-window guard leak CONTROL timing to the attacker?

The attacker can only see its own jobs: when each was released (planned_us) and when it
actually got to run (start_us). If the guard defers UNTRUSTED only while a CONTROL
command is pending, the attacker's start delay will depend on where its release falls
relative to CONTROL's period -- that dependence IS the leak.

Leak metric: mutual information I(delay ; CONTROL phase) in bits, where
  delay = start_us - planned_us            (binned, default 0.5 ms)
  phase = (planned_us - control_planned_us) mod control_period   (binned, 1 ms)
Significance comes from a permutation test (phase labels shuffled), and the reported
MI is bias-corrected by subtracting the permutation mean. Higher corrected MI under
'guard' than under 'none', with a small permutation p, means the guard leaks timing.

Also reported: delay distributions (KS test none vs guard), per-phase mean delay, and
the run-time cost of the guard.

Usage:
  python m4_delay_leakage.py none=cap_none.csv guard=cap_guard.csv [--plot reports/m4_delay_leakage.png]
Several CSVs per condition are allowed: none=a.csv none=b.csv guard=c.csv ...
Needs captures from the updated m4_collector.py (planned_us column + .meta.json).
"""
import argparse, collections, csv, json
from pathlib import Path
import numpy as np
from scipy import stats

def load(path, control_offset_override=None):
    p = Path(path)
    meta_p = p.with_suffix(".meta.json")
    meta = json.loads(meta_p.read_text(encoding="utf-8")) if meta_p.exists() else {}
    rows = list(csv.DictReader(open(p, encoding="utf-8")))
    if not rows or "planned_us" not in rows[0]:
        raise SystemExit(f"{path}: no planned_us column -- recollect with the updated m4_collector.py")
    planned = np.array([int(r["planned_us"]) for r in rows], dtype=np.int64)
    start = np.array([int(r["start_us"]) for r in rows], dtype=np.int64)
    end = np.array([int(r["end_us"]) for r in rows], dtype=np.int64)
    period = int(meta.get("control_period_us", 20000))
    offset = control_offset_override if control_offset_override is not None else meta.get("control_planned_us")
    if offset is None:
        print(f"WARNING: {path}: no CONTROL release offset in meta; phase measured from time 0")
        offset = 0
    return {"path": str(p), "meta": meta, "planned": planned, "start": start, "end": end,
            "period": period, "offset": int(offset)}

def mutual_info(x, y):
    """Plug-in mutual information (bits) between two integer label arrays."""
    n = len(x)
    if n == 0:
        return 0.0
    joint = collections.Counter(zip(x, y))
    px = collections.Counter(x); py = collections.Counter(y)
    mi = 0.0
    for (a, b), c in joint.items():
        mi += (c / n) * np.log2(c * n / (px[a] * py[b]))
    return mi

def leak_test(delay_bins, phase_bins, n_perm, rng):
    mi = mutual_info(delay_bins.tolist(), phase_bins.tolist())
    null = np.empty(n_perm)
    for i in range(n_perm):
        null[i] = mutual_info(delay_bins.tolist(), rng.permutation(phase_bins).tolist())
    p = (1 + np.sum(null >= mi)) / (n_perm + 1)
    return mi, mi - null.mean(), p, np.percentile(null, 95)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("items", nargs="+", help="label=path.csv")
    ap.add_argument("--delay-bin-us", type=int, default=500)
    ap.add_argument("--phase-bin-us", type=int, default=1000)
    ap.add_argument("--perm", type=int, default=2000)
    ap.add_argument("--boot", type=int, default=500)
    ap.add_argument("--control-offset-us", type=int, default=None)
    ap.add_argument("--plot", default=None)
    a = ap.parse_args()
    rng = np.random.default_rng(0)

    groups = collections.defaultdict(list)
    for it in a.items:
        lab, path = it.split("=", 1)
        groups[lab].append(load(path, a.control_offset_us))

    summary = {}
    for lab, runs in groups.items():
        delay = np.concatenate([r["start"] - r["planned"] for r in runs])
        run_t = np.concatenate([r["end"] - r["start"] for r in runs])
        phase = np.concatenate([((r["planned"] - r["offset"]) % r["period"]) for r in runs])
        d_bins = delay // a.delay_bin_us
        ph_bins = phase // a.phase_bin_us
        mi, mi_corr, p, null95 = leak_test(d_bins, ph_bins, a.perm, rng)
        finish = np.concatenate([r["end"] - r["planned"] for r in runs])
        f_bins = finish // a.delay_bin_us
        fmi, fmi_corr, fp, _ = leak_test(f_bins, ph_bins, a.perm, rng)
        summary[lab] = dict(delay=delay, run=run_t, phase=phase, mi=mi, mi_corr=mi_corr, p=p, null95=null95,
                            d_bins=d_bins, f_bins=f_bins, ph_bins=ph_bins, fmi_corr=fmi_corr, fp=fp,
                            mi_max=np.log2(max(len(set(ph_bins.tolist())), 1)))
        guard_info = [r["meta"].get("s11_after") for r in runs]
        print(f"\n[{lab}] runs={len(runs)} jobs={len(delay)} {'(WARNING: <500 jobs)' if len(delay) < 500 else ''}")
        print(f"  S11 after run: {guard_info}")
        print(f"  start delay   mean {delay.mean()/1000:.2f} ms  p95 {np.percentile(delay,95)/1000:.2f} ms  max {delay.max()/1000:.2f} ms")
        print(f"  run time      mean {run_t.mean()/1000:.2f} ms  p95 {np.percentile(run_t,95)/1000:.2f} ms")
        print(f"  release phases seen (ms after CONTROL release): "
              f"{sorted(collections.Counter((phase // 1000).tolist()).items())}")
        for ph in sorted(set((phase // 1000).tolist())):
            m = (phase // 1000) == ph
            print(f"    phase {ph:2d} ms: n={m.sum():4d}  mean delay {delay[m].mean()/1000:.2f} ms")
        mi_max = summary[lab]["mi_max"]
        print(f"  leak via start delay:  I = {mi:.4f} bits, bias-corrected {mi_corr:.4f} bits, "
              f"permutation p = {p:.4g} (null 95th pct {null95:.4f}); max possible {mi_max:.2f} bits")
        print(f"  leak via finish delay: bias-corrected {fmi_corr:.4f} bits, permutation p = {fp:.4g}")
        if mi_max > 0 and fmi_corr >= 0.95 * mi_max:
            print(f"  NOTE: finish delay already reveals CONTROL phase completely ({fmi_corr:.2f} of {mi_max:.2f} bits); "
                  "with this few release phases the metric is saturated and cannot show extra leakage.")

    labs = list(summary)
    if "none" in summary and "guard" in summary:
        ks = stats.ks_2samp(summary["none"]["delay"], summary["guard"]["delay"])
        print(f"\nKS test start delay none vs guard: D={ks.statistic:.3f}, p={ks.pvalue:.3g}")
        g, n = summary["guard"], summary["none"]
        # Is the guard-minus-none MI difference real? Bootstrap jobs within each condition.
        for key, name in [("d_bins", "start delay"), ("f_bins", "finish delay")]:
            diffs = np.empty(a.boot)
            for i in range(a.boot):
                gi = rng.integers(0, len(g[key]), len(g[key])); ni = rng.integers(0, len(n[key]), len(n[key]))
                diffs[i] = (mutual_info(g[key][gi].tolist(), g["ph_bins"][gi].tolist())
                            - mutual_info(n[key][ni].tolist(), n["ph_bins"][ni].tolist()))
            lo, hi = np.percentile(diffs, [2.5, 97.5])
            print(f"MI difference guard - none ({name}): 95% bootstrap CI [{lo:+.4f}, {hi:+.4f}] bits")
            if lo > 0:
                print(f"=> Guard ADDS timing information via {name}: measurable leak.")
            else:
                print(f"=> No significant extra timing information via {name} under the guard.")

    if a.plot:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, axes = plt.subplots(1, 2, figsize=(13, 4.8))
        bins = np.arange(0, max(s["delay"].max() for s in summary.values()) / 1000 + 0.5, 0.25)
        for lab, s in summary.items():
            axes[0].hist(s["delay"] / 1000, bins=bins, alpha=0.6, label=f"{lab} (n={len(s['delay'])})")
        axes[0].set_xlabel("UNTRUSTED start delay after its release (ms)")
        axes[0].set_ylabel("Jobs"); axes[0].set_title("What the attacker observes: its own start delay")
        axes[0].legend(); axes[0].grid(alpha=0.3)
        x = np.arange(len(labs))
        axes[1].bar(x, [summary[l]["mi_corr"] for l in labs], color=["#4a90e2", "#9b59b6", "#5cb85c", "#d9534f"][:len(labs)],
                    edgecolor="black")
        for i, l in enumerate(labs):
            axes[1].text(i, summary[l]["mi_corr"], f"p={summary[l]['p']:.3g}", ha="center", va="bottom", fontsize=9)
        axes[1].axhline(0, color="black", linewidth=0.8)
        axes[1].set_xticks(x); axes[1].set_xticklabels(labs)
        axes[1].set_ylabel("Bias-corrected MI (bits)")
        axes[1].set_title("Leak: information about CONTROL phase in the delay")
        axes[1].grid(axis="y", alpha=0.3)
        plt.tight_layout(); plt.savefig(a.plot, dpi=200); plt.close()
        print(f"saved {a.plot}")
