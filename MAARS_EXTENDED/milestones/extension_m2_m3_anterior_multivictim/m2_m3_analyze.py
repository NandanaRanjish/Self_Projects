"""MILESTONES 2 & 3 shared analyzer.
M2 (anterior vs posterior): compare corruption rate + guard effectiveness for two attack
  models against the SAME victim, matched attacker budget (same #fire attempts).
M3 (multi-victim SVI): compute a weighted Schedule Vulnerability Index across CONTROL and
  SAFETY using their measured attack probabilities and criticality weights (paper Def. 4).
Usage:
  M2: python m2_m3_analyze.py m2 --posterior post.csv --anterior ant.csv
  M3: python m2_m3_analyze.py m3 --control ctrl.csv --safety safety.csv --crit 2 1
Each input CSV: one row per command/job, columns: valid(0/1),corrupted(0/1),fired(0/1)
(fired = attacker attempted on this instance; use 1 for every row if you log attempts per-row)."""
import csv, argparse, numpy as np
from scipy.stats import fisher_exact

def load(path):
    rows = list(csv.DictReader(open(path)))
    v = np.array([int(r["valid"]) for r in rows])
    c = np.array([int(r["corrupted"]) for r in rows])
    f = np.array([int(r.get("fired", 1)) for r in rows])
    return v, c, f

def wilson(k, n, z=1.96):
    if n == 0: return (float("nan"),) * 2
    p = k / n; d = 1 + z*z/n; ctr = (p + z*z/(2*n)) / d; h = z*np.sqrt(p*(1-p)/n + z*z/(4*n*n)) / d
    return 100*(ctr-h), 100*(ctr+h)

def m2(post_path, ant_path):
    for lab, path in [("posterior", post_path), ("anterior", ant_path)]:
        v, c, f = load(path)
        n = v.sum(); k = (c & v.astype(bool)).sum(); fires = f.sum()
        lo, hi = wilson(k, n)
        print(f"{lab:10s} valid={n:4d} corrupted={k:3d} ({100*k/n:5.2f}%, 95% CI [{lo:.2f},{hi:.2f}]) "
              f"fires={fires:4d} success/fire={k/max(fires,1):.3f}")
    v1, c1, _ = load(post_path); v2, c2, _ = load(ant_path)
    k1, n1 = (c1 & v1.astype(bool)).sum(), v1.sum(); k2, n2 = (c2 & v2.astype(bool)).sum(), v2.sum()
    p = fisher_exact([[k1, n1-k1], [k2, n2-k2]])[1]
    print(f"\nFisher exact test posterior vs anterior corruption rate: p={p:.4g}")
    print("(Guard built only for posterior window: if anterior corruption stays high, that's the blind spot.)")

def m3(ctrl_path, safety_path, crit):
    results = {}
    for name, path in [("CONTROL", ctrl_path), ("SAFETY", safety_path)]:
        v, c, _ = load(path); n = v.sum(); k = (c & v.astype(bool)).sum()
        ap = k / n if n else float("nan")
        results[name] = ap; lo, hi = wilson(k, n)
        print(f"{name:8s} AP = {ap:.4f}  ({k}/{n}, 95% CI [{lo:.2f}%,{hi:.2f}%])")
    c1, c2 = crit; cl1, cl2 = c1 / (c1 + c2), c2 / (c1 + c2)
    svi = results["CONTROL"] * cl1 + results["SAFETY"] * cl2
    print(f"\ncriticality levels: CONTROL={cl1:.3f} SAFETY={cl2:.3f}")
    print(f"two-task Schedule Vulnerability Index (paper Def. 4): SVI = {svi:.4f}")
    print("(compare this against your existing CONTROL-only SVI to show it changes the ranking.)")

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); sub = ap.add_subparsers(dest="cmd", required=True)
    p2 = sub.add_parser("m2"); p2.add_argument("--posterior", required=True); p2.add_argument("--anterior", required=True)
    p3 = sub.add_parser("m3"); p3.add_argument("--control", required=True); p3.add_argument("--safety", required=True)
    p3.add_argument("--crit", type=float, nargs=2, default=[2, 1], metavar=("C_CONTROL", "C_SAFETY"))
    a = ap.parse_args()
    if a.cmd == "m2": m2(a.posterior, a.anterior)
    else: m3(a.control, a.safety, a.crit)
