"""Day-1 Capture Analysis module for MAARS Milestone 4 (Guard-Leakage Analysis).
Provides functions to load captures, extract UNTRUSTED grants, compute phase histograms,
evaluate chi-square uniformity, and compute inferability ratios (IR).
"""
import csv
import json
from pathlib import Path
import numpy as np
from scipy import stats

COL_T = "start_us"
COL_EV = "kind"
COL_TASK = "worker"
COL_DUR = "end_us"

def load(path):
    p = Path(path)
    meta = {}
    meta_p = p.with_suffix(".meta.json")
    if meta_p.exists():
        try:
            meta = json.loads(meta_p.read_text(encoding="utf-8"))
        except Exception:
            pass
            
    rows = []
    with p.open(newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            parsed = {}
            for k, v in row.items():
                try:
                    parsed[k] = int(v)
                except ValueError:
                    try:
                        parsed[k] = float(v)
                    except ValueError:
                        parsed[k] = v
            rows.append(parsed)
    return {"meta": meta, "rows": rows, "path": p}

def grants(record):
    """Extract all UNTRUSTED task execution grants from the capture record."""
    res = []
    rows = record.get("rows", [])
    for r in rows:
        # Check standard capture format: kind=='G' and worker==4 (UNTRUSTED)
        kind = r.get("kind", r.get(COL_EV, ""))
        worker = r.get("worker", r.get(COL_TASK, ""))
        task = r.get("task", "")
        
        is_grant = (kind == "G" or kind == "grant" or kind == "EVT")
        is_untrusted = (worker == 4 or worker == "4" or worker == "UNTRUSTED" or task == "UNTRUSTED")
        
        if is_grant and is_untrusted:
            start = r.get("start_us", r.get(COL_T, 0))
            end = r.get("end_us", r.get(COL_DUR, start))
            res.append({"start_us": start, "end_us": end, "raw": r})
    return res

def phase_hist(record, period_us, bin_us=1000):
    """Compute phase histogram of UNTRUSTED grants relative to CONTROL period."""
    num_bins = int(round(period_us / bin_us))
    hist = np.zeros(num_bins, dtype=int)
    gs = grants(record)
    if not gs:
        return hist
        
    # Find initial anchor timestamp (e.g. first grant or capture start)
    start_anchor = record.get("meta", {}).get("start_us", gs[0]["start_us"])
    
    for g in gs:
        t = g["start_us"] - start_anchor
        phase = (t % period_us + period_us) % period_us
        bin_idx = int(phase // bin_us) % num_bins
        hist[bin_idx] += 1
    return hist

def chi2_uniform(hist):
    """Perform chi-square test against uniform distribution.
    Returns (chi2_statistic, p_value).
    """
    h = np.asarray(hist, dtype=float)
    total = np.sum(h)
    if total == 0 or len(h) <= 1:
        return 0.0, 1.0
    expected = np.full_like(h, total / len(h))
    # Pearson chi-square statistic: sum((O - E)^2 / E)
    chi2_stat = np.sum((h - expected) ** 2 / expected)
    df = len(h) - 1
    p_val = stats.chi2.sf(chi2_stat, df)
    return float(chi2_stat), float(p_val)

def inferability_ratio(record, period_us):
    """Compute ladder-based Inferability Ratio (IR).
    IR measures the degree of timing predictability of the schedule:
    IR = 0 means completely uniform/unpredictable;
    IR -> 1 means deterministic timing alignment (leaked schedule).
    """
    h = phase_hist(record, period_us, bin_us=1000)
    total = np.sum(h)
    if total == 0:
        return 0.0
    probs = h / total
    probs = probs[probs > 0]
    entropy = -np.sum(probs * np.log2(probs))
    max_entropy = np.log2(len(h))
    if max_entropy == 0:
        return 0.0
    ir = 1.0 - (entropy / max_entropy)
    return float(ir)
