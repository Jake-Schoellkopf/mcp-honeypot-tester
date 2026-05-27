"""
Before/After Comparison Reports

Save scan results as a baseline, then compare future scans against it.
Shows: fixed findings, new findings, unchanged findings.

Usage:
    python compare.py --save baseline --results reports/findings_2026-05-26.json
    python compare.py --compare baseline --results reports/findings_2026-05-27.json

Requires: Python 3.12+
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

BASELINES_DIR = Path("baselines")


def save_baseline(name: str, results_path: str):
    """Save a scan result as a named baseline."""
    BASELINES_DIR.mkdir(exist_ok=True)
    results = json.loads(Path(results_path).read_text(encoding="utf-8"))
    baseline = {
        "name": name,
        "saved": datetime.now().isoformat(),
        "source": results_path,
        "findings": results.get("findings", results if isinstance(results, list) else []),
    }
    path = BASELINES_DIR / f"{name}.json"
    path.write_text(json.dumps(baseline, indent=2), encoding="utf-8")
    print(f"  Baseline saved: {path} ({len(baseline['findings'])} findings)")


def compare_to_baseline(name: str, results_path: str):
    """Compare current results against a saved baseline."""
    baseline_path = BASELINES_DIR / f"{name}.json"
    if not baseline_path.exists():
        print(f"  Baseline '{name}' not found. Save one first with --save.")
        return

    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    current = json.loads(Path(results_path).read_text(encoding="utf-8"))
    current_findings = current.get("findings", current if isinstance(current, list) else [])
    baseline_findings = baseline["findings"]

    # Create fingerprints for comparison
    def fingerprint(f: dict) -> str:
        return f"{f.get('category', '')}|{f.get('title', '')}|{f.get('severity', '')}"

    baseline_fps = {fingerprint(f) for f in baseline_findings}
    current_fps = {fingerprint(f) for f in current_findings}

    fixed = baseline_fps - current_fps
    new = current_fps - baseline_fps
    unchanged = baseline_fps & current_fps

    print(f"\n  {'═' * 50}")
    print(f"  COMPARISON: current vs '{name}' baseline")
    print(f"  {'═' * 50}")
    print(f"  Baseline: {len(baseline_findings)} findings ({baseline['saved'][:10]})")
    print(f"  Current:  {len(current_findings)} findings")
    print()
    print(f"  \U00002705 Fixed:     {len(fixed)}")
    print(f"  \U0001f534 New:       {len(new)}")
    print(f"  \U00002796 Unchanged: {len(unchanged)}")

    if fixed:
        print(f"\n  FIXED (no longer present):")
        for fp in fixed:
            parts = fp.split("|")
            print(f"    \U00002705 [{parts[2].upper()}] {parts[0]}: {parts[1]}")

    if new:
        print(f"\n  NEW (not in baseline):")
        for fp in new:
            parts = fp.split("|")
            print(f"    \U0001f534 [{parts[2].upper()}] {parts[0]}: {parts[1]}")

    # Generate HTML diff report
    generate_diff_html(name, baseline_findings, current_findings, fixed, new, unchanged)

    print(f"\n  {'═' * 50}")
    if not new and fixed:
        print(f"  RESULT: IMPROVED \U00002705 ({len(fixed)} findings fixed, 0 new)")
    elif new and not fixed:
        print(f"  RESULT: REGRESSED \U0001f534 ({len(new)} new findings)")
    elif new and fixed:
        print(f"  RESULT: MIXED ({len(fixed)} fixed, {len(new)} new)")
    else:
        print(f"  RESULT: NO CHANGE")


def generate_diff_html(name: str, baseline: list, current: list, fixed: set, new: set, unchanged: set):
    """Generate HTML comparison report."""
    Path("reports").mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    path = Path("reports") / f"comparison_{name}_{timestamp}.html"

    def esc(t): return str(t).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    fixed_html = "".join(f'<div class="item fixed">\U00002705 {esc(fp)}</div>' for fp in fixed)
    new_html = "".join(f'<div class="item new">\U0001f534 {esc(fp)}</div>' for fp in new)
    unchanged_html = "".join(f'<div class="item unchanged">\U00002796 {esc(fp)}</div>' for fp in list(unchanged)[:20])

    html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Comparison: {name}</title>
<style>*{{margin:0;padding:0;box-sizing:border-box}}body{{font-family:system-ui;background:#0f1117;color:#e1e4e8;padding:2rem}}
.container{{max-width:800px;margin:0 auto}}h1{{color:#58a6ff;margin-bottom:1rem}}
.stats{{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem;margin:1.5rem 0}}
.stat{{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:1rem;text-align:center}}
.stat .n{{font-size:2rem;font-weight:700}}
h2{{margin:1.5rem 0 0.5rem;color:#bc8cff}}
.item{{padding:0.4rem 0.8rem;margin:0.3rem 0;border-radius:4px;font-size:0.8rem;font-family:monospace}}
.fixed{{background:#3fb95015;border-left:3px solid #3fb950}}
.new{{background:#f8514915;border-left:3px solid #f85149}}
.unchanged{{background:#8b949e10;border-left:3px solid #8b949e}}</style></head>
<body><div class="container">
<h1>Before/After Comparison</h1>
<p style="color:#8b949e">Baseline: {name} | Date: {timestamp}</p>
<div class="stats">
<div class="stat"><div class="n" style="color:#3fb950">{len(fixed)}</div>Fixed</div>
<div class="stat"><div class="n" style="color:#f85149">{len(new)}</div>New</div>
<div class="stat"><div class="n" style="color:#8b949e">{len(unchanged)}</div>Unchanged</div>
</div>
<h2>Fixed</h2>{fixed_html or '<p style="color:#8b949e">None</p>'}
<h2>New</h2>{new_html or '<p style="color:#8b949e">None</p>'}
<h2>Unchanged</h2>{unchanged_html or '<p style="color:#8b949e">None</p>'}
</div></body></html>"""

    path.write_text(html, encoding="utf-8")
    print(f"  Diff report: {path}")


def main():
    parser = argparse.ArgumentParser(description="Before/After Comparison")
    parser.add_argument("--save", help="Save results as named baseline")
    parser.add_argument("--compare", help="Compare results against named baseline")
    parser.add_argument("--results", required=True, help="Path to findings JSON file")
    args = parser.parse_args()

    if args.save:
        save_baseline(args.save, args.results)
    elif args.compare:
        compare_to_baseline(args.compare, args.results)
    else:
        print("Use --save NAME or --compare NAME")


if __name__ == "__main__":
    main()
