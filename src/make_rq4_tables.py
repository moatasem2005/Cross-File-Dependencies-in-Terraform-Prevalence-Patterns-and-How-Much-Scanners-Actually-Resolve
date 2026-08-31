"""
make_rq4_tables.py — emit the RQ4 result tables directly from the experiment output.

The concern is legitimate: if Table 10 / 10b are typed by hand, nothing
guarantees they match `rq4_results.json`. This script is the single path from results
from results to reported tables. It reads the JSON the canonical experiment wrote and emits:

  * rq4_tables.md        - human-readable markdown tables
  * rq4_tables.json      - machine-readable rows, consumed by the paper builder
  * rq4_tables_check.txt - a diff-able digest used by src/verify_results.py

Usage:
    python make_rq4_tables.py [path/to/rq4_results.json] [outdir]
"""
from __future__ import annotations
import json, sys, os
from collections import OrderedDict

ABBREV = {"RESOLVED": "RESOLVED", "NOT_RESOLVED": "NOT",
          "INCONCLUSIVE": "INCONC", "ERROR": "ERROR", "N/A": "N/A",
          "PARTIAL": "PARTIAL"}

LEVEL_ORDER = ["intra-module multi-file", "inter-module propagation"]
LEVEL_TITLE = {"intra-module multi-file": "INTRA-MODULE MULTI-FILE RESOLUTION",
               "inter-module propagation": "INTER-MODULE VALUE PROPAGATION"}

# Display labels (construct key -> printed row label)
LABEL = {
    "C1 variable default":       "C1  Variable default (separate file)",
    "C2 local value":            "C2  Local value (separate file)",
    "C3 terraform.tfvars":       "C3  terraform.tfvars",
    "C7 override.tf":            "C7  override.tf (last-wins merge)",
    "C4 module input":           "C4  Module input (root -> module)",
    "C5 module output chaining": "C5  Module output chaining",
    "C6 nested modules":         "C6  Nested modules (two levels)",
}


def load(path):
    with open(path) as f:
        return json.load(f)


def build_rows(results, prop, tools):
    """Rows grouped by composition level, in the reported order."""
    per_level = OrderedDict((lv, []) for lv in LEVEL_ORDER)
    # discover constructs from the first available tool
    any_tool = next(t for t in tools if t in results[prop])
    for cname, rec in results[prop][any_tool].items():
        lv = rec.get("level", LEVEL_ORDER[0])
        verdicts = []
        for t in tools:
            v = results[prop].get(t, {}).get(cname, {}).get("verdict", "N/A")
            verdicts.append(ABBREV.get(v, v))
        per_level.setdefault(lv, []).append((LABEL.get(cname, cname), verdicts))
    return per_level


def emit_markdown(results, tools, out):
    lines = ["# RQ4 tables (generated from rq4_results.json)", ""]
    for prop in results:
        lines += [f"## {prop}", "",
                  "| Construct | " + " | ".join(tools) + " |",
                  "|---" * (len(tools) + 1) + "|"]
        per_level = build_rows(results, prop, tools)
        for lv in LEVEL_ORDER:
            if not per_level.get(lv):
                continue
            lines.append(f"| **{LEVEL_TITLE[lv]}** | " + " | ".join([""] * len(tools)) + " |")
            for label, verdicts in per_level[lv]:
                lines.append(f"| {label} | " + " | ".join(verdicts) + " |")
        lines.append("")
    with open(os.path.join(out, "rq4_tables.md"), "w") as f:
        f.write("\n".join(lines))
    return lines


def emit_json(results, tools, out):
    payload = {"tools": tools, "properties": {}}
    for prop in results:
        per_level = build_rows(results, prop, tools)
        payload["properties"][prop] = [
            {"level": lv, "rows": [{"construct": lab, "verdicts": v} for lab, v in rows]}
            for lv, rows in per_level.items() if rows
        ]
    with open(os.path.join(out, "rq4_tables.json"), "w") as f:
        json.dump(payload, f, indent=2)
    return payload


def emit_check(payload, out):
    """A compact digest used to detect drift between results and reported tables."""
    lines = []
    for prop, groups in payload["properties"].items():
        lines.append(f"[{prop}] tools={','.join(payload['tools'])}")
        for g in groups:
            for r in g["rows"]:
                lines.append(f"  {r['construct']:38s} {' '.join(f'{v:>9s}' for v in r['verdicts'])}")
    txt = "\n".join(lines)
    with open(os.path.join(out, "rq4_tables_check.txt"), "w") as f:
        f.write(txt + "\n")
    return txt


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else "rq4_results.json"
    out = sys.argv[2] if len(sys.argv) > 2 else os.path.dirname(os.path.abspath(src)) or "."
    if not os.path.exists(src):
        print(f"[!] {src} not found.")
        print("    Run src/rq4_experiment.py first, then point this script at its")
        print("    rq4_results.json. The reported tables must be generated from that file.")
        sys.exit(1)
    os.makedirs(out, exist_ok=True)
    results = load(src)
    tools = sorted({t for prop in results for t in results[prop]})
    # keep the reported column order
    order = [t for t in ["checkov", "tfsec", "terrascan", "trivy"] if t in tools]
    tools = order + [t for t in tools if t not in order]

    emit_markdown(results, tools, out)
    payload = emit_json(results, tools, out)
    txt = emit_check(payload, out)
    print(txt)
    print(f"\nwritten to {out}/: rq4_tables.md, rq4_tables.json, rq4_tables_check.txt")


if __name__ == "__main__":
    main()
