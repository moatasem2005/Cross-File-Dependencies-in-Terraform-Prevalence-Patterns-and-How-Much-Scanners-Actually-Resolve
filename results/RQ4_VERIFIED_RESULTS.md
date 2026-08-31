# RQ4 — verified results (complete four-scanner run)

Produced by `src/rq4_experiment.py` with the four-part oracle, expected-resource-address
matching, distinct ERROR/INCONCLUSIVE/NOT_RESOLVED verdicts, and pre-scan HCL validation.
All generated cases passed validation; 249 tool executions were captured.

**Tool versions (resolved at install time, recorded in `rq4_manifest.json`):**
Checkov 3.3.13 · tfsec v1.28.14 · Terrascan v1.19.9 · Trivy 0.74.0

## P2 — open security-group ingress

| Construct | Level | Checkov | tfsec | Terrascan | Trivy |
|---|---|---|---|---|---|
| C1 variable default | intra-module | R | R | R | R |
| C2 local value | intra-module | R | R | R | R |
| C3 terraform.tfvars | intra-module | R | — | — | — |
| C7 override.tf | intra-module | R | R | — | R |
| C4 module input | inter-module | R | — | R | — |
| C5 module output chaining | inter-module | R | — | — | — |
| C6 nested modules | inter-module | R | — | — | — |

## P1 — S3 public-read ACL (independent replication)

Identical to P2 except **C7 override.tf**, which no tool resolves under P1.

## Headline

Capability is **graded**, not binary:

1. **Universal** — every scanner resolves a variable default or a local in a separate file.
2. **Divergent** — `terraform.tfvars` is resolved only by Checkov, in both properties.
3. **Inter-module** — full support only in Checkov; Terrascan resolves the single-hop
   module input but not output chaining or nesting; tfsec and Trivy resolve none.

Override files sit outside the ordering: property-dependent, and not reliable in either
direction.

## Why the earlier scripts were superseded

The exploratory `phase6*` scripts under `../src/deprecated/` compared only sets of rule
identifiers, without matching the resource address a finding attaches to. When a rule also
fires on an unrelated resource in the control run, the set difference is empty and the
construct is scored NOT RESOLVED even though the value was in fact resolved.

Two verdicts change once the address is matched:

- tools other than Checkov resolve variable defaults across files, not only same-scope
  locals;
- Terrascan resolves the direct module-input construct.

The canonical experiment matches on `(rule, resource address)` and is the only run these
results come from.
