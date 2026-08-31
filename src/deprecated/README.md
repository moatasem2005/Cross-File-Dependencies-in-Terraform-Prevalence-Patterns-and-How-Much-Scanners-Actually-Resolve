# Deprecated RQ4 scripts

These are the exploratory iterations that led to the canonical experiment. They are
retained for transparency about how the design evolved (and about two measurement
defects that were found and corrected), but **none of them backs a claim in the paper**.

Use `../rq4_experiment.py` instead.

| Script | Why superseded |
|---|---|
| `phase6_checkov_experiment.py` | Filtered findings by an `acl` substring, which missed `CKV_AWS_20` and produced a spurious blind-spot signal. |
| `phase6b_checkov_controlled.py` | Introduced the control/treatment/inline design; single tool only. |
| `phase6c_boundary.py` | Compared `(rule, address)` pairs without normalising module prefixes, mislabelling module constructs as PARTIAL. |
| `phase6d_boundary_corrected.py` | Fixed the prefix issue; single tool, single check. |
| `phase6e_multitool.py` | Added tfsec/KICS; no address matching, no error separation. |
| `phase6f_expanded_rq4.py` | Added tools and properties; compared rule-ID sets only; unsound encryption probe. |
| `phase6g_verify.py` | Hardening attempt; invalid compact HCL silently broke parsing for two properties. |

The canonical script fixes all of the above: expected-address matching, distinct
ERROR/INCONCLUSIVE/NOT_RESOLVED verdicts, captured tool output, an environment
manifest, and pre-scan HCL validation.
