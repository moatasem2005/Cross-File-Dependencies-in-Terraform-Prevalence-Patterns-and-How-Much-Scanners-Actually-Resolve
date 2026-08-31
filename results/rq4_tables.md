# RQ4 tables (generated from rq4_results.json)

## P1_s3_public_acl

| Construct | checkov | tfsec | terrascan | trivy |
|---|---|---|---|---|
| **INTRA-MODULE MULTI-FILE RESOLUTION** |  |  |  |  |
| C1  Variable default (separate file) | RESOLVED | RESOLVED | RESOLVED | RESOLVED |
| C2  Local value (separate file) | RESOLVED | RESOLVED | RESOLVED | RESOLVED |
| C3  terraform.tfvars | RESOLVED | NOT | NOT | NOT |
| C7  override.tf (last-wins merge) | NOT | NOT | NOT | NOT |
| **INTER-MODULE VALUE PROPAGATION** |  |  |  |  |
| C4  Module input (root -> module) | RESOLVED | NOT | RESOLVED | NOT |
| C5  Module output chaining | RESOLVED | NOT | NOT | NOT |
| C6  Nested modules (two levels) | RESOLVED | NOT | NOT | NOT |

## P2_sg_open_ingress

| Construct | checkov | tfsec | terrascan | trivy |
|---|---|---|---|---|
| **INTRA-MODULE MULTI-FILE RESOLUTION** |  |  |  |  |
| C1  Variable default (separate file) | RESOLVED | RESOLVED | RESOLVED | RESOLVED |
| C2  Local value (separate file) | RESOLVED | RESOLVED | RESOLVED | RESOLVED |
| C3  terraform.tfvars | RESOLVED | NOT | NOT | NOT |
| C7  override.tf (last-wins merge) | RESOLVED | RESOLVED | NOT | RESOLVED |
| **INTER-MODULE VALUE PROPAGATION** |  |  |  |  |
| C4  Module input (root -> module) | RESOLVED | NOT | RESOLVED | NOT |
| C5  Module output chaining | RESOLVED | NOT | NOT | NOT |
| C6  Nested modules (two levels) | RESOLVED | NOT | NOT | NOT |
