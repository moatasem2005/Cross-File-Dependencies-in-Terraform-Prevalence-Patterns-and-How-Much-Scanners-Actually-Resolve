"""
core.py — canonical shared logic for the cross-file Terraform study.

Every phase imports from here. Previously classify_source(), path resolution, and the
security-sensitive resource set were re-implemented in five separate scripts, which
risked the definitions drifting apart and the reported RQ1-RQ3 numbers becoming
mutually inconsistent. This module is the single source of truth.

Public API
----------
classify_source(source)              -> category string
is_cross_file(category)              -> bool
normalise_module_path(path)          -> canonical repo-relative path
resolve_local_module(src_dir, source, path_index) -> (target, resolved: bool)
SECURITY_SENSITIVE_RESOURCES         -> frozenset of resource type names
SECURITY_DOMAIN                      -> resource type -> control domain
"""
from __future__ import annotations
import os
import re

# --------------------------------------------------------------------------
# Dependency source taxonomy (RQ2)
# --------------------------------------------------------------------------
LOCAL_SUBDIR = "local_subdir"
LOCAL_TRAVERSAL = "local_traversal"
REGISTRY = "registry"
VCS_REMOTE = "vcs_remote"
HTTP_REMOTE = "http_remote"
CLOUD_BUCKET = "cloud_bucket"
OTHER = "other"

CROSS_FILE_CATEGORIES = frozenset({LOCAL_SUBDIR, LOCAL_TRAVERSAL})

_REGISTRY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+$")


def classify_source(source: str) -> str:
    """Classify a Terraform module `source` string into one taxonomy category.

    Deterministic: the category is a function of the source string alone.
    """
    s = (source or "").strip()
    if not s:
        return OTHER
    # Terraform accepts both POSIX and Windows-style relative paths; normalise the
    # separator before classifying so that ".\\modules\\x" is treated as "./modules/x".
    # Omitting this under-counted local sources in an earlier version of the pipeline.
    s_norm = s.replace("\\", "/")
    if s_norm.startswith("./"):
        return LOCAL_SUBDIR
    if s_norm.startswith("../"):
        return LOCAL_TRAVERSAL
    if s.startswith(("git::", "github.com", "git@")) or ".git" in s:
        return VCS_REMOTE
    if s.startswith(("http://", "https://")):
        return HTTP_REMOTE
    if s.startswith(("s3::", "gcs::", "oss::")):
        return CLOUD_BUCKET
    if _REGISTRY_RE.match(s) and not s.startswith("."):
        return REGISTRY
    return OTHER


def is_cross_file(category: str) -> bool:
    """True for intra-repository categories that cross a file/directory boundary."""
    return category in CROSS_FILE_CATEGORIES


# --------------------------------------------------------------------------
# Path resolution (Algorithm 1 in the paper)
# --------------------------------------------------------------------------
def normalise_module_path(path: str) -> str:
    """Canonical repo-relative module directory path."""
    p = (path or "").strip().replace("\\", "/").strip("/")
    if p.startswith("./"):
        p = p[2:]
    return p


def resolve_local_module(src_dir: str, source: str, path_index) -> tuple[str, bool]:
    """Resolve a local module `source` declared from module directory `src_dir`.

    Returns (normalised_target_path, resolved) where `resolved` is True iff the
    target matches a module directory present in `path_index` (a set/dict of
    normalised paths for the same repository).
    """
    sd = normalise_module_path(src_dir)
    joined = os.path.normpath(os.path.join(sd, (source or "").strip())).replace("\\", "/")
    target = normalise_module_path(joined)
    return target, (target in path_index)


def unresolved_reason(src_dir: str, source: str) -> str:
    """Categorise why a local edge failed to resolve (used in Phase 7B)."""
    if not (source or "").strip():
        return "malformed_or_empty_source"
    sd = normalise_module_path(src_dir)
    joined = os.path.normpath(os.path.join(sd, source.strip())).replace("\\", "/")
    if joined.startswith("..") or normalise_module_path(joined).startswith(".."):
        return "parent_traversal_escapes_repo"
    return "target_dir_not_indexed"


# --------------------------------------------------------------------------
# Security-sensitive resource set (RQ3)
# --------------------------------------------------------------------------
# Selection criterion (see paper Section 4.4): resource types governing one of four
# control domains covered by IaC security-smell catalogues and CIS-style cloud
# benchmarks. Deliberately conservative -> RQ3 counts are lower bounds.
SECURITY_DOMAIN = {
    # Identity & access management
    "aws_iam_policy": "IAM",
    "aws_iam_policy_document": "IAM",
    "aws_iam_role": "IAM",
    "aws_iam_role_policy_attachment": "IAM",
    # Network exposure
    "aws_security_group": "Network",
    "aws_security_group_rule": "Network",
    # Data storage
    "aws_s3_bucket": "Storage",
    "aws_db_instance": "Storage",
    "azurerm_storage_account": "Storage",
    # Encryption / key management
    "aws_kms_key": "Encryption",
}

SECURITY_SENSITIVE_RESOURCES = frozenset(SECURITY_DOMAIN)


def security_domain_of(resource_type: str):
    """Control domain for a resource type, or None if not in the target set."""
    return SECURITY_DOMAIN.get(resource_type)


__all__ = [
    "classify_source", "is_cross_file", "normalise_module_path",
    "resolve_local_module", "unresolved_reason",
    "SECURITY_SENSITIVE_RESOURCES", "SECURITY_DOMAIN", "security_domain_of",
    "CROSS_FILE_CATEGORIES", "LOCAL_SUBDIR", "LOCAL_TRAVERSAL",
]
