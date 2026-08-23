"""Miskatonic external review authority."""

__version__ = "0.1.0"

from .attestation_ledger_verifier import verify_execution_evidence_attestation

__all__ = [
    "__version__",
    "verify_execution_evidence_attestation",
]
