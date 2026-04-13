"""
Base dataclass shared across all file-type analyzers.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any


@dataclass
class FileAnalysisResult:
    """
    Standardized result returned by every format-specific analyzer.

    Attributes:
        file_type      : Detected file type label (e.g. "PE32", "PDF", "OLE-Office")
        risk_score     : Aggregated risk for this file, 0–100
        findings       : Human-readable descriptions of each detected indicator
        indicators     : Machine-readable key-value map of raw findings
        mime_mismatch  : True when the actual MIME differs from the declared content_type
    """

    file_type: str = "Unknown"
    risk_score: float = 0.0
    findings: List[str] = field(default_factory=list)
    indicators: Dict[str, Any] = field(default_factory=dict)
    mime_mismatch: bool = False
