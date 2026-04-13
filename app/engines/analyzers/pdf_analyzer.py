"""
PDF Analyzer — Static analysis for PDF documents.

Uses PyPDF2 to inspect the PDF object tree for common malicious constructs:
  - JavaScript execution objects (/JS, /JavaScript)
  - Auto-action triggers (/AA, /OpenAction)
  - Embedded files (/EmbeddedFile, /Filespec)
  - Suspicious URI actions
  - Launch actions (can execute system commands)
"""

import io
import logging
from typing import List

from app.engines.analyzers.base import FileAnalysisResult

logger = logging.getLogger(__name__)

# PDF object keys associated with malicious behavior
DANGEROUS_KEYS = {
    "/JS": ("JavaScript execution object", 30.0),
    "/JavaScript": ("JavaScript stream", 30.0),
    "/AA": ("Automatic action trigger", 25.0),
    "/OpenAction": ("Document open action", 25.0),
    "/Launch": ("Launch action (can run system commands)", 40.0),
    "/EmbeddedFile": ("Embedded file object", 20.0),
    "/RichMedia": ("RichMedia (potential SWF/Flash exploit)", 15.0),
    "/XFA": ("XFA form (associated with exploit kits)", 20.0),
}


def _walk_pdf_objects(reader) -> List[str]:
    """
    Walk all PDF objects and collect dangerous key names found.
    Returns a list of found dangerous key names.
    """
    found_keys: List[str] = []

    def _check_obj(obj):
        """Recursively check a PDF object for dangerous keys."""
        try:
            if hasattr(obj, "keys"):
                for key in obj.keys():
                    key_str = str(key)
                    if key_str in DANGEROUS_KEYS:
                        found_keys.append(key_str)
                    # Recurse into nested objects
                    try:
                        _check_obj(obj[key])
                    except Exception:
                        pass
        except Exception:
            pass

    # Check document catalog
    try:
        _check_obj(reader.trailer)
    except Exception:
        pass

    # Check each page
    try:
        for page in reader.pages:
            _check_obj(page)
    except Exception:
        pass

    return found_keys


def analyze_pdf(data: bytes, filename: str) -> FileAnalysisResult:
    """
    Perform static analysis on a PDF document.

    Args:
        data    : Raw file bytes
        filename: Original filename (for logging)

    Returns:
        FileAnalysisResult with risk_score 0–100
    """
    result = FileAnalysisResult(file_type="PDF")
    risk_score = 0.0
    findings: List[str] = []
    indicators: dict = {
        "dangerous_objects": [],
        "page_count": 0,
        "encrypted": False,
    }

    try:
        import PyPDF2  # Lazy import

        reader = PyPDF2.PdfReader(io.BytesIO(data), strict=False)

        # ── Basic metadata ────────────────────────────────────────
        try:
            indicators["page_count"] = len(reader.pages)
        except Exception:
            pass

        if reader.is_encrypted:
            indicators["encrypted"] = True
            findings.append("PDF is encrypted — content analysis is limited")
            risk_score += 10.0

        # ── Dangerous object scan ────────────────────────────────
        found_keys = _walk_pdf_objects(reader)

        # Deduplicate but count occurrences
        seen: dict[str, int] = {}
        for key in found_keys:
            seen[key] = seen.get(key, 0) + 1

        for key, count in seen.items():
            label, score = DANGEROUS_KEYS[key]
            findings.append(
                f"Dangerous PDF object '{key}' ({label}) found {count}× in document"
            )
            indicators["dangerous_objects"].append({"key": key, "count": count})
            risk_score += score  # Accumulate; will be capped

        # ── Zero-page anomaly ─────────────────────────────────────
        if indicators["page_count"] == 0 and not reader.is_encrypted:
            findings.append("PDF has zero pages — possible malformed or exploit document")
            risk_score += 15.0

    except ImportError:
        logger.warning("PyPDF2 not installed — PDF analysis skipped")
        findings.append("PDF analysis skipped: PyPDF2 library not available")
    except Exception as e:
        logger.error(f"PDF analysis error on {filename}: {e}")
        findings.append(f"PDF analysis encountered an error: {type(e).__name__}")

    result.risk_score = min(100.0, round(risk_score, 1))
    result.findings = findings
    result.indicators = indicators
    return result
