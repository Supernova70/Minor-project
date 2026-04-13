"""
Office Document Analyzer — Static analysis for Microsoft Office files.

Handles two formats:
  1. OLE (Legacy): .doc, .xls, .ppt — analyzed with `olefile`
  2. OOXML (Modern): .docx, .xlsx, .pptx — ZIP-based; analyzed by inspecting internal structure

Checks performed:
  - Presence of VBA/macro streams
  - Auto-run macro names (Document_Open, Auto_Open, Workbook_Open, etc.)
  - External DDE links
  - Presence of embedded OLE objects
"""

import io
import logging
import zipfile
from typing import List

from app.engines.analyzers.base import FileAnalysisResult

logger = logging.getLogger(__name__)

# Macro auto-execution entry points — any of these = high risk
AUTO_RUN_MACROS = {
    "auto_open",
    "autoopen",
    "document_open",
    "documentopen",
    "workbook_open",
    "workbookopen",
    "auto_close",
    "autoclose",
    "document_close",
    "documentclose",
    "auto_exec",
    "autoexec",
    "auto_new",
    "autonew",
}

# OLE stream names indicating macro presence
MACRO_STREAMS = {"vba_project", "_vba_project", "vbaproject"}


def _analyze_ole(data: bytes, filename: str) -> FileAnalysisResult:
    """Analyze a legacy OLE compound document (.doc, .xls, .ppt)."""
    result = FileAnalysisResult(file_type="OLE-Office")
    risk_score = 0.0
    findings: List[str] = []
    indicators: dict = {
        "has_macros": False,
        "auto_run_macros": [],
        "streams": [],
        "embedded_objects": False,
    }

    try:
        import olefile  # Lazy import

        if not olefile.isOleFile(data):
            findings.append("File is not a valid OLE compound document")
            result.findings = findings
            result.indicators = indicators
            return result

        ole = olefile.OleFileIO(io.BytesIO(data))

        # ── List all streams ──────────────────────────────────────
        all_entries = ole.listdir()
        stream_names_lower = {
            "/".join(e).lower() for e in all_entries
        }
        indicators["streams"] = ["/".join(e) for e in all_entries[:20]]  # Cap for brevity

        # ── Macro detection ───────────────────────────────────────
        has_macros = any(
            any(m in part.lower() for m in MACRO_STREAMS)
            for entry in all_entries
            for part in entry
        )
        indicators["has_macros"] = has_macros

        if has_macros:
            findings.append("VBA macro project stream detected in OLE document")
            risk_score += 40.0

            # Try to read macro source for auto-run names
            try:
                import olevba_safe  # Not available — use raw stream heuristic
            except ImportError:
                pass

            # Heuristic: look for auto-run names in the raw VBA stream bytes
            vba_stream = None
            for stream_path in [["Macros", "VBA", "Module1"], ["_VBA_PROJECT_CUR", "VBA", "ThisDocument"]]:
                if ole.exists(stream_path):
                    try:
                        vba_stream = ole.openstream(stream_path).read()
                        break
                    except Exception:
                        pass

            # Fallback — read entire file bytes for keyword matches
            raw_lower = data.lower()
            found_auto: List[str] = []
            for macro_name in AUTO_RUN_MACROS:
                if macro_name.encode() in raw_lower:
                    found_auto.append(macro_name)

            if found_auto:
                indicators["auto_run_macros"] = found_auto
                findings.append(
                    f"Auto-run macro names detected: {', '.join(found_auto)} — will execute on open"
                )
                risk_score += 35.0

        # ── Embedded OLE objects ──────────────────────────────────
        if ole.exists("ObjectPool") or any("objectpool" in "/".join(e).lower() for e in all_entries):
            indicators["embedded_objects"] = True
            findings.append("Embedded OLE objects found — possible dropper")
            risk_score += 20.0

        # ── DDE links (raw bytes heuristic) ──────────────────────
        if b"DDEAUTO" in data or b"DDE(" in data:
            findings.append("DDE/DDEAUTO link detected — can trigger external command execution")
            risk_score += 30.0

        ole.close()

    except ImportError:
        logger.warning("olefile not installed — OLE analysis skipped")
        findings.append("OLE analysis skipped: olefile library not available")
    except Exception as e:
        logger.error(f"OLE analysis error on {filename}: {e}")
        findings.append(f"OLE analysis error: {type(e).__name__}")

    result.risk_score = min(100.0, round(risk_score, 1))
    result.findings = findings
    result.indicators = indicators
    return result


def _analyze_ooxml(data: bytes, filename: str) -> FileAnalysisResult:
    """Analyze a modern OOXML document (.docx, .xlsx, .pptx — ZIP-based)."""
    result = FileAnalysisResult(file_type="OOXML-Office")
    risk_score = 0.0
    findings: List[str] = []
    indicators: dict = {
        "has_macros": False,
        "auto_run_macros": [],
        "external_rels": [],
        "embedded_objects": False,
    }

    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        names_lower = [n.lower() for n in zf.namelist()]

        # ── VBA macro detection ───────────────────────────────────
        if any("vbaproject.bin" in n for n in names_lower):
            indicators["has_macros"] = True
            findings.append("vbaProject.bin found in OOXML archive — document contains VBA macros")
            risk_score += 40.0

            # Read the embedded VBA binary for auto-run keywords
            for n in zf.namelist():
                if "vbaproject.bin" in n.lower():
                    try:
                        vba_bytes = zf.read(n).lower()
                        found_auto = [
                            m for m in AUTO_RUN_MACROS if m.encode() in vba_bytes
                        ]
                        if found_auto:
                            indicators["auto_run_macros"] = found_auto
                            findings.append(
                                f"Auto-run macros in vbaProject.bin: {', '.join(found_auto)}"
                            )
                            risk_score += 35.0
                    except Exception:
                        pass

        # ── External relationship links ───────────────────────────
        for n in zf.namelist():
            if n.endswith(".rels"):
                try:
                    content = zf.read(n).decode("utf-8", errors="replace")
                    if "http://" in content or "https://" in content or "file://" in content:
                        indicators["external_rels"].append(n)
                        findings.append(
                            f"External relationship link in {n} — possible template injection"
                        )
                        risk_score += 20.0
                except Exception:
                    pass

        # ── Embedded OLE objects ──────────────────────────────────
        if any("embeddings" in n for n in names_lower):
            indicators["embedded_objects"] = True
            findings.append("Embedded objects found in OOXML archive")
            risk_score += 15.0

        zf.close()

    except zipfile.BadZipFile:
        findings.append("File claims to be OOXML but is not a valid ZIP archive")
        risk_score += 10.0
    except Exception as e:
        logger.error(f"OOXML analysis error on {filename}: {e}")
        findings.append(f"OOXML analysis error: {type(e).__name__}")

    result.risk_score = min(100.0, round(risk_score, 1))
    result.findings = findings
    result.indicators = indicators
    return result


def analyze_office(data: bytes, filename: str, is_ooxml: bool = False) -> FileAnalysisResult:
    """
    Route to the correct Office analyzer based on format.

    Args:
        data    : Raw file bytes
        filename: Original filename
        is_ooxml: True for .docx/.xlsx/.pptx (ZIP-based), False for .doc/.xls/.ppt (OLE)
    """
    if is_ooxml:
        return _analyze_ooxml(data, filename)
    else:
        return _analyze_ole(data, filename)
