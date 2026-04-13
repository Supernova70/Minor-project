"""
Attachment Analyzer Engine — Orchestrates per-file static analysis.

Scans email attachments using format-specific sub-analyzers:
  - PE/EXE   → pe_analyzer    (pefile)
  - PDF      → pdf_analyzer   (PyPDF2)
  - OLE Doc  → office_analyzer (olefile)
  - OOXML    → office_analyzer (zipfile)
  - Other    → generic_analyzer (stdlib only)

After format-specific analysis, EVERY file is also scanned by the YARA engine:
  - YARA rules live in app/engines/rules/*.yar
  - Add or edit .yar files to customize detection without touching Python code
  - YARA score is blended with the heuristic score (max wins)

Usage (mirrors text_analyzer.py pattern):
    from app.engines.attachment_analyzer import AttachmentAnalyzer

    analyzer = AttachmentAnalyzer()
    result = analyzer.analyze(email.attachments)
    print(result.attachment_score)
"""

import io
import logging
import os
from dataclasses import dataclass, field
from typing import List, Optional, TYPE_CHECKING

from app.config import get_settings
from app.engines.analyzers.base import FileAnalysisResult
from app.engines.analyzers.pe_analyzer import analyze_pe
from app.engines.analyzers.pdf_analyzer import analyze_pdf
from app.engines.analyzers.office_analyzer import analyze_office
from app.engines.analyzers.generic_analyzer import analyze_generic
from app.engines.analyzers.yara_scanner import YaraScanner

if TYPE_CHECKING:
    from app.models.email import Attachment

logger = logging.getLogger(__name__)

# ── MIME / extension routing maps ─────────────────────────────────────────────

# Real MIME types that indicate PE files
PE_MIMES = {
    "application/x-dosexec",
    "application/x-msdownload",
    "application/x-executable",
    "application/octet-stream",  # Common fallback for EXEs
}

PE_EXTS = {".exe", ".dll", ".com", ".sys", ".scr", ".drv", ".cpl"}

PDF_MIMES = {"application/pdf", "application/x-pdf"}
PDF_EXTS = {".pdf"}

# OLE (legacy) Office formats
OLE_OFFICE_EXTS = {".doc", ".xls", ".ppt", ".dot", ".xlt", ".pot"}

# OOXML (modern, ZIP-based) Office formats
OOXML_EXTS = {".docx", ".xlsx", ".pptx", ".dotx", ".xlsm", ".docm", ".pptm"}


@dataclass
class AttachmentAnalysisResult:
    """
    Aggregated result for all attachments in a single email scan.

    Attributes:
        attachment_score : 0–100 overall risk (worst-file dominates)
        total_files      : Number of attachments found
        analyzed_files   : Number successfully analyzed
        per_file_results : List of per-file finding dicts (for breakdown JSON)
        high_risk_files  : Filenames whose individual score >= 60
    """

    attachment_score: float = 0.0
    total_files: int = 0
    analyzed_files: int = 0
    per_file_results: List[dict] = field(default_factory=list)
    high_risk_files: List[str] = field(default_factory=list)


class AttachmentAnalyzer:
    """
    Orchestrates attachment scanning.

    Instantiate fresh per scan (no shared state between runs).
    """

    def __init__(self):
        self._settings = get_settings()
        self._max_bytes = self._settings.MAX_ATTACHMENT_BYTES
        self._yara = YaraScanner()  # Loads/caches compiled rules on first call

    # ── Public API ─────────────────────────────────────────────────────────────

    def analyze(self, attachments: List["Attachment"]) -> AttachmentAnalysisResult:
        """
        Analyze a list of Attachment ORM objects.

        Args:
            attachments: SQLAlchemy Attachment records (already persisted to DB).
                         Each must have .filename, .storage_path, .content_type, .sha256_hash.

        Returns:
            AttachmentAnalysisResult with aggregate score and per-file details.
        """
        result = AttachmentAnalysisResult(total_files=len(attachments))

        if not attachments:
            logger.debug("No attachments to analyze — returning zero score")
            return result

        per_file_scores: List[float] = []

        for att in attachments:
            file_result = self._analyze_single(att)
            if file_result is None:
                continue  # File skipped (path invalid / oversized / missing)

            result.analyzed_files += 1
            score = file_result.risk_score

            per_file_scores.append(score)

            if score >= 60.0:
                result.high_risk_files.append(att.filename)

            result.per_file_results.append({
                "filename": att.filename,
                "file_type": file_result.file_type,
                "risk_score": score,
                "mime_mismatch": file_result.mime_mismatch,
                "findings": file_result.findings,
                "indicators": file_result.indicators,
                "yara_matches": file_result.indicators.get("yara_matches", []),
            })

        # ── Aggregate score: worst file dominates ──────────────────
        if per_file_scores:
            # Use max(individual scores) as the aggregate.
            # This ensures one highly suspicious attachment flags the entire email.
            result.attachment_score = round(max(per_file_scores), 1)

        logger.info(
            f"Attachment analysis complete — "
            f"{result.analyzed_files}/{result.total_files} files analyzed, "
            f"score={result.attachment_score}, high_risk={result.high_risk_files}"
        )
        return result

    # ── Private helpers ────────────────────────────────────────────────────────

    def _analyze_single(self, att: "Attachment") -> Optional[FileAnalysisResult]:
        """
        Load and analyze one attachment.

        Returns None if the file cannot be read or should be skipped.
        """
        filename = att.filename or "unknown"
        storage_path = att.storage_path

        # ── Safety: validate path ─────────────────────────────────
        if not storage_path or not os.path.isfile(storage_path):
            logger.warning(f"Attachment '{filename}' has no valid storage_path — skipping")
            return None

        # ── Safety: size check ────────────────────────────────────
        try:
            file_size = os.path.getsize(storage_path)
        except OSError as e:
            logger.error(f"Cannot stat '{filename}': {e}")
            return None

        if file_size > self._max_bytes:
            logger.warning(
                f"Attachment '{filename}' ({file_size:,} bytes) exceeds "
                f"MAX_ATTACHMENT_BYTES ({self._max_bytes:,}) — skipping"
            )
            # Return a minimal result with a note
            skipped = FileAnalysisResult(file_type="Skipped (too large)")
            skipped.findings = [
                f"File skipped: size {file_size:,} bytes exceeds limit {self._max_bytes:,} bytes"
            ]
            return skipped

        # ── Read file into memory ─────────────────────────────────
        try:
            with open(storage_path, "rb") as f:
                data = f.read()
        except Exception as e:
            logger.error(f"Failed to read attachment '{filename}': {e}")
            return None

        # ── MIME detection ────────────────────────────────────────
        detected_mime = self._detect_mime(data)
        declared_mime = (att.content_type or "").lower().split(";")[0].strip()
        mime_mismatch = bool(
            detected_mime
            and declared_mime
            and detected_mime != declared_mime
            and declared_mime not in ("application/octet-stream", "")
        )

        # ── Route to correct analyzer ─────────────────────────────
        file_result = self._route_analyzer(data, filename, detected_mime)
        file_result.mime_mismatch = mime_mismatch

        if mime_mismatch:
            file_result.findings.insert(
                0,
                f"MIME mismatch: declared '{declared_mime}' but file magic says '{detected_mime}'"
            )
            file_result.risk_score = min(100.0, file_result.risk_score + 20.0)

        # ── YARA scan (runs on ALL files, regardless of type) ─────
        yara_result = self._yara.scan(data, filename)
        if yara_result.matched:
            # Prepend YARA findings so they appear first in the list
            for finding in reversed(yara_result.findings):
                file_result.findings.insert(0, finding)

            # Store structured YARA match data in the indicators dict
            file_result.indicators["yara_matches"] = [
                {
                    "rule": m.rule_name,
                    "severity": m.severity,
                    "tags": m.tags,
                    "description": m.description,
                    "matched_strings": m.matched_strings,
                }
                for m in yara_result.matches
            ]

            # Score blending: highest assessment wins
            # If YARA found something worse than the heuristic, YARA score takes over
            file_result.risk_score = min(
                100.0,
                max(file_result.risk_score, yara_result.yara_score)
            )

        elif yara_result.error:
            logger.debug(f"YARA note for '{filename}': {yara_result.error}")

        return file_result


    def _detect_mime(self, data: bytes) -> Optional[str]:
        """Use python-magic to detect the actual MIME type from file bytes."""
        try:
            import magic  # Lazy import — requires libmagic system dep
            return magic.from_buffer(data, mime=True)
        except ImportError:
            logger.debug("python-magic not available — MIME detection disabled")
            return None
        except Exception as e:
            logger.debug(f"MIME detection failed: {e}")
            return None

    def _route_analyzer(
        self,
        data: bytes,
        filename: str,
        detected_mime: Optional[str],
    ) -> FileAnalysisResult:
        """
        Select the correct format-specific analyzer.

        Routing priority:
          1. Detected MIME (from magic bytes) — most reliable
          2. File extension — fallback when magic is unavailable
        """
        ext = os.path.splitext(filename.lower())[1]
        mime = (detected_mime or "").lower()

        # ── PE files ──────────────────────────────────────────────
        if mime in PE_MIMES or ext in PE_EXTS:
            # Extra guard: check for actual MZ header before routing to PE analyzer
            if data[:2] == b"MZ" or ext in PE_EXTS:
                logger.debug(f"Routing '{filename}' → PE analyzer")
                return analyze_pe(data, filename)

        # ── PDF files ─────────────────────────────────────────────
        if mime in PDF_MIMES or ext in PDF_EXTS:
            if data[:4] == b"%PDF" or ext in PDF_EXTS:
                logger.debug(f"Routing '{filename}' → PDF analyzer")
                return analyze_pdf(data, filename)

        # ── OOXML Office (ZIP-based) ──────────────────────────────
        if ext in OOXML_EXTS or mime == "application/vnd.openxmlformats-officedocument":
            logger.debug(f"Routing '{filename}' → OOXML Office analyzer")
            return analyze_office(data, filename, is_ooxml=True)

        # ── OLE Office (legacy binary) ────────────────────────────
        if ext in OLE_OFFICE_EXTS or mime in (
            "application/msword",
            "application/vnd.ms-excel",
            "application/vnd.ms-powerpoint",
            "application/x-ole-storage",
        ):
            logger.debug(f"Routing '{filename}' → OLE Office analyzer")
            return analyze_office(data, filename, is_ooxml=False)

        # ── Fallback ──────────────────────────────────────────────
        logger.debug(f"Routing '{filename}' → Generic analyzer (ext={ext}, mime={mime})")
        return analyze_generic(data, filename)
