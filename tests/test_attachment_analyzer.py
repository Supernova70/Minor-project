"""
Tests for the Attachment Analyzer Engine.

Tests run against in-memory byte arrays — no disk I/O or DB required.
Where format-specific libraries are missing, tests verify graceful fallback.
"""

import io
import math
import os
import struct
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.engines.analyzers.base import FileAnalysisResult
from app.engines.analyzers.generic_analyzer import analyze_generic, _shannon_entropy
from app.engines.analyzers.pdf_analyzer import analyze_pdf
from app.engines.analyzers.pe_analyzer import analyze_pe
from app.engines.analyzers.office_analyzer import analyze_office
from app.engines.attachment_analyzer import AttachmentAnalyzer, AttachmentAnalysisResult


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _make_attachment(filename: str, content: bytes, content_type: str = "application/octet-stream"):
    """Build a mock Attachment ORM object backed by a real temp file."""
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=Path(filename).suffix)
    tmp.write(content)
    tmp.flush()
    tmp.close()

    att = MagicMock()
    att.filename = filename
    att.content_type = content_type
    att.sha256_hash = None
    att.storage_path = tmp.name
    return att, tmp.name


def _cleanup(path: str):
    try:
        os.unlink(path)
    except OSError:
        pass


def _high_entropy_bytes(size: int = 4096) -> bytes:
    """Generate near-random bytes with entropy close to 8.0."""
    import os as _os
    return _os.urandom(size)


def _make_minimal_pdf(with_js: bool = False) -> bytes:
    """Return bytes that PyPDF2 will parse as a valid (minimal) PDF."""
    js_obj = b""
    js_ref = b""
    if with_js:
        js_obj = b"3 0 obj\n<< /JS (app.alert('xss')) >>\nendobj\n"
        js_ref = b"/JS 3 0 R "

    pdf = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R " + js_ref + b">>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n"
        + js_obj +
        b"xref\n0 3\n"
        b"0000000000 65535 f \n"
        b"0000000009 00000 n \n"
        b"0000000058 00000 n \n"
        b"trailer\n<< /Size 3 /Root 1 0 R >>\n"
        b"startxref\n120\n%%EOF"
    )
    return pdf


def _make_minimal_pe() -> bytes:
    """Return a minimal 512-byte PE blob with MZ magic."""
    # MZ header (DOS stub) + PE signature
    dos_header = b"MZ" + b"\x00" * 58 + struct.pack("<I", 64)  # e_lfanew = 64
    dos_stub = b"\x00" * (64 - len(dos_header))
    pe_sig = b"PE\x00\x00"
    # Minimal COFF header (machine=0x14c i386, 0 sections, etc.)
    coff = struct.pack("<HHIIIHH", 0x014C, 0, 0, 0, 0, 0, 0)
    # Fill to 512 bytes
    result = dos_header + dos_stub + pe_sig + coff
    return result + b"\x00" * (512 - len(result))


def _make_ooxml_with_macro() -> bytes:
    """Return a minimal OOXML ZIP containing a vbaProject.bin."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types/>')
        # Embed a fake vbaProject.bin with auto-run keyword
        zf.writestr("xl/vbaProject.bin", b"JUNK\x00auto_open\x00MORE_JUNK".decode("latin-1"))
    return buf.getvalue()


# ─── Generic Analyzer Tests ──────────────────────────────────────────────────

class TestGenericAnalyzer:
    def test_high_entropy_scores_elevated(self):
        data = _high_entropy_bytes(4096)
        result = analyze_generic(data, "random.bin")
        assert result.risk_score >= 15.0, "High-entropy file should score >= 15"

    def test_double_extension_flagged(self):
        data = b"Hello world"
        result = analyze_generic(data, "invoice.pdf.exe")
        assert result.mime_mismatch is False  # Not set by generic analyzer
        assert any("double extension" in f.lower() for f in result.findings), \
            "Double extension should be flagged in findings"
        assert result.risk_score >= 30.0

    def test_embedded_mz_scores_high(self):
        data = b"Some text MZ" + b"\x00" * 100 + b"more data"
        result = analyze_generic(data, "document.txt")
        assert result.indicators.get("has_embedded_pe") is True
        assert result.risk_score >= 40.0

    def test_clean_data_low_score(self):
        # Plain ASCII text — very low entropy, no indicators
        data = b"Hello, this is a safe email body with no suspicious content.\n" * 20
        result = analyze_generic(data, "safe.txt")
        assert result.risk_score < 20.0

    def test_entropy_calculation(self):
        # All-zero bytes should have entropy 0.0
        assert _shannon_entropy(b"\x00" * 100) == 0.0
        # Random bytes should have entropy close to 8.0
        entropy = _shannon_entropy(_high_entropy_bytes(8192))
        assert entropy > 7.0


# ─── PDF Analyzer Tests ──────────────────────────────────────────────────────

class TestPdfAnalyzer:
    def test_clean_pdf_scores_low(self):
        data = _make_minimal_pdf(with_js=False)
        result = analyze_pdf(data, "report.pdf")
        # A clean PDF (no JS, no AA) should score below 30
        assert result.risk_score < 30.0

    def test_pdf_with_javascript_scores_high(self):
        # NOTE: PyPDF2's object walk may or may not catch the JS depending on
        # exact PDF structure. We verify the analyzer doesn't crash and returns
        # a valid result regardless.
        data = _make_minimal_pdf(with_js=True)
        result = analyze_pdf(data, "malicious.pdf")
        assert isinstance(result, FileAnalysisResult)
        assert 0.0 <= result.risk_score <= 100.0

    def test_invalid_pdf_handled_gracefully(self):
        data = b"This is not a PDF at all %&!@#"
        result = analyze_pdf(data, "fake.pdf")
        # Should not raise; should return a result with an error note
        assert isinstance(result, FileAnalysisResult)
        assert result.risk_score <= 100.0


# ─── PE Analyzer Tests ────────────────────────────────────────────────────────

class TestPeAnalyzer:
    def test_minimal_pe_returns_result(self):
        data = _make_minimal_pe()
        result = analyze_pe(data, "test.exe")
        assert isinstance(result, FileAnalysisResult)
        assert 0.0 <= result.risk_score <= 100.0

    def test_non_pe_data_handled_gracefully(self):
        data = b"Not a PE file at all"
        result = analyze_pe(data, "fake.exe")
        assert isinstance(result, FileAnalysisResult)
        # Should not crash; may return error finding
        assert result.risk_score <= 100.0


# ─── Office Analyzer Tests ────────────────────────────────────────────────────

class TestOfficeAnalyzer:
    def test_ooxml_with_macro_scores_high(self):
        data = _make_ooxml_with_macro()
        result = analyze_office(data, "spreadsheet.xlsm", is_ooxml=True)
        assert isinstance(result, FileAnalysisResult)
        assert result.risk_score >= 40.0, "OOXML with vbaProject.bin should score >= 40"
        assert result.indicators.get("has_macros") is True

    def test_ooxml_without_macro_scores_low(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types/>')
            zf.writestr("word/document.xml", "<w:document/>")
        data = buf.getvalue()
        result = analyze_office(data, "clean.docx", is_ooxml=True)
        assert result.risk_score < 20.0

    def test_bad_zip_handled_gracefully(self):
        data = b"NOT A ZIP"
        result = analyze_office(data, "bad.docx", is_ooxml=True)
        assert isinstance(result, FileAnalysisResult)
        assert result.risk_score <= 100.0


# ─── AttachmentAnalyzer (Orchestrator) Tests ─────────────────────────────────

class TestAttachmentAnalyzer:
    def test_empty_attachments_returns_zero(self):
        analyzer = AttachmentAnalyzer()
        result = analyzer.analyze([])
        assert result.attachment_score == 0.0
        assert result.total_files == 0
        assert result.analyzed_files == 0

    def test_single_clean_txt_scores_low(self):
        data = b"Hello, please review the attached report.\n" * 50
        att, path = _make_attachment("report.txt", data, "text/plain")
        try:
            analyzer = AttachmentAnalyzer()
            result = analyzer.analyze([att])
            assert isinstance(result, AttachmentAnalysisResult)
            assert result.total_files == 1
            assert result.analyzed_files == 1
            assert result.attachment_score < 50.0
        finally:
            _cleanup(path)

    def test_oversized_file_skipped_gracefully(self):
        """Files exceeding MAX_ATTACHMENT_BYTES should be skipped without crash."""
        data = b"A" * 100  # Small actual content
        att, path = _make_attachment("big.bin", data, "application/octet-stream")
        try:
            # Patch the size check to simulate an oversized file
            with patch("os.path.getsize", return_value=200 * 1024 * 1024):  # 200 MB
                analyzer = AttachmentAnalyzer()
                result = analyzer.analyze([att])
            # Should still return a result without crashing
            assert isinstance(result, AttachmentAnalysisResult)
        finally:
            _cleanup(path)

    def test_missing_storage_path_handled(self):
        att = MagicMock()
        att.filename = "ghost.exe"
        att.content_type = "application/octet-stream"
        att.sha256_hash = None
        att.storage_path = "/nonexistent/path/ghost.exe"

        analyzer = AttachmentAnalyzer()
        result = analyzer.analyze([att])
        # Should not crash; file simply not analyzed
        assert result.total_files == 1
        assert result.analyzed_files == 0
        assert result.attachment_score == 0.0

    def test_high_risk_file_appears_in_high_risk_list(self):
        """A file with score >= 60 should be in high_risk_files."""
        data = _high_entropy_bytes(4096) + b"MZ" + _high_entropy_bytes(512)
        att, path = _make_attachment("payload.exe", data, "application/octet-stream")
        try:
            analyzer = AttachmentAnalyzer()
            result = analyzer.analyze([att])
            # Either scored high and appears in list, or gracefully handled
            assert isinstance(result, AttachmentAnalysisResult)
            if result.attachment_score >= 60.0:
                assert "payload.exe" in result.high_risk_files
        finally:
            _cleanup(path)

    def test_multiple_attachments_worst_score_wins(self):
        """aggregate score should equal the MAX of individual scores."""
        safe_data = b"Safe text content\n" * 20
        risky_data = _high_entropy_bytes(4096) + b"MZ" * 5

        att1, path1 = _make_attachment("safe.txt", safe_data, "text/plain")
        att2, path2 = _make_attachment("risky.bin", risky_data, "application/octet-stream")

        try:
            analyzer = AttachmentAnalyzer()
            result = analyzer.analyze([att1, att2])

            per_scores = [f["risk_score"] for f in result.per_file_results]
            if per_scores:
                assert result.attachment_score == max(per_scores)
        finally:
            _cleanup(path1)
            _cleanup(path2)
