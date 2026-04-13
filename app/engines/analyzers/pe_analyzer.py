"""
PE Analyzer — Static analysis for Windows Portable Executable files.

Analyzes .exe, .dll, .com, .sys files using the `pefile` library.

Checks performed:
  1. High-entropy sections (indicator of packing/obfuscation)
  2. Dangerous imported APIs (process injection, code execution primitives)
  3. PE structural anomalies (invalid checksum, missing sections)
  4. Suspicious section names
"""

import io
import logging
import math
from typing import List, Tuple

from app.engines.analyzers.base import FileAnalysisResult

logger = logging.getLogger(__name__)

# Entropy threshold above which a section is considered packed/obfuscated
ENTROPY_THRESHOLD = 7.0

# API names associated with process injection and malicious behavior
DANGEROUS_APIS = {
    "VirtualAlloc",
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtCreateThreadEx",
    "RtlCreateUserThread",
    "SetWindowsHookEx",
    "OpenProcess",
    "ShellExecuteA",
    "ShellExecuteW",
    "WinExec",
    "CreateProcessA",
    "CreateProcessW",
    "URLDownloadToFileA",
    "URLDownloadToFileW",
    "InternetOpenUrlA",
    "InternetOpenUrlW",
}

# Suspicious section names sometimes used by packers
SUSPICIOUS_SECTIONS = {".upx0", ".upx1", ".aspack", ".nsp0", ".nsp1", "UPX0", "UPX1"}


def _shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence. Max is 8.0."""
    if not data:
        return 0.0
    freq: dict[int, int] = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    length = len(data)
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
        if count > 0
    )
    return round(entropy, 4)


def analyze_pe(data: bytes, filename: str) -> FileAnalysisResult:
    """
    Perform static analysis on a PE binary.

    Args:
        data    : Raw file bytes
        filename: Original filename (used for context only)

    Returns:
        FileAnalysisResult with risk_score 0–100
    """
    result = FileAnalysisResult(file_type="PE32")
    risk_score = 0.0
    findings: List[str] = []
    indicators: dict = {
        "sections": [],
        "dangerous_apis": [],
        "anomalies": [],
    }

    try:
        import pefile  # Lazy import — only available inside Docker/analysis env

        pe = pefile.PE(data=data, fast_load=False)

        # ── 1. Section entropy analysis ─────────────────────────────
        for section in pe.sections:
            try:
                name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
            except Exception:
                name = "?"

            entropy = _shannon_entropy(section.get_data())
            sec_info = {"name": name, "entropy": entropy}
            indicators["sections"].append(sec_info)

            if name in SUSPICIOUS_SECTIONS:
                findings.append(f"Suspicious section name detected: '{name}'")
                risk_score += 25.0

            if entropy > ENTROPY_THRESHOLD:
                findings.append(
                    f"High entropy section '{name}' ({entropy:.2f}) — possible packing/obfuscation"
                )
                risk_score += 20.0

        # ── 2. Dangerous imported APIs ───────────────────────────────
        dangerous_found: List[str] = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        api_name = imp.name.decode("utf-8", errors="ignore")
                        if api_name in DANGEROUS_APIS:
                            dangerous_found.append(api_name)

        if dangerous_found:
            indicators["dangerous_apis"] = dangerous_found
            findings.append(
                f"Dangerous APIs imported: {', '.join(dangerous_found[:5])}"
                + (f" (+{len(dangerous_found)-5} more)" if len(dangerous_found) > 5 else "")
            )
            # Each dangerous API adds weight, capped at 40 points
            risk_score += min(40.0, len(dangerous_found) * 8.0)

        # ── 3. Structural anomalies ──────────────────────────────────
        if not pe.verify_checksum():
            findings.append("PE checksum is invalid — common in tampered/packed executables")
            indicators["anomalies"].append("invalid_checksum")
            risk_score += 15.0

        # Detect entry point outside any known section
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        ep_in_section = any(
            s.VirtualAddress <= ep < s.VirtualAddress + s.Misc_VirtualSize
            for s in pe.sections
        )
        if not ep_in_section and pe.sections:
            findings.append("Entry point falls outside all PE sections — strong packing indicator")
            indicators["anomalies"].append("ep_outside_sections")
            risk_score += 25.0

        # Detect file type variants
        if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE:
            result.file_type = "PE32"
        elif pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS:
            result.file_type = "PE32+ (64-bit)"

        pe.close()

    except ImportError:
        logger.warning("pefile not installed — PE analysis skipped")
        findings.append("PE analysis skipped: pefile library not available")
    except Exception as e:
        logger.error(f"PE analysis error on {filename}: {e}")
        findings.append(f"PE analysis error: {type(e).__name__}")

    result.risk_score = min(100.0, round(risk_score, 1))
    result.findings = findings
    result.indicators = indicators
    return result
