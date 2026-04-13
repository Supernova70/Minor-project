# =============================================================================
#  PHISHING GUARD — YARA Rules: PE (Executable) Threat Indicators
# =============================================================================
#
#  YARA HEX PATTERN TIPS
#  ══════════════════════
#  Hex patterns let you match exact byte sequences, including wildcards:
#    { 4D 5A }         -> MZ (PE file magic header)
#    { 4D ?? 5A }      -> "M" + any byte + "Z"
#    { 4D [2] 5A }     -> "M" + exactly 2 any bytes + "Z"
#    { 4D [2-4] 5A }   -> "M" + 2 to 4 any bytes + "Z"
#    { (4D|4E) 5A }    -> either "MZ" or "NZ"
#
#  YARA MODIFIERS FOR TEXT STRINGS
#  ═════════════════════════════════
#    nocase  -> case-insensitive match
#    ascii   -> match ASCII encoding (default)
#    wide    -> match UTF-16LE encoding (Windows Unicode strings)
#    fullword -> only match as a whole word (not part of longer string)
#
# =============================================================================

rule PEPackerUPX : packer pe
{
    meta:
        description = "Detects UPX packer signatures in PE files — common in malware distribution"
        author      = "Phishing Guard"
        severity    = "high"
        reference   = "UPX packer: https://upx.github.io/"

    strings:
        // UPX section names written into packed PE headers
        $upx_section0 = "UPX0"  ascii
        $upx_section1 = "UPX1"  ascii
        $upx_section2 = "UPX2"  ascii

        // UPX string embedded in PE overlay
        $upx_string = "UPX!" ascii

        // UPX magic bytes (version info block)
        $upx_bytes = { 55 50 58 21 }  // "UPX!"

    condition:
        // MZ header must be present (it's a PE) and at least one UPX indicator
        uint16(0) == 0x5A4D and any of them
}


rule PEMPRESSPacker : packer pe
{
    meta:
        description = "Detects MPRESS packer — another common PE packer used to evade AV"
        author      = "Phishing Guard"
        severity    = "high"

    strings:
        $mpress = ".MPRESS1" ascii
        $mpress2 = ".MPRESS2" ascii

    condition:
        uint16(0) == 0x5A4D and any of them
}


rule PESuspiciousAPIImports : pe malware
{
    meta:
        description = "Detects PE files importing process injection / code execution APIs"
        author      = "Phishing Guard"
        severity    = "high"
        explanation = "These APIs are legitimate but heavily abused by malware for injection"

    strings:
        // ── Process injection APIs ──────────────────────────────
        // VirtualAllocEx: allocates memory in another process — used for injection
        $api1 = "VirtualAllocEx"       ascii wide

        // WriteProcessMemory: writes shellcode/payload into another process
        $api2 = "WriteProcessMemory"   ascii wide

        // CreateRemoteThread: starts a thread in another process (classic injection finale)
        $api3 = "CreateRemoteThread"   ascii wide

        // NtCreateThreadEx: lower-level alternative to CreateRemoteThread
        $api4 = "NtCreateThreadEx"     ascii wide

        // ── Shellcode execution ─────────────────────────────────
        // SetWindowsHookEx: installs a global keyboard hook (keylogger technique)
        $api5 = "SetWindowsHookEx"     ascii wide

        // ── Downloader APIs ─────────────────────────────────────
        $api6 = "URLDownloadToFileA"   ascii wide
        $api7 = "URLDownloadToFileW"   ascii wide
        $api8 = "InternetOpenUrlA"     ascii wide

    condition:
        // At least 2 of these dangerous APIs imported together
        uint16(0) == 0x5A4D and 2 of ($api*)
}


rule PEAntiDebugTricks : pe evasion
{
    meta:
        description = "Detects common anti-debugging patterns used by malware to evade analysis"
        author      = "Phishing Guard"
        severity    = "medium"

    strings:
        // IsDebuggerPresent: checks if running inside a debugger
        $adb1 = "IsDebuggerPresent"     ascii wide

        // CheckRemoteDebuggerPresent: deeper debugger check
        $adb2 = "CheckRemoteDebuggerPresent" ascii wide

        // NtQueryInformationProcess: used to detect debugger attachment
        $adb3 = "NtQueryInformationProcess" ascii wide

        // RDTSC timing trick — executes raw RDTSC instruction (0x0F 0x31)
        // to measure execution time delays introduced by debuggers
        $rdtsc = { 0F 31 }

        // OutputDebugString trick — checks if a debugger is listening
        $adb4 = "OutputDebugStringA"    ascii wide

    condition:
        uint16(0) == 0x5A4D and (2 of ($adb*) or $rdtsc)
}


rule PESuspiciousOverlay : pe dropper
{
    meta:
        description = "PE file with appended data after EOF — common in dropper/bundler malware"
        author      = "Phishing Guard"
        severity    = "medium"
        explanation = "Malware often appends an encrypted payload after the PE EOF marker"

    strings:
        // MZ header
        $mz = { 4D 5A }

        // ZIP magic (payload hidden inside PE)
        $zip = { 50 4B 03 04 }

        // Another PE embedded inside — dropper pattern
        $inner_pe = { 4D 5A 90 00 03 00 }

        // RAR magic
        $rar = { 52 61 72 21 1A 07 }

    condition:
        // File starts with MZ (it's a PE) and contains another archive/PE inside
        $mz at 0 and ($zip or $inner_pe or $rar)
}
