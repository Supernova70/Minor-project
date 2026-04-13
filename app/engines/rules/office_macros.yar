# =============================================================================
#  PHISHING GUARD — YARA Rules: Office Document Macro Threats
# =============================================================================
#
#  YARA CONDITION DEEP DIVE
#  ══════════════════════════
#  Beyond simple string matching, YARA conditions support:
#
#  Counting matches:
#    #s1 > 3          -> string $s1 matched more than 3 times in the file
#
#  Offset checks:
#    $s1 in (0..1024) -> $s1 found only in the first 1024 bytes
#    @s1 < 512        -> first occurrence of $s1 is before byte 512
#
#  File size:
#    filesize < 100KB -> only apply rule to files smaller than 100 KB
#    filesize > 1MB   -> only apply to files larger than 1 MB
#
#  Combining sets:
#    1 of ($s*)       -> at least 1 string starting with $s matched
#    all of ($macro*) -> every string starting with $macro matched
#    none of ($safe*) -> none of the $safe strings appear
#
# =============================================================================

rule OfficeMacroPresent : office macro
{
    meta:
        description = "Detects presence of VBA macro code in Office documents"
        author      = "Phishing Guard"
        severity    = "medium"
        explanation = "All macro-enabled documents should be inspected. Not all macros are malicious."

    strings:
        // OLE stream header for VBA project
        $vba_stream = "VBA_PROJECT"   nocase ascii

        // Common VBA keywords that indicate actual code (not just templates)
        $vba_code1 = "Sub " ascii
        $vba_code2 = "Function " ascii
        $vba_code3 = "Dim " ascii

    condition:
        $vba_stream and any of ($vba_code*)
}


rule OfficeMacroAutoRun : office macro autorun
{
    meta:
        description = "Detects auto-executing VBA macros — run automatically when document opens"
        author      = "Phishing Guard"
        severity    = "high"
        explanation = "Auto-run macros execute without user clicking. High risk indicator."

    strings:
        // These Sub names are special — Office calls them automatically on document events
        $ar1 = "Auto_Open"       nocase ascii wide  // Excel: runs on workbook open
        $ar2 = "AutoOpen"        nocase ascii wide  // Word: runs on document open
        $ar3 = "Document_Open"   nocase ascii wide  // Word: modern auto-run
        $ar4 = "Workbook_Open"   nocase ascii wide  // Excel: modern auto-run
        $ar5 = "Auto_Close"      nocase ascii wide  // Runs on document close
        $ar6 = "AutoClose"       nocase ascii wide
        $ar7 = "Auto_Exec"       nocase ascii wide  // Runs on startup
        $ar8 = "AutoExec"        nocase ascii wide
        $ar9 = "AutoNew"         nocase ascii wide  // Runs when new document created

    condition:
        any of ($ar*)
}


rule OfficeMacroShellExecution : office macro shell rce
{
    meta:
        description = "Detects VBA macros that launch shell commands or external processes"
        author      = "Phishing Guard"
        severity    = "critical"
        explanation = "Shell execution from macros is the primary delivery method for malware droppers"

    strings:
        // WScript.Shell — the most common way to run OS commands from VBA
        $wsh1 = "WScript.Shell"   nocase ascii wide
        $wsh2 = "CreateObject(\"WScript.Shell\")" nocase ascii wide

        // Shell() function — built-in VBA command execution
        $shell1 = "Shell("         nocase ascii wide

        // cmd.exe execution
        $cmd1 = "cmd.exe"          nocase ascii wide
        $cmd2 = "/c powershell"    nocase ascii wide
        $cmd3 = "cmd /c"           nocase ascii wide

        // PowerShell execution — macro downloading and running PS scripts
        $ps1 = "powershell"        nocase ascii wide
        $ps2 = "PowerShell.exe"    nocase ascii wide
        $ps3 = "-EncodedCommand"   nocase ascii wide  // Base64 encoded PS — evasion
        $ps4 = "-enc "             nocase ascii wide  // Shortened -enc flag
        $ps5 = "-ExecutionPolicy Bypass" nocase ascii wide

    condition:
        ($wsh1 or $wsh2 or $shell1) and
        (any of ($cmd*) or any of ($ps*))
}


rule OfficeMacroNetworkAccess : office macro network downloader
{
    meta:
        description = "Detects VBA macros making network requests — classic dropper behavior"
        author      = "Phishing Guard"
        severity    = "high"

    strings:
        // XMLHTTP — the most popular way to download files from VBA
        $http1 = "XMLHTTP"             nocase ascii wide
        $http2 = "Microsoft.XMLHTTP"   nocase ascii wide
        $http3 = "MSXML2.XMLHTTP"      nocase ascii wide
        $http4 = "ServerXMLHTTP"       nocase ascii wide

        // WinHTTP — alternative HTTP client from VBA
        $http5 = "WinHttpRequest"      nocase ascii wide
        $http6 = "MSXML2.ServerXMLHTTP" nocase ascii wide

        // URLDownloadToFile — pinvoke'd from VBA to download files
        $http7 = "URLDownloadToFile"   nocase ascii wide

        // Common URL patterns in downloaders
        $url1  = "http://"             nocase ascii
        $url2  = "https://"            nocase ascii

    condition:
        any of ($http*) and any of ($url*)
}


rule OfficeMacroDDEExecution : office dde
{
    meta:
        description = "Detects DDE (Dynamic Data Exchange) command injection in Office documents"
        author      = "Phishing Guard"
        severity    = "critical"
        reference   = "CVE-2017-11826, Follina-related DDE techniques"
        explanation = "DDE allows executing OS commands via formula-like syntax — no macro needed"

    strings:
        // DDEAUTO executes automatically without any user prompt in older Office versions
        $dde1 = "DDEAUTO"       nocase ascii wide
        $dde2 = "DDE("          nocase ascii wide

        // DDE with cmd.exe is the classic weaponized pattern
        $cmd  = "cmd.exe"       nocase ascii wide
        $ps   = "powershell"    nocase ascii wide

        // Obfuscated DDE — attackers split strings to evade simple pattern matching
        $dde_obf1 = { 44 44 45 41 55 54 4F }  // "DDEAUTO" as hex

    condition:
        ($dde1 or $dde2 or $dde_obf1) and ($cmd or $ps)
}


rule OfficeMacroEnvVarRecon : office macro reconnaissance
{
    meta:
        description = "Detects macros reading environment variables for system reconnaissance"
        author      = "Phishing Guard"
        severity    = "medium"
        explanation = "Malware reads env vars to fingerprint the victim machine before deploying payload"

    strings:
        // Environ() reads environment variables — used for recon
        $env1 = "Environ("       nocase ascii wide
        $env2 = "Environ(\""     nocase ascii wide

        // Specific variables that malware commonly checks
        $var1 = "COMPUTERNAME"   nocase ascii wide  // Identify the machine
        $var2 = "USERNAME"       nocase ascii wide  // Identify the user
        $var3 = "USERPROFILE"    nocase ascii wide  // Path to user home
        $var4 = "APPDATA"        nocase ascii wide  // Common dropper location
        $var5 = "TEMP"           nocase ascii wide  // Drop zone for payloads
        $var6 = "PROCESSOR_ARCHITECTURE" nocase ascii wide  // x86 vs x64 targeting

    condition:
        $env1 and 2 of ($var*)
}
