# =============================================================================
#  PHISHING GUARD — YARA Rules: Phishing & Credential Harvesting Indicators
# =============================================================================
#
#  HOW YARA RULES WORK
#  ═══════════════════
#  A YARA rule has three sections:
#
#  meta:     Descriptive metadata — author, description, severity, etc.
#            These are just comments stored with the rule; they do NOT affect matching.
#
#  strings:  Patterns to search for inside a file's raw bytes.
#            Three types:
#              - Text strings:  $s = "some text"  nocase ascii wide
#              - Hex patterns:  $h = { 4D 5A 90 00 }  (byte sequence)
#              - Regex:         $r = /pattern/  (PCRE-like)
#
#  condition: Boolean logic combining the string matches.
#             Examples:
#               any of them          -> any ONE defined string matched
#               all of them          -> ALL strings must match
#               2 of ($s*)           -> at least 2 strings starting with $s
#               $a and not $b        -> $a found, $b not found
#               #s1 > 5              -> string $s1 appears more than 5 times
#               @s1 < 1024           -> $s1 found within first 1 KB
#               filesize < 500KB     -> match only small files
#
# =============================================================================

rule PhishingCredentialHarvest : phishing credentials
{
    meta:
        description = "Detects credential-harvesting form patterns typical of phishing pages"
        author      = "Phishing Guard"
        severity    = "high"
        reference   = "Common phishing kit analysis"

    strings:
        // Input field names used to steal usernames/passwords
        $form1 = "name=\"password\""   nocase ascii
        $form2 = "name=\"passwd\""     nocase ascii
        $form3 = "name=\"email\""      nocase ascii
        $form4 = "name=\"username\""   nocase ascii

        // Form POST action — phishing kits POST stolen data to their server
        $post  = "method=\"post\""     nocase ascii

        // PHP mailer snippet found in phishing kits — sends creds to attacker email
        $mail1 = "mail("               nocase ascii
        $mail2 = "$_POST["             nocase ascii

    condition:
        // A credential form + a POST + either a mailer or POST variable grab
        ( ($form1 or $form2) and $post ) and ($mail1 or $mail2)
}


rule PhishingUrgencyLanguage : phishing social_engineering
{
    meta:
        description = "Detects extreme urgency language used in phishing emails/pages"
        author      = "Phishing Guard"
        severity    = "medium"

    strings:
        $u1 = "your account has been suspended"  nocase ascii wide
        $u2 = "verify your account immediately"  nocase ascii wide
        $u3 = "unusual sign-in activity"         nocase ascii wide
        $u4 = "confirm your identity now"        nocase ascii wide
        $u5 = "your account will be terminated"  nocase ascii wide
        $u6 = "click here to restore access"     nocase ascii wide
        $u7 = "limited time offer"               nocase ascii wide
        $u8 = "act now or lose access"           nocase ascii wide

    condition:
        // Two or more urgency phrases = strong social engineering signal
        2 of ($u*)
}


rule PhishingBrandImpersonation : phishing impersonation
{
    meta:
        description = "Detects common brand impersonation strings in non-brand domains"
        author      = "Phishing Guard"
        severity    = "medium"

    strings:
        // Brands commonly impersonated in phishing
        $b1 = "paypal"     nocase ascii wide
        $b2 = "microsoft"  nocase ascii wide
        $b3 = "apple"      nocase ascii wide
        $b4 = "amazon"     nocase ascii wide
        $b5 = "google"     nocase ascii wide
        $b6 = "netflix"    nocase ascii wide
        $b7 = "facebook"   nocase ascii wide
        $b8 = "instagram"  nocase ascii wide
        $b9 = "twitter"    nocase ascii wide
        $b10 = "linkedin"  nocase ascii wide

        // These combined with login/verify language = high confidence phishing
        $action1 = "login"    nocase ascii wide
        $action2 = "sign in"  nocase ascii wide
        $action3 = "verify"   nocase ascii wide
        $action4 = "confirm"  nocase ascii wide

    condition:
        any of ($b*) and any of ($action*)
}


rule PhishingFakeInvoiceAttachment : phishing invoice
{
    meta:
        description = "Detects fake invoice/payment document lure patterns"
        author      = "Phishing Guard"
        severity    = "medium"

    strings:
        $i1 = "invoice"         nocase ascii wide
        $i2 = "payment due"     nocase ascii wide
        $i3 = "outstanding"     nocase ascii wide
        $i4 = "remittance"      nocase ascii wide
        $i5 = "purchase order"  nocase ascii wide

        $a1 = "open attachment"  nocase ascii wide
        $a2 = "enable content"   nocase ascii wide
        $a3 = "enable macros"    nocase ascii wide
        $a4 = "click to view"    nocase ascii wide

    condition:
        any of ($i*) and any of ($a*)
}
