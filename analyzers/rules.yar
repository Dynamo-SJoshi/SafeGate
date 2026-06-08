rule suspicious_strings {
    meta:
        description = "Detects dummy malicious strings for testing"
    strings:
        $suspicious1 = "eval(base64_decode" ascii
        $suspicious2 = "WScript.Shell" ascii nocase
        $suspicious3 = "powershell -bypass" ascii nocase
    condition:
        any of them
}
