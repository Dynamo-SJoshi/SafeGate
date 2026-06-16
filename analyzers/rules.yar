rule suspicious_pdf_actions {
    meta:
        description = "Detects PDF files with JavaScript or auto-open actions that could indicate exploit vectors or downloaders."
        author = "SafeGate"
    strings:
        // PDF magic header: %PDF-
        $pdf_magic = { 25 50 44 46 }
        $js1 = /\/JavaScript/
        $js2 = /\/JS/
        $open_action = /\/OpenAction/
    condition:
        $pdf_magic at 0 and ($js1 or $js2 or $open_action)
}

rule vba_macro_indicator {
    meta:
        description = "Detects VBA macro signatures inside office documents or legacy binary files."
        author = "SafeGate"
    strings:
        $auto_open = "AutoOpen" ascii nocase
        $doc_open = "Document_Open" ascii nocase
        $workbook_open = "Workbook_Open" ascii nocase
        $vb_name = "Attribute VB_Name" ascii
        $macro_enabled = "word/vbaProject.bin" ascii nocase
    condition:
        any of them
}

rule webshell_php_backdoor {
    meta:
        description = "Detects common PHP webshell backdoors and execution functions."
        author = "SafeGate"
    strings:
        $eval = "eval(" ascii nocase
        $base64 = "base64_decode" ascii
        $exec1 = "system(" ascii nocase
        $exec2 = "shell_exec(" ascii nocase
        $exec3 = "passthru(" ascii nocase
        $exec4 = "exec(" ascii nocase
        $exec5 = "popen(" ascii nocase
        $c99 = "c99shell" ascii nocase
        $r57 = "r57shell" ascii nocase
    condition:
        ($eval and $base64) or any of ($exec*) or $c99 or $r57
}

rule powershell_suspicious_script {
    meta:
        description = "Detects suspicious PowerShell command-line arguments and script keywords."
        author = "SafeGate"
    strings:
        $bypass = "-ExecutionPolicy Bypass" ascii nocase
        $ep_bypass = "-ep Bypass" ascii nocase
        $noprofile = "-NoProfile" ascii nocase
        $hidden = "-WindowStyle Hidden" ascii nocase
        $iex = "Invoke-Expression" ascii nocase
        $iex_alias = /\biex(\s+|\()/ ascii nocase
        $download_string = ".DownloadString(" ascii nocase
        $download_file = ".DownloadFile(" ascii nocase
    condition:
        any of them
}

rule suspicious_pdf_obfuscation {
    meta:
        description = "Detects obfuscation techniques, launch actions, or URI links in PDFs."
        author = "SafeGate"
    strings:
        $pdf_magic = { 25 50 44 46 }
        $launch = /\/Launch/
        $uri = /\/URI/
        $obf_js1 = /\/J#61vaScript/
        $obf_js2 = /\/J#53/
        $colorspace_obf = "/ColorSpace"
    condition:
        $pdf_magic at 0 and ($launch or $uri or $obf_js1 or $obf_js2 or $colorspace_obf)
}

rule office_macro_code_execution {
    meta:
        description = "Detects VBA macro execution or shell spawning cmdlets in documents."
        author = "SafeGate"
    strings:
        $wscript = "WScript.Shell" ascii nocase
        $shell = "shell32.dll" ascii nocase
        $environ = "Environ(" ascii nocase
        $exe4m = "ExecuteExcel4Macro" ascii nocase
        $cmd = "cmd.exe" ascii nocase
        $powershell = "powershell.exe" ascii nocase
    condition:
        any of them
}

rule hidden_pe_inside_archive {
    meta:
        description = "Detects DOS MZ executable headers embedded inside general data/text files."
        author = "SafeGate"
    strings:
        $mz = { 4d 5a }
        $pe_sig = "This program cannot be run in DOS mode" ascii
    condition:
        $mz at 0 and $pe_sig
}
