// ----------------------------------------------------------------------------
// odysseus_starter.yar  –  Cross-platform heuristics (no PE-only constraint)
//
// These rules scan ANY file (scripts, ELF, Mach-O, archives, plaintext) and
// fire on indicators that consistently correlate with malicious behavior.
// They are deliberately conservative: prefer false negatives to false
// positives, because YARA is the LOUD layer of the pipeline (results show
// up directly in the UI with rule names and family attribution).
// ----------------------------------------------------------------------------

rule Embedded_PowerShell_Encoded_Command
{
    meta:
        family      = "Script/Loader"
        description = "Encoded PowerShell command (-enc / -EncodedCommand)"
        severity    = "high"
        author      = "Odysseus-AI"

    strings:
        $a1 = "powershell -enc"      nocase
        $a2 = "powershell -e "       nocase
        $a3 = "powershell.exe -enc"  nocase
        $a4 = "-EncodedCommand"      nocase

    condition:
        any of them
}

rule Reverse_Shell_Strings
{
    meta:
        family      = "Backdoor/ReverseShell"
        description = "Strings consistent with a reverse-shell payload"
        severity    = "high"
        author      = "Odysseus-AI"

    strings:
        $a1 = "/bin/sh -i"                   ascii
        $a2 = "bash -i >& /dev/tcp/"         ascii
        $a3 = "nc -e /bin/sh"                ascii
        $a4 = "socket.SOCK_STREAM"           ascii
        $a5 = "subprocess.call([\"/bin/sh\""  ascii

    condition:
        2 of them      // require at least two distinct indicators
}

rule Mass_File_Encryption_Indicators
{
    meta:
        family      = "Ransomware"
        description = "Multiple ransomware-style indicators in a single file"
        severity    = "high"
        author      = "Odysseus-AI"

    strings:
        $a1 = ".encrypted"     ascii nocase
        $a2 = ".locked"        ascii nocase
        $a3 = "your files have been encrypted"  ascii nocase
        $a4 = "AES_256_CBC"    ascii
        $a5 = "RSA_2048"       ascii
        $a6 = "bitcoin"        ascii nocase

    condition:
        3 of them
}

rule MachO_Suspicious_Strings
{
    meta:
        family      = "Generic/MachO"
        description = "Mach-O binary with suspicious dylib loading APIs"
        severity    = "medium"
        author      = "Odysseus-AI"

    strings:
        $magic1 = { CA FE BA BE }   // Mach-O fat / universal
        $magic2 = { CF FA ED FE }   // Mach-O 64-bit LE
        $magic3 = { FE ED FA CF }   // Mach-O 64-bit BE
        $api1   = "dlopen"          ascii
        $api2   = "task_for_pid"    ascii
        $api3   = "ptrace"          ascii

    condition:
        any of ($magic*) and 2 of ($api*)
}

rule ELF_Suspicious_Imports
{
    meta:
        family      = "Generic/ELF"
        description = "ELF binary referencing process-hiding / hooking APIs"
        severity    = "medium"
        author      = "Odysseus-AI"

    strings:
        $magic = { 7F 45 4C 46 }    // ELF magic
        $a1    = "ptrace"           ascii
        $a2    = "/proc/self/maps"  ascii
        $a3    = "LD_PRELOAD"       ascii

    condition:
        $magic at 0 and 2 of ($a*)
}
