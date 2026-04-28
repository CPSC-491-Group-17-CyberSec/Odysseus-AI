// ----------------------------------------------------------------------------
// eicar.yar  –  Standard antivirus test pattern
//
// EICAR is the universally agreed-upon "this string MUST be detected" test
// pattern for AV products. We include it as the canonical end-to-end YARA
// integration test: drop an EICAR file in your scan path and YARA should fire.
//
// Reference: https://www.eicar.org/download-anti-malware-testfile/
// ----------------------------------------------------------------------------

rule EICAR_Test_File
{
    meta:
        family      = "EICAR-Test"
        description = "EICAR Anti-Virus test file (intentionally benign)"
        severity    = "low"
        author      = "Odysseus-AI"
        reference   = "https://www.eicar.org"

    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $eicar
}
