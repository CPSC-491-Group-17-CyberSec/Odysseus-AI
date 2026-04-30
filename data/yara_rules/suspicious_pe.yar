// ----------------------------------------------------------------------------
// suspicious_pe.yar  –  Generic heuristics for Windows PE binaries
//
// These rules don't identify specific families; they flag construction
// patterns that are statistically associated with malware:
//   • UPX-style packers without legit metadata
//   • Suspicious imports (CreateRemoteThread / VirtualAllocEx pair, etc.)
//   • Section-name anomalies
//
// Severity is intentionally "medium" — these fire on legitimate packed
// software too (installers, DRM-wrapped games). Use as a SIGNAL combined
// with hash + AI scoring, not as a standalone verdict.
// ----------------------------------------------------------------------------

import "pe"

rule Generic_UPX_Packed
{
    meta:
        family      = "Packer/UPX"
        description = "UPX-packed PE binary (often used to evade AV)"
        severity    = "medium"
        author      = "Odysseus-AI"

    condition:
        uint16(0) == 0x5A4D and    // MZ header
        for any section in pe.sections : (
            section.name == "UPX0" or
            section.name == "UPX1" or
            section.name == "UPX2"
        )
}

rule Suspicious_Process_Injection_APIs
{
    meta:
        family      = "Injection"
        description = "PE imports the canonical process-injection API set"
        severity    = "medium"
        author      = "Odysseus-AI"

    condition:
        uint16(0) == 0x5A4D and
        pe.imports("kernel32.dll", "VirtualAllocEx") and
        pe.imports("kernel32.dll", "WriteProcessMemory") and
        pe.imports("kernel32.dll", "CreateRemoteThread")
}

rule Suspicious_PE_Section_Names
{
    meta:
        family      = "Generic/SectionAnomaly"
        description = "PE has uncommon / suspicious section names"
        severity    = "low"
        author      = "Odysseus-AI"

    condition:
        uint16(0) == 0x5A4D and
        for any section in pe.sections : (
            section.name == ".vmp0" or       // VMProtect
            section.name == ".vmp1" or
            section.name == ".vmp2" or
            section.name == ".aspack" or     // ASPack
            section.name == ".adata" or      // ASPack (older)
            section.name == ".themida" or    // Themida
            section.name == ".enigma1" or    // Enigma Protector
            section.name == ".enigma2"
        )
}
