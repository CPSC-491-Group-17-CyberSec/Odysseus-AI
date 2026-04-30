// ----------------------------------------------------------------------------
// aggressive_heuristics.yar  –  EXPERIMENTAL rules (high false-positive rate)
//
// These rules are gated by `experimentalRules: true` in odysseus_config.json.
// They fire on patterns that are statistically associated with malware but
// also occur in legitimate dev/admin tooling. Use only when you're triaging
// a known-suspect machine and want maximum signal.
//
// Expected false positives:
//   • Penetration-testing tools (Metasploit, Cobalt Strike payload templates)
//   • Reverse-engineering frameworks (radare2, Frida script bundles)
//   • Some installer wrappers (Inno Setup with custom DLLs)
// ----------------------------------------------------------------------------

rule Aggressive_Suspicious_Strings_Combo
{
    meta:
        family      = "Heuristic/Aggressive"
        description = "Combination of obfuscation + persistence + network strings"
        severity    = "medium"
        author      = "Odysseus-AI"
        experimental = "true"

    strings:
        $obf1 = "FromBase64String"        ascii nocase
        $obf2 = "DeflateStream"           ascii nocase
        $obf3 = "GzipStream"              ascii nocase
        $per1 = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $per2 = "/Library/LaunchAgents"   nocase
        $per3 = "/etc/cron.d/"            nocase
        $net1 = "WebClient.DownloadString" nocase
        $net2 = "Invoke-WebRequest"        nocase
        $net3 = "curl http"                nocase

    condition:
        any of ($obf*) and any of ($per*) and any of ($net*)
}

rule Aggressive_AntiAnalysis_Indicators
{
    meta:
        family      = "Heuristic/AntiAnalysis"
        description = "Common anti-debugger / anti-VM / anti-sandbox strings"
        severity    = "medium"
        author      = "Odysseus-AI"
        experimental = "true"

    strings:
        $a1 = "IsDebuggerPresent"          ascii
        $a2 = "CheckRemoteDebuggerPresent" ascii
        $a3 = "VBoxService"                ascii
        $a4 = "vmtoolsd"                   ascii
        $a5 = "Sandboxie"                  ascii
        $a6 = "SbieDll"                    ascii nocase
        $a7 = "QEMU"                       ascii

    condition:
        3 of them
}
