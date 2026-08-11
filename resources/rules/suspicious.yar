/*
  Safe training rules for DFIR Copilot. These rules detect command patterns;
  they do not contain malware signatures or operational payloads.
*/

rule Suspicious_Encoded_PowerShell
{
    meta:
        description = "Encoded PowerShell execution pattern detected"
        severity = "high"
        mitre = "T1059.001"
    strings:
        $powershell = /powershell(\.exe)?/ nocase ascii wide
        $encoded = /-(enc|encodedcommand)\s+/ nocase ascii wide
    condition:
        filesize < 20MB and all of them
}

rule PowerShell_Download_Behavior
{
    meta:
        description = "PowerShell download behavior detected"
        severity = "high"
        mitre = "T1105"
    strings:
        $a = "Invoke-WebRequest" nocase ascii wide
        $b = "DownloadString" nocase ascii wide
        $c = "Start-BitsTransfer" nocase ascii wide
    condition:
        filesize < 20MB and any of them
}

rule Common_Persistence_Command
{
    meta:
        description = "Command associated with persistence was detected"
        severity = "high"
        mitre = "T1053.005"
    strings:
        $task = /schtasks\s+\/create/ nocase ascii wide
        $run = "CurrentVersion\\Run" nocase ascii wide
    condition:
        filesize < 20MB and any of them
}

