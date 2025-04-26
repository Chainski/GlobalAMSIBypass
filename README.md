</h1>
<p align= "center">
   <img src="https://img.shields.io/github/stars/Chainski/GlobalAMSIBypass?style=flat&color=%23add8e6">
   <img src="https://img.shields.io/github/forks/Chainski/GlobalAMSIBypass?style=flat&color=%23add8e6">
   <img src="https://img.shields.io/github/issues/Chainski/GlobalAMSIBypass.svg?color=%23add8e6">
    <br>
  <img src="https://hits.sh/github.com/Chainski/GlobalAMSIBypass.svg?label=views&color=%23add8e6">
   <br>
   <img src="https://img.shields.io/github/last-commit/Chainski/GlobalAMSIBypass?color=%23add8e6">
   <img src="https://img.shields.io/github/license/Chainski/GlobalAMSIBypass.svg?color=%23add8e6">
   <br>
</p>

# PowerShell Global AMSI Bypass

# Overview
This PowerShell script implements a global Anti-Malware Scan Interface (AMSI) bypass by patching the AmsiScanBuffer function in amsi.dll within the current process memory. This approach disables `AMSI` scanning for all scripts and commands executed in the process, making it a powerful tool for security researchers and red teamers.

## Why This AMSI Bypass Stands Out
- Global Scope: Unlike local `AMSI` bypasses that only affect specific script blocks or sessions, this bypass modifies the behavior of `AmsiScanBuffer` globally within the process. Once applied, all subsequent `AMSI` scans return `AMSI_RESULT_CLEAN`, effectively disabling `AMSI` for the entire process lifecycle.
- No Add-Type Usage: Many `AMSI` bypass techniques rely on `Add-Type` to compile C# code, which is a common detection vector for endpoint security solutions. This script avoids `Add-Type` entirely, using reflection and dynamic assembly creation to reduce the likelihood of detection.
- Low-Level Memory Manipulation: By directly patching `amsi.dll` in memory using `VirtualProtect` and custom byte patches, this method operates at a lower level than most bypasses, making it harder to detect and mitigate.
- Stealth and Stability: The script carefully manages memory protections, ensuring the patch is applied and reverted cleanly, minimizing the risk of crashes or memory corruption.

# Global vs. Local AMSI Bypass

## Global AMSI Bypass:
Affects the entire process, disabling `AMSI` for all scripts and commands executed within it.
Achieved by patching `AmsiScanBuffer` in `amsi.dll` to always return `AMSI_RESULT_CLEAN`.
Persistent for the duration of the process, requiring no re-application for subsequent scripts.
Ideal for scenarios where multiple scripts or commands need to run without `AMSI` interference.
Higher risk of detection due to its broader impact, but this implementation mitigates that with stealth techniques.

## Local AMSI Bypass:
Limited to a specific script block, session, or PowerShell instance.
Typically achieved by modifying AMSI-related objects or variables (e.g., `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils'))`.
Must be re-applied for each new session or script block, making it less convenient for extensive operations.
Lower detection footprint but less comprehensive in scope.

# Features
- Dynamic Function Lookup: Uses `GetProcAddress` and `GetModuleHandle` to locate `AmsiScanBuffer` dynamically, avoiding hardcoded offsets that may break across Windows versions.
- Custom Delegate Creation: Employs Reflection.Emit to create delegate types for native function calls, without the need for `Add-Type`.
- Memory Protection Management: Safely modifies memory protections using `VirtualProtect` to apply and restore patches, ensuring process stability.
- Minimal Dependencies: Relies solely on native PowerShell and `.NET` reflection, requiring no external modules or libraries.

# Usage

Run the Script:
```powershell
.\GlobalAMSIBypass.ps1
```
The script will execute the `GlobalAMSIBypass` function, patch `amsi.dll`, and display progress messages.
After execution, `AMSI` will be disabled for the current process. You can test this by running a script that would typically trigger `AMSI` (e.g., running `Invoke-Mimikatz` or other known malicious commands).

# Example Output
![output](https://raw.githubusercontent.com/Chainski/GlobalAMSIBypass/refs/heads/main/assets/output.jpg)

# References
[PowerShell and the .NET AMSI Interface](https://s3cur3th1ssh1t.github.io/Powershell-and-the-.NET-AMSI-Interface)

# License
This project is licensed under the MIT License. See the [LICENSE](https://github.com/Chainski/GlobalAMSIBypass#GPL-3.0-1-ov-file) file for details.

# Caution 
- Intended Use: This script is designed for educational purposes, security research, and authorized red team engagements. Unauthorized use may violate applicable laws or policies.
- Detection Avoidance: While this bypass avoids `Add-Type` and uses stealth techniques, modern EDR solutions may still detect memory patching or suspicious PowerShell activity. Use with caution and test in a controlled environment.
