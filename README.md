# Reverse Engineering Projects

## Project 1: Malware Analysis and Reverse Engineering
[Reverse Project 1](revproject1.pdf)

**Objective:**  
The goal of this assignment was to find malicious files and perform malware analysis using both static and dynamic techniques to analyze an infected executable file.

**Phases:**
- **Virtualization Phase:**  
  - Setting up virtual environments using VMware and VirtualBox for Windows XP and Windows 10.
  
- **Malware Collection:**  
  - Obtaining malware samples from online sources such as [Malware Bazaar](https://bazaar.abuse.ch/).

- **Static Analysis Techniques:**  
  - VirusTotal scan and hash calculations using `MD5Deep` and `HashCalc`.  
  - Analyzing file structure using **PE analysis tools** like `PEiD`, `LordPE`, and `PEview`.  
  - Extracting embedded strings and suspicious text using tools such as `Strings` and `BinText`.  

- **Dynamic Analysis Techniques:**  
  - Observing runtime behavior using sandbox environments such as Triage.  
  - Using tools like `Process Monitor`, `Process Explorer`, and `RegShot` to track system changes.  

**Conclusion:**  
The malware sample exhibited clear signs of obfuscation and malicious behavior, including suspicious timestamps, injected processes, and unauthorized system access.

---

## Project 2: Reverse Engineering of Suspicious Executables
[Reverse Project 2](revproject2.pdf)

**Objective:**  
The purpose of this assignment was to reverse engineer various malware samples (`MAL01.dll`, `MAL02.py`, `MAL03.exe`, `MAL04.exe`) that were provided, using disassembly and static analysis techniques.

**Phases:**
- **Static Analysis:**  
  - Using **IDA Pro** (versions 5.0 on Windows XP and version 8.3 on Windows 10) to analyze disassembled code across different operating systems.  
  - Investigating API calls such as `gethostbyname`, `CreateThread`, and `RegOpenKeyExA`.  
  - Identifying obfuscation techniques and understanding malware functionalities.  

- **Behavioral Analysis:**  
  - Examining network-based indicators like URLs accessed.
  - Investigating system interactions such as registry key manipulations and process injections.  
  - Analyzing encrypted strings and encoded payloads.

**Conclusion:**  
Reverse engineering revealed that the malware samples leveraged stealth techniques such as process injection and command execution based on the host OS version.

---
