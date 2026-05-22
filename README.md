# YellowKey
YellowKey Bitlocker Bypass Vulnerability

Been a while since I saw a bitlocker bypass around, my turn.

This is one of the most insane discoveries I ever found, almost feels like **backdoor** but what do you know, maybe I'm just insane.

How to reproduce : 
1. Copy the FsTx folder to "**YourUSBStick:**\System Volume Information\FsTx" as is and make sure to use a filesystem that's compatible with Windows (NTFS is preferable but I think FAT32/exFAT should work as well). Funny thing is, the vulnerability is extremely convenient, you don't even need to plug an external storage device, you can just pull out the disk, copy the files in the EFI partition, put it back and it will still work. That's how bad it is.
2. Plug the USB stick in your target windows computer with bitlocker protection turned on.
3. Reboot to Windows Recovery Environment Agent (you can do that by holding SHIFT and clicking on the restart button using your mouse)
4. Once you click on the restart button, lift your finger off the SHIFT key and hold CRTL and do NOT lift your finger off it.
5. If you did everything properly, a shell will spawn with unrestricted access to the bitlocker protected volume.

<img width="1370" height="777" alt="shell" src="https://github.com/user-attachments/assets/eda6c823-4a6b-4aec-bad2-b9afad640dd6" />


Now why would I say this is a **backdoor** ? The component that is responsible for this bug is not present anywhere (even in the internet) except inside WinRE image and what makes it raise suspicions is the fact that the exact same component is also present with the exact same name in a normal windows installation but without the functionalities that trigger the bitlocker bypass issue. Why ? I just can't come up with an explanation beside the fact that this was intentional. Also for whatever reason, only windows 11 (+Server 2022/2025) are affect, windows 10 is not.

A huge thanks to MORSE, MSTIC and Microsoft GHOST for making this public disclosure possible ;)

---

## Detection

[`Detect-YellowKey.ps1`](Detect-YellowKey.ps1) is a PowerShell detection script that scans for all known IoCs associated with this vulnerability. Must be run as Administrator.

```powershell
powershell -ExecutionPolicy Bypass -File .\Detect-YellowKey.ps1
```

Checks performed:
- FsTx artifact directory on all volumes (by path, file size, and CLFS magic bytes)
- UTF-16 `winpeshl.ini` target path embedded in CLFS log containers
- KTM registry entries for known transaction GUIDs
- `$TXF_DATA` alternate data stream on `winpeshl.ini`
- TxF metadata directories on all volumes
- KTM operational event log

---

## Analysis

[`IS-THIS-MALWARE.md`](IS-THIS-MALWARE.md) contains a full binary analysis of the FsTx artifact, including entropy measurements, malware pattern checks, and a complete accounting of every string found in the files.

**Verdict: not malware.** The artifact contains no executable code, no shellcode, no network infrastructure, and no hidden payload. Every byte is accounted for as standard CLFS/TxF data structures and the two file paths that form the exploit mechanism.
