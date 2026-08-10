# winget-pkgs PR Test [![License][license-badge]][license-link] ![Visitors](https://api.visitorbadge.io/api/visitors?path=https%3A%2F%2Fgithub.com%2FUnownPlain%2Fwinget-pkgs-pr-test%2F&label=Visitors&labelColor=%230c0d10&countColor=%233a71c1)

[license-badge]: https://img.shields.io/github/license/UnownPlain/winget-pkgs-pr-test?style=for-the-badge&labelColor=0c0d10&color=3a71c1&&logo=data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjQiIGhlaWdodD0iMjQiIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHBhdGggZD0iTTEwLjk2ODQgMi4zMjQ2NUMxMS41ODMgMS44NzYxNiAxMi40MTcgMS44NzYxNiAxMy4wMzE2IDIuMzI0NjVMMjAuNDUzNCA3Ljc0MDZDMjEuNDI5OSA4LjQ1MzE1IDIwLjkyNjggOS45OTgzNSAxOS43MTg5IDEwLjAwMDNINC4yODEwOEMzLjA3MzE4IDkuOTk4MzUgMi41NzAxMSA4LjQ1MzE1IDMuNTQ2NTcgNy43NDA2TDEwLjk2ODQgMi4zMjQ2NVpNMTMgNi4yNTAzNEMxMyA1LjY5ODA1IDEyLjU1MjMgNS4yNTAzNCAxMiA1LjI1MDM0QzExLjQ0NzcgNS4yNTAzNCAxMSA1LjY5ODA1IDExIDYuMjUwMzRDMTEgNi44MDI2MiAxMS40NDc3IDcuMjUwMzQgMTIgNy4yNTAzNEMxMi41NTIzIDcuMjUwMzQgMTMgNi44MDI2MiAxMyA2LjI1MDM0WiIgZmlsbD0iIzNhNzFjMSIvPgo8cGF0aCBkPSJNMTEuMjUgMTYuMDAwM0g5LjI1VjExLjAwMDNIMTEuMjVWMTYuMDAwM1oiIGZpbGw9IiMzYTcxYzEiLz4KPHBhdGggZD0iTTE0Ljc1IDE2LjAwMDNIMTIuNzVWMTEuMDAwM0gxNC43NVYxNi4wMDAzWiIgZmlsbD0iIzNhNzFjMSIvPgo8cGF0aCBkPSJNMTguNSAxNi4wMDAzSDE2LjI1VjExLjAwMDNIMTguNVYxNi4wMDAzWiIgZmlsbD0iIzNhNzFjMSIvPgo8cGF0aCBkPSJNMTguNzUgMTcuMDAwM0g1LjI1QzQuMDA3MzYgMTcuMDAwMyAzIDE4LjAwNzcgMyAxOS4yNTAzVjE5Ljc1MDNDMyAyMC4xNjQ1IDMuMzM1NzkgMjAuNTAwMyAzLjc1IDIwLjUwMDNIMjAuMjVDMjAuNjY0MiAyMC41MDAzIDIxIDIwLjE2NDUgMjEgMTkuNzUwM1YxOS4yNTAzQzIxIDE4LjAwNzcgMTkuOTkyNiAxNy4wMDAzIDE4Ljc1IDE3LjAwMDNaIiBmaWxsPSIjM2E3MWMxIi8+CjxwYXRoIGQ9Ik03Ljc1IDE2LjAwMDNINS41VjExLjAwMDNINy43NVYxNi4wMDAzWiIgZmlsbD0iIzNhNzFjMSIvPgo8L3N2Zz4K
[license-link]: https://github.com/UnownPlain/winget-pkgs-pr-test/blob/HEAD/LICENSE.md

Fast and simple PowerShell script to test WinGet manifest PRs in a VM. Does not require a clone of the repository.

## Setup

### Automatic

You can use the [`autounattend.xml`](https://github.com/UnownPlain/winget-pkgs-pr-test/blob/HEAD/autounattend.xml) or [`unattend.iso`](https://github.com/UnownPlain/winget-pkgs-pr-test/blob/HEAD/unattend.iso) file present in this repository to automatically setup a minimal VM.

- [Hyper-V](https://schneegans.de/windows/unattend-generator/usage/#installation-hyperv)
- [VMware Workstation](https://schneegans.de/windows/unattend-generator/usage/#installation-vmware)
- [Oracle VirtualBox](https://schneegans.de/windows/unattend-generator/usage/#installation-virtualbox)
- [Proxmox VE](https://schneegans.de/windows/unattend-generator/usage/#installation-proxmox)
- [Parallels Desktop](https://schneegans.de/windows/unattend-generator/usage/#installation-parallels)

### Manual

Create a VM and run the following in an elevated PowerShell window:

```powershell
irm https://raw.githubusercontent.com/UnownPlain/winget-pkgs-pr-test/HEAD/bootstrap.ps1 | iex
```

## Usage

Once the VM is setup, snapshot the VM and start testing:

```powershell
PRTest {pr_number}
PRTest https://github.com/{owner}/{repository}/pull/{pr_number}
```

A PR number uses [`microsoft/winget-pkgs`](https://github.com/microsoft/winget-pkgs) by default. Use the full GitHub PR URL to test a PR from any repository with the same `manifests` or `fonts` directory structure.

Font manifests require WinGet 1.12 or later. `PRTest` detects font manifests automatically and reports the font files registered for the current user or machine.

It's recommended to restore to the snapshot after every test.
